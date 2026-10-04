"""Analizador de accesos directos de Windows (.lnk).

Un .lnk adjunto no tiene ningún uso comercial legítimo y es uno de los vehículos favoritos para
entregar malware desde 2022 (cuando Office bloqueó las macros): parece un documento pero al abrirlo
lanza cmd/PowerShell/mshta. Por eso cualquier .lnk ya es HIGH, y se buscan además:

- objetivo = LOLBin (cmd, powershell, mshta, wscript, rundll32, regsvr32, msiexec, certutil...) => HIGH 85;
- argumentos revisados con el motor de `_indicators` (descargas, -EncodedCommand, ofuscación...);
- argumentos "rellenados" con espacios/saltos de línea para esconder el comando real en la ventana
  de propiedades (técnica ZDI-CAN-25373, explotada masivamente en 2024-2025);
- ícono de PDF/Word/Edge o de las bibliotecas de íconos del sistema para disfrazarse de documento;
- archivos .lnk enormes o con datos pegados al final (payload embebido).

El formato (MS-SHLLINK) se parsea con un lector propio, acotado y tolerante a archivos rotos; si
LnkParse3 está instalado se usa además para enriquecer los nombres de la lista de IDs del objetivo.
"""

from __future__ import annotations

import asyncio
import logging
import re
import struct
import threading
import warnings
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, ClassVar

from centinela.analyzers import _indicators as ind
from centinela.analyzers.base import ArtifactAnalyzer
from centinela.core.models import Finding, FindingCategory, Severity

if TYPE_CHECKING:
    from centinela.analyzers.base import AnalysisContext
    from centinela.core.models import Artifact

log = logging.getLogger(__name__)

HEADER_SIZE = 0x4C
LINK_CLSID = bytes.fromhex("0114020000000000c000000000000046")
MAX_LNK_PARSE_BYTES = 4 * 1024 * 1024
MAX_IDLIST_ITEMS = 64
MAX_EXTRA_BLOCKS = 64
LARGE_LNK_BYTES = 100 * 1024
APPENDED_DATA_MIN = 4096

# LinkFlags (MS-SHLLINK 2.1.1)
F_HAS_IDLIST = 0x1
F_HAS_LINKINFO = 0x2
F_HAS_NAME = 0x4
F_HAS_RELPATH = 0x8
F_HAS_WORKDIR = 0x10
F_HAS_ARGS = 0x20
F_HAS_ICON = 0x40
F_UNICODE = 0x80
F_FORCE_NO_LINKINFO = 0x100

SW_SHOWMINNOACTIVE = 7
SW_SHOWMAXIMIZED = 3

# objetivos que convierten al .lnk en un lanzador de código (spec + LOLBins frecuentes en campañas)
LOLBIN_TARGETS = frozenset(
    {
        "cmd.exe",
        "powershell.exe",
        "powershell_ise.exe",
        "pwsh.exe",
        "mshta.exe",
        "wscript.exe",
        "cscript.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "conhost.exe",
        "msiexec.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "curl.exe",
        "forfiles.exe",
        "wmic.exe",
        "schtasks.exe",
        "hh.exe",
        "cmstp.exe",
        "msbuild.exe",
        "installutil.exe",
        "regasm.exe",
        "regsvcs.exe",
        "odbcconf.exe",
        "pcalua.exe",
        "finger.exe",
        "ftp.exe",
        "msdt.exe",
        "scriptrunner.exe",
        "bash.exe",
        "wsl.exe",
        "mavinject.exe",
        "presentationhost.exe",
        "syncappvpublishingserver.exe",
        "syncappvpublishingserver.vbs",
        "msxsl.exe",
        "tar.exe",
        "expand.exe",
        "extrac32.exe",
        "esentutl.exe",
    }
)
SCRIPT_EXTS = frozenset({"js", "jse", "vbs", "vbe", "wsf", "wsh", "bat", "cmd", "ps1", "hta", "py", "pyw"})
DOC_EXTS = frozenset(
    {
        "pdf",
        "doc",
        "docx",
        "docm",
        "xls",
        "xlsx",
        "xlsm",
        "ppt",
        "pptx",
        "rtf",
        "txt",
        "csv",
        "odt",
        "ods",
        "jpg",
        "jpeg",
        "png",
        "gif",
        "bmp",
        "htm",
        "html",
        "zip",
        "rar",
        "7z",
        "xml",
    }
)
DOC_APPS = frozenset(
    {
        "acrord32.exe",
        "acrobat.exe",
        "msedge.exe",
        "chrome.exe",
        "firefox.exe",
        "iexplore.exe",
        "winword.exe",
        "excel.exe",
        "powerpnt.exe",
        "notepad.exe",
        "wordpad.exe",
        "write.exe",
        "foxitreader.exe",
        "foxitpdfreader.exe",
        "sumatrapdf.exe",
        "mspaint.exe",
        "outlook.exe",
        "onenote.exe",
    }
)
SYSTEM_ICON_LIBS = frozenset(
    {"shell32.dll", "imageres.dll", "moricons.dll", "pifmgr.dll", "ddores.dll", "wmploc.dll"}
)

_WS_CHARS = " \t\r\n\x0b\x0c"
_WS_RUN_RE = re.compile(r"(?<![ \t\r\n\x0b\x0c])[ \t\r\n\x0b\x0c]{50,}")
_URL_RE = re.compile(r"(?i)\b(?:https?|ftp)://|\\\\[\w.\-]+@(?:ssl|\d+)\\|\\\\[\w.\-]+\\")
_UNC_RE = re.compile(r"^\s*[\"']?\\\\[^\\\s]+\\", re.IGNORECASE)


class LnkFormatError(ValueError):
    """El archivo no es un ShellLink válido."""


@dataclass
class LnkData:
    flags: int = 0
    file_attributes: int = 0
    icon_index: int = 0
    show_command: int = 1
    idlist_names: list[str] = field(default_factory=list)
    idlist_strings: list[str] = field(default_factory=list)
    local_base_path: str | None = None
    common_path_suffix: str | None = None
    net_name: str | None = None
    name: str | None = None
    relative_path: str | None = None
    working_dir: str | None = None
    arguments: str | None = None
    icon_location: str | None = None
    env_target: str | None = None
    icon_env_target: str | None = None
    darwin: bool = False
    machine_id: str | None = None
    extra_blocks: list[str] = field(default_factory=list)
    parsed_size: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def linkinfo_path(self) -> str | None:
        if self.local_base_path:
            return self.local_base_path + (self.common_path_suffix or "")
        if self.net_name:
            suffix = self.common_path_suffix or ""
            return self.net_name + ("\\" + suffix if suffix else "")
        return None

    @property
    def idlist_path(self) -> str | None:
        return "\\".join(n.rstrip("\\") for n in self.idlist_names) if self.idlist_names else None

    def target_candidates(self) -> list[str]:
        out = [self.linkinfo_path, self.env_target, self.idlist_path, self.relative_path]
        return [c for c in out if c]

    @property
    def target(self) -> str | None:
        cands = self.target_candidates()
        return cands[0] if cands else None


class _Truncated(Exception):
    pass


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data

    def u16(self, off: int) -> int:
        if off < 0 or off + 2 > len(self.data):
            raise _Truncated(off)
        return struct.unpack_from("<H", self.data, off)[0]

    def u32(self, off: int) -> int:
        if off < 0 or off + 4 > len(self.data):
            raise _Truncated(off)
        return struct.unpack_from("<I", self.data, off)[0]

    def i32(self, off: int) -> int:
        if off < 0 or off + 4 > len(self.data):
            raise _Truncated(off)
        return struct.unpack_from("<i", self.data, off)[0]

    def take(self, off: int, n: int) -> bytes:
        if off < 0 or n < 0 or off + n > len(self.data):
            raise _Truncated(off)
        return self.data[off : off + n]


def _cstr(buf: bytes, off: int, *, unicode: bool = False, limit: int = 4096) -> str | None:
    if off <= 0 or off >= len(buf):
        return None
    if unicode:
        end = off
        while end + 1 < len(buf) and end - off < limit * 2:
            if buf[end] == 0 and buf[end + 1] == 0:
                break
            end += 2
        return buf[off:end].decode("utf-16-le", "replace") or None
    end = buf.find(b"\x00", off, off + limit)
    if end < 0:
        end = min(len(buf), off + limit)
    return buf[off:end].decode("cp1252", "replace") or None


def _fixed_str(raw: bytes, *, unicode: bool) -> str | None:
    if unicode:
        for i in range(0, len(raw) - 1, 2):
            if raw[i] == 0 and raw[i + 1] == 0:
                raw = raw[:i]
                break
        return raw.decode("utf-16-le", "replace") or None
    return raw.split(b"\x00", 1)[0].decode("cp1252", "replace") or None


_ASCII_STR_RE = re.compile(rb"[\x20-\x7e]{3,}")
_UTF16_STR_RE = re.compile(rb"(?:[\x20-\x7e]\x00){3,}")


def _parse_idlist(idlist: bytes, out: LnkData) -> None:
    off = 0
    for _ in range(MAX_IDLIST_ITEMS):
        if off + 2 > len(idlist):
            break
        size = struct.unpack_from("<H", idlist, off)[0]
        if size == 0:
            break
        if size < 3:
            out.errors.append("elemento de IDList inválido")
            break
        item = idlist[off + 2 : off + size]
        off += size
        if not item:
            continue
        cls = item[0]
        if cls & 0x70 == 0x20 and len(item) > 1:  # volumen ("C:\")
            name = item[1:21].split(b"\x00", 1)[0].decode("cp1252", "replace")
            if name:
                out.idlist_names.append(name)
        elif cls & 0x70 == 0x30 and len(item) > 12:  # archivo / carpeta
            unicode = bool(cls & 0x04)
            primary = _cstr(item, 12, unicode=unicode, limit=260)
            if primary:
                out.idlist_names.append(primary)
        for m in _UTF16_STR_RE.finditer(item):
            out.idlist_strings.append(m.group(0).decode("utf-16-le", "replace"))
        for m in _ASCII_STR_RE.finditer(item):
            out.idlist_strings.append(m.group(0).decode("ascii", "replace"))
        if len(out.idlist_strings) > 128:
            break


def _parse_linkinfo(li: bytes, out: LnkData) -> None:
    r = _Reader(li)
    header_size = r.u32(4)
    li_flags = r.u32(8)
    local_off = r.u32(16)
    cnrl_off = r.u32(20)
    suffix_off = r.u32(24)
    local_u_off = r.u32(28) if header_size >= 0x24 else 0
    suffix_u_off = r.u32(32) if header_size >= 0x24 else 0
    if li_flags & 0x1:
        out.local_base_path = _cstr(li, local_u_off, unicode=True) if local_u_off else None
        out.local_base_path = out.local_base_path or _cstr(li, local_off)
    if li_flags & 0x2 and 0 < cnrl_off < len(li):
        try:
            net_name_off = r.u32(cnrl_off + 8)
            out.net_name = _cstr(li, cnrl_off + net_name_off)
        except _Truncated:
            out.errors.append("CommonNetworkRelativeLink truncado")
    suffix = _cstr(li, suffix_u_off, unicode=True) if suffix_u_off else None
    out.common_path_suffix = suffix or _cstr(li, suffix_off)


def parse_lnk(data: bytes) -> LnkData:
    """Parsea un .lnk (MS-SHLLINK) de forma defensiva. Lanza LnkFormatError si no es un ShellLink."""
    data = data[:MAX_LNK_PARSE_BYTES]
    r = _Reader(data)
    if len(data) < HEADER_SIZE or data[:4] != b"\x4c\x00\x00\x00" or data[4:20] != LINK_CLSID:
        raise LnkFormatError("cabecera ShellLink inválida")
    out = LnkData(
        flags=r.u32(20),
        file_attributes=r.u32(24),
        icon_index=r.i32(56),
        show_command=r.u32(60),
    )
    pos = HEADER_SIZE
    try:
        if out.flags & F_HAS_IDLIST:
            size = r.u16(pos)
            _parse_idlist(r.take(pos + 2, size), out)
            pos += 2 + size
        if out.flags & F_HAS_LINKINFO and not out.flags & F_FORCE_NO_LINKINFO:
            size = r.u32(pos)
            if size < 0x1C:
                raise _Truncated(pos)
            try:
                _parse_linkinfo(r.take(pos, size), out)
            except _Truncated:
                out.errors.append("LinkInfo truncado")
            pos += size
        unicode = bool(out.flags & F_UNICODE)
        for flag, attr in (
            (F_HAS_NAME, "name"),
            (F_HAS_RELPATH, "relative_path"),
            (F_HAS_WORKDIR, "working_dir"),
            (F_HAS_ARGS, "arguments"),
            (F_HAS_ICON, "icon_location"),
        ):
            if out.flags & flag:
                count = r.u16(pos)
                nbytes = count * 2 if unicode else count
                raw = r.take(pos + 2, nbytes)
                setattr(out, attr, raw.decode("utf-16-le" if unicode else "cp1252", "replace"))
                pos += 2 + nbytes
        for _ in range(MAX_EXTRA_BLOCKS):
            size = r.u32(pos)
            if size < 4:  # TerminalBlock
                pos += 4
                break
            if size < 8:
                out.errors.append("bloque extra inválido")
                break
            sig = r.u32(pos + 4)
            block = r.take(pos, size)
            out.extra_blocks.append(f"0x{sig:08X}")
            if sig in (0xA0000001, 0xA0000007, 0xA0000006) and size >= 0x314:
                target = _fixed_str(block[268:788], unicode=True) or _fixed_str(block[8:268], unicode=False)
                if sig == 0xA0000001:
                    out.env_target = target
                elif sig == 0xA0000007:
                    out.icon_env_target = target
                else:
                    out.darwin = True
            elif sig == 0xA0000003 and size >= 0x60:
                out.machine_id = _fixed_str(block[16:32], unicode=False)
            pos += size
    except _Truncated:
        out.errors.append("archivo truncado o con tamaños inconsistentes")
    out.parsed_size = min(pos, len(data))
    return out


# --------------------------------------------------------------------------- LnkParse3 (opcional)

_LNKPARSE_LOCK = threading.Lock()  # catch_warnings toca estado global: serializamos su uso


def _lnkparse3_strings(data: bytes) -> list[str]:
    """Nombres extra del objetivo según LnkParse3 (si está instalado). Nunca lanza excepciones."""
    try:
        import LnkParse3  # noqa: N813 - nombre del paquete
    except ImportError:
        return []
    out: list[str] = []
    try:
        with _LNKPARSE_LOCK, warnings.catch_warnings():
            warnings.simplefilter("ignore")
            info = LnkParse3.lnk_file(indata=data[:MAX_LNK_PARSE_BYTES]).get_json()
        for item in (info.get("target") or {}).get("items") or []:
            if isinstance(item, dict):
                for key in ("primary_name", "volume_name", "location"):
                    val = item.get(key)
                    if isinstance(val, str) and val:
                        out.append(val)
        link_info = info.get("link_info") or {}
        for key in ("local_base_path", "local_base_path_unicode", "common_path_suffix"):
            val = link_info.get(key)
            if isinstance(val, str) and val:
                out.append(val)
        env = (info.get("extra") or {}).get("ENVIRONMENTAL_VARIABLES_LOCATION_BLOCK") or {}
        for key in ("target_unicode", "target_ansi"):
            val = env.get(key)
            if isinstance(val, str) and val:
                out.append(val)
    except Exception as exc:  # noqa: BLE001 - archivos hostiles: LnkParse3 puede fallar de mil formas
        log.debug("LnkParse3 no pudo parsear el .lnk: %s", type(exc).__name__)
    return out[:64]


# --------------------------------------------------------------------------- helpers


_ENV_ALIASES = {"%comspec%": "cmd.exe"}


def _basename(path: str) -> str:
    """Nombre de archivo en minúsculas de una ruta Windows (acepta comillas y %VARIABLES%)."""
    p = path.strip().strip("\"'").strip()
    alias = _ENV_ALIASES.get(p.lower())
    if alias:
        return alias
    for sep in ("\\", "/"):
        if sep in p:
            p = p.rsplit(sep, 1)[-1]
    return p.strip().lower()


def _ext(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def _lolbin_of(name: str) -> str | None:
    if name in LOLBIN_TARGETS:
        return name
    if "." not in name and f"{name}.exe" in LOLBIN_TARGETS:
        return f"{name}.exe"
    return None


def _first_token(cmdline: str) -> str:
    s = cmdline.strip()
    if s.startswith('"'):
        end = s.find('"', 1)
        return s[1:end] if end > 0 else s[1:]
    return s.split(None, 1)[0] if s else ""


class LnkAnalyzer(ArtifactAnalyzer):
    name: ClassVar[str] = "lnk"

    def accepts(self, artifact: Artifact) -> bool:
        return artifact.detected_type == "lnk"

    async def analyze(self, ctx: AnalysisContext, artifact: Artifact) -> list[Finding]:
        return await asyncio.to_thread(self._analyze_sync, artifact)

    # ------------------------------------------------------------------ síncrono (en thread)
    def _analyze_sync(self, artifact: Artifact) -> list[Finding]:
        data = artifact.data or b""
        findings: list[Finding] = []
        try:
            lnk = parse_lnk(data)
        except (LnkFormatError, _Truncated, struct.error) as exc:
            findings.append(
                self._baseline(artifact, None, note=f"no se pudo interpretar el acceso directo ({exc})")
            )
            if len(data) > LARGE_LNK_BYTES:
                findings.append(self._appended(artifact, data, 0))
            return findings
        extra_names = _lnkparse3_strings(data)

        findings.append(self._baseline(artifact, lnk))

        target = lnk.target or ""
        names = [_basename(c) for c in lnk.target_candidates()]
        names += [_basename(s) for s in lnk.idlist_strings + extra_names]
        args = lnk.arguments or ""
        lolbin = next((lb for lb in (_lolbin_of(n) for n in names if n) if lb), None)
        if lolbin is None and not target and args:
            # sin objetivo explícito: a veces el ejecutable va al principio de los argumentos
            lolbin = _lolbin_of(_basename(_first_token(args)))

        hidden_window = lnk.show_command == SW_SHOWMINNOACTIVE
        common_ev = {
            "objetivo": ind.clean_snippet(target or "(desconocido)", 200),
            "argumentos": ind.clean_snippet(args, 200) if args else None,
            "ventana": "minimizada/oculta" if hidden_window else None,
        }
        common_ev = {k: v for k, v in common_ev.items() if v}

        if lolbin:
            findings.append(
                Finding(
                    analyzer=self.name,
                    rule="lnk.lolbin_target",
                    title=f"El acceso directo ejecuta {lolbin}",
                    description=(
                        f"Al abrir este acceso directo se ejecuta {lolbin}, una herramienta de Windows capaz de "
                        "correr comandos, descargar archivos o instalar programas. Es exactamente cómo se "
                        "disfrazan hoy los virus que llegan por mail: parecen un documento, pero lanzan "
                        "un comando escondido."
                    ),
                    category=FindingCategory.SUSPICIOUS_FILE,
                    severity=Severity.HIGH,
                    score=85,
                    artifact_id=artifact.id,
                    evidence={**common_ev, "programa": lolbin},
                )
            )
        elif any(n == "explorer.exe" for n in names) and _URL_RE.search(args):
            findings.append(
                Finding(
                    analyzer=self.name,
                    rule="lnk.lolbin_target",
                    title="El acceso directo abre una dirección remota con explorer.exe",
                    description=(
                        "Este acceso directo usa el Explorador de Windows para abrir una dirección de Internet o "
                        "una carpeta de red remota, una técnica usada para traer y ejecutar archivos del atacante."
                    ),
                    category=FindingCategory.SUSPICIOUS_FILE,
                    severity=Severity.HIGH,
                    score=85,
                    artifact_id=artifact.id,
                    evidence={**common_ev, "programa": "explorer.exe"},
                )
            )
        else:
            target_name = _basename(target) if target else ""
            if _ext(target_name) in SCRIPT_EXTS:
                findings.append(
                    Finding(
                        analyzer=self.name,
                        rule="lnk.script_target",
                        title="El acceso directo ejecuta un script",
                        description=(
                            f"Este acceso directo lanza el script '{ind.clean_snippet(target_name, 80)}'. Un acceso "
                            "directo que ejecuta un script es una forma típica de esconder un virus."
                        ),
                        category=FindingCategory.SUSPICIOUS_FILE,
                        severity=Severity.HIGH,
                        score=75,
                        artifact_id=artifact.id,
                        evidence=common_ev,
                    )
                )
        if any(_UNC_RE.match(c) for c in lnk.target_candidates()) or _UNC_RE.match(_first_token(args) or ""):
            findings.append(
                Finding(
                    analyzer=self.name,
                    rule="lnk.remote_target",
                    title="El acceso directo apunta a un servidor remoto",
                    description=(
                        "El programa que ejecuta este acceso directo está en una carpeta de red o servidor WebDAV "
                        "de Internet, no en tu computadora: el atacante puede cambiarlo cuando quiera."
                    ),
                    category=FindingCategory.SUSPICIOUS_FILE,
                    severity=Severity.HIGH,
                    score=80,
                    artifact_id=artifact.id,
                    evidence=common_ev,
                )
            )

        hidden = self._hidden_args(artifact, args)
        if hidden:
            findings.append(hidden)
        icon = self._deceptive_icon(artifact, lnk, bool(lolbin))
        if icon:
            findings.append(icon)
        trailing = len(data) - lnk.parsed_size
        if len(data) > LARGE_LNK_BYTES or trailing >= APPENDED_DATA_MIN:
            findings.append(self._appended(artifact, data, lnk.parsed_size))

        # comando completo (objetivo + argumentos) por el motor compartido de indicadores
        scan_parts = [target, args]
        if trailing > 0:
            tail, _ = ind.decode_text(data[lnk.parsed_size :][: 1024 * 1024], 1024 * 1024)
            if ind.printable_ratio(tail[:8192]) >= 0.85:
                scan_parts.append(tail)
        command = " ".join(p for p in scan_parts if p)
        if command.strip():
            result = ind.scan_text(command, profile="script")
            findings.extend(
                ind.findings_from_scan(
                    result,
                    analyzer=self.name,
                    prefix="lnk",
                    artifact_id=artifact.id,
                    where="acceso directo (.lnk)",
                )
            )
        return findings

    # ------------------------------------------------------------------ hallazgos
    def _baseline(self, artifact: Artifact, lnk: LnkData | None, *, note: str | None = None) -> Finding:
        evidence: dict = {"archivo": ind.clean_snippet(artifact.filename or "", 120), "tamano": artifact.size}
        if lnk is not None:
            if lnk.target:
                evidence["objetivo"] = ind.clean_snippet(lnk.target, 200)
            if lnk.arguments:
                evidence["argumentos"] = ind.clean_snippet(lnk.arguments, 200)
            if lnk.name:
                evidence["descripcion"] = ind.clean_snippet(lnk.name, 120)
            if lnk.working_dir:
                evidence["carpeta_de_trabajo"] = ind.clean_snippet(lnk.working_dir, 120)
            if lnk.machine_id:
                evidence["equipo_de_origen"] = ind.clean_snippet(lnk.machine_id, 40)
            if lnk.darwin:
                evidence["instalador_msi_anunciado"] = True
            if lnk.errors:
                evidence["anomalias"] = ind.cap_list(lnk.errors, 4)
        if artifact.depth > 0:
            evidence["dentro_de"] = artifact.parent_id
        if note:
            evidence["nota"] = note
        return Finding(
            analyzer=self.name,
            rule="lnk.attachment",
            title="Acceso directo de Windows (.lnk) adjunto",
            description=(
                "Llegó un acceso directo de Windows. No es un documento: al abrirlo ejecuta un programa. No hay "
                "ningún motivo comercial para mandar accesos directos por mail y es una de las formas más usadas "
                "hoy para instalar virus. No lo abras."
            ),
            category=FindingCategory.SUSPICIOUS_FILE,
            severity=Severity.HIGH,
            score=60,
            artifact_id=artifact.id,
            evidence=evidence,
        )

    def _hidden_args(self, artifact: Artifact, args: str) -> Finding | None:
        if not args:
            return None
        lead = len(args) - len(args.lstrip(_WS_CHARS))
        longest = max((len(m.group(0)) for m in _WS_RUN_RE.finditer(args)), default=0)
        has_newline = any(c in args for c in "\r\n\x0b\x0c")
        padded = len(args) > 255 and (lead >= 50 or longest >= 50)
        if not (padded or (has_newline and args.strip())):
            return None
        visible = ind.clean_snippet(args[:260], 120) or "(solo espacios)"
        hidden_part = args[260:] if len(args) > 260 else args.strip(_WS_CHARS)
        return Finding(
            analyzer=self.name,
            rule="lnk.hidden_arguments",
            title="Comando escondido con espacios en blanco",
            description=(
                "Los argumentos del acceso directo están rellenados con espacios o saltos de línea para que Windows "
                "no muestre el comando real en la ventana de propiedades. Es un engaño deliberado."
            ),
            category=FindingCategory.SUSPICIOUS_FILE,
            severity=Severity.MEDIUM,
            score=45,
            artifact_id=artifact.id,
            evidence={
                "largo_argumentos": len(args),
                "espacios_al_inicio": lead,
                "mayor_relleno": longest,
                "parte_visible": visible,
                "parte_oculta": ind.clean_snippet(hidden_part, 160),
            },
        )

    def _deceptive_icon(self, artifact: Artifact, lnk: LnkData, lolbin: bool) -> Finding | None:
        icon = lnk.icon_location or lnk.icon_env_target
        if not icon:
            return None
        base = _basename(icon)
        ext = _ext(base)
        reason = None
        if ext in DOC_EXTS:
            reason = f"usa el ícono de un archivo .{ext}"
        elif base in DOC_APPS:
            reason = f"usa el ícono de {base}"
        elif base in SYSTEM_ICON_LIBS and lolbin:
            reason = f"usa un ícono de {base} (índice {lnk.icon_index}) para parecer un documento"
        if reason is None:
            return None
        return Finding(
            analyzer=self.name,
            rule="lnk.deceptive_icon",
            title="El acceso directo se disfraza de documento",
            description=(
                f"El acceso directo {reason}, así en el Explorador parece un PDF, una planilla o una página web, "
                "cuando en realidad ejecuta un programa."
            ),
            category=FindingCategory.SUSPICIOUS_FILE,
            severity=Severity.MEDIUM,
            score=40,
            artifact_id=artifact.id,
            evidence={"icono": ind.clean_snippet(icon, 160), "indice": lnk.icon_index},
        )

    def _appended(self, artifact: Artifact, data: bytes, parsed: int) -> Finding:
        tail = data[parsed:] if parsed else b""
        evidence: dict = {"tamano": len(data)}
        if parsed:  # parsed == 0: no se pudo interpretar, no se sabe dónde termina el acceso directo
            evidence["datos_extra"] = len(tail)
        kind = ind.sniff_magic(tail[: ind.ISO_PROBE_BYTES]) if tail else None
        if kind:
            evidence["contenido"] = ind.PAYLOAD_LABELS.get(kind, kind)
        elif tail:
            evidence["entropia"] = round(ind.shannon_entropy(tail[: 1024 * 1024]), 2)
        return Finding(
            analyzer=self.name,
            rule="lnk.appended_payload",
            title="Acceso directo con datos escondidos",
            description=(
                "Un acceso directo normal pesa unos pocos KB. Este es mucho más grande o tiene datos pegados al "
                "final: suele ser un programa o script escondido que el propio acceso directo extrae y ejecuta."
            ),
            category=FindingCategory.SUSPICIOUS_FILE,
            severity=Severity.HIGH,
            score=70,
            artifact_id=artifact.id,
            evidence=evidence,
        )
