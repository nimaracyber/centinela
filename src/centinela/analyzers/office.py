"""Analizador de documentos de Office: Word, Excel, PowerPoint, RTF, XML de Office y código VBA suelto.

Detecta las técnicas de entrega de malware más usadas en documentos:

- macros VBA (autoejecución + ejecución de comandos / descargas / objetos peligrosos), ofuscación,
  VBA stomping (código compilado distinto del código fuente visible);
- macros de Excel 4.0 (XLM), en .xls (BIFF), .xlsm/.xlsb (macrosheets) y SYLK;
- campos DDE/DDEAUTO (Word, RTF, Excel) y fórmulas DDE peligrosas;
- inyección de plantillas remotas, marcos y objetos OLE externos; Follina (CVE-2022-30190) y MSHTML
  (CVE-2021-40444); rutas UNC que filtran credenciales NTLM;
- objetos del Editor de Ecuaciones (CVE-2017-11882 / CVE-2018-0802) y OLE2Link (CVE-2017-0199);
- paquetes OLE ("Package") con ejecutables/scripts incrustados, controles ActiveX;
- documentos cifrados (evasión), con intento de descifrado EN MEMORIA con claves conocidas
  (la clave por defecto de Excel "VelvetSweatshop", las de la configuración y las mencionadas en el mail).

Todo se analiza en memoria con oletools/olefile: nunca se ejecuta ni se escribe a disco el contenido.
El parser de RTF es propio (lineal) porque el de oletools es cuadrático ante RTF hostiles.
Los objetos incrustados en OOXML que el parser ya extrajo como artifacts hijos se analizan en el hijo
(acá solo se lista su presencia/naturaleza) para no contar dos veces el mismo hallazgo.
"""

from __future__ import annotations

import asyncio
import binascii
import contextlib
import hashlib
import html
import io
import itertools
import logging
import re
import threading
import time
import types
import uuid
import warnings
import zipfile
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from centinela.analyzers.base import ArtifactAnalyzer
from centinela.core.models import Finding, FindingCategory, Severity

if TYPE_CHECKING:
    from centinela.analyzers.base import AnalysisContext
    from centinela.core.models import Artifact

log = logging.getLogger(__name__)

try:  # dependencias opcionales: sin oletools el analizador se omite (available() = False)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # olevba usa APIs deprecadas de pyparsing al importarse
        import olefile
        from oletools import oleobj, olevba

    _OLETOOLS_ERROR: str | None = None
except Exception as _exc:  # noqa: BLE001 - cualquier fallo de import deja el analizador no disponible
    olefile = oleobj = olevba = None  # type: ignore[assignment]
    _OLETOOLS_ERROR = f"{type(_exc).__name__}: {_exc}"

# oletools/olefile/msoffcrypto loguean mucho (y a veces contenido del archivo): se silencian.
_QUIET_LOGGERS = (
    "olevba",
    "rtfobj",
    "msodde",
    "oleobj",
    "ooxml",
    "crypto",
    "ftguess",
    "olefile",
    "xls_parser",
    "record_base",
    "ppt_parser",
    "ppt_record_parser",
    "oleform",
    "pcodedmp",
    "msoffcrypto",
)


def _quiet_third_party_logs() -> None:
    for name in _QUIET_LOGGERS:
        lg = logging.getLogger(name)
        lg.setLevel(logging.CRITICAL + 1)
        lg.propagate = False
        if not any(isinstance(h, logging.NullHandler) for h in lg.handlers):
            lg.addHandler(logging.NullHandler())


_quiet_third_party_logs()

# --------------------------------------------------------------------------- límites defensivos

_MAX_INPUT = 80 * 1024 * 1024  # más que esto: no se analiza en profundidad
_MAX_PART = 16 * 1024 * 1024  # parte XML leída de un ZIP (se lee acotada aunque declare más)
_MAX_EMBED = 32 * 1024 * 1024  # objeto incrustado a inspeccionar en el lugar
_MAX_EMBED_TOTAL = 96 * 1024 * 1024
_MAX_ZIP_ENTRIES = 5000
_MAX_RELS = 400
_MAX_EMBEDDINGS = 64
_MAX_VBA_PARTS = 8
_MAX_SHEETS_DDE = 32
_MAX_VBA_CHARS = 4_000_000
_MAX_SCANNER_CHARS = 1_500_000
_MAX_FORM_STRINGS = 400
_MAX_XLM_LINES = 5000
_MAX_OLE_ENTRIES = 4000
_MAX_OLE_STREAM = 24 * 1024 * 1024
_MAX_RTF_TOKENS = 4_000_000
_MAX_RTF_OBJECTS = 64
_MAX_RTF_HEX_TOTAL = 96 * 1024 * 1024
_MAX_RTF_FIELDS = 2000
_MAX_DECRYPT_TRIES = 10
_MAX_XLS_RECORDS = 2_000_000
_EV_STR = 300
_EV_ITEMS = 12

_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_LNK_MAGIC = b"L\x00\x00\x00\x01\x14\x02\x00"
_EXCEL_DEFAULT_KEY = "VelvetSweatshop"  # clave "por defecto" de Excel: el archivo abre sin pedir contraseña

_OFFICE_TYPES = frozenset({"ole", "ooxml", "rtf", "script/vba"})
_OFFICE_EXTS = frozenset(
    "doc docx docm dot dotx dotm wbk xls xlsx xlsm xlsb xlt xltx xltm xla xlam ppt pptx pptm pot potx "
    "potm pps ppsx ppsm ppa ppam sldx sldm rtf".split()
)
_OOXML_EXTS = frozenset(e for e in _OFFICE_EXTS if e.endswith(("x", "m", "b")) and e not in {"xlm"})
_OFFICE_XML_MARKERS = (
    b"schemas.microsoft.com/office/word/2003/wordml",
    b"schemas.microsoft.com/office/2006/xmlpackage",
    b"<?mso-application",
)

# Extensiones que, incrustadas en un documento, son ejecutables o lanzan código con doble clic.
_EXEC_EXTS = frozenset(
    "exe scr com pif bat cmd vbs vbe js jse wsf wsh wsc hta ps1 psm1 psd1 ps1xml lnk dll cpl msi msp msc "
    "jar sct inf reg chm url scf iso img vhd vhdx appref-ms application gadget xll hlp jnlp".split()
)

_EQUATION_CLSIDS = {
    "0002CE02-0000-0000-C000-000000000046": "eqnedt",  # Microsoft Equation 3.0 (EQNEDT32.EXE)
    "00021700-0000-0000-C000-000000000046": "eqnedt",  # Microsoft Equation 2.0
    "0003000B-0000-0000-C000-000000000046": "eqnedt",  # Microsoft Equation
    "0004A6B0-0000-0000-C000-000000000046": "eqnedt",  # Microsoft Equation 2.0
    "0002CE03-0000-0000-C000-000000000046": "mathtype",  # MathType (también usado por exploits)
}
_EQUATION_CLSID_BYTES = {uuid.UUID(k).bytes_le: v for k, v in _EQUATION_CLSIDS.items()}
_STDOLELINK_CLSID = "00000300-0000-0000-C000-000000000046"
_URL_MONIKER = uuid.UUID("79EAC9E0-BAF9-11CE-8C82-00AA004BA90B").bytes_le
_SCRIPT_MONIKER = uuid.UUID("06290BD3-48AA-11D2-8432-006008C3FBFC").bytes_le

# Hosts de Microsoft 365 donde las organizaciones guardan plantillas legítimas.
_M365_TEMPLATE_HOSTS = (".sharepoint.com", ".sharepoint.de", ".sharepoint.cn", ".officeapps.live.com")
_MACRO_FREE_TEMPLATE_EXTS = (".dotx", ".xltx", ".potx", ".thmx")

# --------------------------------------------------------------------------- regex (todas acotadas)

_UTF16_STR_RE = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")
_TAG_RE = re.compile(r"<[^>]{0,2000}>")
_ASCII_URL_RE = re.compile(rb"(?:https?|ftp)://[\x21-\x7e]{3,2000}", re.I)
_WS_BYTES = b" \t\r\n\f\v"

# Campos de Word (OOXML / Word 2003 XML / Flat OPC): fldChar, instrText y fldSimple en orden de aparición.
_FIELD_RE = re.compile(
    rb"<(?:[\w.-]{1,32}:)?(fldChar|instrText|fldSimple)\b([^>]{0,65536})>(?:([^<]{0,65536})<)?"
)
_FLDCHARTYPE_RE = re.compile(rb"fldCharType\s*=\s*[\"'](begin|separate|end)[\"']", re.I)
_DDE_FIELD_RE = re.compile(r"^\s*DDE(?:AUTO)?\b\s*(.{0,1000})", re.I | re.S)
_DANGEROUS_CMD_RE = re.compile(
    r"\b(?:cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh|mshta|rundll32|regsvr32|wscript|cscript|certutil|"
    r"bitsadmin|msiexec|schtasks|curl|bash)\b",
    re.I,
)
_XL_FORMULA_RE = re.compile(rb"<(?:[\w.-]{1,32}:)?f\b[^>]{0,1024}>([^<]{1,8192})</")
_XL_DDE_FORMULA_RE = re.compile(r"^[=+\-@\s]*([A-Za-z0-9_.\\:$~-]{1,128})\s*\|\s*'?([^'!]{0,500})'?\s*!")
_XL_DDE_APPS = frozenset(
    "cmd powershell pwsh mshta msexcel rundll32 regsvr32 wscript cscript certutil bitsadmin msiexec "
    "schtasks explorer conhost forfiles".split()
)
_DDELINK_RE = re.compile(rb"<(?:[\w.-]{1,32}:)?ddeLink\b([^>]{0,8192})>")
_DEFINED_NAME_RE = re.compile(rb"<(?:[\w.-]{1,32}:)?definedName\b([^>]{0,4096})>")
_SHEET_RE = re.compile(rb"<(?:[\w.-]{1,32}:)?sheet\b([^>]{0,4096})>")
_OVERRIDE_RE = re.compile(rb"<(?:[\w.-]{1,32}:)?Override\b([^>]{0,4096})>")
_REL_RE = re.compile(
    rb"<(?:[\w.-]{1,32}:)?Relationship\b((?:[^>\"']|\"[^\"]{0,8192}\"|'[^']{0,8192}'){0,20000})>"
)
_XML_ATTR_RE = re.compile(rb"([\w.:-]{1,64})\s*=\s*(?:\"([^\"]{0,8192})\"|'([^']{0,8192})')")
_ACTIVEX_CLSID_RE = re.compile(rb"classid\s*=\s*[\"']\{?([0-9A-Fa-f-]{36})\}?[\"']", re.I)
_W2003_TEMPLATE_RE = re.compile(rb"<(?:[\w.-]{1,32}:)?attachedTemplate\b([^>]{0,8192})>")
_PKG_PART_RE = re.compile(rb"<(?:[\w.-]{1,32}:)?part\b([^>]{0,4096})>")
_PKG_BINDATA_RE = re.compile(rb"<(?:[\w.-]{1,32}:)?binaryData\s*>")
_W_BINDATA_RE = re.compile(rb"<(?:[\w.-]{1,32}:)?binData\b([^>]{0,4096})>")
_DOC_DDE_RE = re.compile(
    rb"\x13[\x00 \t\r\n]{0,40}(d\x00?d\x00?e\x00?(?:a\x00?u\x00?t\x00?o\x00?)?[\x00 \t][^\x14\x15]{0,1000})",
    re.I,
)
_BODY_PASSWORD_RE = re.compile(
    r"(?:contrase(?:ñ|n)a|clave|password|passwd|senha|pwd|pass|c[oó]digo)\s*"
    r"(?:es|del archivo|del documento|de apertura|para abrir(?:lo)?)?\s*[:=\-]?\s*[\"'«“]?([^\s\"'»”]{3,32})",
    re.I,
)

# Indicadores en código VBA (categoría -> regex). Se usan para graduar la severidad.
_VBA_INDICATORS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "ejecucion",
        re.compile(
            r"\bShell\s*[(\"]|\bShell\s+\w|WScript\.Shell|Shell\.Application|\bShellExecute[AW]?\b|\bWinExec\b|"
            r"\bCreateProcess[AW]?\b|Win32_Process|\bMacScript\b|\bAppleScriptTask\b|\bExecuteExcel4Macro\b|"
            r"\bInvokeVerb(?:Ex)?\b",
            re.I,
        ),
    ),
    (
        "comando",
        re.compile(
            r"\bpowershell(?:\.exe)?\b|\bpwsh\b|\bcmd(?:\.exe)?\s*[/\\][ck]\b|\bmshta(?:\.exe)?\b|\brundll32\b|"
            r"\bregsvr32\b|\bcertutil\b|\bbitsadmin\b|\bwscript(?:\.exe)?\b|\bcscript(?:\.exe)?\b|\bmsiexec\b|"
            r"\bschtasks\b|-e(?:nc|ncodedcommand)\s+[A-Za-z0-9+/=]{20,}",
            re.I,
        ),
    ),
    (
        "descarga",
        re.compile(
            r"URLDownloadToFile[AW]?|(?:MSXML2|Microsoft)\.(?:Server)?XMLHTTP|WinHttp\.WinHttpRequest|"
            r"\bInternetOpen(?:Url)?[AW]?\b|\bInternetReadFile\b|Net\.WebClient|\bDownload(?:File|String|Data)\b|"
            r"Invoke-WebRequest|Start-BitsTransfer|\bXMLHTTP\b",
            re.I,
        ),
    ),
    (
        "objeto_peligroso",
        re.compile(
            r"(?:Create|Get)Object\s*\(\s*\"(?:WScript\.Shell|Shell\.Application|Scripting\.FileSystemObject|"
            r"MSXML2\.|Microsoft\.XMLHTTP|WinHttp\.|ADODB\.Stream|Schedule\.Service|WScript\.Network|new:)|"
            r"GetObject\s*\(\s*\"winmgmts",
            re.I,
        ),
    ),
    (
        "escritura",
        re.compile(
            r"ADODB\.Stream|\.SaveToFile\b|\bCreateTextFile\b|\bOpen\b[^\r\n]{0,200}?\bFor\s+(?:Binary|Output)\b",
            re.I,
        ),
    ),
    (
        "shellcode",
        re.compile(
            r"\bVirtualAlloc(?:Ex)?\b|\bRtlMoveMemory\b|\bCreateThread\b|\bCreateRemoteThread\b|"
            r"\bWriteProcessMemory\b|\bQueueUserAPC\b|\bEnumSystemLanguageGroups[AW]?\b|\bEnumDateFormats\w*",
            re.I,
        ),
    ),
    (
        "entorno",
        re.compile(
            r"\bEnviron\$?\s*\(|ExpandEnvironmentStrings|%(?:TEMP|TMP|APPDATA|LOCALAPPDATA|PUBLIC|USERPROFILE|"
            r"PROGRAMDATA)%",
            re.I,
        ),
    ),
    (
        "evasion",
        re.compile(
            r"\bCallByName\b|\bStrReverse\b|AccessVBOM|VBAWarnings|\bProtectedView\b|"
            r"Application\.Visible\s*=\s*False|\.Variables\s*\(",
            re.I,
        ),
    ),
)
_VBA_DANGEROUS = frozenset({"ejecucion", "comando", "descarga", "objeto_peligroso", "shellcode"})
_CHR_RE = re.compile(r"\bChr[BW]?\$?\s*\(", re.I)
_LONG_STRING_RE = re.compile(r"\"[^\"\r\n]{400,}\"")
_VBA_PROC_RE = re.compile(
    r"^[ \t]*(?:(?:Private|Public|Friend|Static)[ \t]+)*(?:Sub|Function)[ \t]+([A-Za-z_][\w]{0,80})",
    re.I | re.M,
)
_AUTOEXEC_STRONG = frozenset(
    "autoopen auto_open autoexec autonew autoclose auto_close autoexit document_open documentopen "
    "document_new newdocument document_close documentbeforeclose document_beforeclose workbook_open "
    "workbook_activate workbook_close workbook_beforeclose worksheet_calculate auto_ope".split()
)
_AUTOEXEC_STRONG_SUFFIXES = (
    "_layout",
    "_painted",
    "_painting",
    "_gotfocus",
    "_resize",
    "_documentcomplete",
    "_beforenavigate2",
    "_navigatecomplete2",
    "_contentcontrolonenter",
)
_AUTOEXEC_WEAK_SUFFIXES = (
    "_click",
    "_change",
    "_mousemove",
    "_mouseenter",
    "_mouseleave",
    "_mousehover",
    "_lostfocus",
    "_followhyperlink",
    "_activate",
    "_beforeclose",
    "_open",
)
_XLM_DANGER_RE = re.compile(
    r"\b(EXEC|CALL|REGISTER|URLDownloadToFile[AW]?|ShellExecute[AW]?|WinExec|CreateThread|VirtualAlloc)\b",
    re.I,
)
_XLM_AUTO_RE = re.compile(r"auto_ope|auto_close|built-in-name\s+[12]\b", re.I)
_XLM_OBF_RE = re.compile(r"\b(?:CHAR|FORMULA(?:\.FILL)?|GET\.WORKSPACE|SET\.VALUE|SET\.NAME)\s*\(", re.I)

_PCODE_LOCK = threading.Lock()  # pcodedmp usa estado global de módulo


# --------------------------------------------------------------------------- utilidades


def _s(value: Any, n: int = _EV_STR) -> str:
    """Texto acotado y sin caracteres de control, apto para evidencia."""
    if isinstance(value, bytes | bytearray):
        value = bytes(value).decode("utf-8", "replace")
    text = str(value)
    text = "".join(c if c.isprintable() else f"\\x{ord(c):02x}" for c in text[: n * 2])
    return text if len(text) <= n else text[: n - 1] + "…"


def _uniq(items: list[Any], n: int = _EV_ITEMS) -> list[Any]:
    out: list[Any] = []
    seen: set[str] = set()
    for it in items:
        key = repr(it)
        if key in seen:
            continue
        seen.add(key)
        out.append(it)
        if len(out) >= n:
            break
    return out


def _magic_kind(blob: bytes) -> str:
    if blob.startswith(b"MZ"):
        return "pe"
    if blob.startswith(_OLE_MAGIC):
        return "ole"
    if blob.startswith(b"PK\x03\x04"):
        return "zip"
    if blob.startswith(_LNK_MAGIC):
        return "lnk"
    if b"%PDF" in blob[:1024]:
        return "pdf"
    if blob.startswith(b"{\\rt"):
        return "rtf"
    if blob.startswith(b"\x7fELF"):
        return "elf"
    if blob.startswith(
        (b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"BM", b"\x01\x00\x00\x00", b"\xd7\xcd\xc6\x9a")
    ):
        return "imagen"
    return "otro"


def _ext_of(name: str) -> str:
    name = name.replace("\\", "/").rsplit("/", 1)[-1].strip().strip("\x00").rstrip(". ")
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def _parse_attrs(blob: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in _XML_ATTR_RE.finditer(blob):
        key = m.group(1).decode("latin-1").rsplit(":", 1)[-1].lower()
        raw = m.group(2) if m.group(2) is not None else (m.group(3) or b"")
        out.setdefault(key, html.unescape(raw.decode("utf-8", "replace")))
    return out


def _meaningful_vba(code: str) -> bool:
    """True si el módulo tiene código real (no solo las líneas `Attribute VB_...` que Office genera)."""
    for line in code.splitlines():
        s = line.strip()
        if not s or s.startswith("'") or s.lower().startswith(("attribute vb_", "option ")):
            continue
        return True
    return False


def _utf16_strings(blob: bytes, limit: int = 8) -> list[str]:
    out = []
    for m in itertools.islice(_UTF16_STR_RE.finditer(blob), limit):
        out.append(m.group(0).decode("utf-16-le", "replace"))
    return out


def _extract_body_passwords(text: str) -> list[str]:
    out: list[str] = []
    for m in _BODY_PASSWORD_RE.finditer(text[:20000]):
        pw = m.group(1).strip(".,;:)]}")
        if 3 <= len(pw) <= 32 and pw not in out:
            out.append(pw)
        if len(out) >= 4:
            break
    return out


def _classify_target(target: str) -> str | None:
    """Clasifica el destino de una relación externa: follina / http / unc / protocol / None (local o vacío)."""
    t = target.strip().strip("\"'").lower()
    if not t:
        return None
    if t.startswith(("mhtml:", "ms-msdt:")) or "!x-usc:" in t:
        return "follina"
    if t.startswith(("http://", "https://", "ftp://")):
        return "http"
    if t.startswith(("\\\\", "//")):
        return "unc"
    if t.startswith("file:"):
        rest = t[5:]
        # file:///C:/... es local; file://host/share, file:////host y file:///\\host son UNC
        if rest.startswith("///") and not rest.startswith(("////", "///\\\\")):
            return None
        return "unc"
    if re.match(
        r"^(?:search-ms|ms-search|ms-officecmd|ms-word|ms-excel|ms-powerpoint|ms-its|its|mk|javascript|"
        r"vbscript|ms-appinstaller|ms-cxh|ms-settings):",
        t,
    ):
        return "protocol"
    return None


def _host_of(url: str) -> str:
    m = re.match(r"^[a-z][a-z0-9+.-]{0,20}://([^/\\?#:@]{1,255}@)?([^/\\?#:]{1,255})", url.strip(), re.I)
    return (m.group(2) if m else "").lower()


# --------------------------------------------------------------------------- estado del análisis


@dataclass
class _Job:
    artifact_id: str
    filename: str
    detected_type: str
    extension: str
    data: bytes
    child_hashes: frozenset[str]
    passwords: tuple[str, ...]
    internal_sender: bool
    deadline: float

    def expired(self) -> bool:
        return time.monotonic() > self.deadline


@dataclass
class _Report:
    vba_modules: list[tuple[str, str, str]] = field(default_factory=list)  # (dónde, módulo, código)
    vba_chars: int = 0
    vba_is_text: bool = False
    form_strings: list[str] = field(default_factory=list)
    stomping: list[str] = field(default_factory=list)
    xlm_sources: list[str] = field(default_factory=list)
    xlm_text: list[str] = field(default_factory=list)
    xlm_auto: bool = False
    xlm_hidden: bool = False
    dde: list[dict[str, Any]] = field(default_factory=list)
    remote: list[dict[str, Any]] = field(default_factory=list)
    follina: list[dict[str, Any]] = field(default_factory=list)
    unc: list[dict[str, Any]] = field(default_factory=list)
    equation: list[dict[str, Any]] = field(default_factory=list)
    ole_link: list[dict[str, Any]] = field(default_factory=list)
    packages: list[dict[str, Any]] = field(default_factory=list)
    activex: list[dict[str, Any]] = field(default_factory=list)
    embedded: list[dict[str, Any]] = field(default_factory=list)
    encrypted: dict[str, Any] | None = None
    rtf_objects: list[dict[str, Any]] = field(default_factory=list)
    rtf_objupdate: int = 0
    rtf_objautlink: int = 0
    rtf_obfuscation: list[str] = field(default_factory=list)
    has_workbook_stream: bool = False
    corrupted: bool = False
    decrypted: bool = False
    errors: list[str] = field(default_factory=list)
    partial: list[str] = field(default_factory=list)

    def note_partial(self, why: str) -> None:
        if why not in self.partial and len(self.partial) < 20:
            self.partial.append(why)

    def note_error(self, why: str) -> None:
        if why not in self.errors and len(self.errors) < 20:
            self.errors.append(_s(why, 200))


# --------------------------------------------------------------------------- analizador


class OfficeAnalyzer(ArtifactAnalyzer):
    """Documentos de Office (OLE, OOXML, RTF, XML de Office, MHT/SYLK disfrazados) y VBA suelto."""

    name = "office"

    @classmethod
    def available(cls) -> bool:
        return _OLETOOLS_ERROR is None

    def accepts(self, artifact: Artifact) -> bool:
        if artifact.listing_only or not artifact.data:  # entrada solo listada: no hay contenido que abrir
            return False
        t = artifact.detected_type
        if t in _OFFICE_TYPES:
            return True
        if t == "xml":
            return _is_office_xml(artifact.data[:8192])
        return artifact.extension in _OFFICE_EXTS

    async def analyze(self, ctx: AnalysisContext, artifact: Artifact) -> list[Finding]:
        if not artifact.data or artifact.listing_only:
            return []
        limits = ctx.settings.limits
        budget = max(5.0, float(limits.analyzer_timeout_s) * 0.8)
        body = ctx.message.body_text or _TAG_RE.sub(" ", (ctx.message.body_html or "")[:100_000])
        # primero las claves mencionadas en el mail (lo más probable), después las de la configuración
        passwords = _extract_body_passwords(body) + list(limits.archive_passwords)[:6]
        domains = [d.lower().lstrip("@") for d in ctx.settings.general.company_domains]
        sender = (ctx.message.from_addr or "").lower()
        internal = bool(sender and domains and any(sender.endswith("@" + d) for d in domains))
        job = _Job(
            artifact_id=artifact.id,
            filename=artifact.filename or "documento",
            detected_type=artifact.detected_type,
            extension=artifact.extension,
            data=artifact.data,
            child_hashes=frozenset(
                a.sha256 for a in ctx.children(artifact.id) if a.sha256 and not a.listing_only
            ),
            passwords=tuple(passwords),
            internal_sender=internal,
            deadline=time.monotonic() + budget,
        )
        return await asyncio.to_thread(_run_job, job)


def _is_office_xml(head: bytes) -> bool:
    low = head.lower()
    return any(m in low for m in _OFFICE_XML_MARKERS)


def _run_job(job: _Job) -> list[Finding]:
    rep = _Report()
    if len(job.data) > _MAX_INPUT:
        rep.note_partial(f"archivo demasiado grande ({len(job.data)} bytes): no se analizó en profundidad")
        return _build_findings(job, rep)
    try:
        _dispatch(job, job.data, rep, depth=0)
    except Exception as exc:  # noqa: BLE001 - un archivo hostil no debe tumbar el análisis
        log.debug("office: error analizando %s", job.artifact_id, exc_info=True)
        rep.note_error(f"error interno: {type(exc).__name__}")
    return _build_findings(job, rep)


def _sniff(data: bytes, detected_type: str) -> str:
    if data.startswith(_OLE_MAGIC):
        return "ole"
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return "zip"
    if data.startswith(b"{\\rt") or (detected_type == "rtf" and data.lstrip(_WS_BYTES).startswith(b"{\\rt")):
        return "rtf"
    if detected_type == "script/vba":
        return "vba_text"
    head = data[:8192].lower()
    if any(m in head for m in _OFFICE_XML_MARKERS):
        return "office_xml"
    if b"mime-version" in head[:4096] and b"multipart" in head:
        return "mht"
    if data[:2] == b"ID" and data[2:3] in (b";", b"\r", b"\n"):
        return "slk"
    return "other"


def _dispatch(job: _Job, data: bytes, rep: _Report, *, depth: int) -> None:
    kind = _sniff(data, job.detected_type if depth == 0 else "")
    if kind == "ole":
        _analyze_ole(job, data, rep, depth=depth)
    elif kind == "zip":
        _analyze_zip(job, data, rep)
    elif kind == "rtf":
        _analyze_rtf(job, data, rep)
    elif kind == "office_xml":
        _analyze_office_xml(job, data, rep)
    elif kind in ("mht", "slk"):
        where = "documento MHT" if kind == "mht" else "planilla SYLK"
        _vba_scan(job, data, rep, where)
    elif kind == "vba_text":
        rep.vba_is_text = True
        _vba_scan(job, data, rep, "código VBA", allow_text=True)


# --------------------------------------------------------------------------- OLE (doc/xls/ppt, cifrados)


def _analyze_ole(job: _Job, data: bytes, rep: _Report, *, depth: int) -> None:
    try:
        ole = olefile.OleFileIO(io.BytesIO(data))
    except Exception as exc:  # noqa: BLE001
        rep.note_error(f"OLE ilegible: {type(exc).__name__}")
        return
    enc_kind = None
    try:
        _scan_ole_structure(job, ole, rep, "documento", check_dde=True)
        enc_kind = _ole_encryption(ole)
    finally:
        with contextlib.suppress(Exception):
            ole.close()

    if enc_kind:
        if rep.encrypted is None:
            rep.encrypted = {
                "tipo": "OOXML cifrado" if enc_kind == "ooxml" else "documento Office 97-2003 cifrado"
            }
        if depth == 0 and not job.expired():
            dec, how = _try_decrypt(job, data)
            if dec is not None:
                rep.decrypted = True
                rep.encrypted["descifrado"] = True
                rep.encrypted["clave"] = how
                _dispatch(job, dec, rep, depth=depth + 1)
                return
        if enc_kind == "ooxml":
            return  # el contenido real está cifrado: no hay nada más que ver

    if job.expired():
        rep.note_partial("tiempo de análisis agotado")
        return
    _vba_scan(job, data, rep, "documento")
    if rep.has_workbook_stream:
        _xls_dde(job, data, rep)


def _ole_encryption(ole: Any) -> str | None:
    try:
        if ole.exists("EncryptionInfo") and ole.exists("EncryptedPackage"):
            return "ooxml"
    except Exception:  # noqa: BLE001
        log.debug("office: error buscando streams de cifrado", exc_info=True)
    try:
        from oletools import crypto

        if crypto.is_encrypted(ole):
            return "legacy"
    except Exception:  # noqa: BLE001
        log.debug("office: crypto.is_encrypted falló", exc_info=True)
    return None


def _read_stream(ole: Any, path: list[str], cap: int) -> bytes:
    try:
        with ole.openstream(path) as s:
            return s.read(cap)
    except Exception:  # noqa: BLE001
        log.debug("office: no se pudo leer el stream %r", path, exc_info=True)
        return b""


def _scan_ole_structure(job: _Job, ole: Any, rep: _Report, where: str, *, check_dde: bool) -> None:
    """Revisa CLSIDs y streams de un OLE: Editor de Ecuaciones, OLE2Link, paquetes, ActiveX, DDE."""
    try:
        entries = ole.listdir(streams=True, storages=True)
    except Exception as exc:  # noqa: BLE001
        rep.note_error(f"{where}: estructura OLE inválida ({type(exc).__name__})")
        return
    if len(entries) > _MAX_OLE_ENTRIES:
        rep.note_partial(f"{where}: demasiadas entradas OLE")
        entries = entries[:_MAX_OLE_ENTRIES]
    clsids: list[tuple[str, str]] = []
    with contextlib.suppress(Exception):
        clsids.append(("raíz", str(ole.root.clsid or "")))
    activex_storages: set[str] = set()
    for e in entries:
        if job.expired():
            rep.note_partial("tiempo de análisis agotado")
            break
        path = "/".join(e)
        try:
            etype = ole.get_type(e)
        except Exception:  # noqa: BLE001
            log.debug("office: get_type falló", exc_info=True)
            continue
        if etype == olefile.STGTY_STORAGE:
            with contextlib.suppress(Exception):
                c = ole.getclsid(e)
                if c:
                    clsids.append((path, str(c)))
            continue
        if etype != olefile.STGTY_STREAM:
            continue
        low = e[-1].lower()
        if low == "equation native":
            rep.equation.append(
                {"donde": where, "detalle": f"stream '{_s(path, 120)}'", "variante": "eqnedt"}
            )
        elif low == "\x01ole10native":
            blob = _read_stream(ole, e, _MAX_OLE_STREAM)
            _parse_native_package(blob, rep, f"{where}: {_s(path, 120)}", package=False)
        elif low == "\x01ole":
            _check_moniker(_read_stream(ole, e, 65536), rep, f"{where}: {_s(path, 120)}")
        elif low in ("\x03ocxname", "\x03ocxdata"):
            storage = "/".join(e[:-1]) or "raíz"
            if storage not in activex_storages:
                activex_storages.add(storage)
                rep.activex.append({"donde": where, "detalle": _s(storage, 120)})
        elif low == "\x01compobj":
            _check_compobj(_read_stream(ole, e, 4096), rep, f"{where}: {_s(path, 120)}")
        elif low == "worddocument" and len(e) == 1 and check_dde:
            _doc_dde(_read_stream(ole, e, _MAX_OLE_STREAM), rep, where)
        elif low in ("workbook", "book") and len(e) == 1:
            rep.has_workbook_stream = True
        elif low == "ctls" and len(e) == 1:
            rep.activex.append({"donde": where, "detalle": "stream Ctls (controles de Excel)"})
    for path, c in clsids:
        cu = c.upper()
        variant = _EQUATION_CLSIDS.get(cu)
        if variant:
            rep.equation.append(
                {"donde": where, "detalle": f"CLSID {cu} en '{_s(path, 120)}'", "variante": variant}
            )
        elif cu == _STDOLELINK_CLSID:
            rep.ole_link.append({"donde": where, "tipo": "OLE2Link", "detalle": _s(path, 120)})


def _check_compobj(blob: bytes, rep: _Report, where: str) -> None:
    m = re.search(rb"Equation\.(?:2|3|DSMT\d{0,2})", blob, re.I)
    if m:
        variant = "mathtype" if b"dsmt" in m.group(0).lower() else "eqnedt"
        rep.equation.append({"donde": where, "detalle": f"ProgID {_s(m.group(0))}", "variante": variant})
    if re.search(rb"OLE2Link", blob, re.I):
        rep.ole_link.append({"donde": where, "tipo": "OLE2Link", "detalle": "CompObj"})


def _check_moniker(blob: bytes, rep: _Report, where: str) -> None:
    for clsid_bytes, label in ((_URL_MONIKER, "URL moniker"), (_SCRIPT_MONIKER, "script moniker")):
        pos = blob.find(clsid_bytes)
        if pos < 0:
            continue
        window = blob[pos + 16 : pos + 16 + 4096]
        strings = _utf16_strings(window, 4)
        url = next((s for s in strings if "://" in s or s.startswith("\\\\")), strings[0] if strings else "")
        rep.ole_link.append({"donde": where, "tipo": label, "url": _s(url)})


def _parse_native_package(blob: bytes, rep: _Report, where: str, *, package: bool) -> None:
    if not blob:
        return
    try:
        pkg = oleobj.OleNativeStream(bindata=blob, package=package)
    except Exception:  # noqa: BLE001
        log.debug("office: paquete OLE ilegible en %s", where, exc_info=True)
        return
    payload = pkg.data if isinstance(pkg.data, bytes | bytearray) else b""
    _add_package(
        rep,
        where,
        str(pkg.filename or ""),
        str(pkg.src_path or ""),
        str(pkg.temp_path or ""),
        bytes(payload[:64]),
        size=int(pkg.actual_size or 0),
    )


def _add_package(
    rep: _Report, where: str, filename: str, src: str, tmp: str, head: bytes, *, size: int = 0
) -> None:
    kind = _magic_kind(head) if head else "desconocido"
    exts = {_ext_of(x) for x in (filename, src, tmp) if x}
    dangerous = bool(exts & _EXEC_EXTS) or kind in ("pe", "lnk", "elf")
    rep.packages.append(
        {
            "donde": where,
            "nombre": _s(filename, 160),
            "ruta_origen": _s(src, 200),
            "tipo_contenido": kind,
            "tamaño": size,
            "peligroso": dangerous,
        }
    )


def _doc_dde(blob: bytes, rep: _Report, where: str) -> None:
    for m in itertools.islice(_DOC_DDE_RE.finditer(blob), 20):
        raw = m.group(1)
        if raw.count(b"\x00") > len(raw) // 4:
            text = raw.decode("utf-16-le", "replace")
        else:
            text = raw.decode("latin-1", "replace")
        text = " ".join(text.replace("\x00", "").split())
        _register_dde(rep, where, text, word=True)


def _register_dde(rep: _Report, where: str, instruction: str, *, word: bool) -> None:
    m = _DDE_FIELD_RE.match(instruction)
    if not m:
        return
    cmd = " ".join(instruction.split())
    rep.dde.append(
        {"donde": where, "comando": _s(cmd), "peligroso": bool(_DANGEROUS_CMD_RE.search(cmd)) or word}
    )


def _xls_dde(job: _Job, data: bytes, rep: _Report) -> None:
    """Vínculos DDE en .xls (registros SUPBOOK de tipo OLE/DDE)."""
    try:
        from oletools import xls_parser
    except Exception:  # noqa: BLE001
        return
    xls = None
    try:
        xls = xls_parser.XlsFile(io.BytesIO(data))
        n = 0
        for stream in xls.iter_streams():
            if not isinstance(stream, xls_parser.WorkbookStream):
                continue
            for record in stream.iter_records():
                n += 1
                if n > _MAX_XLS_RECORDS or (not n & 0xFFFF and job.expired()):
                    rep.note_partial("planilla con demasiados registros: DDE revisado parcialmente")
                    return
                if (
                    isinstance(record, xls_parser.XlsRecordSupBook)
                    and record.support_link_type == xls_parser.XlsRecordSupBook.LINK_TYPE_OLE_DDE
                ):
                    target = str(getattr(record, "virt_path", "") or "").replace("\x03", " ")
                    rep.dde.append(
                        {
                            "donde": "planilla",
                            "comando": _s(target),
                            "peligroso": bool(_DANGEROUS_CMD_RE.search(target)),
                        }
                    )
    except Exception:  # noqa: BLE001
        log.debug("office: xls_parser falló", exc_info=True)
    finally:
        if xls is not None:
            with contextlib.suppress(Exception):
                xls.close()


def _try_decrypt(job: _Job, data: bytes) -> tuple[bytes | None, str | None]:
    """Intenta descifrar EN MEMORIA con claves conocidas. Devuelve (bytes, cómo) o (None, None)."""
    try:
        import msoffcrypto
    except Exception:  # noqa: BLE001
        return None, None
    candidates: list[tuple[str, str]] = [("clave por defecto de Excel (VelvetSweatshop)", _EXCEL_DEFAULT_KEY)]
    candidates += [("contraseña de la configuración o del mail", p) for p in job.passwords if p]
    tried: set[str] = set()
    for label, pw in candidates:
        if pw in tried:
            continue
        if len(tried) >= _MAX_DECRYPT_TRIES or job.expired():
            break
        tried.add(pw)
        try:
            office_file = msoffcrypto.OfficeFile(io.BytesIO(data))
            try:
                office_file.load_key(password=pw, verify_password=True)
            except TypeError:
                office_file.load_key(password=pw)
            out = io.BytesIO()
            office_file.decrypt(out)
            dec = out.getvalue()
        except Exception:  # noqa: BLE001 - contraseña incorrecta o formato no soportado
            log.debug("office: descifrado fallido con un candidato")
            continue
        if dec.startswith((_OLE_MAGIC, b"PK\x03\x04")):
            return dec, label
    return None, None


# --------------------------------------------------------------------------- VBA / XLM (olevba)


def _vba_scan(job: _Job, data: bytes, rep: _Report, where: str, *, allow_text: bool = False) -> None:
    if job.expired():
        rep.note_partial("tiempo de análisis agotado")
        return
    try:
        vp = olevba.VBA_Parser(job.filename or "documento", data=data)
    except Exception:  # noqa: BLE001 - FileOpenError: no es un formato con macros
        log.debug("office: VBA_Parser no pudo abrir %s", where, exc_info=True)
        return
    try:
        if vp.type == olevba.TYPE_TEXT and not allow_text:
            return  # olevba trata cualquier texto como VBA: solo se acepta si el tipo real es script/vba
        _collect_vba(job, vp, rep, where)
    except Exception as exc:  # noqa: BLE001
        log.debug("office: error extrayendo macros de %s", where, exc_info=True)
        rep.note_error(f"macros ({where}): {type(exc).__name__}")
    finally:
        with contextlib.suppress(Exception):
            vp.close()


def _collect_vba(job: _Job, vp: Any, rep: _Report, where: str) -> None:
    is_text = vp.type == olevba.TYPE_TEXT
    has_vba = bool(vp.detect_vba_macros())
    has_xlm = False
    if not is_text:
        try:
            has_xlm = bool(vp.detect_xlm_macros())
        except Exception:  # noqa: BLE001
            log.debug("office: detección XLM falló", exc_info=True)
    if not (has_vba or has_xlm):
        return
    for _sub, _stream, vba_filename, code in vp.extract_all_macros():
        if vba_filename in ("xlm_macro.txt", "VBA_P-code.txt"):
            continue
        if not isinstance(code, str):
            code = bytes(code or b"").decode("latin-1", "replace")
        room = _MAX_VBA_CHARS - rep.vba_chars
        if room <= 0:
            rep.note_partial("código VBA demasiado largo: analizado parcialmente")
            break
        code = code[:room]
        rep.vba_chars += len(code)
        rep.vba_modules.append((where, _s(vba_filename, 80), code))
    if has_vba and not is_text:
        with contextlib.suppress(Exception):
            for _f, _p, form_string in itertools.islice(vp.extract_form_strings(), _MAX_FORM_STRINGS):
                rep.form_strings.append(str(form_string)[:2000])
    if has_xlm and vp.xlm_macros:
        rep.xlm_sources.append(where)
        rep.xlm_text.append("\n".join(str(x) for x in vp.xlm_macros[:_MAX_XLM_LINES]))
    if has_vba and not is_text and not job.expired() and _detect_stomping(vp):
        rep.stomping.append(where)


def _detect_stomping(vp: Any) -> bool:
    """VBA stomping: el P-code compilado no corresponde al código fuente visible (en memoria, con pcodedmp)."""
    try:
        from pcodedmp import pcodedmp
    except Exception:  # noqa: BLE001
        return False
    parsers = (
        [vp] if getattr(vp, "ole_file", None) is not None else list(getattr(vp, "ole_subfiles", []) or [])
    )
    for p in parsers[:_MAX_VBA_PARTS]:
        if getattr(p, "ole_file", None) is None:
            continue
        try:
            if not p.find_vba_projects():
                continue
            out = io.StringIO()
            args = types.SimpleNamespace(disasmOnly=True, verbose=False)
            with _PCODE_LOCK:
                pcodedmp.processProject(p, args, output_file=out)
            if _stomping_from_pcode(out.getvalue(), p.get_vba_code_all_modules()):
                return True
        except Exception:  # noqa: BLE001
            log.debug("office: análisis de P-code falló", exc_info=True)
    return False


def _stomping_from_pcode(pcode: str, source: str) -> bool:
    """Compara identificadores y literales del P-code (salida de pcodedmp) con el código fuente.

    Misma lógica que olevba, algo más conservadora: exige 2+ identificadores ausentes, o P-code con
    contenido y código fuente vacío.
    """
    keywords: set[str] = set()
    for line in pcode.splitlines()[:200_000]:
        if not line.startswith("\t"):
            continue
        tokens = line.split(None, 1)
        if not tokens:
            continue
        mnemonic = tokens[0]
        args = tokens[1].strip() if len(tokens) == 2 else ""
        if mnemonic in ("ArgsCall", "ArgsLd", "St", "Ld", "MemSt", "Label"):
            if args.startswith("(Call) "):
                args = args[7:]
            if not args:
                continue
            name = args.split(None, 1)[0]
            if not name.startswith("id_"):
                keywords.add(name)
        elif mnemonic == "LitStr":
            parts = args.split(None, 1)
            if len(parts) < 2:
                continue
            lit = parts[1]
            if len(lit) >= 2 and lit[0] == '"' and lit[-1] == '"':
                lit = '"' + lit[1:-1].replace('"', '""') + '"'
            keywords.add(lit)
    if not keywords:
        return False
    if not _meaningful_vba(source):
        return True
    missing = [k for k in keywords if k not in source]
    return len(missing) >= 2


# --------------------------------------------------------------------------- OOXML (zip)


def _zip_read(zf: zipfile.ZipFile, info: zipfile.ZipInfo, cap: int, rep: _Report) -> bytes | None:
    try:
        with zf.open(info) as fh:
            data = fh.read(cap)
    except Exception as exc:  # noqa: BLE001 - cifrado, compresión rota, zip bomb truncada...
        rep.note_error(f"parte '{_s(info.filename, 120)}' ilegible ({type(exc).__name__})")
        return None
    if info.file_size > cap:
        rep.note_partial(f"parte '{_s(info.filename, 120)}' leída parcialmente")
    return data


def _analyze_zip(job: _Job, data: bytes, rep: _Report) -> None:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = zf.infolist()
    except Exception as exc:  # noqa: BLE001
        if job.extension in _OOXML_EXTS or job.detected_type == "ooxml":
            rep.corrupted = True
        rep.note_error(f"ZIP ilegible ({type(exc).__name__})")
        return
    with zf:
        if len(infos) > _MAX_ZIP_ENTRIES:
            rep.note_partial("documento con demasiadas partes: análisis parcial")
            infos = infos[:_MAX_ZIP_ENTRIES]
        overrides: dict[str, str] = {}
        ct = next((i for i in infos if i.filename.lower().lstrip("/") == "[content_types].xml"), None)
        if ct is not None:
            blob = _zip_read(zf, ct, _MAX_PART, rep) or b""
            for m in itertools.islice(_OVERRIDE_RE.finditer(blob), 5000):
                attrs = _parse_attrs(m.group(1))
                part = attrs.get("partname", "").lower().lstrip("/")
                if part:
                    overrides[part] = attrs.get("contenttype", "").lower()
        macrosheets = {p for p, c in overrides.items() if "macrosheet" in c}
        vba_parts = {p for p, c in overrides.items() if "vbaproject" in c}
        activex_parts = {p for p, c in overrides.items() if "activex" in c}

        counters = {"rels": 0, "sheets": 0, "vba": 0, "embed": 0, "embed_bytes": 0}
        for info in infos:
            if job.expired():
                rep.note_partial("tiempo de análisis agotado")
                break
            if info.is_dir():
                continue
            name = info.filename
            nl = name.lower().lstrip("/")
            if nl.endswith(".rels"):
                if counters["rels"] < _MAX_RELS:
                    counters["rels"] += 1
                    blob = _zip_read(zf, info, _MAX_PART, rep)
                    if blob:
                        _scan_rels(job, blob, rep, name)
            elif nl.startswith(
                (
                    "word/document",
                    "word/header",
                    "word/footer",
                    "word/footnotes",
                    "word/endnotes",
                    "word/comments",
                )
            ) or nl.startswith("word/glossary/document"):
                if nl.endswith(".xml"):
                    blob = _zip_read(zf, info, _MAX_PART, rep)
                    if blob:
                        _scan_word_fields(blob, rep, name)
            elif nl.startswith("xl/externallinks/") and nl.endswith(".xml"):
                blob = _zip_read(zf, info, _MAX_PART, rep)
                if blob:
                    _scan_ddelinks(blob, rep, name)
            elif "/macrosheets/" in nl or nl in macrosheets:
                rep.xlm_sources.append(name)
                if nl.endswith(".xml"):
                    blob = _zip_read(zf, info, _MAX_PART, rep) or b""
                    formulas = [
                        html.unescape(m.group(1).decode("utf-8", "replace"))
                        for m in itertools.islice(_XL_FORMULA_RE.finditer(blob), _MAX_XLM_LINES)
                    ]
                    rep.xlm_text.append("\n".join(formulas))
            elif nl.startswith("xl/worksheets/") and nl.endswith(".xml"):
                if counters["sheets"] < _MAX_SHEETS_DDE:
                    counters["sheets"] += 1
                    blob = _zip_read(zf, info, _MAX_PART, rep)
                    if blob:
                        _scan_xl_dde_formulas(blob, rep, name)
            elif nl == "xl/workbook.xml":
                blob = _zip_read(zf, info, _MAX_PART, rep)
                if blob:
                    _scan_workbook_xml(blob, rep)
            elif nl == "xl/workbook.bin":
                blob = (_zip_read(zf, info, _MAX_PART, rep) or b"").lower()
                if b"auto_open" in blob or "auto_open".encode("utf-16-le") in blob:
                    rep.xlm_auto = True
            elif "/activex/" in nl or nl in activex_parts:
                if nl.endswith(".xml"):
                    blob = _zip_read(zf, info, 1024 * 1024, rep) or b""
                    m = _ACTIVEX_CLSID_RE.search(blob)
                    rep.activex.append(
                        {
                            "donde": _s(name, 120),
                            "detalle": f"CLSID {m.group(1).decode().upper()}" if m else "control",
                        }
                    )
            elif "/embeddings/" in nl:
                _handle_embedding(job, zf, info, rep, counters)
            elif nl.endswith(".bin") or nl in vba_parts:
                if counters["vba"] >= _MAX_VBA_PARTS or nl.endswith("printersettings1.bin"):
                    continue
                head = _zip_read(zf, info, 8, rep) or b""
                if head.startswith(_OLE_MAGIC):
                    counters["vba"] += 1
                    blob = _zip_read(zf, info, _MAX_EMBED, rep)
                    if blob:
                        _vba_scan(job, blob, rep, name)


def _handle_embedding(
    job: _Job, zf: zipfile.ZipFile, info: zipfile.ZipInfo, rep: _Report, counters: dict
) -> None:
    if counters["embed"] >= _MAX_EMBEDDINGS or counters["embed_bytes"] >= _MAX_EMBED_TOTAL:
        rep.note_partial("demasiados objetos incrustados: se revisaron los primeros")
        return
    counters["embed"] += 1
    blob = _zip_read(zf, info, _MAX_EMBED, rep)
    if blob is None:
        return
    counters["embed_bytes"] += len(blob)
    name = info.filename
    kind = _magic_kind(blob)
    covered = hashlib.sha256(blob).hexdigest() in job.child_hashes
    rep.embedded.append(
        {"parte": _s(name, 160), "tamaño": info.file_size, "tipo": kind, "analizado_aparte": covered}
    )
    ext = _ext_of(name)
    if kind in ("pe", "lnk", "elf") or ext in _EXEC_EXTS:
        _add_package(rep, _s(name, 160), name.rsplit("/", 1)[-1], "", "", blob[:64], size=info.file_size)
    if not covered and kind == "ole":
        _scan_ole_part(job, blob, rep, _s(name, 160))


def _scan_ole_part(job: _Job, blob: bytes, rep: _Report, where: str, *, vba: bool = True) -> None:
    try:
        ole = olefile.OleFileIO(io.BytesIO(blob))
    except Exception:  # noqa: BLE001
        rep.note_error(f"{where}: objeto OLE ilegible")
        return
    try:
        _scan_ole_structure(job, ole, rep, where, check_dde=False)
    finally:
        with contextlib.suppress(Exception):
            ole.close()
    if vba:
        _vba_scan(job, blob, rep, where)


def _scan_rels(job: _Job, blob: bytes, rep: _Report, part: str) -> None:
    for m in itertools.islice(_REL_RE.finditer(blob), 5000):
        attrs = _parse_attrs(m.group(1))
        rel_type = attrs.get("type", "").rstrip("/").rsplit("/", 1)[-1].lower()
        target = attrs.get("target", "").strip()
        mode = attrs.get("targetmode", "").lower()
        if rel_type == "hyperlink" or not target:
            continue  # los hipervínculos requieren un clic: los evalúa el analizador de URLs
        _register_remote(job, rep, part, rel_type, target, external=(mode == "external"))


def _register_remote(
    job: _Job, rep: _Report, where: str, rel_type: str, target: str, *, external: bool
) -> None:
    kind = _classify_target(target)
    if kind is None:
        return
    entry = {"donde": _s(where, 160), "tipo": rel_type, "destino": _s(target)}
    if kind == "follina" or (rel_type == "oleobject" and kind == "http" and target.rstrip().endswith("!")):
        rep.follina.append(entry)
        return
    if rel_type in ("attachedtemplate", "frame", "oleobject", "subdocument", "package"):
        if kind == "http" and not external:
            return  # sin TargetMode="External" Office no lo descarga
        entry["clase"] = kind
        rep.remote.append(entry)
    elif kind in ("unc", "protocol"):
        rep.unc.append(entry)


def _scan_word_fields(blob: bytes, rep: _Report, where: str) -> None:
    """Reconstruye las instrucciones de campo (aunque estén partidas en varios 'runs') y busca DDE/DDEAUTO."""
    stack: list[list[str]] = []
    collecting: list[bool] = []
    done: list[str] = []
    for m in itertools.islice(_FIELD_RE.finditer(blob), 200_000):
        tag = m.group(1)
        if tag == b"fldChar":
            fm = _FLDCHARTYPE_RE.search(m.group(2))
            kind = fm.group(1).lower() if fm else b""
            if kind == b"begin":
                if len(stack) < 64:
                    stack.append([])
                    collecting.append(True)
            elif kind == b"separate" and collecting:
                collecting[-1] = False
            elif kind == b"end" and stack:
                instr = _unquote_field("".join(stack.pop()))
                collecting.pop()
                done.append(instr)
                if stack and collecting[-1]:
                    stack[-1].append(instr)  # campo anidado: su resultado forma parte del campo padre
        elif tag == b"instrText":
            text = html.unescape((m.group(3) or b"").decode("utf-8", "replace"))
            if stack and collecting[-1]:
                stack[-1].append(text)
            else:
                done.append(text)
        else:  # fldSimple
            attrs = _parse_attrs(m.group(2))
            if "instr" in attrs:
                done.append(_unquote_field(attrs["instr"]))
        if len(done) > _MAX_RTF_FIELDS:
            break
    done.extend(_unquote_field("".join(parts)) for parts in stack)  # campos sin cerrar
    for instr in done:
        _register_dde(rep, where, instr, word=True)


def _unquote_field(text: str) -> str:
    """Decodifica el truco `QUOTE 68 68 69 ...` (códigos de carácter) usado para ocultar DDEAUTO."""
    parts = text.split()
    if len(parts) > 1 and parts[0].upper() == "QUOTE" and all(p.isdigit() for p in parts[1:]):
        try:
            return "".join(chr(int(p)) for p in parts[1:] if int(p) < 0x110000)
        except ValueError:
            return text
    return text


def _scan_ddelinks(blob: bytes, rep: _Report, where: str) -> None:
    for m in itertools.islice(_DDELINK_RE.finditer(blob), 200):
        attrs = _parse_attrs(m.group(1))
        service = attrs.get("ddeservice", "")
        topic = attrs.get("ddetopic", "")
        base = service.replace("\\", "/").rsplit("/", 1)[-1].lower().removesuffix(".exe")
        rep.dde.append(
            {
                "donde": _s(where, 160),
                "comando": _s(f"{service} {topic}".strip()),
                "peligroso": base in _XL_DDE_APPS or bool(_DANGEROUS_CMD_RE.search(topic)),
            }
        )


def _scan_xl_dde_formulas(blob: bytes, rep: _Report, where: str) -> None:
    found = 0
    for m in itertools.islice(_XL_FORMULA_RE.finditer(blob), 200_000):
        formula = html.unescape(m.group(1).decode("utf-8", "replace"))
        if "|" not in formula:
            continue
        fm = _XL_DDE_FORMULA_RE.match(formula)
        if not fm:
            continue
        app = fm.group(1).replace("\\", "/").rsplit("/", 1)[-1].lower().removesuffix(".exe")
        if app in _XL_DDE_APPS:
            rep.dde.append({"donde": _s(where, 160), "comando": _s(formula), "peligroso": True})
            found += 1
            if found >= 10:
                return


def _scan_workbook_xml(blob: bytes, rep: _Report) -> None:
    for m in itertools.islice(_DEFINED_NAME_RE.finditer(blob), 20000):
        name = _parse_attrs(m.group(1)).get("name", "").lower()
        if name.startswith(("_xlnm.auto_open", "auto_open", "_xlnm.auto_close", "auto_close")):
            rep.xlm_auto = True
    for m in itertools.islice(_SHEET_RE.finditer(blob), 5000):
        state = _parse_attrs(m.group(1)).get("state", "").lower()
        if state == "veryhidden":
            rep.xlm_hidden = True


# --------------------------------------------------------------------------- XML de Office (2003 / Flat OPC)


def _analyze_office_xml(job: _Job, data: bytes, rep: _Report) -> None:
    where = "documento XML"
    _vba_scan(job, data, rep, where)
    _scan_rels(job, data, rep, where)
    _scan_word_fields(data, rep, where)
    for m in itertools.islice(_W2003_TEMPLATE_RE.finditer(data), 20):
        val = _parse_attrs(m.group(1)).get("val", "")
        if val:
            _register_remote(job, rep, where, "attachedtemplate", val, external=True)
    # Partes binarias en Flat OPC (pkg:binaryData) y Word 2003 (w:binData con ActiveMime).
    for m in itertools.islice(_PKG_PART_RE.finditer(data), 400):
        if job.expired():
            rep.note_partial("tiempo de análisis agotado")
            return
        attrs = _parse_attrs(m.group(1))
        part = attrs.get("name", "")
        if "vbaproject" in attrs.get("contenttype", "").lower():
            continue  # olevba ya lo analiza
        bm = _PKG_BINDATA_RE.search(data, m.end(), m.end() + 4096)
        if not bm:
            continue
        blob = _b64_until_tag(data, bm.end())
        if blob.startswith(_OLE_MAGIC):
            _scan_ole_part(job, blob, rep, _s(part, 160) or where)
    for m in itertools.islice(_W_BINDATA_RE.finditer(data), 200):
        blob = _b64_until_tag(data, m.end())
        try:
            if olevba.is_mso_file(blob):
                blob = olevba.mso_file_extract(blob)
        except Exception:  # noqa: BLE001
            log.debug("office: ActiveMime ilegible", exc_info=True)
            continue
        if blob.startswith(_OLE_MAGIC):
            _scan_ole_part(job, blob, rep, "objeto binario (w:binData)", vba=False)


def _b64_until_tag(data: bytes, start: int) -> bytes:
    end = data.find(b"<", start, start + 64 * 1024 * 1024)
    chunk = data[start:end] if end >= 0 else b""
    try:
        return binascii.a2b_base64(chunk)
    except (binascii.Error, ValueError):
        return b""


# --------------------------------------------------------------------------- RTF (parser propio, lineal)

_RTF_TOKEN_RE = re.compile(
    rb"\\([a-zA-Z]{1,250})(-?\d{1,250})? ?"  # 1-2: palabra de control + parámetro
    rb"|\\'([\s\S]{0,2})"  # 3: \'hh
    rb"|\\([\s\S])"  # 4: símbolo de control
    rb"|([{}])"  # 5: grupo
    rb"|([^\\{}]+)"  # 6: texto
    rb"|\\"  # barra final suelta
)
_NON_HEX_RE = re.compile(rb"[^0-9A-Fa-f]+")
_RTF_TEXT_DESTS = {b"fldinst": 65536, b"objclass": 512, b"template": 8192}
_RTF_COUNTED = frozenset(
    {b"objupdate", b"objautlink", b"objlink", b"objemb", b"objocx", b"objhtml", b"objdata", b"object"}
)
_RTF_DEFAULT_DESTS = frozenset(
    {b"objdata", b"fldinst", b"objclass", b"template", b"pict", b"field", b"fldrslt", b"object", b"result"}
)


@dataclass
class _RtfFrame:
    dest: bytes | None
    buf: bytearray | None
    owner: bool


@dataclass
class _RtfResult:
    objects: list[bytes] = field(default_factory=list)
    fields: list[bytes] = field(default_factory=list)
    objclasses: list[bytes] = field(default_factory=list)
    templates: list[bytes] = field(default_factory=list)
    counts: dict[bytes, int] = field(default_factory=dict)
    bin_in_objdata: int = 0
    quote_in_objdata: int = 0
    hex_total: int = 0
    objects_skipped: int = 0
    partial: bool = False


def _rtf_destinations() -> frozenset[bytes]:
    try:
        from oletools import rtfobj

        return frozenset(rtfobj.DESTINATION_CONTROL_WORDS) | _RTF_DEFAULT_DESTS
    except Exception:  # noqa: BLE001
        return _RTF_DEFAULT_DESTS


def _rtf_close(frame: _RtfFrame, res: _RtfResult) -> None:
    if not frame.owner:
        return
    frame.owner = False
    buf = frame.buf
    if buf is None:
        return
    if frame.dest == b"objdata":
        if len(buf) & 1:
            del buf[-1]
        if not buf:
            return
        if len(res.objects) < _MAX_RTF_OBJECTS:
            res.objects.append(binascii.unhexlify(bytes(buf)))
        else:
            res.objects_skipped += 1
    elif frame.dest == b"fldinst" and len(res.fields) < _MAX_RTF_FIELDS:
        res.fields.append(bytes(buf))
    elif frame.dest == b"objclass" and len(res.objclasses) < 200:
        res.objclasses.append(bytes(buf))
    elif frame.dest == b"template" and len(res.templates) < 20:
        res.templates.append(bytes(buf))


def _rtf_scan(data: bytes, deadline: float) -> _RtfResult:
    """Tokenizador RTF de una sola pasada que emula a Word/rtfobj para \\objdata, \\fldinst, \\objclass y
    \\template: ignora caracteres no hexadecimales, \\bin, el bug de \\'hh y grupos anidados."""
    res = _RtfResult()
    dests = _rtf_destinations()
    stack = [_RtfFrame(None, None, False)]
    overflow = 0
    pos = 0
    n = len(data)
    tokens = 0
    match = _RTF_TOKEN_RE.match
    while pos < n:
        m = match(data, pos)
        if m is None or m.end() == pos:
            pos += 1
            continue
        pos = m.end()
        tokens += 1
        if tokens >= _MAX_RTF_TOKENS:
            res.partial = True
            break
        if not tokens & 0x3FFF and time.monotonic() > deadline:
            res.partial = True
            break
        top = stack[-1]
        word = m.group(1)
        if word is not None:
            if word in _RTF_COUNTED:
                res.counts[word] = res.counts.get(word, 0) + 1
            if word == b"bin":
                param = m.group(2)
                size = int(param) if param and not param.startswith(b"-") else 0
                size = min(size, n - pos)
                if top.dest == b"objdata" and top.buf is not None:
                    res.bin_in_objdata += 1
                    room = max(0, (_MAX_RTF_HEX_TOTAL - res.hex_total) // 2)
                    chunk = binascii.hexlify(data[pos : pos + min(size, room)])
                    top.buf += chunk
                    res.hex_total += len(chunk)
                pos += size
            elif word in dests:
                _rtf_close(top, res)
                top.dest = word
                top.owner = True
                top.buf = bytearray() if (word == b"objdata" or word in _RTF_TEXT_DESTS) else None
            elif top.dest in _RTF_TEXT_DESTS and top.buf is not None and word in (b"par", b"line", b"tab"):
                top.buf += b" "
            continue
        quote = m.group(3)
        if quote is not None:
            if top.dest == b"objdata" and top.buf is not None:
                res.quote_in_objdata += 1
                if len(top.buf) & 1:  # bug de Word: descarta el último dígito si la cantidad es impar
                    del top.buf[-1]
            elif top.dest in _RTF_TEXT_DESTS and top.buf is not None and len(quote) == 2:
                with contextlib.suppress(ValueError):
                    top.buf.append(int(quote, 16))
            continue
        sym = m.group(4)
        if sym is not None:
            if top.dest in _RTF_TEXT_DESTS and top.buf is not None and sym in (b"\\", b"{", b"}"):
                top.buf += sym
            continue
        brace = m.group(5)
        if brace is not None:
            if brace == b"{":
                if len(stack) < 4096:
                    stack.append(_RtfFrame(top.dest, top.buf, False))
                else:
                    overflow += 1
            elif overflow:
                overflow -= 1
            elif len(stack) > 1:
                _rtf_close(stack.pop(), res)
            continue
        text = m.group(6)
        if text is not None and top.buf is not None:
            if top.dest == b"objdata":
                if res.hex_total < _MAX_RTF_HEX_TOTAL:
                    chunk = _NON_HEX_RE.sub(b"", text)[: _MAX_RTF_HEX_TOTAL - res.hex_total]
                    top.buf += chunk
                    res.hex_total += len(chunk)
                else:
                    res.partial = True
            elif top.dest in _RTF_TEXT_DESTS:
                cap = _RTF_TEXT_DESTS[top.dest]
                if len(top.buf) < cap:
                    top.buf += text[: cap - len(top.buf)]
    while stack:
        _rtf_close(stack.pop(), res)
    return res


def _analyze_rtf(job: _Job, data: bytes, rep: _Report) -> None:
    res = _rtf_scan(data, job.deadline)
    if res.partial:
        rep.note_partial("RTF muy grande o complejo: análisis parcial")
    rep.rtf_objupdate = res.counts.get(b"objupdate", 0)
    rep.rtf_objautlink = res.counts.get(b"objautlink", 0)
    if res.counts.get(b"objocx"):
        rep.activex.append({"donde": "RTF", "detalle": f"{res.counts[b'objocx']} objeto(s) \\objocx"})
    if res.bin_in_objdata:
        rep.rtf_obfuscation.append(f"\\bin dentro de \\objdata ({res.bin_in_objdata})")
    if res.quote_in_objdata:
        rep.rtf_obfuscation.append(f"\\'hh dentro de \\objdata ({res.quote_in_objdata})")
    if res.objects_skipped:
        rep.note_partial(f"{res.objects_skipped} objeto(s) RTF adicionales sin analizar")

    for i, raw in enumerate(res.objects):
        if job.expired():
            rep.note_partial("tiempo de análisis agotado")
            break
        _analyze_rtf_object(job, raw, i, rep)
    for fld in res.fields:
        _register_dde(rep, "RTF", " ".join(fld.decode("latin-1").split()), word=True)
    for tpl in res.templates:
        target = tpl.decode("latin-1").strip()
        if target:
            _register_remote(job, rep, "RTF (\\template)", "attachedtemplate", target, external=True)
    for cls in res.objclasses:
        low = cls.decode("latin-1").strip().lower()
        if low.startswith("equation"):
            variant = "mathtype" if "dsmt" in low else "eqnedt"
            rep.equation.append({"donde": "RTF", "detalle": f"\\objclass {_s(low, 60)}", "variante": variant})
        elif low == "ole2link":
            rep.ole_link.append({"donde": "RTF", "tipo": "OLE2Link", "detalle": "\\objclass OLE2Link"})

    # Respaldo: firmas hexadecimales en el texto crudo (sin espacios), por si la ofuscación evadió al parser.
    if not rep.equation or not rep.ole_link:
        compact = data.translate(None, _WS_BYTES).lower()
        if not rep.equation:
            for clsid_bytes, variant in _EQUATION_CLSID_BYTES.items():
                if binascii.hexlify(clsid_bytes) in compact:
                    rep.equation.append(
                        {"donde": "RTF (datos hex)", "detalle": "CLSID de ecuación", "variante": variant}
                    )
                    break
            else:
                if (
                    binascii.hexlify(b"equation.3") in compact
                    or binascii.hexlify(b"Equation.3").lower() in compact
                ):
                    rep.equation.append(
                        {"donde": "RTF (datos hex)", "detalle": "clase Equation.3", "variante": "eqnedt"}
                    )
        if not rep.ole_link and binascii.hexlify(_URL_MONIKER) in compact:
            rep.ole_link.append(
                {"donde": "RTF (datos hex)", "tipo": "URL moniker", "detalle": "CLSID de URL moniker"}
            )


def _analyze_rtf_object(job: _Job, raw: bytes, idx: int, rep: _Report) -> None:
    where = f"objeto RTF #{idx + 1}"
    info: dict[str, Any] = {"n": idx + 1, "tamaño": len(raw)}
    payload = b""
    class_name = ""
    try:
        obj = oleobj.OleObject()
        obj.parse(raw)
        class_name = (obj.class_name or b"").rstrip(b"\x00").decode("latin-1", "replace")
        payload = bytes(obj.data or b"")
        info["formato"] = "vinculado" if obj.format_id == 1 else "incrustado"
    except Exception:  # noqa: BLE001 - encabezado OLE1 roto (frecuente en exploits): buscar el OLE adentro
        pos = raw.find(_OLE_MAGIC)
        if pos >= 0:
            payload = raw[pos:]
        info["encabezado_ole1"] = "inválido"
    info["clase"] = _s(class_name, 80)
    low = class_name.lower()
    if low.startswith("equation"):
        variant = "mathtype" if "dsmt" in low else "eqnedt"
        rep.equation.append({"donde": where, "detalle": f"clase {_s(class_name, 60)}", "variante": variant})
    elif low == "ole2link":
        rep.ole_link.append({"donde": where, "tipo": "OLE2Link", "detalle": "clase OLE2Link"})
    elif low == "package":
        _parse_native_package(payload, rep, where, package=True)
    if payload.startswith(_OLE_MAGIC):
        _scan_ole_part(job, payload, rep, where)
    for clsid_bytes, variant in _EQUATION_CLSID_BYTES.items():
        if clsid_bytes in raw and not any(e["donde"] == where for e in rep.equation):
            rep.equation.append(
                {"donde": where, "detalle": "CLSID de ecuación en los datos", "variante": variant}
            )
    if (_URL_MONIKER in raw or _SCRIPT_MONIKER in raw) and not any(e["donde"] == where for e in rep.ole_link):
        _check_moniker(raw, rep, where)
    rep.rtf_objects.append(info)


# --------------------------------------------------------------------------- hallazgos


def _sev_for(score: int) -> Severity:
    if score >= 60:
        return Severity.HIGH
    if score >= 25:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO


def _mk(
    job: _Job,
    rule: str,
    title: str,
    description: str,
    score: int,
    evidence: dict[str, Any],
    *,
    category: FindingCategory = FindingCategory.SUSPICIOUS_FILE,
    severity: Severity | None = None,
) -> Finding:
    score = max(0, min(100, int(score)))
    return Finding(
        analyzer="office",
        rule=rule,
        title=title,
        description=description,
        category=category,
        severity=severity if severity is not None else _sev_for(score),
        score=score,
        artifact_id=job.artifact_id,
        evidence={k: v for k, v in evidence.items() if v not in (None, [], {}, "")},
    )


def _grade_vba(job: _Job, rep: _Report) -> Finding | None:
    modules = [(w, n, c) for (w, n, c) in rep.vba_modules if _meaningful_vba(c)]
    if not modules:
        return None
    code = "\n".join(c for _, _, c in modules)
    scan_text = code + "\n" + "\n".join(rep.form_strings)
    indicators: dict[str, list[str]] = {}
    for cat, rx in _VBA_INDICATORS:
        hits = [m.group(0).strip() for m in itertools.islice(rx.finditer(scan_text), 200)]
        if hits:
            indicators[cat] = _uniq(hits, 8)
    # olevba: autoejecución, IOCs y strings codificadas
    results: list[tuple[str, str, str]] = []
    with contextlib.suppress(Exception):
        results = list(olevba.VBA_Scanner(scan_text[:_MAX_SCANNER_CHARS]).scan(False, False) or [])
    auto_names = {m.group(1) for m in _VBA_PROC_RE.finditer(code)}
    auto_names = {n for n in auto_names if _autoexec_kind(n)}
    auto_names |= {str(kw) for t, kw, _d in results if t == "AutoExec"}
    strong = sorted(n for n in auto_names if _autoexec_kind(n) == "strong")
    weak = sorted(n for n in auto_names if _autoexec_kind(n) == "weak")
    iocs = [
        str(kw)
        for t, kw, _d in results
        if t == "IOC"
        and "schemas.openxmlformats.org" not in str(kw)
        and "schemas.microsoft.com" not in str(kw)
    ]
    encoded = sum(1 for t, _k, _d in results if t in ("Hex String", "Base64 String", "Dridex string"))
    chr_calls = len(_CHR_RE.findall(code))
    obfuscated = (
        chr_calls >= 15 or "evasion" in indicators or encoded >= 3 or bool(_LONG_STRING_RE.search(code))
    )
    dangerous = bool(_VBA_DANGEROUS & indicators.keys())
    evidence: dict[str, Any] = {
        "donde": _uniq([w for w, _n, _c in modules], 6),
        "modulos": _uniq([n for _w, n, _c in modules], 10),
        "autoejecucion": _uniq(strong + weak, 10),
        "indicadores": indicators,
        "iocs": [_s(i, 200) for i in _uniq(iocs, 15)],
        "llamadas_chr": chr_calls or None,
        "strings_codificadas": encoded or None,
        "caracteres_de_codigo": len(code),
        "documento_descifrado": rep.decrypted or None,
    }
    if (strong or weak) and dangerous:
        score = 78 if strong else 75
        if ({"ejecucion", "comando"} & indicators.keys()) and "descarga" in indicators:
            score += 4
        if obfuscated:
            score += 3
        score = min(score, 85)
        rule = "office.vba.autoexec"
        title = "Macro maliciosa: se ejecuta sola y lanza programas o descargas"
        desc = (
            "Las macros del documento se ejecutan automáticamente al habilitar el contenido y usan instrucciones "
            "para ejecutar programas (por ejemplo PowerShell o la consola de Windows), crear objetos del sistema o "
            "descargar archivos de Internet. Es la forma clásica de instalar troyanos de acceso remoto, ladrones "
            "de contraseñas y ransomware. No se debe habilitar el contenido de este documento."
        )
    elif dangerous:
        score = 45 if obfuscated else 40
        rule = "office.vba.suspicious"
        title = "Macros con instrucciones peligrosas"
        desc = (
            "Las macros incluyen instrucciones que permiten ejecutar programas, descargar archivos de Internet o "
            "escribir archivos en el disco. Es un patrón típico de documentos que instalan malware cuando se "
            "habilitan las macros."
        )
    elif strong or weak:
        score = 45 if obfuscated else 40
        rule = "office.vba.autorun"
        title = "Macros que se ejecutan solas al abrir el documento"
        desc = (
            "Las macros están programadas para ejecutarse automáticamente al abrir (o cerrar) el documento si se "
            "habilita el contenido. No se vieron instrucciones claramente peligrosas, pero no es habitual en "
            "documentos que llegan por mail."
        )
    else:
        score = 30 if obfuscated else 25
        rule = "office.vba.macros"
        title = "Documento con macros"
        desc = (
            "El documento contiene macros (código VBA). Las macros pueden ejecutar acciones en la computadora al "
            "habilitarlas y muchos programas maliciosos llegan así. Si no se esperaba un documento con macros, "
            "no conviene habilitarlas."
        )
    if obfuscated:
        desc += " Además, el código está ofuscado (disfrazado) para dificultar su análisis."
    if rep.vba_is_text:
        score = max(20, score - 15)
        desc += " (Es código VBA suelto: no se ejecuta solo, pero su contenido es el de una macro maliciosa.)"
    return _mk(
        job, rule, title, desc, score, evidence, severity=Severity.HIGH if score >= 60 else Severity.MEDIUM
    )


def _autoexec_kind(name: str) -> str | None:
    n = name.lower()
    if n in _AUTOEXEC_STRONG or n.endswith(_AUTOEXEC_STRONG_SUFFIXES):
        return "strong"
    if n.endswith(_AUTOEXEC_WEAK_SUFFIXES):
        return "weak"
    return None


def _grade_xlm(job: _Job, rep: _Report) -> Finding | None:
    if not rep.xlm_sources:
        return None
    text = "\n".join(rep.xlm_text)
    auto = rep.xlm_auto or bool(_XLM_AUTO_RE.search(text))
    funcs = _uniq(
        sorted({m.group(1).upper() for m in itertools.islice(_XLM_DANGER_RE.finditer(text), 500)}), 10
    )
    obf = len(_XLM_OBF_RE.findall(text[:2_000_000])) >= 20
    hidden = rep.xlm_hidden or "very hidden" in text.lower()
    evidence = {
        "donde": _uniq([_s(w, 160) for w in rep.xlm_sources], 6),
        "autoejecucion": auto or None,
        "funciones_peligrosas": funcs,
        "hoja_muy_oculta": hidden or None,
        "ofuscacion": obf or None,
        "muestra": _s(" | ".join(line.strip() for line in text.splitlines() if line.strip())[:600], 400),
    }
    if auto and funcs:
        score = min(85, 80 + (5 if hidden or obf else 0))
        return _mk(
            job,
            "office.xlm.autoexec",
            "Macros de Excel 4.0 que se ejecutan al abrir y lanzan comandos",
            "La planilla tiene macros de Excel 4.0 (XLM) que se ejecutan solas al abrirla y llaman a funciones "
            "para ejecutar programas o cargar código (EXEC, CALL, REGISTER...). Es una técnica muy usada para "
            "distribuir malware porque muchos antivirus no la analizan bien.",
            score,
            evidence,
        )
    if auto or funcs:
        return _mk(
            job,
            "office.xlm.suspicious",
            "Macros de Excel 4.0 sospechosas",
            "La planilla contiene macros de Excel 4.0 (XLM) que se ejecutan al abrir o que usan funciones capaces "
            "de ejecutar programas. Este formato antiguo hoy casi solo se usa para distribuir malware.",
            50 + (5 if hidden or obf else 0),
            evidence,
        )
    return _mk(
        job,
        "office.xlm.macros",
        "Planilla con macros antiguas de Excel 4.0 (XLM)",
        "La planilla contiene una hoja de macros de Excel 4.0, un formato antiguo que hoy casi solo se usa para "
        "distribuir malware porque muchos antivirus no lo revisan bien.",
        40 + (5 if hidden or obf else 0),
        evidence,
    )


def _build_findings(job: _Job, rep: _Report) -> list[Finding]:
    out: list[Finding] = []
    vba = _grade_vba(job, rep)
    if vba:
        out.append(vba)
    if rep.stomping:
        out.append(
            _mk(
                job,
                "office.vba.stomping",
                "Macros con código oculto (VBA stomping)",
                "El código fuente visible de las macros no coincide con el código compilado que realmente ejecuta "
                "Office. Es una técnica para engañar a los antivirus y a los analistas; los documentos legítimos "
                "no la usan.",
                70,
                {"donde": _uniq(rep.stomping, 6)},
            )
        )
    xlm = _grade_xlm(job, rep)
    if xlm:
        out.append(xlm)
    if rep.dde:
        dangerous = any(d.get("peligroso") for d in rep.dde)
        out.append(
            _mk(
                job,
                "office.dde",
                "Documento que ejecuta comandos mediante DDE",
                "El documento contiene un vínculo o campo DDE: al abrirlo, Office ofrece 'actualizar vínculos' y, "
                "si se acepta, ejecuta el programa indicado. Es una técnica conocida para ejecutar malware sin "
                "usar macros.",
                (80 if any(_DANGEROUS_CMD_RE.search(d.get("comando", "")) for d in rep.dde) else 75)
                if dangerous
                else 35,
                {"vinculos": _uniq(rep.dde, 8)},
            )
        )
    if rep.follina:
        out.append(
            _mk(
                job,
                "office.follina",
                "Exploit tipo 'Follina' (CVE-2022-30190) en el documento",
                "El documento referencia un recurso externo con un protocolo especial (mhtml:, ms-msdt: o un "
                "objeto HTML remoto) que se usa para ejecutar código en Windows apenas se abre o se previsualiza "
                "el archivo, sin macros (CVE-2022-30190 'Follina' / CVE-2021-40444). Es un ataque grave.",
                85,
                {"relaciones": _uniq(rep.follina, 8), "cve": ["CVE-2022-30190", "CVE-2021-40444"]},
            )
        )
    remote_f = _grade_remote(job, rep)
    if remote_f:
        out.append(remote_f)
    if rep.unc:
        out.append(
            _mk(
                job,
                "office.external_unc",
                "Documento que se conecta a un servidor externo al abrirse",
                "El documento carga un recurso desde una ruta de red (\\\\servidor\\...) o un protocolo especial de "
                "Windows. Al abrirlo, Windows puede enviar automáticamente las credenciales del usuario (hash NTLM) "
                "a ese servidor o abrir aplicaciones locales.",
                40,
                {"relaciones": _uniq(rep.unc, 8)},
            )
        )
    if rep.equation:
        eqn = any(e.get("variante") == "eqnedt" for e in rep.equation)
        desc = (
            "El documento contiene un objeto del antiguo Editor de Ecuaciones de Office, un componente con una "
            "vulnerabilidad muy explotada (CVE-2017-11882 / CVE-2018-0802) que permite ejecutar código solo con "
            "abrir el archivo en equipos sin actualizar. Hoy casi no existen documentos legítimos con estos objetos."
        )
        if not eqn:
            desc += " (El objeto se identifica como MathType: podría ser una ecuación legítima, conviene verificarlo.)"
        out.append(
            _mk(
                job,
                "office.cve_2017_11882",
                "Objeto del Editor de Ecuaciones: posible exploit CVE-2017-11882",
                desc,
                80 if eqn else 70,
                {"objetos": _uniq(rep.equation, 8), "cve": ["CVE-2017-11882", "CVE-2018-0802"]},
            )
        )
    if rep.ole_link:
        out.append(
            _mk(
                job,
                "office.cve_2017_0199",
                "Objeto vinculado que descarga contenido remoto (CVE-2017-0199)",
                "El documento contiene un objeto OLE vinculado (OLE2Link / moniker de URL o de script) que al "
                "abrirse descarga y ejecuta contenido remoto, por ejemplo una aplicación HTA. Es un exploit "
                "conocido (CVE-2017-0199 / CVE-2017-8570).",
                80,
                {"objetos": _uniq(rep.ole_link, 8), "cve": ["CVE-2017-0199", "CVE-2017-8570"]},
            )
        )
    dangerous_pkgs = [p for p in rep.packages if p.get("peligroso")]
    if dangerous_pkgs:
        is_pe = any(p.get("tipo_contenido") in ("pe", "elf") for p in dangerous_pkgs)
        names = ", ".join(p["nombre"] for p in dangerous_pkgs[:3] if p.get("nombre")) or "sin nombre"
        out.append(
            _mk(
                job,
                "office.ole_package_executable",
                "Documento con un programa o script incrustado",
                f"Dentro del documento hay un archivo incrustado que es un programa o script ({names}). Los "
                "atacantes lo disfrazan con un ícono para que el usuario haga doble clic y lo ejecute.",
                80 if is_pe else 75,
                {"paquetes": _uniq(dangerous_pkgs, 8)},
            )
        )
    if rep.rtf_objupdate or rep.rtf_objautlink:
        out.append(
            _mk(
                job,
                "office.rtf.objupdate",
                "RTF que fuerza la carga automática de objetos",
                "El documento RTF le indica a Word que cargue o actualice automáticamente los objetos incrustados "
                "al abrirlo (\\objupdate / \\objautlink). Es un truco habitual de los exploits para activar el "
                "objeto sin intervención del usuario.",
                30,
                {
                    "objupdate": rep.rtf_objupdate or None,
                    "objautlink": rep.rtf_objautlink or None,
                    "objetos": _uniq(rep.rtf_objects, 8),
                },
            )
        )
    if rep.rtf_obfuscation:
        out.append(
            _mk(
                job,
                "office.rtf.obfuscation",
                "RTF con datos de objetos ofuscados",
                "Los datos de los objetos del RTF están escritos con trucos que Word tolera pero que confunden a "
                "los antivirus. Los documentos generados por programas normales no hacen esto.",
                15,
                {"tecnicas": rep.rtf_obfuscation},
            )
        )
    if rep.activex:
        out.append(
            _mk(
                job,
                "office.activex",
                "Documento con controles ActiveX",
                "El documento contiene controles ActiveX, componentes que pueden ejecutar código o disparar macros "
                "automáticamente al abrirlo. Son poco comunes en documentos que llegan por mail.",
                25,
                {"controles": _uniq(rep.activex, 8)},
            )
        )
    if rep.encrypted is not None:
        decrypted = bool(rep.encrypted.get("descifrado"))
        default_key = "VelvetSweatshop" in str(rep.encrypted.get("clave", ""))
        desc = (
            "El documento está cifrado con contraseña, por lo que los antivirus no pueden revisar su contenido. "
            "Los atacantes envían documentos cifrados (con la clave en el texto del mail) justamente para evadir "
            "los controles. Si no se esperaba, conviene confirmar con el remitente por otro medio."
        )
        if decrypted and default_key:
            desc += (
                " Usa la clave por defecto de Excel, un truco para que abra sin pedir contraseña pero quede "
                "oculto para los antivirus; Centinela lo abrió en memoria y analizó su contenido."
            )
        elif decrypted:
            desc += " Centinela pudo abrirlo en memoria con una contraseña conocida y analizó su contenido."
        out.append(
            _mk(
                job,
                "office.encrypted",
                "Documento protegido con contraseña",
                desc,
                35 if (not decrypted or default_key) else 25,
                dict(rep.encrypted),
                category=FindingCategory.POLICY,
                severity=Severity.MEDIUM,
            )
        )
    if rep.embedded:
        out.append(
            _mk(
                job,
                "office.embedded_objects",
                "Documento con objetos incrustados",
                "El documento contiene archivos u objetos incrustados. Su contenido se revisa por separado.",
                0,
                {"objetos": _uniq(rep.embedded, 15)},
            )
        )
    elif rep.rtf_objects and not (rep.rtf_objupdate or rep.rtf_objautlink):
        out.append(
            _mk(
                job,
                "office.embedded_objects",
                "Documento RTF con objetos incrustados",
                "El documento RTF contiene objetos incrustados (OLE). Se revisaron en busca de exploits conocidos.",
                0,
                {"objetos": _uniq(rep.rtf_objects, 15)},
            )
        )
    if rep.corrupted:
        out.append(
            _mk(
                job,
                "office.corrupted",
                "Documento de Office dañado o manipulado",
                "El archivo dice ser un documento de Office pero su estructura está rota. Office puede 'repararlo' y "
                "mostrar su contenido igual, un truco usado para que los antivirus no lo revisen.",
                10,
                {"errores": rep.errors[:5]},
                category=FindingCategory.POLICY,
            )
        )
    elif rep.errors:
        out.append(
            _mk(
                job,
                "office.parse_error",
                "No se pudo leer completamente el documento",
                "Parte del documento no se pudo interpretar; el análisis puede estar incompleto.",
                0,
                {"errores": rep.errors[:8]},
                category=FindingCategory.POLICY,
            )
        )
    if rep.partial:
        out.append(
            _mk(
                job,
                "office.partial_analysis",
                "Análisis parcial del documento",
                "El documento es muy grande o complejo y se analizó solo en parte.",
                0,
                {"motivos": rep.partial[:8]},
                category=FindingCategory.POLICY,
            )
        )
    best: dict[str, Finding] = {}
    for f in out:
        if f.rule not in best or f.score > best[f.rule].score:
            best[f.rule] = f
    return list(best.values())


def _grade_remote(job: _Job, rep: _Report) -> Finding | None:
    if not rep.remote:
        return None
    score = 0
    for r in rep.remote:
        target = r.get("destino", "")
        if r.get("clase") == "unc":
            s = 30 if job.internal_sender else 70
        elif r.get("clase") == "protocol":
            s = 70
        else:
            host = _host_of(target)
            path = target.split("?", 1)[0].lower()
            if host.endswith(_M365_TEMPLATE_HOSTS) and path.endswith(_MACRO_FREE_TEMPLATE_EXTS):
                s = 10  # plantilla corporativa de SharePoint sin macros: habitual y legítimo
            else:
                s = 70 if r.get("tipo") == "frame" else 75
        r["puntaje"] = s
        score = max(score, s)
    return _mk(
        job,
        "office.remote_template",
        "Documento que descarga una plantilla o contenido remoto al abrirse",
        "Al abrir el documento, Office descarga automáticamente contenido desde una dirección externa (plantilla, "
        "marco u objeto). Los atacantes usan esta 'inyección de plantilla' para traer macros o exploits que no "
        "están dentro del archivo, así los antivirus no los ven. Si la dirección es una ruta de red (\\\\servidor), "
        "además puede filtrar credenciales de Windows.",
        score,
        {"relaciones": _uniq(rep.remote, 8)},
    )


__all__ = ["OfficeAnalyzer"]
