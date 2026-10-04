"""Analizador de archivos de OneNote (.one).

Desde 2023 los atacantes envían "cuadernos" de OneNote con un botón falso ("Doble clic para ver el
documento") que tapa un archivo incrustado: un .hta, .js, .vbs, .bat, .cmd, .ps1, .wsf, .lnk o un .exe
directamente (Qakbot, AsyncRAT, IcedID, Emotet, RedLine...). OneNote ejecuta el archivo con un doble clic.

Se buscan los objetos `FileDataStoreObject` ([MS-ONESTORE] 2.6.13: GUID de cabecera
{BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC}, cbLength de 8 bytes, 12 bytes reservados y luego los datos)
y se clasifica cada payload por su contenido real. Los nombres de los archivos incrustados se recuperan
de las cadenas UTF-16 del archivo. Los payloads ya los extrae el parser como artifacts hijos: acá solo
se señala su presencia y naturaleza.
"""

from __future__ import annotations

import asyncio
import hashlib
import itertools
import logging
import re
import struct
import time
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from centinela.analyzers.base import ArtifactAnalyzer
from centinela.core.models import Finding, FindingCategory, Severity

if TYPE_CHECKING:
    from centinela.analyzers.base import AnalysisContext
    from centinela.core.models import Artifact

log = logging.getLogger(__name__)

ONENOTE_HEADER = uuid.UUID("7B5C52E4-D88C-4DA7-AEB1-5378D02996D3").bytes_le  # guidFileType de .one
FDSO_HEADER = uuid.UUID("BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC").bytes_le  # FileDataStoreObject.guidHeader
FDSO_FOOTER = uuid.UUID("71FBA722-0F79-4A0B-BB13-899256426B24").bytes_le
_FDSO_DATA_OFFSET = 16 + 8 + 4 + 8  # guidHeader + cbLength + unused + reserved

_MAX_INPUT = 120 * 1024 * 1024
_MAX_OBJECTS = 200
_MAX_NAMES = 30
_EV_ITEMS = 10

_SCRIPT_EXTS = frozenset(
    "hta js jse vbs vbe bat cmd ps1 psm1 wsf wsh wsc lnk chm scr pif com sct url".split()
)
_PE_EXTS = frozenset("exe dll cpl msi scr com pif".split())
_DANGEROUS_EXTS = _SCRIPT_EXTS | _PE_EXTS
_NAME_EXT_RE = re.compile(rb"\.\x00((?:[A-Za-z0-9]\x00){2,5})(?![A-Za-z0-9]\x00)")
_LURES = (
    "double click",
    "double-click",
    "doble clic",
    "doble click",
    "click to view",
    "haga doble",
    "hacé doble",
    "hace doble",
    "clique duas",
    "duplo clique",
    "view document",
    "ver documento",
)


def _s(value: Any, n: int = 200) -> str:
    text = str(value)
    text = "".join(c if c.isprintable() else "?" for c in text[: n * 2])
    return text if len(text) <= n else text[: n - 1] + "…"


@dataclass
class _Payload:
    offset: int
    size: int
    kind: str  # pe, lnk, hta, js, vbs, bat, ps1, wsf, chm, html, image, document, archive, other
    family: str  # ejecutable | script | html | imagen | documento | otro
    sha256: str
    truncated: bool

    def evidence(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "tipo": self.kind,
            "tamaño": self.size,
            "offset": self.offset,
            "sha256": self.sha256,
        }
        if self.truncated:
            out["truncado"] = True
        return out


@dataclass
class _Scan:
    payloads: list[_Payload] = field(default_factory=list)
    names: list[str] = field(default_factory=list)
    lures: list[str] = field(default_factory=list)
    has_header: bool = False
    skipped: int = 0


class OneNoteAnalyzer(ArtifactAnalyzer):
    """Archivos de OneNote con ejecutables o scripts escondidos detrás de botones falsos."""

    name = "onenote"

    def accepts(self, artifact: Artifact) -> bool:
        if artifact.listing_only or not artifact.data:  # entrada solo listada: no hay contenido que abrir
            return False
        if artifact.detected_type == "onenote":
            return True
        return artifact.extension == "one" and artifact.detected_type in ("unknown", "onenote")

    async def analyze(self, ctx: AnalysisContext, artifact: Artifact) -> list[Finding]:
        if not artifact.data or artifact.listing_only:
            return []
        deadline = time.monotonic() + max(5.0, float(ctx.settings.limits.analyzer_timeout_s) * 0.8)
        scan = await asyncio.to_thread(scan_onenote, artifact.data, deadline)
        return _findings(artifact, scan)


def scan_onenote(data: bytes, deadline: float | None = None) -> _Scan:
    """Busca FileDataStoreObjects, clasifica cada payload y junta nombres de archivo y textos señuelo."""
    scan = _Scan(has_header=data.startswith(ONENOTE_HEADER))
    data = data[:_MAX_INPUT]
    pos = 0
    n = len(data)
    while True:
        idx = data.find(FDSO_HEADER, pos)
        if idx < 0:
            break
        pos = idx + 16
        if len(scan.payloads) >= _MAX_OBJECTS or (deadline is not None and time.monotonic() > deadline):
            scan.skipped += 1
            break
        if idx + _FDSO_DATA_OFFSET > n:
            break
        (cb,) = struct.unpack_from("<Q", data, idx + 16)
        start = idx + _FDSO_DATA_OFFSET
        available = n - start
        truncated = cb > available
        size = min(cb, available)
        payload = data[start : start + size]
        kind, family = _classify(payload)
        scan.payloads.append(
            _Payload(
                offset=idx,
                size=int(cb),
                kind=kind,
                family=family,
                sha256=hashlib.sha256(payload).hexdigest(),
                truncated=truncated,
            )
        )
        if not truncated and size > 0:
            pos = max(pos, start + size)  # saltar el payload: un archivo incrustado podría contener el GUID
    scan.names = _embedded_names(data)
    low = data.lower()
    for lure in _LURES:
        if lure.encode("utf-16-le") in low or lure.encode() in low:
            scan.lures.append(lure)
    return scan


def _classify(payload: bytes) -> tuple[str, str]:
    head = payload[:4096]
    if head.startswith(b"MZ"):
        return "pe", "ejecutable"
    if head.startswith(b"\x7fELF"):
        return "elf", "ejecutable"
    if head.startswith(b"L\x00\x00\x00\x01\x14\x02\x00"):
        return "lnk", "script"
    if head.startswith(b"ITSF"):
        return "chm", "script"
    if head.startswith(
        (
            b"\x89PNG",
            b"\xff\xd8\xff",
            b"GIF87a",
            b"GIF89a",
            b"BM",
            b"\xd7\xcd\xc6\x9a",
            b"II*\x00",
            b"MM\x00*",
        )
    ):
        return "image", "imagen"
    if len(head) > 44 and head[:4] == b"\x01\x00\x00\x00" and head[40:44] == b" EMF":
        return "image", "imagen"
    if head.startswith(b"%PDF"):
        return "pdf", "documento"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole", "documento"
    if head.startswith(b"PK\x03\x04"):
        return "zip", "documento"
    if head.startswith((b"Rar!", b"7z\xbc\xaf", b"MSCF")) or payload[0x8001:0x8006] == b"CD001":
        return "archive", "documento"
    if head.startswith(b"{\\rt"):
        return "rtf", "documento"
    text = _as_text(head)
    if text is None:
        return "other", "otro"
    t = text.lower()
    has_markup = "<html" in t or "<head" in t
    if "<hta:application" in t or (
        has_markup and ("vbscript" in t or ("<script" in t and "activexobject" in t))
    ):
        return "hta", "script"
    if ("<job" in t or "<package" in t) and "<script" in t:
        return "wsf", "script"
    if "<html" in t or "<!doctype html" in t or "<svg" in t:
        return "html", "html"
    if _PS1_RE.search(t):
        return "ps1", "script"
    if _BAT_RE.search(t):
        return "bat", "script"
    if _VBS_RE.search(t):
        return "vbs", "script"
    if _JS_RE.search(t):
        return "js", "script"
    return "text", "otro"


_PS1_RE = re.compile(
    r"\$env:|invoke-(?:expression|webrequest|restmethod)|\biex\b|frombase64string|new-object\s+(?:system\.)?net\.|"
    r"-encodedcommand|start-process|downloadstring\s*\("
)
_BAT_RE = re.compile(
    r"^\s*@?echo\s+off\b|%comspec%|%~dp0|\bcmd(?:\.exe)?\s+/[ck]\b|^\s*(?:start\s+/[a-z]|call\s+:|goto\s+:|"
    r"if\s+(?:not\s+)?exist\b)",
    re.M,
)
_VBS_RE = re.compile(
    r"\bwscript\.|createobject\s*\(|\bon error resume next\b|\bexecute(?:global)?\s*\(|^\s*dim\s+\w+", re.M
)
_JS_RE = re.compile(
    r"activexobject|wscript\.shell|\beval\s*\(|string\.fromcharcode|\bfunction\s+\w+\s*\(|\bvar\s+\w+\s*="
)


def _as_text(head: bytes) -> str | None:
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return head.decode("utf-16")
        except UnicodeDecodeError:
            return None
    sample = head[:1024]
    if not sample:
        return None
    printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
    if printable / len(sample) < 0.85:
        return None
    return head.decode("latin-1")


def _embedded_names(data: bytes) -> list[str]:
    """Nombres de archivo en UTF-16LE con extensión peligrosa (búsqueda lineal: se ubica la extensión y se
    camina hacia atrás)."""
    out: list[str] = []
    for m in itertools.islice(_NAME_EXT_RE.finditer(data), 20000):
        ext = m.group(1).decode("utf-16-le", "replace").lower()
        if ext not in _DANGEROUS_EXTS:
            continue
        start = m.start()
        i = start
        while i >= 2 and start - i < 240:
            ch = data[i - 2 : i]
            if ch[1] != 0 or not (0x20 <= ch[0] < 0x7F) or ch[0] in b'\\/:*?"<>|':
                break
            i -= 2
        stem = data[i:start].decode("utf-16-le", "replace").strip()
        if not stem:
            continue
        name = f"{stem}.{ext}"
        if name not in out:
            out.append(name)
        if len(out) >= _MAX_NAMES:
            break
    return out


def _mk(
    artifact: Artifact,
    rule: str,
    title: str,
    description: str,
    severity: Severity,
    score: int,
    evidence: dict[str, Any],
    category: FindingCategory = FindingCategory.SUSPICIOUS_FILE,
) -> Finding:
    return Finding(
        analyzer="onenote",
        rule=rule,
        title=title,
        description=description,
        category=category,
        severity=severity,
        score=max(0, min(100, score)),
        artifact_id=artifact.id,
        evidence={k: v for k, v in evidence.items() if v not in (None, [], {}, "")},
    )


_TRICK = (
    " Desde 2023 los atacantes envían archivos de OneNote con un botón falso ('doble clic para ver el "
    "documento') que tapa el archivo malicioso."
)


def _findings(artifact: Artifact, scan: _Scan) -> list[Finding]:
    out: list[Finding] = []
    pe = [p for p in scan.payloads if p.family == "ejecutable"]
    scripts = [p for p in scan.payloads if p.family == "script"]
    html = [p for p in scan.payloads if p.family == "html"]
    docs = [p for p in scan.payloads if p.family == "documento"]
    images = [p for p in scan.payloads if p.family == "imagen"]
    dangerous_names = [n for n in scan.names if n.rsplit(".", 1)[-1].lower() in _DANGEROUS_EXTS]
    bump = 5 if scan.lures else 0
    common = {
        "nombres_incrustados": [_s(n) for n in dangerous_names[:_EV_ITEMS]],
        "textos_señuelo": scan.lures[:5],
    }

    if pe:
        out.append(
            _mk(
                artifact,
                "onenote.embedded_pe",
                "OneNote con un programa (.exe) escondido adentro",
                "El archivo de OneNote trae incrustado un programa ejecutable de Windows. Con un doble clic sobre "
                "el botón o imagen que lo tapa, el programa se ejecuta e instala el malware." + _TRICK,
                Severity.HIGH,
                min(90, 85 + bump),
                {"payloads": [p.evidence() for p in pe[:_EV_ITEMS]], **common},
            )
        )
    if scripts:
        kinds = sorted({p.kind for p in scripts})
        out.append(
            _mk(
                artifact,
                "onenote.embedded_script",
                "OneNote con un script escondido adentro",
                f"El archivo de OneNote trae incrustado un script o acceso directo ({', '.join(kinds)}). Con un "
                "doble clic se ejecuta y descarga o instala malware (troyanos de acceso remoto, ladrones de "
                "contraseñas, ransomware)." + _TRICK,
                Severity.HIGH,
                min(85, 80 + bump),
                {"payloads": [p.evidence() for p in scripts[:_EV_ITEMS]], **common},
            )
        )
    if dangerous_names and not (pe or scripts):
        out.append(
            _mk(
                artifact,
                "onenote.dangerous_filename",
                "OneNote que referencia un archivo ejecutable o script",
                "Dentro del archivo de OneNote aparece el nombre de un archivo ejecutable o script incrustado ("
                + ", ".join(_s(n, 60) for n in dangerous_names[:3])
                + "). Es la forma en que se esconden programas maliciosos en OneNote."
                + _TRICK,
                Severity.HIGH,
                70 + bump,
                common,
            )
        )
    if html:
        out.append(
            _mk(
                artifact,
                "onenote.embedded_html",
                "OneNote con una página web incrustada",
                "El archivo de OneNote trae incrustada una página web: al abrirla puede mostrar un formulario falso "
                "para robar contraseñas o descargar un archivo malicioso.",
                Severity.MEDIUM,
                35,
                {"payloads": [p.evidence() for p in html[:_EV_ITEMS]], **common},
            )
        )
    if docs:
        out.append(
            _mk(
                artifact,
                "onenote.embedded_file",
                "OneNote con documentos o comprimidos incrustados",
                "El archivo de OneNote trae incrustados otros archivos (documentos o comprimidos) que pueden contener "
                "malware; se analizan por separado." + _TRICK,
                Severity.MEDIUM,
                30,
                {"payloads": [p.evidence() for p in docs[:_EV_ITEMS]]},
            )
        )
    if images:
        out.append(
            _mk(
                artifact,
                "onenote.embedded_image",
                "OneNote con imágenes incrustadas",
                "El archivo de OneNote contiene imágenes (contexto: los señuelos suelen ser una imagen con un botón "
                "'abrir').",
                Severity.INFO,
                0,
                {"cantidad": len(images)},
            )
        )
    if not any(f.severity >= Severity.MEDIUM for f in out) and (scan.has_header or scan.payloads):
        out.append(
            _mk(
                artifact,
                "onenote.file",
                "Archivo de OneNote adjunto",
                "Llegó un archivo de OneNote (.one). No se encontraron programas escondidos, pero no es un formato "
                "habitual para compartir documentos por mail." + _TRICK,
                Severity.LOW,
                10,
                {"objetos_incrustados": len(scan.payloads), "textos_señuelo": scan.lures[:5]},
            )
        )
    return out


__all__ = ["OneNoteAnalyzer", "scan_onenote"]
