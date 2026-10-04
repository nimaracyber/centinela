"""Analizador de PDF.

Dos capas complementarias:

1. Conteo de palabras clave estilo *pdfid* sobre los bytes crudos (/JS, /JavaScript, /OpenAction, /AA,
   /Launch, /EmbeddedFile, /URI, /SubmitForm, /GoToR, /GoToE, /RichMedia, /XFA, /AcroForm, /ObjStm,
   /Encrypt...), des-ofuscando nombres con escapes `#xx`. Funciona aunque el PDF esté roto o cifrado
   (los nombres de las claves nunca se cifran).
2. Recorrido estructural con pypdf (strict=False, acotado): acciones JavaScript y su disparo automático
   (/OpenAction, /AA, JavaScript a nivel documento), destinos de /Launch, archivos incrustados (nombre y
   tipo real), links, formularios que envían datos, XFA y texto de las primeras páginas para detectar
   PDFs "señuelo" que solo llevan a un link de phishing.

Extras: PDF que es también un documento de Word con macros ("MalDoc in PDF", JPCERT 2023) y payloads
pegados después del final del PDF. Nada se ejecuta ni se escribe a disco; los streams se descomprimen
en memoria con límite de tamaño.
"""

from __future__ import annotations

import asyncio
import io
import itertools
import logging
import re
import time
import zlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from centinela.analyzers.base import ArtifactAnalyzer
from centinela.core.models import Finding, FindingCategory, Severity

if TYPE_CHECKING:
    from centinela.analyzers.base import AnalysisContext
    from centinela.core.models import Artifact

log = logging.getLogger(__name__)
logging.getLogger("pypdf").setLevel(logging.ERROR)  # los PDF hostiles generan cientos de warnings

# --------------------------------------------------------------------------- límites

_MAX_INPUT = 80 * 1024 * 1024
_MAX_OBJECTS = 50_000
_MAX_NODES = 400_000
_MAX_DEPTH = 12
_MAX_JS = 20
_MAX_JS_CHARS = 256 * 1024
_MAX_STREAM_READ = 512 * 1024
_MAX_TEXT_PAGES = 3
_MAX_PAGE_CONTENT = 2 * 1024 * 1024
_MAX_TEXT_CHARS = 50_000
_MAX_URIS = 200
_EV_STR = 300
_EV_ITEMS = 10

_KEYWORDS = frozenset(
    {
        b"JS",
        b"JavaScript",
        b"OpenAction",
        b"AA",
        b"Launch",
        b"EmbeddedFile",
        b"EmbeddedFiles",
        b"URI",
        b"SubmitForm",
        b"GoToR",
        b"GoToE",
        b"RichMedia",
        b"XFA",
        b"AcroForm",
        b"ObjStm",
        b"Encrypt",
        b"JBIG2Decode",
        b"Page",
        b"ImportData",
    }
)
_NAME_RE = re.compile(rb"/([^\x00\t\n\x0c\r ()<>\[\]{}/%]{1,100})")
_HEX_ESC_RE = re.compile(rb"#([0-9A-Fa-f]{2})")
_LAUNCH_RAW_RE = re.compile(rb"/Launch\b")
_RAW_URI_RE = re.compile(rb"/URI\s*\(([^)\\]{4,2000})\)")

_EXEC_TARGET_RE = re.compile(
    r"\b(?:cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh|mshta|wscript|cscript|rundll32|regsvr32|certutil|"
    r"bitsadmin|msiexec|conhost|forfiles|curl(?:\.exe)?|/bin/(?:ba)?sh|bash)\b",
    re.I,
)
_EXEC_EXTS = frozenset(
    "exe scr com pif bat cmd vbs vbe js jse wsf wsh wsc hta ps1 psm1 lnk dll cpl msi msp msc jar sct inf "
    "reg chm url scf appref-ms application gadget xll hlp jnlp".split()
)
_RISKY_EXTS = frozenset(
    "zip rar 7z iso img vhd vhdx cab gz tar docm dotm xlsm xltm xlam pptm ppsm doc xls ppt rtf one html htm "
    "svg xht xhtml shtml".split()
)
_JS_EXPLOIT_RE = re.compile(
    r"util\.printf|Collab\.(?:collectEmailInfo|getIcon)|media\.newPlayer|spell\.customDictionaryOpen|"
    r"\.getAnnots\s*\(|%u0c0c|%u9090|\\x0c\\x0c\\x0c|0x0c0c0c0c|\.rawValue\s*=.{0,40}unescape",
    re.I | re.S,
)
_JS_DROPPER_RE = re.compile(
    r"exportDataObject\s*\([^)]{0,500}nLaunch|importDataObject|app\.openDoc\s*\(", re.I | re.S
)
_JS_URL_RE = re.compile(r"(?:app\.)?launchURL\s*\(|getURL\s*\(|submitForm\s*\(", re.I)
_JS_OBF_RE = re.compile(
    r"\beval\s*\(|String\.fromCharCode|\bunescape\s*\(|\batob\s*\(|(?:\\x[0-9a-f]{2}){8}", re.I
)
_LURE_RE = re.compile(
    r"\b(?:ver|abrir|descargar|acceder\s+al?|revisar|visualizar|consultar)\s+(?:el\s+|la\s+|su\s+|tu\s+|los\s+|las\s+)?"
    r"(?:documento|factura|archivo|comprobante|pdf|adjunto|pago|transferencia|recibo|orden|propuesta|contrato|"
    r"presupuesto|resumen|cotizaci[oó]n|mensaje|fotos?)"
    r"|\bclic(?:k)?\s+(?:aqu[ií]|ac[aá]|here)\b|\bclick\s+here\b|\bhaga\s+clic\b|\bhac[eé]\s+clic\b|"
    r"\bpresione\s+aqu[ií]\b|\bclique\s+aqui\b"
    r"|\b(?:view|download|open|access|review)\s+(?:the\s+|your\s+)?(?:document|file|invoice|pdf|attachment|"
    r"message|statement)s?\b"
    r"|\bdocumento\s+(?:protegido|seguro|compartido|cifrado)\b|\bsecured?\s+document\b|\bshared\s+(?:a\s+)?"
    r"document\b|\bbaixar\s+(?:o\s+)?(?:documento|arquivo|boleto)\b",
    re.I,
)
_MALDOC_RE = re.compile(rb"QWN0aXZlTWltZQ|application/x-mso|Content-Type:\s*application/x-mso", re.I)
_APPENDED_MAGICS = (
    (b"MZ", "ejecutable de Windows"),
    (b"PK\x03\x04", "ZIP"),
    (b"Rar!", "RAR"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "documento OLE de Office"),
)


# --------------------------------------------------------------------------- utilidades


def _s(value: Any, n: int = _EV_STR) -> str:
    if isinstance(value, bytes | bytearray):
        value = bytes(value).decode("latin-1", "replace")
    text = " ".join(str(value)[: n * 4].split())
    text = "".join(c if c.isprintable() else "?" for c in text)
    return text if len(text) <= n else text[: n - 1] + "…"


def _uniq(items: list[Any], n: int = _EV_ITEMS) -> list[Any]:
    out: list[Any] = []
    seen: set[str] = set()
    for it in items:
        key = repr(it)
        if key not in seen:
            seen.add(key)
            out.append(it)
            if len(out) >= n:
                break
    return out


def _ext_of(name: str) -> str:
    name = name.replace("\\", "/").rsplit("/", 1)[-1].strip().strip("\x00").rstrip(". ")
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def _magic_kind(head: bytes) -> str:
    if head.startswith(b"MZ"):
        return "pe"
    if head.startswith(b"L\x00\x00\x00\x01\x14\x02\x00"):
        return "lnk"
    if head.startswith(b"PK\x03\x04"):
        return "zip"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if head.startswith(b"%PDF"):
        return "pdf"
    if head.startswith(b"{\\rt"):
        return "rtf"
    if head.startswith((b"Rar!", b"7z\xbc\xaf")):
        return "archivo comprimido"
    if head[:64].lstrip().lower().startswith((b"<html", b"<!doctype html", b"<script", b"<svg", b"<hta")):
        return "html"
    return "otro" if head else "desconocido"


def _host_of(url: str) -> str:
    m = re.match(r"^[a-z][a-z0-9+.-]{0,20}://([^/\\?#@]{1,255}@)?([^/\\?#:]{1,255})", url.strip(), re.I)
    return (m.group(2) if m else "").lower().rstrip(".")


# --------------------------------------------------------------------------- estado


@dataclass
class _PdfJob:
    artifact_id: str
    data: bytes
    company_domains: tuple[str, ...]
    deadline: float

    def expired(self) -> bool:
        return time.monotonic() > self.deadline


@dataclass
class _Sig:
    counts: dict[str, int] = field(default_factory=dict)
    obfuscated: dict[str, int] = field(default_factory=dict)
    header_offset: int = 0
    appended: str | None = None
    maldoc: bool = False
    parsed: bool = False
    parse_error: str | None = None
    encrypted: bool = False
    decrypted: bool = False
    pages: int | None = None
    js: list[tuple[str, str]] = field(default_factory=list)  # (origen, código)
    auto_js: bool = False
    auto_reason: list[str] = field(default_factory=list)
    doc_js: bool = False
    auto_uri: list[str] = field(default_factory=list)
    launch: list[str] = field(default_factory=list)
    uris: list[str] = field(default_factory=list)
    links: list[tuple[str, float]] = field(default_factory=list)  # (uri, fracción de la página que ocupa)
    submit: list[str] = field(default_factory=list)
    goto_remote: list[str] = field(default_factory=list)
    embedded: list[dict[str, Any]] = field(default_factory=list)
    richmedia: bool = False
    xfa: bool = False
    text: str = ""
    words: int | None = None
    partial: list[str] = field(default_factory=list)

    def c(self, key: str) -> int:
        return self.counts.get(key, 0)

    def add_js(self, origin: str, code: str) -> None:
        code = code.strip()
        if code and len(self.js) < _MAX_JS and all(code != c for _o, c in self.js):
            self.js.append((origin, code[:_MAX_JS_CHARS]))

    def note_partial(self, why: str) -> None:
        if why not in self.partial and len(self.partial) < 10:
            self.partial.append(why)


# --------------------------------------------------------------------------- analizador


class PdfAnalyzer(ArtifactAnalyzer):
    """PDF con JavaScript, acciones automáticas, /Launch, adjuntos ejecutables y señuelos de phishing."""

    name = "pdf"

    def accepts(self, artifact: Artifact) -> bool:
        if artifact.listing_only or not artifact.data:  # entrada solo listada: no hay contenido que abrir
            return False
        if artifact.detected_type == "pdf":
            return True
        return artifact.extension == "pdf" and b"%PDF" in artifact.data[:1024]

    async def analyze(self, ctx: AnalysisContext, artifact: Artifact) -> list[Finding]:
        if not artifact.data or artifact.listing_only:
            return []
        budget = max(5.0, float(ctx.settings.limits.analyzer_timeout_s) * 0.8)
        job = _PdfJob(
            artifact_id=artifact.id,
            data=artifact.data,
            company_domains=tuple(d.lower().lstrip("@") for d in ctx.settings.general.company_domains),
            deadline=time.monotonic() + budget,
        )
        return await asyncio.to_thread(_run_pdf, job)


def _run_pdf(job: _PdfJob) -> list[Finding]:
    sig = _Sig()
    data = job.data
    if len(data) > _MAX_INPUT:
        sig.note_partial(f"PDF demasiado grande ({len(data)} bytes): solo se revisaron los primeros bytes")
        data = data[:_MAX_INPUT]
    try:
        _raw_scan(data, sig)
    except Exception:  # noqa: BLE001
        log.debug("pdf: error en el escaneo crudo", exc_info=True)
    if not job.expired():
        try:
            _pypdf_scan(job, data, sig)
        except Exception as exc:  # noqa: BLE001 - PDF hostil o roto: se sigue con lo crudo
            log.debug("pdf: pypdf falló", exc_info=True)
            sig.parse_error = f"{type(exc).__name__}"
    return _build_findings(job, sig)


# --------------------------------------------------------------------------- capa 1: bytes crudos


def _raw_scan(data: bytes, sig: _Sig) -> None:
    sig.header_offset = max(0, data.find(b"%PDF", 0, 1024))
    for m in _NAME_RE.finditer(data):
        name = m.group(1)
        if b"#" in name:
            decoded = _HEX_ESC_RE.sub(lambda h: bytes([int(h.group(1), 16)]), name)
            if decoded != name and decoded in _KEYWORDS:
                k = "/" + decoded.decode("latin-1")
                sig.obfuscated[k] = sig.obfuscated.get(k, 0) + 1
            name = decoded
        if name in _KEYWORDS:
            k = "/" + name.decode("latin-1")
            sig.counts[k] = sig.counts.get(k, 0) + 1
    sig.maldoc = bool(_MALDOC_RE.search(data))  # el MHT suele ir pegado al final del PDF
    last = data.rfind(b"%%EOF")
    if last >= 0:
        tail = data[last + 5 :].lstrip(b"\r\n\x00 \t")
        for magic, label in _APPENDED_MAGICS:
            if tail.startswith(magic):
                sig.appended = label
                break


# --------------------------------------------------------------------------- capa 2: pypdf


def _pypdf_scan(job: _PdfJob, data: bytes, sig: _Sig) -> None:
    try:
        from pypdf import PdfReader
    except Exception:  # noqa: BLE001 - sin pypdf queda solo el análisis crudo
        sig.parse_error = "pypdf no disponible"
        return
    reader = PdfReader(io.BytesIO(data), strict=False)
    sig.encrypted = bool(reader.is_encrypted)
    if sig.encrypted:
        try:
            sig.decrypted = int(reader.decrypt("")) != 0
        except Exception:  # noqa: BLE001
            sig.decrypted = False
        if not sig.decrypted:
            return  # sin clave no se puede leer el contenido: quedan los conteos crudos
    sig.parsed = True
    with _suppress():
        sig.pages = len(reader.pages)
    with _suppress():
        _catalog_scan(reader, sig)
    _object_scan(job, reader, sig)
    if sig.pages is not None and sig.pages <= _MAX_TEXT_PAGES and not job.expired():
        with _suppress():
            _first_pages_scan(reader, sig)


class _suppress:
    """contextlib.suppress(Exception) que además deja rastro en debug."""

    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type, exc, tb) -> bool:
        if exc_type is not None and issubclass(exc_type, Exception):
            log.debug("pdf: error ignorado: %s", exc_type.__name__)
            return True
        return False


def _generic() -> Any:
    from pypdf import generic

    return generic


def _res(value: Any) -> Any:
    g = _generic()
    for _ in range(8):
        if isinstance(value, g.IndirectObject):
            try:
                value = value.get_object()
            except Exception:  # noqa: BLE001
                return None
        else:
            break
    return value


def _dget(d: Any, key: str) -> Any:
    if not isinstance(d, dict):
        return None
    return _res(dict.get(d, key))


def _name(value: Any) -> str:
    return str(value) if isinstance(value, str) else ""


def _pdf_text(value: Any, cap: int = _MAX_JS_CHARS) -> str:
    g = _generic()
    value = _res(value)
    if isinstance(value, g.StreamObject):
        return _stream_bytes(value, cap).decode("latin-1", "replace")
    if isinstance(value, g.ByteStringObject):
        return bytes(value)[:cap].decode("latin-1", "replace")
    if isinstance(value, str):
        return str(value)[:cap]
    if isinstance(value, bytes | bytearray):
        return bytes(value)[:cap].decode("latin-1", "replace")
    return ""


def _stream_bytes(stream: Any, cap: int) -> bytes:
    """Contenido de un stream, descomprimido con límite (nunca más de `cap` bytes)."""
    g = _generic()
    if not isinstance(stream, g.StreamObject):
        return b""
    raw = getattr(stream, "_data", b"") or b""
    filt = _dget(stream, "/Filter")
    if isinstance(filt, str):
        filters = [str(filt)]
    elif isinstance(filt, list):
        filters = [str(_res(f)) for f in filt[:8]]
    else:
        filters = []
    if not filters:
        return bytes(raw[:cap])
    if filters in (["/FlateDecode"], ["/Fl"]):
        for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
            try:
                return zlib.decompressobj(wbits).decompress(bytes(raw), cap)
            except zlib.error:
                continue
        return b""
    if len(raw) <= 1024 * 1024:
        try:
            return bytes(stream.get_data())[:cap]
        except Exception:  # noqa: BLE001
            return b""
    return b""


def _filespec_str(value: Any) -> str:
    value = _res(value)
    if isinstance(value, dict):
        for key in ("/UF", "/F", "/DOS", "/Unix", "/Mac"):
            s = _pdf_text(_dget(value, key), 2000)
            if s:
                return s
        return ""
    return _pdf_text(value, 2000)


def _action_chain(action: Any, limit: int = 20) -> list[Any]:
    """Una acción y sus /Next encadenadas (acotado y sin ciclos)."""
    out: list[Any] = []
    queue = [action]
    seen: set[int] = set()
    while queue and len(out) < limit:
        a = _res(queue.pop(0))
        if isinstance(a, list):
            queue.extend(a[:limit])
            continue
        if not isinstance(a, dict) or id(a) in seen:
            continue
        seen.add(id(a))
        out.append(a)
        nxt = dict.get(a, "/Next")
        if nxt is not None:
            queue.append(nxt)
    return out


def _catalog_scan(reader: Any, sig: _Sig) -> None:
    root = _res(dict.get(reader.trailer, "/Root"))
    if not isinstance(root, dict):
        return
    oa = _dget(root, "/OpenAction")
    if isinstance(oa, dict):
        for act in _action_chain(oa):
            s = _name(_dget(act, "/S"))
            if s == "/JavaScript" or "/JS" in act:
                sig.auto_js = True
                sig.auto_reason.append("/OpenAction")
                sig.add_js("/OpenAction", _pdf_text(dict.get(act, "/JS")))
            elif s == "/Launch":
                sig.auto_reason.append("/OpenAction → /Launch")
            elif s == "/URI":
                sig.auto_uri.append(_pdf_text(dict.get(act, "/URI"), 2000))
    aa = _dget(root, "/AA")
    if isinstance(aa, dict):
        for trigger, act in list(aa.items())[:20]:
            for a in _action_chain(act):
                if _name(_dget(a, "/S")) == "/JavaScript" or "/JS" in a:
                    sig.auto_js = True
                    sig.auto_reason.append(f"/AA {trigger}")
                    sig.add_js(f"/AA {trigger}", _pdf_text(dict.get(a, "/JS")))
    names = _dget(root, "/Names")
    if isinstance(names, dict) and dict.get(names, "/JavaScript") is not None:
        sig.doc_js = True
    acro = _dget(root, "/AcroForm")
    if isinstance(acro, dict) and dict.get(acro, "/XFA") is not None:
        sig.xfa = True
    with _suppress():
        first = reader.pages[0]
        paa = _dget(first, "/AA")
        if isinstance(paa, dict):
            for a in _action_chain(dict.get(paa, "/O")):
                if _name(_dget(a, "/S")) == "/JavaScript" or "/JS" in a:
                    sig.auto_js = True
                    sig.auto_reason.append("página 1 /AA /O")


def _object_scan(job: _PdfJob, reader: Any, sig: _Sig) -> None:
    """Recorre todos los objetos (tabla xref + objetos en ObjStm + lo alcanzable desde el trailer)."""
    g = _generic()
    queue: list[tuple[int, int]] = []
    with _suppress():
        for gen, table in list(reader.xref.items()):
            queue.extend((int(idnum), int(gen)) for idnum in list(table))
    with _suppress():
        queue.extend((int(idnum), 0) for idnum in list(reader.xref_objStm))
    seen: set[tuple[int, int]] = set()
    nodes = [_MAX_NODES]
    # el trailer y lo que referencia (por si la tabla xref está rota)
    _walk(reader.trailer, sig, queue, nodes)
    i = 0
    while i < len(queue):
        ref = queue[i]
        i += 1
        if ref in seen:
            continue
        seen.add(ref)
        if len(seen) > _MAX_OBJECTS or nodes[0] <= 0:
            sig.note_partial("PDF con demasiados objetos: análisis parcial")
            return
        if not len(seen) & 255 and job.expired():
            sig.note_partial("tiempo de análisis agotado")
            return
        try:
            obj = reader.get_object(g.IndirectObject(ref[0], ref[1], reader))
        except Exception:  # noqa: BLE001
            log.debug("pdf: objeto %s ilegible", ref)
            continue
        if obj is not None:
            _walk(obj, sig, queue, nodes)


def _walk(obj: Any, sig: _Sig, queue: list[tuple[int, int]], nodes: list[int]) -> None:
    g = _generic()
    stack: list[tuple[Any, int]] = [(obj, 0)]
    while stack:
        o, depth = stack.pop()
        nodes[0] -= 1
        if nodes[0] <= 0:
            return
        if isinstance(o, g.IndirectObject):
            queue.append((int(o.idnum), int(o.generation)))
            continue
        if isinstance(o, dict):
            with _suppress():
                _inspect_dict(o, sig)
            if depth < _MAX_DEPTH:
                stack.extend((v, depth + 1) for v in list(dict.values(o))[:2000])
        elif isinstance(o, list) and depth < _MAX_DEPTH:
            stack.extend((v, depth + 1) for v in o[:5000])


def _inspect_dict(d: dict, sig: _Sig) -> None:
    s = _name(_dget(d, "/S"))
    if s == "/JavaScript" or "/JS" in d:
        sig.add_js("acción JavaScript", _pdf_text(dict.get(d, "/JS")))
    if s == "/Launch":
        parts = [_filespec_str(dict.get(d, "/F"))]
        for key in ("/Win", "/Unix", "/Mac"):
            sub = _dget(d, key)
            if isinstance(sub, dict):
                parts += [_filespec_str(dict.get(sub, "/F")), _pdf_text(dict.get(sub, "/P"), 2000)]
        target = " ".join(p for p in parts if p).strip()
        sig.launch.append(target or "(sin destino legible)")
    elif s == "/URI":
        uri = _pdf_text(dict.get(d, "/URI"), 2000).strip()
        if uri and len(sig.uris) < _MAX_URIS:
            sig.uris.append(uri)
    elif s == "/SubmitForm":
        sig.submit.append(_filespec_str(dict.get(d, "/F")) or "(sin destino)")
    elif s in ("/GoToR", "/GoToE"):
        sig.goto_remote.append(_filespec_str(dict.get(d, "/F")) or "(sin destino)")
    if "/RichMediaContent" in d or _name(_dget(d, "/Subtype")) == "/RichMedia":
        sig.richmedia = True
    if "/EF" in d:
        ef = _dget(d, "/EF")
        name = _filespec_str(d) or "(sin nombre)"
        head = b""
        if isinstance(ef, dict):
            stream = _dget(ef, "/UF") or _dget(ef, "/F")
            head = _stream_bytes(stream, 512)
        if len(sig.embedded) < 50:
            sig.embedded.append({"nombre": _s(name, 160), "tipo": _magic_kind(head), "_head": head[:8]})
    if "/XFA" in d:
        sig.xfa = True
        xfa = _dget(d, "/XFA")
        parts = [xfa] if not isinstance(xfa, list) else [_res(x) for x in xfa[:60]]
        for part in parts:
            text = _pdf_text(part, _MAX_STREAM_READ) if not isinstance(part, str) else ""
            for m in itertools.islice(
                re.finditer(r"<script\b[^>]{0,500}>(.{0,20000}?)</script>", text, re.I | re.S), 5
            ):
                sig.add_js("XFA", m.group(1))


def _first_pages_scan(reader: Any, sig: _Sig) -> None:
    texts: list[str] = []
    for page in list(reader.pages)[:_MAX_TEXT_PAGES]:
        area = 0.0
        with _suppress():
            box = page.mediabox
            area = abs(float(box.width) * float(box.height))
        annots = _dget(page, "/Annots")
        if isinstance(annots, list):
            for a in annots[:300]:
                a = _res(a)
                if not isinstance(a, dict) or _name(_dget(a, "/Subtype")) != "/Link":
                    continue
                act = _dget(a, "/A")
                if not isinstance(act, dict) or _name(_dget(act, "/S")) != "/URI":
                    continue
                uri = _pdf_text(dict.get(act, "/URI"), 2000).strip()
                ratio = 0.0
                with _suppress():
                    r = [float(_res(x)) for x in _dget(a, "/Rect")[:4]]
                    if area > 0:
                        ratio = min(1.0, abs((r[2] - r[0]) * (r[3] - r[1])) / area)
                if uri:
                    sig.links.append((uri, ratio))
        if _content_size(page) > _MAX_PAGE_CONTENT:
            sig.note_partial("página con contenido muy grande: texto no extraído")
            continue
        with _suppress():
            texts.append((page.extract_text() or "")[:_MAX_TEXT_CHARS])
    sig.text = "\n".join(texts)[:_MAX_TEXT_CHARS]
    sig.words = len(re.findall(r"\w+", sig.text))


def _content_size(page: Any) -> int:
    contents = _dget(page, "/Contents")
    items = contents if isinstance(contents, list) else [contents]
    total = 0
    for c in items[:200]:
        c = _res(c)
        total += len(getattr(c, "_data", b"") or b"")
    return total


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
    job: _PdfJob,
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
        analyzer="pdf",
        rule=rule,
        title=title,
        description=description,
        category=category,
        severity=severity if severity is not None else _sev_for(score),
        score=score,
        artifact_id=job.artifact_id,
        evidence={k: v for k, v in evidence.items() if v not in (None, [], {}, "")},
    )


def _build_findings(job: _PdfJob, sig: _Sig) -> list[Finding]:
    out: list[Finding] = []
    precise = sig.parsed
    counts_ev = {k: v for k, v in sorted(sig.counts.items()) if k not in ("/Page",)}

    # --- JavaScript
    raw_js = sig.c("/JS") + sig.c("/JavaScript")
    has_js = bool(sig.js) or (not precise and raw_js > 0) or (precise and sig.doc_js)
    if has_js:
        auto = sig.auto_js if precise else (sig.c("/OpenAction") > 0 and raw_js > 0)
        code = "\n".join(c for _o, c in sig.js)[:1_000_000]
        exploit = sorted({m.group(0) for m in itertools.islice(_JS_EXPLOIT_RE.finditer(code), 50)})
        dropper = sorted({m.group(0)[:40] for m in itertools.islice(_JS_DROPPER_RE.finditer(code), 20)})
        urls = sorted({m.group(0) for m in itertools.islice(_JS_URL_RE.finditer(code), 20)})
        obf = sorted({m.group(0)[:20] for m in itertools.islice(_JS_OBF_RE.finditer(code), 50)})
        if auto:
            score = 65
        elif sig.doc_js:
            score = 40
        else:
            score = 35
        if exploit or dropper:
            score = max(score, 75 if auto else 60)
        if obf:
            score += 5
        score = min(score, 80)
        evidence = {
            "ejecucion_automatica": auto,
            "disparadores": _uniq(sig.auto_reason, 6),
            "javascript_a_nivel_documento": sig.doc_js or None,
            "funciones_de_exploit": exploit[:8],
            "suelta_o_abre_adjuntos": dropper[:5],
            "abre_urls": urls[:5],
            "ofuscacion": obf[:8],
            "fragmentos": [{"origen": o, "codigo": _s(c, 300)} for o, c in sig.js[:3]],
            "conteos": counts_ev or None,
        }
        if auto:
            out.append(
                _mk(
                    job,
                    "pdf.javascript_autorun",
                    "PDF con JavaScript que se ejecuta al abrirlo",
                    "El PDF tiene código JavaScript que se ejecuta automáticamente al abrirlo (acción de apertura). "
                    "Los PDF normales casi nunca lo necesitan; es una técnica para explotar vulnerabilidades del "
                    "lector de PDF, abrir sitios de phishing o soltar archivos.",
                    score,
                    evidence,
                )
            )
        else:
            out.append(
                _mk(
                    job,
                    "pdf.javascript",
                    "PDF con código JavaScript",
                    "El PDF contiene código JavaScript. Algunos formularios legítimos lo usan, pero también es una "
                    "vía habitual para ataques; conviene abrirlo solo si se esperaba.",
                    score,
                    evidence,
                )
            )

    # --- /Launch
    if sig.launch or sig.c("/Launch"):
        targets = sig.launch[:]
        if not targets:
            targets = _raw_launch_targets(job.data)
        joined = " ".join(targets)
        exts = {_ext_of(t.split()[0]) for t in targets if t.strip()}
        if _EXEC_TARGET_RE.search(joined):
            score = 85
        elif exts & _EXEC_EXTS:
            score = 75
        else:
            score = 45
        out.append(
            _mk(
                job,
                "pdf.launch",
                "PDF que intenta ejecutar un programa",
                "El PDF contiene una acción 'Launch' que le pide al lector abrir un programa o comando del equipo "
                "(por ejemplo la consola de Windows o PowerShell). Es una técnica para instalar malware desde un PDF.",
                score,
                {"destinos": [_s(t) for t in _uniq(targets, 6)], "conteo": sig.c("/Launch") or None},
            )
        )

    # --- archivos incrustados
    if sig.embedded:
        exec_files = [
            e for e in sig.embedded if _ext_of(e["nombre"]) in _EXEC_EXTS or e["tipo"] in ("pe", "lnk")
        ]
        risky = [
            e
            for e in sig.embedded
            if e not in exec_files
            and (_ext_of(e["nombre"]) in _RISKY_EXTS or e["tipo"] in ("ole", "html", "rtf"))
        ]
        clean = [{k: v for k, v in e.items() if not k.startswith("_")} for e in sig.embedded]
        if exec_files:
            names = ", ".join(e["nombre"] for e in exec_files[:3])
            out.append(
                _mk(
                    job,
                    "pdf.embedded_executable",
                    "PDF con un programa o script adjunto adentro",
                    f"El PDF trae incrustado un archivo ejecutable o script ({names}). Abrirlo desde el lector de PDF "
                    "puede instalar malware; los documentos legítimos no lo necesitan.",
                    70,
                    {"archivos": _uniq(clean, 10)},
                )
            )
        elif risky:
            out.append(
                _mk(
                    job,
                    "pdf.embedded_risky",
                    "PDF con documentos o comprimidos adjuntos adentro",
                    "El PDF trae incrustados otros archivos (comprimidos, documentos de Office o páginas web) que "
                    "pueden contener malware. Se analizan por separado.",
                    30,
                    {"archivos": _uniq(clean, 10)},
                )
            )
        else:
            out.append(
                _mk(
                    job,
                    "pdf.embedded_file",
                    "PDF con archivos adjuntos",
                    "El PDF contiene archivos incrustados (por ejemplo, el XML de una factura electrónica). Se "
                    "analizan por separado.",
                    0,
                    {"archivos": _uniq(clean, 10)},
                )
            )
    elif sig.c("/EmbeddedFile") and not precise:
        out.append(
            _mk(
                job,
                "pdf.embedded_file",
                "PDF con archivos adjuntos",
                "El PDF parece contener archivos incrustados que no se pudieron leer.",
                0,
                {"conteo": sig.c("/EmbeddedFile")},
            )
        )

    # --- phishing: PDF señuelo que solo lleva a un link
    phish = _phishing_check(job, sig)
    if phish:
        out.append(phish)

    if sig.richmedia or sig.c("/RichMedia"):
        out.append(
            _mk(
                job,
                "pdf.richmedia",
                "PDF con contenido multimedia incrustado (Flash)",
                "El PDF incluye contenido 'RichMedia' (Flash o 3D), una tecnología obsoleta que hoy solo aparece en "
                "PDFs maliciosos que buscan explotar el lector.",
                30,
                {"conteo": sig.c("/RichMedia") or None},
            )
        )
    unc = [t for t in sig.goto_remote if t.startswith(("\\\\", "//")) or t.lower().startswith("file://")]
    if unc:
        out.append(
            _mk(
                job,
                "pdf.remote_goto",
                "PDF que abre un archivo en un servidor de red",
                "El PDF contiene un vínculo a un archivo en una ruta de red (\\\\servidor\\...). Al seguirlo, Windows "
                "puede enviar las credenciales del usuario (hash NTLM) a ese servidor.",
                40,
                {"destinos": [_s(t) for t in _uniq(unc, 6)]},
            )
        )
    if sig.submit:
        external = [t for t in sig.submit if t.lower().startswith(("http://", "https://"))]
        if external:
            out.append(
                _mk(
                    job,
                    "pdf.submit_form",
                    "PDF con formulario que envía datos a Internet",
                    "El PDF tiene un formulario que envía lo que se escriba a una dirección de Internet. Si pide "
                    "usuarios, contraseñas o datos bancarios, puede ser phishing.",
                    10,
                    {"destinos": [_s(t) for t in _uniq(external, 6)]},
                    category=FindingCategory.PHISHING,
                )
            )
    if sig.obfuscated:
        out.append(
            _mk(
                job,
                "pdf.name_obfuscation",
                "PDF con palabras clave disfrazadas",
                "El PDF escribe sus comandos internos de forma disfrazada (por ejemplo /J#61vaScript en lugar de "
                "/JavaScript) para engañar a los antivirus. Los PDF generados por programas normales no lo hacen.",
                30,
                {"nombres_ofuscados": dict(sorted(sig.obfuscated.items()))},
            )
        )
    if sig.maldoc:
        out.append(
            _mk(
                job,
                "pdf.maldoc_in_pdf",
                "PDF que también es un documento de Word con macros",
                "El archivo parece un PDF pero contiene un documento de Word (formato MHT/ActiveMime) con macros: si "
                "se abre con Word, las macros pueden ejecutarse. Es la técnica 'MalDoc in PDF' para evadir antivirus.",
                75,
                {"tecnica": "MalDoc in PDF (JPCERT, 2023)"},
            )
        )
    if sig.appended:
        out.append(
            _mk(
                job,
                "pdf.appended_payload",
                "PDF con otro archivo pegado al final",
                f"Después del final del PDF hay pegado otro archivo ({sig.appended}). Es un truco para esconder un "
                "programa o comprimido dentro de un PDF de apariencia normal.",
                30,
                {"tipo": sig.appended},
            )
        )

    # --- cifrado y errores
    if sig.encrypted and sig.decrypted:
        out.append(
            _mk(
                job,
                "pdf.encrypted",
                "PDF cifrado sin contraseña de apertura",
                "El PDF usa cifrado sin contraseña para abrirlo (habitual para impedir copiar o imprimir). Se pudo "
                "analizar normalmente.",
                0,
                {},
                category=FindingCategory.POLICY,
            )
        )
    elif sig.encrypted:
        out.append(
            _mk(
                job,
                "pdf.encrypted_password",
                "PDF protegido con contraseña",
                "El PDF necesita una contraseña para abrirse, por lo que los antivirus no pueden revisar su "
                "contenido. Los atacantes lo usan (con la clave en el texto del mail) para evadir controles. Si no "
                "se esperaba, conviene confirmar con el remitente por otro medio.",
                35,
                {"conteos": counts_ev or None},
                category=FindingCategory.POLICY,
            )
        )
    if sig.parse_error and not sig.encrypted:
        out.append(
            _mk(
                job,
                "pdf.parse_error",
                "PDF dañado o con estructura inválida",
                "No se pudo interpretar la estructura del PDF; solo se hizo un análisis básico de su contenido.",
                0,
                {"error": sig.parse_error, "conteos": counts_ev or None},
                category=FindingCategory.POLICY,
            )
        )
    if sig.partial:
        out.append(
            _mk(
                job,
                "pdf.partial_analysis",
                "Análisis parcial del PDF",
                "El PDF es muy grande o complejo y se analizó solo en parte.",
                0,
                {"motivos": sig.partial},
                category=FindingCategory.POLICY,
            )
        )
    return out


def _raw_launch_targets(data: bytes) -> list[str]:
    out: list[str] = []
    for m in itertools.islice(_LAUNCH_RAW_RE.finditer(data), 10):
        window = data[m.start() : m.start() + 4096].decode("latin-1", "replace")
        hit = _EXEC_TARGET_RE.search(window)
        out.append(window[hit.start() : hit.start() + 200] if hit else "(no se pudo leer el destino)")
    return out


def _phishing_check(job: _PdfJob, sig: _Sig) -> Finding | None:
    pages = sig.pages
    if pages is None or pages > _MAX_TEXT_PAGES:
        return None
    uris = [u for u, _r in sig.links] + sig.uris + sig.auto_uri
    external = []
    for u in uris:
        if not u.lower().startswith(("http://", "https://")):
            continue
        host = _host_of(u)
        if not host or any(host == d or host.endswith("." + d) for d in job.company_domains):
            continue
        external.append(u)
    external = _uniq(external, 50)
    if not external:
        return None
    hosts = {_host_of(u) for u in external}
    if len(hosts) > 2 or len(external) > 5:
        return None
    lure = _LURE_RE.search(sig.text or "")
    words = sig.words if sig.words is not None else 0
    biggest = max((r for _u, r in sig.links), default=0.0)
    evidence = {
        "urls": [_s(u, 300) for u in external],
        "paginas": pages,
        "palabras": words,
        "texto_señuelo": _s(lure.group(0), 80) if lure else None,
        "link_ocupa_pagina": round(biggest, 2) if biggest else None,
        "abre_url_al_iniciar": bool(sig.auto_uri) or None,
    }
    if (lure and words <= 300) or sig.auto_uri:
        return _mk(
            job,
            "pdf.phishing_link",
            "PDF señuelo que lleva a un link externo",
            "El PDF casi no tiene contenido propio y su objetivo es que se haga clic en un enlace (por ejemplo "
            "'ver documento' o 'descargar factura'). Es la forma típica de llevar a una página falsa que roba "
            "contraseñas o descarga malware. No conviene ingresar datos en el sitio al que lleva.",
            40,
            evidence,
            category=FindingCategory.PHISHING,
        )
    if words < 15 and biggest >= 0.10:
        return _mk(
            job,
            "pdf.link_only",
            "PDF que es solo una imagen con un link",
            "El PDF no tiene texto: es una imagen con un enlace que ocupa buena parte de la página. Así suelen "
            "armarse los PDF de phishing; puede ser también un folleto legítimo.",
            15,
            evidence,
            category=FindingCategory.PHISHING,
        )
    return None


__all__ = ["PdfAnalyzer"]
