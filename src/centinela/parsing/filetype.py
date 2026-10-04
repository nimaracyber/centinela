"""Detección del tipo REAL de un archivo (lo que es, no lo que dice el atacante).

`detect_type(data, filename)` devuelve un valor del vocabulario de `Artifact.detected_type`
definido en docs/ARCHITECTURE.md. Reglas:

1. Primero magic bytes / estructura (un "factura.pdf" que empieza con MZ+PE es `pe`).
2. La extensión solo desempata formatos de TEXTO (un .js y un .vbs son ambos texto plano).
3. Para texto sin extensión conocida se olfatea el contenido (scripts, HTML, mails...).

Aplicaciones HTML: un `.hta` (o texto sin extensión con `<HTA:APPLICATION`) es `script/hta`, NO `html`:
lo ejecuta mshta.exe con permisos de programa. Un `.html` con esa etiqueta sigue siendo `html` (se abre
en el navegador). El analizador `html` acepta `script/hta`; el de `scripts` lo excluye.

Todo es defensivo: se mira como mucho una muestra acotada del contenido, nunca se ejecuta nada
y ninguna regex tiene backtracking catastrófico (clases de caracteres simples y repeticiones acotadas).
"""

from __future__ import annotations

import codecs
import contextlib
import io
import re
import struct
import zipfile

__all__ = [
    "ALL_TYPES",
    "CONTAINER_TYPES",
    "IMAGE_TYPES",
    "LOTL_TYPES",
    "SCRIPT_TYPES",
    "TEXT_LIKE_TYPES",
    "decode_text_sample",
    "detect_type",
    "file_extension",
    "is_container",
    "is_text_like",
]

# --------------------------------------------------------------------------- vocabulario

CONTAINER_TYPES: frozenset[str] = frozenset(
    {"zip", "jar", "7z", "rar", "gzip", "bzip2", "xz", "tar", "cab", "iso", "udf", "vhd", "vhdx", "img"}
)

SCRIPT_TYPES: frozenset[str] = frozenset(
    {
        "script/js",
        "script/vbs",
        "script/ps1",
        "script/bat",
        "script/wsf",
        "script/hta",
        "script/vba",
        "script/python",
        "script/sh",
    }
)

LOTL_TYPES: frozenset[str] = frozenset(
    {"url_shortcut", "iqy", "slk", "reg", "settingcontent", "library-ms", "search-ms"}
)

IMAGE_TYPES: frozenset[str] = frozenset(
    {"image/png", "image/jpeg", "image/gif", "image/bmp", "image/webp", "image/ico"}
)

TEXT_LIKE_TYPES: frozenset[str] = frozenset(
    {"text", "html", "svg", "xml", "eml", "rtf"} | SCRIPT_TYPES | LOTL_TYPES
)

ALL_TYPES: frozenset[str] = frozenset(
    {"pe", "elf", "macho", "msi", "ole", "ooxml", "rtf", "pdf", "onenote", "chm", "lnk", "eml"}
    | {"html", "svg", "xml", "text", "unknown"}
    | CONTAINER_TYPES
    | SCRIPT_TYPES
    | LOTL_TYPES
    | IMAGE_TYPES
)


def is_container(detected_type: str) -> bool:
    """True para contenedores de archivos (zip, 7z, rar, iso, vhd...). `jar` cuenta como contenedor
    aunque no se expande. Documentos con objetos embebidos (ooxml, pdf, onenote) y `eml` NO son
    contenedores en este sentido, aunque `archives.expand` también extraiga cosas de ellos."""
    return detected_type in CONTAINER_TYPES


def is_text_like(detected_type: str) -> bool:
    """True si el contenido es texto legible (scripts, HTML, XML, mails, formatos LOTL de texto, rtf)."""
    return detected_type in TEXT_LIKE_TYPES


def file_extension(filename: str | None) -> str:
    """Extensión en minúsculas tal como la interpreta Windows (ignora puntos y espacios finales:
    "factura.exe. " se abre como .exe)."""
    if not filename:
        return ""
    name = filename.replace("\x00", "").rstrip(" .\t\r\n")
    name = name.replace("\\", "/").rsplit("/", 1)[-1]
    if "." not in name:
        return ""
    return name.rsplit(".", 1)[-1].lower()[:32]


# --------------------------------------------------------------------------- magic

_OLE_MAGIC = bytes.fromhex("D0CF11E0A1B11AE1")
# CLSID del root entry (bytes tal como están en disco, little-endian GUID)
_MSI_CLSIDS = {
    bytes.fromhex("84100C0000000000C000000000000046"),  # {000C1084-...}: MSI database
    bytes.fromhex("86100C0000000000C000000000000046"),  # {000C1086-...}: MSP patch
}
_LNK_HEADER = bytes.fromhex("4C0000000114020000000000C000000000000046")
_ONENOTE_GUID = bytes.fromhex("E4525C7B8CD8A74DAEB15378D02996D3")  # {7B5C52E4-D88C-4DA7-AEB1-5378D02996D3}
_RAR4 = b"Rar!\x1a\x07\x00"
_RAR5 = b"Rar!\x1a\x07\x01\x00"
_7Z = b"7z\xbc\xaf\x27\x1c"
_XZ = b"\xfd7zXZ\x00"
_MACHO = {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"}
_ISO_OFFSETS = (0x8001, 0x8801, 0x9001)
_UDF_MARKERS = (b"BEA01", b"NSR02", b"NSR03", b"TEA01")

# extensiones de texto -> tipo (la extensión manda solo si el contenido ES texto)
_TEXT_EXT_MAP: dict[str, str] = {
    "js": "script/js",
    "jse": "script/js",
    "vbs": "script/vbs",
    "vbe": "script/vbs",
    "ps1": "script/ps1",
    "psm1": "script/ps1",
    "psd1": "script/ps1",
    "bat": "script/bat",
    "cmd": "script/bat",
    "wsf": "script/wsf",
    "wsc": "script/wsf",
    "sct": "script/wsf",
    "hta": "script/hta",
    "vba": "script/vba",
    "bas": "script/vba",
    "py": "script/python",
    "pyw": "script/python",
    "sh": "script/sh",
    "bash": "script/sh",
    "zsh": "script/sh",
    "command": "script/sh",
    "html": "html",
    "htm": "html",
    "xhtml": "html",
    "shtml": "html",
    "svg": "svg",
    "xml": "xml",
    "xsl": "xml",
    "xslt": "xml",
    "xaml": "xml",
    "url": "url_shortcut",
    "website": "url_shortcut",
    "iqy": "iqy",
    "slk": "slk",
    "reg": "reg",
    "settingcontent-ms": "settingcontent",
    "library-ms": "library-ms",
    "search-ms": "search-ms",
    "searchconnector-ms": "search-ms",
}
# extensiones que no dicen nada: se olfatea el contenido
_GENERIC_TEXT_EXT = {"", "txt", "text", "log", "dat", "tmp", "bin", "csv", "ini", "cfg", "conf", "md", "json"}
# extensiones que contienen MIME (se parsean como mail si lo parecen)
_MIME_EXT = {"eml", "mht", "mhtml", "msg822", "mbox"}

_SAMPLE = 64 * 1024
_ZIP_MAX_NAMES = 5000


def _u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def _u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def _is_pe(data: bytes) -> bool:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return False
    e_lfanew = _u32(data, 0x3C)
    if e_lfanew < 0x40 - 4 or e_lfanew > len(data) - 24 or e_lfanew > 0x10000000:
        return False
    return data[e_lfanew : e_lfanew + 4] == b"PE\x00\x00"


def _ole_type(data: bytes) -> str:
    """Distingue MSI (CLSID del root entry) de otros OLE2/CFB."""
    try:
        if len(data) < 512:
            return "ole"
        sector_shift = _u16(data, 0x1E)
        if sector_shift not in (9, 12):
            return "ole"
        sector_size = 1 << sector_shift
        first_dir = _u32(data, 0x30)
        if first_dir >= 0xFFFFFFFA:
            return "ole"
        off = (first_dir + 1) * sector_size
        if off + 128 > len(data):
            return "ole"
        entry = data[off : off + 128]
        if entry[0x42] != 5:  # tipo 5 = root storage
            return "ole"
        if entry[0x50:0x60] in _MSI_CLSIDS:
            return "msi"
    except (struct.error, IndexError):
        pass
    return "ole"


def _zip_names(data: bytes) -> list[str]:
    """Nombres del zip: central directory si se puede; si no, recorre local headers (zip truncado)."""
    with contextlib.suppress(Exception):  # zip roto: seguimos con el plan B
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            return [i.filename for i in zf.infolist()[:_ZIP_MAX_NAMES]]
    names: list[str] = []
    pos = 0
    while len(names) < _ZIP_MAX_NAMES:
        pos = data.find(b"PK\x03\x04", pos)
        if pos < 0 or pos + 30 > len(data):
            break
        n = _u16(data, pos + 26)
        names.append(data[pos + 30 : pos + 30 + n].decode("cp437", "replace"))
        pos += 30
    return names


def _zip_type(data: bytes, ext: str) -> str:
    names = _zip_names(data)
    lower = {n.replace("\\", "/").lower() for n in names}
    if "[content_types].xml" in lower:
        return "ooxml"
    if "meta-inf/manifest.mf" in lower:
        return "jar"
    if ext == "jar" and any(n.endswith(".class") for n in lower):
        return "jar"
    return "zip"


def _is_tar(data: bytes) -> bool:
    if len(data) < 512:
        return False
    if data[257:262] == b"ustar":
        return True
    # tar v7 (sin "ustar"): validar checksum de la cabecera
    try:
        stored = data[148:156].split(b"\x00", 1)[0].strip()
        if not stored or not all(48 <= c <= 55 for c in stored):
            return False
        chk = int(stored, 8)
        calc = sum(data[:148]) + 8 * 32 + sum(data[156:512])
        return chk == calc and data[0] != 0
    except ValueError:
        return False


def _iso_type(data: bytes) -> str | None:
    if len(data) < 0x8006:
        return None
    for off in _ISO_OFFSETS:
        if data[off : off + 5] == b"CD001":
            return "iso"
    end = min(len(data) - 5, 0x8001 + 0x800 * 32)
    for off in range(0x8001, end, 0x800):
        if data[off : off + 5] in _UDF_MARKERS:
            return "udf"
    return None


def _is_vhd(data: bytes) -> bool:
    if data[:8] == b"conectix":
        return True
    if len(data) >= 512 and (data[-512:-504] == b"conectix" or data[-511:-503] == b"conectix"):
        return True
    return False


def _is_disk_image(data: bytes, ext: str) -> bool:
    """Imagen de disco cruda (FAT/NTFS/exFAT o MBR) — típico .img."""
    if len(data) < 512 or data[510:512] != b"\x55\xaa":
        return False
    if data[0x36:0x3B] in (b"FAT12", b"FAT16") or data[0x52:0x57] == b"FAT32":
        return True
    if data[3:11] in (b"NTFS    ", b"EXFAT   "):
        return True
    return ext in {"img", "ima", "vfd", "dsk"}


def _image_type(data: bytes) -> str | None:
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if data[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    if data[:2] == b"BM" and len(data) >= 26:
        dib = _u32(data, 14)
        if dib in (12, 40, 52, 56, 64, 108, 124):
            return "image/bmp"
    if data[:4] == b"\x00\x00\x01\x00" and len(data) >= 22:
        count = _u16(data, 4)
        if 0 < count <= 256 and data[9] == 0:  # reserved = 0
            return "image/ico"
    return None


def _macho_fat(data: bytes) -> bool:
    # CAFEBABE: Mach-O "fat" o .class de Java; en Java a continuación viene la versión (>= 45)
    if data[:4] != b"\xca\xfe\xba\xbe" or len(data) < 8:
        return False
    n = struct.unpack_from(">I", data, 4)[0]
    return 0 < n < 30


def _binary_magic(data: bytes, ext: str) -> str | None:
    head = data[:16]
    if head[:2] == b"MZ":
        return "pe" if _is_pe(data) else None
    if head[:4] == b"\x7fELF":
        return "elf"
    if head[:4] in _MACHO or _macho_fat(data):
        return "macho"
    if head[:8] == _OLE_MAGIC:
        return _ole_type(data)
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return _zip_type(data, ext)
    if head[:7] == _RAR4 or head[:8] == _RAR5:
        return "rar"
    if head[:6] == _7Z:
        return "7z"
    if head[:2] == b"\x1f\x8b":
        return "gzip"
    if head[:3] == b"BZh" and len(head) > 3 and 0x31 <= head[3] <= 0x39:
        return "bzip2"
    if head[:6] == _XZ:
        return "xz"
    if head[:4] == b"MSCF" and data[4:8] == b"\x00\x00\x00\x00":
        return "cab"
    if head[:4] == b"ITSF":
        return "chm"
    if data[:20] == _LNK_HEADER or (head[:8] == _LNK_HEADER[:8] and ext == "lnk"):
        return "lnk"
    if head[:16] == _ONENOTE_GUID:
        return "onenote"
    if head[:8] == b"vhdxfile":
        return "vhdx"
    if b"%PDF" in data[:1024]:
        return "pdf"
    if head[:4] == b"{\\rt":
        return "rtf"
    img = _image_type(data)
    if img:
        return img
    if _is_tar(data):
        return "tar"
    iso = _iso_type(data)
    if iso:
        return iso
    if _is_vhd(data):
        return "vhd"
    if _is_disk_image(data, ext):
        return "img"
    return None


# --------------------------------------------------------------------------- texto

_TEXT_BYTES = bytes([7, 8, 9, 10, 11, 12, 13, 27]) + bytes(range(0x20, 0x7F)) + bytes(range(0x80, 0x100))


def decode_text_sample(data: bytes, limit: int = _SAMPLE) -> str | None:
    """Devuelve el texto de la muestra si el contenido parece texto; None si es binario."""
    sample = data[:limit]
    if not sample:
        return None
    for bom, enc in (
        (codecs.BOM_UTF8, "utf-8"),
        (codecs.BOM_UTF32_LE, "utf-32-le"),
        (codecs.BOM_UTF32_BE, "utf-32-be"),
        (codecs.BOM_UTF16_LE, "utf-16-le"),
        (codecs.BOM_UTF16_BE, "utf-16-be"),
    ):
        if sample.startswith(bom):
            body = sample[len(bom) :]
            if enc.startswith("utf-16"):
                body = body[: len(body) // 2 * 2]
            elif enc.startswith("utf-32"):
                body = body[: len(body) // 4 * 4]
            return body.decode(enc, "replace")
    if b"\x00" in sample:
        # UTF-16LE sin BOM (típico de .reg / .ps1 guardados por herramientas de Windows)
        even, odd = sample[0::2], sample[1::2]
        if len(sample) >= 8 and odd.count(0) >= 0.9 * len(odd) and even.count(0) <= 0.05 * len(even):
            text = sample[: len(sample) // 2 * 2].decode("utf-16-le", "replace")
            if _printable_ratio(text) > 0.95:
                return text
        return None
    nontext = len(sample.translate(None, _TEXT_BYTES))
    if nontext > len(sample) * 0.01:
        return None
    try:
        return sample.decode("utf-8")
    except UnicodeDecodeError as exc:
        if exc.start >= len(sample) - 4:  # corte de la muestra a mitad de un caracter multibyte
            return sample[: exc.start].decode("utf-8", "replace")
    try:
        return sample.decode("cp1252")
    except UnicodeDecodeError:
        return sample.decode("latin-1")


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    ok = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    return ok / len(text)


_HEADER_LINE_RE = re.compile(r"^[!-9;-~]{1,76}:")
_KNOWN_MAIL_HEADERS = {
    "from",
    "to",
    "cc",
    "subject",
    "date",
    "received",
    "message-id",
    "mime-version",
    "return-path",
    "delivered-to",
    "content-type",
    "reply-to",
    "sender",
    "x-mailer",
    "user-agent",
    "dkim-signature",
    "authentication-results",
    "x-originating-ip",
    "thread-topic",
    "content-transfer-encoding",
}


def _looks_like_mail(text: str, ext: str) -> bool:
    lines = text[:16384].splitlines()
    if lines and lines[0].startswith("From "):  # formato mbox
        lines = lines[1:]
    known = 0
    seen = 0
    for line in lines[:200]:
        if not line.strip():
            break
        if line[:1] in (" ", "\t"):
            continue  # continuación de header
        m = _HEADER_LINE_RE.match(line)
        if not m:
            return False
        seen += 1
        if line.split(":", 1)[0].strip().lower() in _KNOWN_MAIL_HEADERS:
            known += 1
    if seen == 0:
        return False
    return known >= 3 or (known >= 1 and ext in _MIME_EXT)


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.MULTILINE)


_PS_HINTS = [
    _rx(r"\$env:"),
    _rx(r"\b(?:invoke-expression|iex)\b"),
    _rx(r"\bnew-object\b"),
    _rx(r"\b(?:invoke-webrequest|invoke-restmethod|iwr|irm)\b"),
    _rx(r"\bstart-process\b"),
    _rx(r"\s-(?:encodedcommand|enc|ec)\s"),
    _rx(r"\[system\.[a-z]"),
    _rx(r"-executionpolicy\b|\bset-executionpolicy\b"),
    _rx(r"\b(?:get|set|add|remove|out|write|test)-[a-z]{2,30}\b"),
    _rx(r"^\s*\$[a-z_][a-z0-9_]{0,40}\s*=\s*"),
    _rx(r"\bparam\s*\("),
    _rx(r"\bfrombase64string\b"),
]
_BAT_HINTS = [
    _rx(r"^\s*@?echo\s+(?:off|on)\b"),
    _rx(r"^\s*set\s+(?:/[ap]\s+)?[a-z0-9_]{1,40}="),
    _rx(r"%~dp0|%temp%|%appdata%|%userprofile%|%localappdata%|%programdata%|%comspec%"),
    _rx(r"^\s*goto\s+:?[a-z0-9_]+"),
    _rx(r"^\s*:[a-z0-9_]{1,40}\s*$"),
    _rx(r"^\s*(?:start|call)\s+"),
    _rx(r"^\s*rem\s"),
    _rx(r"\bcmd(?:\.exe)?\s+/[ck]\b"),
    _rx(r"^\s*if\s+(?:not\s+)?(?:exist|errorlevel|defined)\b"),
]
_VBS_HINTS = [
    _rx(r"\bcreateobject\s*\("),
    _rx(r"\bwscript\.(?:shell|createobject|sleep|echo|scriptfullname|arguments)"),
    _rx(r"^\s*dim\s+[a-z_]"),
    _rx(r"^\s*(?:private\s+|public\s+)?(?:sub|function)\s+[a-z_][a-z0-9_]{0,60}"),
    _rx(r"\bend\s+(?:sub|function|if)\b"),
    _rx(r"^\s*set\s+[a-z_][a-z0-9_]{0,40}\s*=\s*"),
    _rx(r"\bon\s+error\s+resume\s+next\b"),
    _rx(r"\bmsgbox\b"),
    _rx(r"\bexecute(?:global)?\s*[\(\"]"),
    _rx(r"\bchrw?\s*\(\s*\d"),
]
_JS_HINTS = [
    _rx(r"\bnew\s+activexobject\s*\("),
    _rx(r"\bwscript\.createobject\s*\("),
    _rx(r"\bvar\s+[a-z_$][a-z0-9_$]{0,60}\s*="),
    _rx(r"\bfunction\s*[a-z0-9_$]{0,60}\s*\("),
    _rx(r"\beval\s*\("),
    _rx(r"\bstring\.fromcharcode\s*\("),
    _rx(r"\b(?:let|const)\s+[a-z_$][a-z0-9_$]{0,60}\s*="),
    _rx(r"\b(?:document|window)\.[a-z]"),
    _rx(r"\)\s*;\s*$"),
]
_VBA_HINTS = [
    _rx(r"^\s*attribute\s+vb_name\s*="),
    _rx(r"\bsub\s+(?:auto_?open|autoexec|document_open|workbook_open|autoclose|document_close)\b"),
]
_PY_HINTS = [
    _rx(r"^\s*import\s+[a-z_][a-z0-9_.]{0,60}\s*$"),
    _rx(r"^\s*from\s+[a-z_][a-z0-9_.]{0,60}\s+import\b"),
    _rx(r"^\s*def\s+[a-z_][a-z0-9_]{0,60}\s*\("),
    _rx(r"\bif\s+__name__\s*==\s*['\"]__main__['\"]"),
    _rx(r"\b(?:subprocess|os\.system|base64\.b64decode)\b"),
]
_HTML_MARKERS = (
    "<!doctype html",
    "<html",
    "<head",
    "<body",
    "<script",
    "<iframe",
    "<meta ",
    "<form",
    "<a href",
    "<div",
    "<table",
    "<title",
    "<img ",
    "<style",
    "<span",
    "<input",
    "<p>",
    "<br",
)
_SHEBANG_RE = re.compile(r"^#!\s*(?:/usr)?(?:/local)?/bin/(?:env\s+)?([a-z0-9_.-]{1,30})")


def _score(hints: list[re.Pattern[str]], text: str) -> int:
    return sum(1 for rx in hints if rx.search(text))


def _sniff_text(text: str, ext: str) -> str:
    """Clasifica un texto por contenido (sin extensión útil)."""
    stripped = text.lstrip("﻿ \t\r\n")
    low = stripped[:8192].lower()

    m = _SHEBANG_RE.match(low)
    if m:
        prog = m.group(1)
        if prog.startswith("python"):
            return "script/python"
        if prog in ("node", "nodejs"):
            return "script/js"
        if prog in ("pwsh", "powershell"):
            return "script/ps1"
        return "script/sh"

    if low.startswith("[internetshortcut]") or (low.startswith("[default]") and "[internetshortcut]" in low):
        return "url_shortcut"
    if low.startswith("id;p"):  # SYLK (Excel lo abre y puede ejecutar fórmulas DDE/XLM)
        return "slk"
    if low.startswith("windows registry editor version") or low.startswith("regedit4"):
        return "reg"
    first_lines = [ln.strip().lower() for ln in stripped[:2048].splitlines()[:4]]
    if (
        first_lines
        and first_lines[0] == "web"
        and any(ln.startswith(("http://", "https://")) for ln in first_lines)
    ):
        return "iqy"

    if "<hta:application" in text[:_SAMPLE].lower():
        return "script/hta"
    if low.startswith("<"):
        if "<librarydescription" in low:
            return "library-ms"
        if "<searchconnectordescription" in low:
            return "search-ms"
        if "<pcsettings" in low:
            return "settingcontent"
        if (
            "<job" in low or "<package" in low or "<scriptlet" in low or "<component" in low
        ) and "<script" in low:
            return "script/wsf"
        svg_at = low.find("<svg")
        html_at = low.find("<html")
        if svg_at >= 0 and (html_at < 0 or svg_at < html_at):
            return "svg"
        if any(mk in low[:4096] for mk in _HTML_MARKERS):
            return "html"
        if low.startswith("<?xml"):
            return "xml"
    elif sum(1 for mk in _HTML_MARKERS if mk in low[:4096]) >= 2:
        return "html"

    if _looks_like_mail(stripped, ext):
        return "eml"

    if _score(_VBA_HINTS, stripped) >= 1:
        return "script/vba"

    scores = {
        "script/ps1": _score(_PS_HINTS, stripped),
        "script/vbs": _score(_VBS_HINTS, stripped),
        "script/js": _score(_JS_HINTS, stripped),
        "script/bat": _score(_BAT_HINTS, stripped),
        "script/python": _score(_PY_HINTS, stripped),
    }
    if low.startswith("@echo off"):
        scores["script/bat"] += 2
    if low.startswith("#@~^"):  # JScript.Encode / VBScript.Encode
        return "script/vbs" if ext == "vbe" else "script/js" if ext == "jse" else "script/vbs"
    best = max(scores, key=lambda k: scores[k])  # en empate gana el primero (orden del dict)
    if scores[best] >= 2:
        return best
    return "text"


def _text_type(text: str, ext: str) -> str:
    mapped = _TEXT_EXT_MAP.get(ext)
    if mapped:
        return mapped
    if ext in _MIME_EXT:
        return "eml" if _looks_like_mail(text.lstrip("﻿"), ext) else "text"
    return _sniff_text(text, ext)


# --------------------------------------------------------------------------- API


def detect_type(data: bytes, filename: str | None) -> str:
    """Tipo real del archivo según el vocabulario de ARCHITECTURE.md. Nunca lanza excepciones."""
    try:
        if not data:
            return "unknown"
        ext = file_extension(filename)
        magic = _binary_magic(data, ext)
        if magic:
            return magic
        text = decode_text_sample(data)
        if text is not None:
            return _text_type(text, ext)
        # zip con basura adelante (polyglot / evasión): el EOCD está al final
        if b"PK\x05\x06" in data[-66000:] and b"PK\x03\x04" in data:
            with contextlib.suppress(Exception):
                if zipfile.is_zipfile(io.BytesIO(data)):
                    return _zip_type(data, ext)
        return "unknown"
    except Exception:  # noqa: BLE001 - la detección nunca debe tumbar el parseo
        return "unknown"
