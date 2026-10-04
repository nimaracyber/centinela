"""Parser MIME robusto: RawMessage -> ParsedMessage (sync, CPU; el pipeline lo corre en un thread).

Pensado para mail HOSTIL o roto:
- `email.parser.BytesParser` con `policy=compat32` (el más tolerante) y recorrido propio, iterativo y
  acotado (cantidad de partes y anidamiento), con try/except por parte;
- headers RFC 2047 decodificados con un decodificador propio tolerante (padding roto, charsets raros,
  bytes 8-bit crudos); charsets con fallback declarado -> utf-8 -> cp1252 -> latin-1;
- base64 roto (padding faltante, basura intercalada) decodificado de forma tolerante;
- mensaje más grande que `limits.max_message_bytes`: solo headers + nota en `parse_errors`.

Adjuntos: toda parte no-multipart con nombre de archivo, o `Content-Disposition: attachment`, o que no sea
text/plain|text/html (imágenes inline incluidas). `message/rfc822` (y cualquier artifact detectado como
`eml`) se parsea recursivamente: sus adjuntos quedan como hijos del artifact eml y sus URLs con origen
"artifact:<id>". winmail.dat (TNEF) lo expande `archives`. Bloques uuencode ("begin 644 x.exe") en el
cuerpo de texto se convierten en artifacts.

Contraseñas: se buscan candidatas en el asunto y los cuerpos ("contraseña: X", "clave X", "password: X",
"senha: X", "pwd X") del mail, de los mails adjuntos (.eml, a cualquier profundidad: se expanden antes que
los comprimidos) y de los .msg de Outlook adjuntos, y se prueban junto con `limits.archive_passwords`.
Si una candidata aparece DESPUÉS de haber probado un contenedor (ej: venía en un .eml dentro de otro
zip), ese contenedor se reintenta una vez. Viven solo en memoria durante el parseo: no se guardan en el
ParsedMessage ni se loguean. `message_password_candidates(pm)` las recalcula para los analizadores.

Si el mail no tiene parte text/plain pero sí HTML, `body_text` se completa con el texto visible del HTML
(para que los analizadores de contenido funcionen igual con mails solo-HTML, que son la mayoría del
phishing).
"""

from __future__ import annotations

import binascii
import contextlib
import logging
import quopri
import re
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC
from email import policy as email_policy
from email.generator import BytesGenerator
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from html.parser import HTMLParser
from io import BytesIO
from typing import TYPE_CHECKING

from centinela.core.models import Artifact, ExtractedUrl, ParsedMessage
from centinela.parsing import archives
from centinela.parsing.archives import (
    NOTE_DEPTH,
    NOTE_DUPLICATE,
    NOTE_MAX_ARTIFACTS,
    NOTE_MSG_BODY,
    NOTE_TOO_LARGE,
    ChildBuilder,
    ExtractionBudget,
    ExtractionStopped,
    add_note,
    build_artifact,
)
from centinela.parsing.filetype import SCRIPT_TYPES, decode_text_sample
from centinela.parsing.urls import MAX_URLS, dedupe_urls, extract_urls_html, extract_urls_text

if TYPE_CHECKING:
    from centinela.core.config import LimitsConfig
    from centinela.core.models import RawMessage

__all__ = [
    "decode_bytes",
    "decode_rfc2047",
    "find_password_candidates",
    "html_to_text",
    "message_password_candidates",
    "parse_message",
]

log = logging.getLogger(__name__)

MAX_PARTS = 2000
MAX_MIME_DEPTH = 60
MAX_HEADERS = 1000
MAX_HEADER_VALUE = 32 * 1024
MAX_BODY_CHARS = 2_000_000
MAX_ADDRESSES = 500
HEADER_ONLY_CAP = 1024 * 1024
MAX_UU_BLOCKS = 20
MAX_PASSWORD_CANDIDATES = 10
MAX_PASSWORD_SCAN_CHARS = 300_000
MAX_EMBEDDED_MAILS = 20  # mails/cuerpos adjuntos que revisa message_password_candidates
MAX_EMBEDDED_SCAN_BYTES = 2 * 1024 * 1024  # de cada .eml adjunto solo el principio (ahí van los cuerpos)
MAX_URL_SCAN_BYTES = 2 * 1024 * 1024

_COMPAT = email_policy.compat32
_GEN_POLICY = email_policy.compat32.clone(max_line_length=0)

# tipos de artifact de los que se extraen URLs
_HTML_URL_TYPES = {"html", "svg", "script/hta"}
_TEXT_URL_TYPES = {
    "text",
    "xml",
    "url_shortcut",
    "iqy",
    "slk",
    "reg",
    "settingcontent",
    "library-ms",
    "search-ms",
} | (SCRIPT_TYPES - {"script/hta"})


# --------------------------------------------------------------------------- decodificación


def decode_bytes(data: bytes, declared: str | None = None) -> str:
    """bytes -> str con fallback: charset declarado -> utf-8 -> cp1252 -> latin-1 (nunca falla)."""
    tried: set[str] = set()
    for cs in (declared, "utf-8", "cp1252"):
        if not cs:
            continue
        cs = cs.strip().strip("\"'").lower()
        if not cs or cs in tried:
            continue
        tried.add(cs)
        try:
            return data.decode(cs)
        except (LookupError, UnicodeDecodeError, ValueError):
            continue
    return data.decode("latin-1")


def _fix_surrogates(value: object) -> str:
    """Headers 8-bit crudos llegan como surrogates (o como objetos Header): volver a texto real."""
    if value is None:
        return ""
    s = value if isinstance(value, str) else str(value)
    if any("\udc80" <= ch <= "\udcff" for ch in s):
        try:
            return decode_bytes(s.encode("utf-8", "surrogateescape"))
        except UnicodeEncodeError:
            return s.encode("utf-8", "replace").decode("utf-8", "replace")
    return s


_UNFOLD_RE = re.compile(r"\r?\n(?=[ \t])")
_EW_RE = re.compile(r"=\?([^?\s]{1,64})\?([bBqQ])\?([^?\s]*)\?=")
_B64_JUNK_RE = re.compile(rb"[^A-Za-z0-9+/]")


def _b64_lenient(data: bytes) -> bytes:
    """base64 tolerante: ignora basura y '=' intermedios, completa padding, descarta un caracter suelto."""
    cleaned = _B64_JUNK_RE.sub(b"", data)
    rem = len(cleaned) % 4
    if rem == 1:
        cleaned = cleaned[:-1]
    elif rem:
        cleaned += b"=" * (4 - rem)
    try:
        return binascii.a2b_base64(cleaned)
    except binascii.Error:
        return b""


def _decode_encoded_word(m: re.Match[str]) -> str:
    charset = m.group(1).split("*", 1)[0]
    enc = m.group(2).lower()
    text = m.group(3)
    try:
        raw = (
            _b64_lenient(text.encode("ascii", "ignore"))
            if enc == "b"
            else binascii.a2b_qp(text.encode("ascii", "ignore"), header=True)
        )
    except (binascii.Error, ValueError):
        return m.group(0)
    return decode_bytes(raw, charset)


def decode_rfc2047(value: str) -> str:
    """Decodifica encoded-words (=?charset?B|Q?...?=) de forma tolerante. Une palabras adyacentes."""
    if not value or "=?" not in value:
        return value or ""
    out: list[str] = []
    last = 0
    prev_end: int | None = None
    for m in _EW_RE.finditer(value):
        between = value[last : m.start()]
        if not (prev_end == last and between.strip() == ""):
            out.append(between)
        out.append(_decode_encoded_word(m))
        last = m.end()
        prev_end = last
    out.append(value[last:])
    return "".join(out)


def _header_text(raw: object) -> str:
    s = _fix_surrogates(raw)
    s = _UNFOLD_RE.sub("", s).replace("\r", " ").replace("\n", " ")
    return decode_rfc2047(s)


def _clean_filename(name: str | None) -> str | None:
    if not name:
        return None
    name = decode_rfc2047(_fix_surrogates(name))
    name = re.sub(r"[\x00-\x1f\x7f]", "", name).strip().strip('"')
    name = name.replace("\\", "/").rsplit("/", 1)[-1]
    return name[:255] or None


# --------------------------------------------------------------------------- HTML -> texto


class _TextExtractor(HTMLParser):
    _BLOCK = {"br", "p", "div", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6", "table", "blockquote", "hr"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.size = 0
        self._skip = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("script", "style", "template"):
            self._skip += 1
        elif tag in self._BLOCK:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style", "template") and self._skip:
            self._skip -= 1
        elif tag in self._BLOCK:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._skip and self.size < MAX_BODY_CHARS:
            self.parts.append(data)
            self.size += len(data)


def html_to_text(html: str) -> str:
    """Texto visible aproximado de un HTML (sin scripts ni estilos)."""
    if not html:
        return ""
    p = _TextExtractor()
    with contextlib.suppress(Exception):  # HTML hostil: alcanza con lo leído
        p.feed(html[: MAX_BODY_CHARS * 2])
        p.close()
    text = "".join(p.parts)
    text = re.sub(r"[ \t ]+", " ", text)
    text = re.sub(r"\n\s*\n+", "\n\n", text)
    return text.strip()[:MAX_BODY_CHARS]


# --------------------------------------------------------------------------- contraseñas candidatas

_PWD_RE = re.compile(
    r"(?i)(?<![\w])"
    r"(?:contrase(?:ñ|n|ã)a|clave|password|passwort|passwd|passcode|pass|pwd|senha|kennwort"
    r"|c[oó]digo\s+de\s+(?:acceso|apertura))(?!\w)"
    r"[^\S\r\n]{0,4}"
    r"(?:(?:(?:del?|de\s+la|para|pra|do|da|of|for|the|el|la|archivo|arquivo|adjunto|anexo|file|zip|rar|7z"
    r"|documento|pdf|abrir|apertura|acceso|is|es|é|e|será|sera|seria|sería)\b|[:=\-–→>])[^\S\r\n]{0,4}){0,6}"
    r"(?:\r?\n[^\S\r\n]{0,8})?"
    r"[\"'«“‘\[(*]{0,2}([^\s\"'»”’\])<>*]{1,64})"
)
_PWD_STOP = {
    "de", "del", "es", "is", "the", "para", "y", "and", "o", "or", "que", "por", "favor", "please", "no",
    "su", "tu", "your", "my", "mi", "segura", "seguro", "incorrecta", "incorrecto", "olvidada", "olvidaste",
    "vencida", "expira", "expirada", "nueva", "nuevo", "new", "reset", "here", "aquí", "aqui", "abajo",
    "below", "adjunta", "adjunto", "attached", "enviada", "sent", "contraseña", "contrasena", "clave",
    "password", "senha", "pwd", "pass", "será", "sera", "en", "in", "un", "una", "a", "to", "con", "with",
    "archivo", "file", "protegido", "protegida", "protected", "required", "requerida", "temporal",
    "actual", "current", "anterior", "siguiente", "following", "este", "esta", "this", "mensaje", "mail",
    "correo", "email", "usuario", "user", "segue", "abaixo", "é",
}  # fmt: skip


def find_password_candidates(text: str, limit: int = MAX_PASSWORD_CANDIDATES) -> list[str]:
    """Posibles contraseñas de adjuntos mencionadas en un texto ("Contraseña: 4455", "senha 9999")."""
    out: list[str] = []
    if not text:
        return out
    for m in _PWD_RE.finditer(text[:MAX_PASSWORD_SCAN_CHARS]):
        token = m.group(1)
        stripped = token.rstrip(".,;:!?")
        if len(stripped) < 3 or stripped.lower() in _PWD_STOP or "://" in token or "@" in token:
            continue
        for cand in (stripped, token):
            if cand not in out:
                out.append(cand)
        if len(out) >= limit:
            break
    return out[:limit]


def _is_msg_body(art: Artifact) -> bool:
    """Hijo con el cuerpo de texto de un .msg de Outlook adjunto (archives lo crea con NOTE_MSG_BODY)."""
    return bool(art.data) and (art.extraction_note or "").startswith(NOTE_MSG_BODY)


def _msg_body_text(art: Artifact) -> str:
    return art.data[: MAX_PASSWORD_SCAN_CHARS * 4].decode("utf-8", "replace")


def _embedded_mail_texts(art: Artifact) -> list[str]:
    """Textos donde un mail adjunto puede traer una contraseña: asunto y cuerpos de un .eml (solo el
    principio del archivo, sin decodificar sus adjuntos) o el cuerpo de un .msg."""
    if _is_msg_body(art):
        return [_msg_body_text(art)]
    if art.detected_type != "eml" or not art.data:
        return []
    msg = _parse_bytes(art.data[:MAX_EMBEDDED_SCAN_BYTES], [])
    content = _collect(msg, MAX_EMBEDDED_SCAN_BYTES, bodies_only=True)
    texts = [_header_text(msg.get("subject", "")), *content.texts]
    texts += [html_to_text(h[: MAX_PASSWORD_SCAN_CHARS * 4]) for h in content.htmls]
    return texts


def message_password_candidates(message: ParsedMessage, limit: int = MAX_PASSWORD_CANDIDATES) -> list[str]:
    """Contraseñas candidatas de un mail YA parseado, en orden: asunto, cuerpos y después los mails
    adjuntos (.eml, a cualquier profundidad) y los cuerpos de .msg de Outlook adjuntos (un reenvío con "la
    clave es 4455" adentro). Son las mismas fuentes que usa `parse_message` para abrir comprimidos.

    Para analizadores que necesitan probar claves (ej: documentos Office cifrados). Acotado (cantidad de
    mails adjuntos y bytes mirados). El resultado vive solo en memoria: NO guardarlo, ni loguearlo, ni
    ponerlo en la evidencia de un Finding."""
    out: list[str] = []

    def add(text: str) -> None:
        for cand in find_password_candidates(text, limit):
            if len(out) >= limit:
                return
            if cand not in out:
                out.append(cand)

    add(message.subject)
    add(message.body_text)
    if message.body_html:
        add(html_to_text(message.body_html[: MAX_PASSWORD_SCAN_CHARS * 4]))
    scanned = 0
    for art in message.artifacts:
        if len(out) >= limit or scanned >= MAX_EMBEDDED_MAILS:
            break
        if art.detected_type != "eml" and not _is_msg_body(art):
            continue
        scanned += 1
        try:
            texts = _embedded_mail_texts(art)
        except Exception:  # noqa: BLE001 - mail adjunto hostil: se sigue con el resto
            log.debug("no se pudieron leer los cuerpos de %s", art.id, exc_info=True)
            continue
        for text in texts:
            add(text)
    return out


# --------------------------------------------------------------------------- recorrido MIME


@dataclass
class _Leaf:
    filename: str | None
    content_type: str | None
    data: bytes
    is_eml: bool = False
    note: str | None = None


@dataclass
class _Content:
    texts: list[str] = field(default_factory=list)
    htmls: list[str] = field(default_factory=list)
    leaves: list[_Leaf] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _parse_bytes(data: bytes, errors: list[str], *, headers_only: bool = False) -> Message:
    parser = BytesParser(policy=_COMPAT)
    try:
        return parser.parsebytes(data, headersonly=headers_only)
    except RecursionError:
        errors.append("estructura MIME demasiado anidada: solo se analizaron los encabezados")
        return parser.parsebytes(data[:HEADER_ONLY_CAP], headersonly=True)


def _params_view(part: Message) -> Message:
    """Copia de Content-Type/Content-Disposition con los bytes 8-bit ya decodificados, para que
    `get_filename()` y compañía (RFC 2231) funcionen bien con nombres no-ASCII crudos."""
    tmp = Message()
    for k, v in part.raw_items():
        if k.lower() in ("content-type", "content-disposition"):
            tmp[k] = _UNFOLD_RE.sub("", _fix_surrogates(v))
    return tmp


def _cte(part: Message) -> str:
    for k, v in part.raw_items():
        if k.lower() == "content-transfer-encoding":
            return _fix_surrogates(v).split(";", 1)[0].strip().lower()
    return ""


def _raw_payload_bytes(part: Message) -> bytes:
    # OJO: get_payload() sin decode re-decodifica cuerpos 8-bit con el charset declarado y errors="replace"
    # (pierde bytes). El atributo interno conserva los bytes originales como surrogates.
    payload = getattr(part, "_payload", None)
    if payload is None:
        payload = part.get_payload()
    if payload is None or isinstance(payload, list):
        return b""
    if isinstance(payload, bytes):
        return payload
    try:
        return payload.encode("ascii", "surrogateescape")
    except UnicodeEncodeError:
        return payload.encode("utf-8", "surrogateescape")


def _uu_decode(lines: list[str], max_bytes: int) -> bytes:
    out = bytearray()
    for line in lines:
        if not line or line in ("`", " "):
            continue
        try:
            chunk = binascii.a2b_uu(line)
        except (binascii.Error, ValueError):
            try:
                nbytes = (((ord(line[0]) - 32) & 63) * 4 + 5) // 3
                chunk = binascii.a2b_uu(line[:nbytes])
            except (binascii.Error, ValueError, IndexError):
                continue
        out += chunk
        if len(out) > max_bytes:
            break
    return bytes(out)


def _decode_payload(part: Message, max_bytes: int) -> bytes:
    raw = _raw_payload_bytes(part)
    cte = _cte(part)
    if cte == "base64":
        return _b64_lenient(raw)
    if cte == "quoted-printable":
        try:
            return quopri.decodestring(raw)
        except (ValueError, binascii.Error):
            return binascii.a2b_qp(raw)
    if cte in ("x-uuencode", "uuencode", "x-uue", "uue"):
        text = raw.decode("latin-1")
        lines = text.splitlines()
        body: list[str] = []
        started = False
        for ln in lines:
            if not started:
                started = ln.startswith("begin ")
                continue
            if ln.strip() == "end":
                break
            body.append(ln)
        return _uu_decode(body if started else lines, max_bytes)
    return raw


def _embedded_message_bytes(part: Message) -> tuple[bytes, Message | None]:
    """Bytes del mail adjunto (message/rfc822) y su objeto Message si el parser ya lo armó."""
    payload = part.get_payload()
    cte = _cte(part)
    inner: Message | None = None
    data = b""
    if isinstance(payload, list) and payload and isinstance(payload[0], Message):
        inner = payload[0]
        buf = BytesIO()
        try:
            BytesGenerator(buf, mangle_from_=False, policy=_GEN_POLICY).flatten(inner)
            data = buf.getvalue()
        except (RecursionError, Exception):  # noqa: BLE001 - mensaje interno patológico
            data = b""
    elif isinstance(payload, str):
        data = _raw_payload_bytes(part)
    if cte == "base64":
        data = _b64_lenient(data.split(b"\n\n", 1)[-1] if inner is not None else data)
        inner = None
    elif cte == "quoted-printable":
        data = quopri.decodestring(data)
        inner = None
    return data, inner


def _collect(msg: Message, max_bytes: int, *, bodies_only: bool = False) -> _Content:
    """Recorre el árbol MIME (iterativo, acotado) separando cuerpos y adjuntos.

    `bodies_only=True`: solo los cuerpos de texto/HTML; los adjuntos y los mails internos ni se decodifican."""
    content = _Content()
    stack: list[tuple[Message, int]] = [(msg, 0)]
    count = 0
    while stack:
        part, depth = stack.pop()
        count += 1
        if count > MAX_PARTS:
            content.errors.append(f"más de {MAX_PARTS} partes MIME: se ignoró el resto")
            break
        try:
            view = _params_view(part)
            if view.get("content-type") is not None:
                ctype = view.get_content_type()
            else:  # sin Content-Type: text/plain (o message/rfc822 dentro de multipart/digest)
                ctype = (part.get_content_type() or "text/plain").lower()
            if ctype == "message/rfc822" or (ctype.startswith("message/") and part.is_multipart()):
                if bodies_only or ctype not in ("message/rfc822", "message/global"):
                    continue  # delivery-status, disposition-notification...: no son mails
                data, inner = _embedded_message_bytes(part)
                filename = _clean_filename(view.get_filename())
                if not filename:
                    subject = _header_text(inner.get("subject", "")) if inner is not None else ""
                    subject = re.sub(r"[\\/:*?\"<>|\x00-\x1f]", "_", subject).strip()[:80]
                    filename = f"{subject or 'mensaje_adjunto'}.eml"
                content.leaves.append(_Leaf(filename, "message/rfc822", data, is_eml=True))
                continue
            if part.is_multipart():
                if depth >= MAX_MIME_DEPTH:
                    content.errors.append("anidamiento MIME excesivo: se ignoraron partes internas")
                    continue
                payload = part.get_payload()
                if isinstance(payload, list):
                    for sub in reversed(payload):
                        if isinstance(sub, Message):
                            stack.append((sub, depth + 1))
                continue
            filename = _clean_filename(view.get_filename())
            disposition = view.get_content_disposition()
            charset = None
            try:
                charset = view.get_content_charset()
            except (LookupError, ValueError):
                charset = None
            declared = view.get_content_type() if view.get("content-type") is not None else None
            if ctype.startswith("multipart/"):
                # multipart sin boundary válido: el cliente lo muestra como texto
                content.errors.append("parte multipart sin boundary válido: se tomó como texto")
                content.texts.append(decode_bytes(_decode_payload(part, max_bytes), charset))
                continue
            if ctype in ("text/plain", "text/html") and not filename and disposition != "attachment":
                text = decode_bytes(_decode_payload(part, max_bytes), charset)
                (content.htmls if ctype == "text/html" else content.texts).append(text)
                continue
            if bodies_only:
                continue
            if ctype == "message/global" and not filename:
                filename = "mensaje_adjunto.eml"
            content.leaves.append(_Leaf(filename, declared, _decode_payload(part, max_bytes)))
        except Exception as exc:  # noqa: BLE001 - una parte rota no tumba el resto
            log.debug("parte MIME ilegible", exc_info=True)
            content.errors.append(f"parte MIME ilegible ({type(exc).__name__})")
    return content


_UU_BEGIN_RE = re.compile(r"^begin(-base64)? [0-7]{3,4} ([^\r\n]{1,255})\r?$", re.MULTILINE)
_UU_END_RE = re.compile(r"^end\r?$", re.MULTILINE)
_B64_END_RE = re.compile(r"^====\r?$", re.MULTILINE)


def _uu_blocks(text: str, max_bytes: int) -> list[tuple[str, bytes]]:
    """Bloques uuencode / uuencode -m embebidos en un cuerpo de texto."""
    out: list[tuple[str, bytes]] = []
    if "begin" not in text:
        return out
    pos = 0
    while len(out) < MAX_UU_BLOCKS:
        m = _UU_BEGIN_RE.search(text, pos)
        if not m:
            break
        end_re = _B64_END_RE if m.group(1) else _UU_END_RE
        e = end_re.search(text, m.end())
        stop = e.start() if e else len(text)
        lines = text[m.end() : stop].splitlines()
        lines = [ln.rstrip("\r") for ln in lines if ln.strip()]
        try:
            if m.group(1):
                data = _b64_lenient("".join(lines).encode("ascii", "ignore"))[: max_bytes + 1]
            else:
                data = _uu_decode([ln for ln in lines if ln.isascii()], max_bytes)
        except Exception:  # noqa: BLE001
            data = b""
        if data:
            out.append((m.group(2).strip(), data))
        pos = e.end() if e else len(text)
    return out


# --------------------------------------------------------------------------- headers


def _addresses(values: list[str]) -> list[tuple[str, str]]:
    """[(nombre visible decodificado, dirección en minúsculas)] tolerante a headers raros."""
    values = [v for v in values if v]
    if not values:
        return []
    pairs: list[tuple[str, str]] = []
    try:
        pairs = getaddresses(values)
    except Exception:  # noqa: BLE001
        pairs = []
    if not any(addr for _, addr in pairs):
        try:
            pairs = getaddresses(values, strict=False)
        except Exception:  # noqa: BLE001
            pairs = []
    if not any(addr for _, addr in pairs):
        pairs = [("", a) for v in values for a in re.findall(r"[\w.+'=-]{1,64}@[\w.-]{1,255}", v)]
    out: list[tuple[str, str]] = []
    for name, addr in pairs[:MAX_ADDRESSES]:
        addr = addr.strip().strip("<>").lower()
        if not addr or "@" not in addr:
            continue
        out.append((decode_rfc2047(name).strip(), addr))
    return out


def _fill_headers(pm: ParsedMessage, msg: Message) -> None:
    raw_items = list(msg.raw_items())
    if len(raw_items) > MAX_HEADERS:
        pm.parse_errors.append(f"más de {MAX_HEADERS} encabezados: se ignoró el resto")
        raw_items = raw_items[:MAX_HEADERS]
    raw_by_name: dict[str, list[str]] = {}
    for k, v in raw_items:
        name = _fix_surrogates(k).strip()
        raw = _UNFOLD_RE.sub("", _fix_surrogates(v)).replace("\r", " ").replace("\n", " ")
        raw_by_name.setdefault(name.lower(), []).append(raw)
        value = decode_rfc2047(raw)
        if len(value) > MAX_HEADER_VALUE:
            value = value[:MAX_HEADER_VALUE]
        pm.headers.append((name, value))

    def first(name: str) -> str | None:
        vals = raw_by_name.get(name)
        return vals[0] if vals else None

    subject = first("subject")
    if subject is not None:
        pm.subject = re.sub(r"\s+", " ", decode_rfc2047(subject)).strip()[:2000]
    mid = first("message-id")
    if mid:
        pm.message_id = mid.strip()[:998] or None
    frm = _addresses(raw_by_name.get("from", [])[:1])
    if frm:
        pm.from_display = frm[0][0] or None
        pm.from_addr = frm[0][1]
    elif first("from"):
        pm.parse_errors.append("header From ilegible")
    pm.reply_to = [a for _, a in _addresses(raw_by_name.get("reply-to", []))]
    pm.to = [a for _, a in _addresses(raw_by_name.get("to", []))]
    pm.cc = [a for _, a in _addresses(raw_by_name.get("cc", []))]
    rp = first("return-path")
    if rp is not None:
        rp_addrs = _addresses([rp])
        pm.return_path = rp_addrs[0][1] if rp_addrs else None
    date = first("date")
    if date:
        try:
            dt = parsedate_to_datetime(date)
            pm.date = dt if dt.tzinfo else dt.replace(tzinfo=UTC)
        except (TypeError, ValueError, IndexError, OverflowError):
            pm.date = None


def _header_block(data: bytes) -> bytes:
    head = data[:HEADER_ONLY_CAP]
    for sep in (b"\r\n\r\n", b"\n\n"):
        i = head.find(sep)
        if i >= 0:
            return head[: i + len(sep)]
    return head


# --------------------------------------------------------------------------- armado del ParsedMessage


class _State:
    def __init__(self, pm: ParsedMessage, limits: LimitsConfig) -> None:
        self.pm = pm
        self.limits = limits
        self.budget = ExtractionBudget.from_limits(limits)
        self.passwords: list[str] = []
        self.urls: list[ExtractedUrl] = []

    def add_passwords(self, text: str) -> None:
        if len(self.passwords) >= MAX_PASSWORD_CANDIDATES:
            return
        for cand in find_password_candidates(text):
            if cand not in self.passwords:
                self.passwords.append(cand)
            if len(self.passwords) >= MAX_PASSWORD_CANDIDATES:
                break

    def harvest(self, art: Artifact) -> None:
        """Cuerpo de un .msg adjunto recién extraído: puede traer la clave de un comprimido hermano (que
        todavía está en la cola, así que la aprovecha)."""
        if _is_msg_body(art):
            self.add_passwords(_msg_body_text(art))

    def add_urls(self, urls: list[ExtractedUrl]) -> None:
        if len(self.urls) < MAX_URLS * 2:
            self.urls.extend(urls)


def _join_bodies(parts: list[str], errors: list[str], label: str) -> str:
    text = "\n".join(p for p in parts if p)
    if len(text) > MAX_BODY_CHARS:
        errors.append(f"cuerpo {label} truncado a {MAX_BODY_CHARS} caracteres")
        text = text[:MAX_BODY_CHARS]
    return text


def _bodies_from_content(
    content: _Content, state: _State, source_text: str, source_html: str
) -> tuple[str, str]:
    """Une cuerpos, extrae URLs y contraseñas candidatas. Devuelve (texto, html)."""
    errors: list[str] = []
    text = _join_bodies(content.texts, errors, "de texto")
    html = _join_bodies(content.htmls, errors, "HTML")
    content.errors.extend(errors)
    if text:
        state.add_urls(extract_urls_text(text, source_text))
        state.add_passwords(text)
    if html:
        state.add_urls(extract_urls_html(html, source_html))
        state.add_passwords(html_to_text(html[: MAX_PASSWORD_SCAN_CHARS * 4]))
    return text, html


def _leaf_artifact(
    leaf: _Leaf, art_id: str, limits: LimitsConfig, *, depth: int = 0, parent_id: str | None = None
) -> Artifact:
    art = build_artifact(
        id=art_id,
        data=leaf.data,
        filename=leaf.filename,
        depth=depth,
        parent_id=parent_id,
        declared_content_type=leaf.content_type,
        detected_type="eml" if leaf.is_eml else None,
    )
    if len(leaf.data) > limits.max_artifact_bytes:
        art.data = b""
        add_note(art, _hash_only_note(len(leaf.data), limits.max_artifact_bytes))
    return art


def _hash_only_note(size: int, limit: int) -> str:
    return (
        f"{NOTE_TOO_LARGE} ({size // (1024 * 1024)} MB; límite {limit // (1024 * 1024)} MB): "
        "solo se calcularon los hashes"
    )


def _expand_eml(art: Artifact, state: _State) -> list[Artifact]:
    """Parsea un mail adjunto: URLs y contraseñas de sus cuerpos + sus adjuntos como hijos."""
    budget = state.budget
    if art.depth >= budget.max_depth:
        add_note(art, f"{NOTE_DEPTH} ({budget.max_depth} niveles)")
        return []
    if art.sha256:
        previous = budget.expanded.get(art.sha256)
        if previous is not None:
            add_note(art, f"{NOTE_DUPLICATE}: idéntico a {previous}")
            return []
        budget.expanded[art.sha256] = art.id
    if budget.time_exceeded():
        add_note(art, archives.NOTE_TIMEOUT)
        return []
    errors: list[str] = []
    msg = _parse_bytes(art.data, errors)
    content = _collect(msg, state.limits.max_artifact_bytes)
    source = f"artifact:{art.id}"
    subject = msg.get("subject")
    if subject:
        state.add_passwords(_header_text(subject))
    text, _html = _bodies_from_content(content, state, source, source)
    for e in errors + content.errors:
        add_note(art, e)
    builder = ChildBuilder(art, state.limits, state.passwords, budget)
    try:
        for leaf in content.leaves:
            if builder.stopped:
                break
            if len(leaf.data) > builder.max_entry:
                # los bytes ya están en memoria: como con un adjunto directo, hashes sí (reputación), datos no
                builder.add(
                    leaf.filename,
                    leaf.data,
                    declared_content_type=leaf.content_type,
                    note=_hash_only_note(len(leaf.data), builder.max_entry),
                    hash_only=True,
                )
                continue
            child = builder.add(leaf.filename, leaf.data, declared_content_type=leaf.content_type)
            if leaf.is_eml:
                child.detected_type = "eml"
        for name, data in _uu_blocks(text, builder.max_entry):
            builder.add(name, data, note="extraído de un bloque uuencode en el cuerpo")
    except ExtractionStopped:
        pass
    return builder.children


def _artifact_urls(art: Artifact, state: _State) -> None:
    t = art.detected_type
    if not art.data or (t not in _HTML_URL_TYPES and t not in _TEXT_URL_TYPES):
        return
    text = decode_text_sample(art.data, MAX_URL_SCAN_BYTES)
    if text is None:
        return
    source = f"artifact:{art.id}"
    if t in _HTML_URL_TYPES:
        state.add_urls(extract_urls_html(text, source))
    else:
        state.add_urls(extract_urls_text(text, source))


@dataclass
class _Locked:
    """Contenedor con contraseña que quedó sin abrir, por si después aparecen candidatas nuevas."""

    art: Artifact
    known: int  # cuántas candidatas había cuando se expandió
    before: tuple[str | None, bool, bool]  # (extraction_note, encrypted, password_protected) previos
    children: list[Artifact]


def _reopen_locked(locked: list[_Locked], state: _State, all_artifacts: list[Artifact]) -> list[Artifact]:
    """Contenedores cerrados para los que aparecieron candidatas NUEVAS después de expandirlos (ej: la clave
    venía en un .eml que estaba dentro de OTRO zip, y ese zip se abrió después). Se descartan sus hijos
    "solo listados", se devuelve el cupo de artifacts y se devuelven para re-expandirlos (el llamador
    garantiza que cada uno se reintenta una sola vez). Si algo ya se había extraído, no se toca."""
    pending = [
        x for x in locked if len(state.passwords) > x.known and all(c.listing_only for c in x.children)
    ]
    locked.clear()
    if not pending:
        return []
    drop = {id(c) for x in pending for c in x.children}
    all_artifacts[:] = [a for a in all_artifacts if id(a) not in drop]
    budget = state.budget
    for x in pending:
        budget.remaining_artifacts += len(x.children)
        if x.art.sha256 and budget.expanded.get(x.art.sha256) == x.art.id:
            del budget.expanded[x.art.sha256]  # si no, expand() lo trataría como "contenedor repetido"
        x.art.extraction_note, x.art.encrypted, x.art.password_protected = x.before
    return [x.art for x in pending]


def _ordered(artifacts: list[Artifact]) -> list[Artifact]:
    """Orden de lectura: cada hijo inmediatamente después de su padre (DFS), estable."""
    by_parent: dict[str | None, list[Artifact]] = {}
    ids = {a.id for a in artifacts}
    for a in artifacts:
        key = a.parent_id if a.parent_id in ids else None
        by_parent.setdefault(key, []).append(a)
    out: list[Artifact] = []
    stack = list(reversed(by_parent.get(None, [])))
    while stack:
        a = stack.pop()
        out.append(a)
        stack.extend(reversed(by_parent.get(a.id, [])))
    return out if len(out) == len(artifacts) else artifacts


def _parse_into(pm: ParsedMessage, data: bytes, limits: LimitsConfig) -> None:
    if len(data) > limits.max_message_bytes:
        msg = _parse_bytes(_header_block(data), pm.parse_errors, headers_only=True)
        _fill_headers(pm, msg)
        pm.parse_errors.append(
            f"mensaje demasiado grande ({len(data) // (1024 * 1024)} MB; límite "
            f"{limits.max_message_bytes // (1024 * 1024)} MB): solo se analizaron los encabezados"
        )
        return

    msg = _parse_bytes(data, pm.parse_errors)
    _fill_headers(pm, msg)
    state = _State(pm, limits)
    content = _collect(msg, limits.max_artifact_bytes)

    if pm.subject:
        state.add_passwords(pm.subject)
    text, html = _bodies_from_content(content, state, "body_text", "body_html")
    pm.parse_errors.extend(content.errors)
    pm.body_text = text or (html_to_text(html) if html else "")
    pm.body_html = html

    # adjuntos de primer nivel: att0, att1, ...
    leaves = list(content.leaves)
    for name, blob in _uu_blocks(text, limits.max_artifact_bytes):
        leaves.append(_Leaf(name, None, blob, note="extraído de un bloque uuencode en el cuerpo"))
    roots: list[Artifact] = []
    for leaf in leaves:
        if not state.budget.take_artifact():
            pm.parse_errors.append(f"{NOTE_MAX_ARTIFACTS}: se ignoraron adjuntos")
            break
        art = _leaf_artifact(leaf, f"att{len(roots)}", limits)
        if leaf.note:
            add_note(art, leaf.note)
        roots.append(art)

    # expansión recursiva (BFS; los .eml primero para juntar sus contraseñas antes de abrir zips)
    all_artifacts: list[Artifact] = list(roots)
    emls: deque[Artifact] = deque()
    others: deque[Artifact] = deque()
    locked: list[_Locked] = []
    retried: set[str] = set()

    def push(a: Artifact) -> None:
        (emls if a.detected_type == "eml" else others).append(a)

    for a in roots:
        push(a)
    while True:
        while emls or others:
            art = emls.popleft() if emls else others.popleft()
            known = len(state.passwords)
            before = (art.extraction_note, art.encrypted, art.password_protected)
            try:
                if art.detected_type == "eml" and art.data:
                    children = _expand_eml(art, state)
                elif archives.can_expand(art):
                    children = archives.expand(art, limits, state.passwords, state.budget)
                else:
                    continue
            except Exception as exc:  # noqa: BLE001 - defensa en profundidad
                log.debug("fallo expandiendo %s", art.id, exc_info=True)
                add_note(art, f"{archives.NOTE_CORRUPT} ({type(exc).__name__})")
                continue
            all_artifacts.extend(children)
            for c in children:
                state.harvest(c)
                push(c)
            if art.encrypted and art.id not in retried:
                locked.append(_Locked(art, known, before, children))
        again = _reopen_locked(locked, state, all_artifacts)
        if not again:
            break
        for a in again:
            retried.add(a.id)
            others.append(a)
    pm.artifacts = _ordered(all_artifacts)

    for art in pm.artifacts:
        if len(state.urls) >= MAX_URLS * 2:
            break
        try:
            _artifact_urls(art, state)
        except Exception:  # noqa: BLE001
            log.debug("no se pudieron extraer URLs de %s", art.id, exc_info=True)
    pm.urls = dedupe_urls(state.urls, MAX_URLS)


def parse_message(raw: RawMessage, limits: LimitsConfig) -> ParsedMessage:
    """Parsea el mail crudo. Nunca lanza por input malformado: los problemas van a `parse_errors`."""
    data = raw.raw or b""
    pm = ParsedMessage(ref=raw.ref, received_at=raw.received_at, size=len(data))
    try:
        _parse_into(pm, data, limits)
    except Exception as exc:  # noqa: BLE001 - el pipeline trata excepciones como ERROR; preferimos resultado parcial
        log.debug("error inesperado parseando %s", raw.ref.remote_id, exc_info=True)
        pm.parse_errors.append(f"error interno del parser: {type(exc).__name__}")
    return pm


# para quien necesite decodificar base64 de forma tolerante (analizadores de scripts/HTML)
b64decode_lenient = _b64_lenient
