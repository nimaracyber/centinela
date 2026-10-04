"""Extracción de URLs de texto plano y HTML (cuerpos del mail y adjuntos html/svg/texto).

- HTML: `html.parser` de la stdlib (tolerante a HTML roto). Se toman a[href] (con su texto visible,
  para detectar links engañosos), area/link[href], form[action], button/input[formaction],
  iframe/frame/img/script/embed/source/audio/video[src], object[data], meta refresh, `<base href>`
  para resolver relativas, `href` en cualquier otro tag (SVG `<a xlink:href>`, VML de Outlook) y además
  URLs "sueltas" en texto, comentarios (los botones VML de Outlook viven en comentarios condicionales)
  y scripts.
- Texto: http(s)/ftp, `www.`, `file:` y esquemas de Windows abusados (search-ms:, ms-msdt:, ms-word:...).

Esquemas peligrosos como javascript:, data:, file:, search-ms:, ms-msdt: SE CONSERVAN (importan para el
análisis). Se ignoran cid:, mailto:, tel:, sms:, about: y referencias relativas sin `<base>`.
Las `data:` de imágenes raster en `<img src>` (logos embebidos) se omiten: son ruido benigno.

Normalización (como un navegador): sin tabs/saltos de línea internos, esquema y host en minúsculas,
`\\` -> `/` en esquemas web, "https:/x" o "https:\\\\x" -> "https://x", `//host` -> `https://host`,
rutas UNC `\\\\srv\\share` -> `file://srv/share`. Deduplicado, tope de 1000 URLs, largo acotado.
"""

from __future__ import annotations

import contextlib
import logging
import re
from html.parser import HTMLParser
from urllib.parse import urljoin

from centinela.core.models import ExtractedUrl

__all__ = [
    "MAX_URLS",
    "dedupe_urls",
    "extract_urls_html",
    "extract_urls_text",
    "normalize_url",
]

log = logging.getLogger(__name__)

MAX_URLS = 1000
MAX_URL_LEN = 2048
MAX_DATA_URL_LEN = 512
MAX_DISPLAY_LEN = 500
MAX_INPUT_CHARS = 5_000_000
_MAX_SCAN_CHARS = 5_000_000

_IGNORED_SCHEMES = {"cid", "mid", "mailto", "tel", "sms", "callto", "about"}
_WEB_SCHEMES = {"http", "https", "ftp", "ws", "wss"}

_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]{0,31}):")
_WS_INNER_RE = re.compile(r"[\t\r\n]+")
_C0_STRIP = "".join(chr(i) for i in range(0x21)) + "\x7f"
_META_URL_RE = re.compile(r"""(?i)\burl\s*=\s*['"]?\s*([^'"\s>][^'">]{0,4096})""")
_RASTER_DATA_RE = re.compile(r"(?i)^data:image/(?:png|jpe?g|gif|webp|bmp|x-icon|vnd\.microsoft\.icon)[;,]")

# URLs en texto libre (todas las repeticiones acotadas y con clases simples: sin backtracking explosivo)
_URL_CHARS = r"[^\s<>\"'`\x00-\x1f\x7f]"
_TEXT_URL_RE = re.compile(
    r"(?i)"
    r"(?:\b(?:https?|ftps?)://" + _URL_CHARS + r"{1,4096})"
    r"|(?:\bfile:(?://|\\\\)" + _URL_CHARS + r"{1,4096})"
    r"|(?:\b(?:search-ms|search|ms-[a-z]{2,20}(?:-[a-z]{2,10})?):" + _URL_CHARS + r"{2,4096})"
    r"|(?:(?<![\w@./-])www\d{0,3}\.[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63}){1,10}(?:[/?#:]"
    + _URL_CHARS
    + r"{0,4096})?)"
)
_TRAILING = ".,;:!?'\")]}>»”’*"
_PAIRS = {")": "(", "]": "[", "}": "{"}


def _cap(url: str) -> str:
    if url[:5].lower() == "data:":
        return url[:MAX_DATA_URL_LEN]
    return url[:MAX_URL_LEN]


def normalize_url(raw: str, base: str | None = None) -> str | None:
    """Normaliza una URL como lo haría un navegador. None si no es una URL absoluta interesante."""
    if not raw:
        return None
    u = raw.strip(_C0_STRIP)
    u = _WS_INNER_RE.sub("", u)
    if not u or u.startswith("#"):
        return None
    if u.startswith("\\\\"):  # ruta UNC (WebDAV/SMB): \\servidor\share\x.exe
        u = "file:" + u.replace("\\", "/")
    m = _SCHEME_RE.match(u)
    if m and len(m.group(1)) == 1:  # "C:\carpeta\x.exe": ruta local de Windows
        u = "file:///" + u.replace("\\", "/")
        m = _SCHEME_RE.match(u)
    if not m:
        if u.startswith(("//", "\\\\", "/\\", "\\/")):
            u = "https:" + u
        elif re.match(r"(?i)www\d{0,3}\.", u):
            u = "http://" + u
        elif base:
            try:
                return normalize_url(urljoin(base, u))
            except ValueError:
                return None
        else:
            return None
        m = _SCHEME_RE.match(u)
        if not m:
            return None
    scheme = m.group(1).lower()
    if scheme in _IGNORED_SCHEMES:
        return None
    rest = u[m.end() :]
    if scheme in _WEB_SCHEMES or scheme == "file":
        rest = rest.replace("\\", "/")
        if scheme == "file":
            if rest.startswith("//"):
                return _cap(f"file:{rest}")
            return _cap(f"file://{rest.lstrip('/')}") if rest.startswith("/") else _cap(f"file:{rest}")
        rest = rest.lstrip("/")
        end = len(rest)
        for sep in "/?#":
            i = rest.find(sep)
            if 0 <= i < end:
                end = i
        authority, tail = rest[:end], rest[end:]
        if "@" in authority:
            userinfo, _, hostport = authority.rpartition("@")
            authority = f"{userinfo}@{hostport.lower()}"
        else:
            authority = authority.lower()
        if not authority:
            return None
        return _cap(f"{scheme}://{authority}{tail}")
    return _cap(f"{scheme}:{rest}")


def _trim_trailing(url: str) -> str:
    while url and url[-1] in _TRAILING:
        ch = url[-1]
        opener = _PAIRS.get(ch)
        if opener and url.count(opener) >= url.count(ch):
            break
        url = url[:-1]
    return url


def _scan_text(text: str) -> list[str]:
    out: list[str] = []
    for m in _TEXT_URL_RE.finditer(text[:_MAX_SCAN_CHARS]):
        url = _trim_trailing(m.group(0))
        if url:
            out.append(url)
        if len(out) >= MAX_URLS * 4:
            break
    return out


def dedupe_urls(urls: list[ExtractedUrl], cap: int = MAX_URLS) -> list[ExtractedUrl]:
    """Quita duplicados (url, origen, texto visible) preservando el orden; corta en `cap`."""
    seen: set[tuple[str, str, str | None]] = set()
    out: list[ExtractedUrl] = []
    for u in urls:
        key = (u.url, u.source, u.display_text)
        if key in seen:
            continue
        seen.add(key)
        out.append(u)
        if len(out) >= cap:
            break
    return out


def extract_urls_text(text: str, source: str = "body_text") -> list[ExtractedUrl]:
    """URLs en texto plano (cuerpo text/plain, .txt, .url, scripts...)."""
    if not text:
        return []
    out: list[ExtractedUrl] = []
    seen: set[str] = set()
    for raw in _scan_text(text[:MAX_INPUT_CHARS]):
        url = normalize_url(raw)
        if not url or url in seen:
            continue
        seen.add(url)
        out.append(ExtractedUrl(url=url, source=source))
        if len(out) >= MAX_URLS:
            break
    return out


# --------------------------------------------------------------------------- HTML

_SRC_TAGS = {
    "iframe",
    "frame",
    "img",
    "script",
    "embed",
    "source",
    "audio",
    "video",
    "track",
    "input",
    "image",
}


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.found: list[tuple[str, str | None]] = []  # (url cruda, texto visible)
        self.base: str | None = None
        self._anchors: list[tuple[str | None, list[str], int]] = []  # (href, partes de texto, largo)
        self.text_parts: list[str] = []
        self._text_len = 0

    # -- helpers
    def _add(self, value: str | None, display: str | None = None, *, img: bool = False) -> None:
        if not value or len(self.found) >= MAX_URLS * 4:
            return
        if img and _RASTER_DATA_RE.match(value.lstrip()):
            return
        self.found.append((value, display))

    def _keep_text(self, data: str) -> None:
        if self._text_len < _MAX_SCAN_CHARS:
            chunk = data[: _MAX_SCAN_CHARS - self._text_len]
            self.text_parts.append(chunk)
            self._text_len += len(chunk)

    def _close_anchor(self) -> None:
        href, parts, _ = self._anchors.pop()
        if href is not None:
            display = " ".join("".join(parts).split())[:MAX_DISPLAY_LEN] or None
            self._add(href, display)

    # -- eventos
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a: dict[str, str] = {}
        for k, v in attrs:
            if v is not None and k not in a:  # como los navegadores: gana el primer atributo repetido
                a[k] = v
        if tag == "a":
            if self._anchors:  # <a> anidado: el navegador cierra el anterior
                self._close_anchor()
            self._anchors.append((a.get("href") or a.get("xlink:href"), [], 0))
            return
        if tag == "base":
            if self.base is None and a.get("href"):
                self.base = a["href"].strip()
            return
        if tag == "meta":
            if a.get("http-equiv", "").strip().lower() == "refresh":
                m = _META_URL_RE.search(a.get("content", ""))
                if m:
                    self._add(m.group(1).strip())
            return
        if tag == "form":
            self._add(a.get("action"))
            return
        if tag == "object":
            self._add(a.get("data"))
            self._add(a.get("codebase"))
            return
        if tag in _SRC_TAGS:
            self._add(a.get("src"), img=tag in ("img", "input", "image"))
        if tag in ("button", "input"):
            self._add(a.get("formaction"))
        for key in ("href", "xlink:href"):
            if key in a:
                self._add(a[key])
        if "background" in a:
            self._add(a["background"], img=True)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":  # <a href="..."/>: link sin texto
            for k, v in attrs:
                if k in ("href", "xlink:href") and v:
                    self._add(v, None)
                    break
            return
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._anchors:
            self._close_anchor()

    def handle_data(self, data: str) -> None:
        if self._anchors:
            # el texto visible de un link queda como display_text; no es una URL "suelta"
            href, parts, n = self._anchors[-1]
            if n < MAX_DISPLAY_LEN * 4:
                parts.append(data[: MAX_DISPLAY_LEN * 4])
                self._anchors[-1] = (href, parts, n + len(data))
            if href is not None:
                return
        self._keep_text(data)

    def handle_comment(self, data: str) -> None:
        self._keep_text(data)  # comentarios condicionales de Outlook (<!--[if mso]> VML con href)

    def finish(self) -> None:
        while self._anchors:
            self._close_anchor()


def extract_urls_html(html: str, source: str = "body_html") -> list[ExtractedUrl]:
    """URLs de un documento HTML/SVG, con el texto visible de cada <a>."""
    if not html:
        return []
    parser = _LinkParser()
    try:
        parser.feed(html[:MAX_INPUT_CHARS])
        parser.close()
    except Exception:  # noqa: BLE001 - HTML hostil: nos quedamos con lo que se alcanzó a leer
        log.debug("html.parser falló; se usan resultados parciales", exc_info=True)
    with contextlib.suppress(Exception):
        parser.finish()

    base = None
    if parser.base:
        base = normalize_url(parser.base)
    out: list[ExtractedUrl] = []
    seen_pairs: set[tuple[str, str | None]] = set()
    seen_urls: set[str] = set()
    for raw, display in parser.found:
        url = normalize_url(raw, base)
        if not url or (url, display) in seen_pairs:
            continue
        seen_pairs.add((url, display))
        seen_urls.add(url)
        out.append(ExtractedUrl(url=url, source=source, display_text=display))
        if len(out) >= MAX_URLS:
            return out
    for raw in _scan_text("".join(parser.text_parts)):
        url = normalize_url(raw)
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)
        out.append(ExtractedUrl(url=url, source=source))
        if len(out) >= MAX_URLS:
            break
    return out
