"""Analizador de HTML, SVG y HTA adjuntos.

Los adjuntos HTML/SVG son hoy uno de los vectores de phishing más usados porque se abren localmente
(file://) y esquivan los filtros de URLs del proveedor de correo. Se buscan:

- HTML smuggling: la página arma un archivo (Blob/atob/Uint8Array/msSaveOrOpenBlob/createObjectURL)
  y lo descarga sola. Se DECODIFICA el blob (acotado) y se mira su tipo real: .exe/.zip/.7z/.iso => HIGH 85;
- páginas de login falsas: formulario con contraseña que envía a un servidor externo (o JS que la manda
  con fetch/XMLHttpRequest/Telegram), marcas imitadas (Microsoft 365, AFIP/ARCA, bancos, Mercado Pago...)
  y mail de la víctima precargado => PHISHING HIGH 70+;
- redirecciones (meta refresh / window.location) a sitios externos => MEDIUM;
- JavaScript ofuscado (eval(atob(...)), document.write(unescape(...)), fromCharCode, packers...);
- SVG con <script>, <foreignObject> con HTML o links javascript:/data: (tendencia 2024-2025) => HIGH 70;
- ClickFix: página que copia un comando de PowerShell/mshta al portapapeles y pide pegarlo en Ejecutar;
- .hta (HTML con permisos completos de Windows) => HIGH 70 + indicadores de scripts.

Las capas codificadas (atob/unescape/fromCharCode/escapes \\xNN) se decodifican y se vuelven a analizar
como HTML o JS, con profundidad y tamaño acotados. Nada se ejecuta: es solo lectura de texto.
"""

from __future__ import annotations

import asyncio
import logging
import re
import urllib.parse
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import TYPE_CHECKING, ClassVar

from centinela.analyzers import _indicators as ind
from centinela.analyzers.base import ArtifactAnalyzer
from centinela.core.models import Finding, FindingCategory, Severity

if TYPE_CHECKING:
    from centinela.analyzers.base import AnalysisContext
    from centinela.core.models import Artifact

log = logging.getLogger(__name__)

MAX_HTML_BYTES = 32 * 1024 * 1024
MAX_PARSE_CHARS = 8 * 1024 * 1024  # html.parser en Python < 3.13.4 tiene casos cuadráticos: no le damos más
MAX_SCRIPT_CHARS = 16 * 1024 * 1024
MAX_VISIBLE_CHARS = 512 * 1024
MAX_TAGS = 200_000
MAX_LIST = 2000
MAX_LAYERS = 12
MAX_DEPTH = 3
MAX_DECODED_CHARS = 8 * 1024 * 1024
SMUGGLING_MIN_B64 = 1000
MAX_PAYLOAD_CANDIDATES = 32

_SVG_ROOT_RE = re.compile(
    r"^\s*(?:<\?xml[^>]{0,500}\?>\s*)?(?:<!--.{0,4000}?-->\s*|<!DOCTYPE[^>]{0,4000}>\s*){0,20}<(?:[\w-]{1,30}:)?svg[\s>/]",
    re.IGNORECASE | re.DOTALL,
)
_HTML_TAG_RE = re.compile(
    r"<\s*(?:html|head|body|form|input|div|script|iframe|meta|a|img|table|span|p|svg|style|link|title|button)\b",
    re.IGNORECASE,
)

# ------------------------------------------------------------------ patrones JS
_SINK_RE = re.compile(
    r"\bnew\s+Blob\s*\(|\bURL\.createObjectURL\s*\(|\bmsSaveOrOpenBlob\s*\(|\bmsSaveBlob\s*\(|\bsaveAs\s*\(|\bnew\s+File\s*\(\s*\[",
    re.IGNORECASE,
)
_TRIGGER_RE = re.compile(
    r"\.download\s*=|setAttribute\s*\(\s*[\"']download[\"']|\.click\s*\(\s*\)|dispatchEvent\s*\(\s*new\s+MouseEvent"
    r"|\bmsSaveOrOpenBlob\s*\(|\bmsSaveBlob\s*\(|\bsaveAs\s*\(",
    re.IGNORECASE,
)
_DATA_PRIM_RE = re.compile(
    r"\batob\s*\(|\bnew\s+Uint8Array\s*\(|\bUint8Array\.from\s*\(|\bcharCodeAt\s*\(|\bfromCharCode\b|\.arrayBuffer\s*\(\s*\)",
    re.IGNORECASE,
)
# Prefijos de llamadas cuyo primer argumento literal se decodifica. El literal se extrae a mano
# (`_string_literal`) para que un archivo hostil sin comillas de cierre no provoque escaneos cuadráticos.
_ATOB_PREFIX_RE = re.compile(r"\batob\s*\(\s*([\"'`])", re.IGNORECASE)
_UNESCAPE_PREFIX_RE = re.compile(
    r"\b(?:unescape|decodeURIComponent|decodeURI)\s*\(\s*([\"'`])", re.IGNORECASE
)
_HTML_SINK_PREFIX_RE = re.compile(
    r"(?:\bdocument\.write(?:ln)?\s*\(|\.(?:innerHTML|outerHTML)\s*=|\.insertAdjacentHTML\s*\([^,()]{0,40},)\s*([\"'`])",
    re.IGNORECASE,
)
MAX_LITERAL_CHARS = 4 * 1024 * 1024
MAX_LITERALS = 32
_STRONG_OBF_RE = re.compile(
    r"\beval\s*\(\s*(?:window\.)?(?:atob|unescape|decodeURIComponent|String\.fromCharCode|escape)\s*\("
    r"|\bdocument\.write(?:ln)?\s*\(\s*(?:window\.)?(?:unescape|atob|decodeURIComponent|String\.fromCharCode)\s*\("
    r"|\beval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)"
    r"|\bnew\s+Function\s*\(\s*(?:atob|unescape|decodeURIComponent)\s*\("
    r"|(?:window|self|this|globalThis|top)\s*\[\s*[\"'](?:\\x[0-9a-f]{2}){2,}",
    re.IGNORECASE,
)
_NETWORK_RE = re.compile(
    r"\bXMLHttpRequest\b|\bfetch\s*\(|\$\.(?:ajax|post|get|getJSON)\s*\(|\bnavigator\.sendBeacon\s*\(|\baxios\b"
    r"|\.open\s*\(\s*[\"']POST[\"']|\bnew\s+Image\s*\(\s*\)\s*\.src\s*=",
    re.IGNORECASE,
)
_JS_PASSWORD_RE = re.compile(
    r"type\s*[=:]\s*\\?[\"']?password\b|\.type\s*=\s*[\"']password[\"']|getElementById\s*\(\s*[\"'](?:pass|pwd|password|passwd|contrase)",
    re.IGNORECASE,
)
_EXFIL_SERVICES_RE = re.compile(
    r"api\.telegram\.org/bot|discord(?:app)?\.com/api/webhooks|formspree\.io|formsubmit\.co|getform\.io|submit-form\.com"
    r"|usebasin\.com|web3forms\.com|api\.emailjs\.com|script\.google\.com/macros/s/|webhook\.site|pipedream\.net",
    re.IGNORECASE,
)
_GEO_RE = re.compile(
    r"ip-api\.com|ipapi\.co|ipinfo\.io|api\.ipify\.org|geoplugin\.net|ipwho\.is|ipdata\.co|extreme-ip-lookup\.com|db-ip\.com",
    re.IGNORECASE,
)
_JS_REDIRECT_RE = re.compile(
    r"(?:\b(?:window|document|top|self|parent)\.)?\blocation(?:\.href)?\s*=\s*([\"'])((?:https?:)?//[^\"'\s]{3,500})\1"
    r"|\blocation\.(?:replace|assign)\s*\(\s*([\"'])((?:https?:)?//[^\"'\s]{3,500})\3"
    r"|\bwindow\.open\s*\(\s*([\"'])(https?://[^\"'\s]{3,500})\5",
    re.IGNORECASE,
)
_JS_REDIRECT_DYN_RE = re.compile(
    r"\blocation(?:\.href)?\s*=\s*(?:window\.)?(?:atob|unescape|decodeURIComponent|String\.fromCharCode)\s*\(",
    re.IGNORECASE,
)
_META_REFRESH_URL_RE = re.compile(r"url\s*=\s*['\"]?([^'\"\s>]{1,2000})", re.IGNORECASE)
_URL_LITERAL_RE = re.compile(
    r"[\"'`]((?:https?:)?//[A-Za-z0-9.\-]{3,253}(?::\d{1,5})?(?:/[^\"'`\s]{0,500})?)[\"'`]"
)
_CLIPBOARD_RE = re.compile(
    r"\bnavigator\.clipboard\.writeText\s*\(|\bdocument\.execCommand\s*\(\s*[\"']copy[\"']|\bclipboardData\.setData\s*\(",
    re.IGNORECASE,
)
_CLICKFIX_TEXT_RE = re.compile(
    r"\b(?:win(?:dows)?\s*(?:key\s*)?\+\s*r|ctrl\s*\+\s*v|windows\s*\+\s*x|verify\s+you\s+are\s+human|i'?m\s+not\s+a\s+robot"
    r"|no\s+soy\s+un\s+robot|verificaci[oó]n\s+humana|presion[ea]\s+win|pulse\s+win)",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63}){0,8}\.[A-Za-z]{2,24}\b"
)
_JOIN_ARRAY_RE = re.compile(r"[\"']\s*,\s*[\"']")

_BRANDS_CI = (
    "Microsoft 365",
    "Microsoft",
    "Office 365",
    "Office365",
    "Outlook",
    "OneDrive",
    "SharePoint",
    "Teams",
    "Excel Online",
    "Adobe",
    "Acrobat",
    "DocuSign",
    "Dropbox",
    "WeTransfer",
    "Webmail",
    "cPanel",
    "Roundcube",
    "Zimbra",
    "Gmail",
    "Google Drive",
    "Google Docs",
    "Mercado Pago",
    "MercadoPago",
    "Mercado Libre",
    "Banco",
    "Santander",
    "Galicia",
    "Banco Nación",
    "Itaú",
    "Bancolombia",
    "Banorte",
    "Interbank",
    "PayPal",
    "Apple ID",
    "iCloud",
    "Netflix",
    "DHL",
    "FedEx",
    "Correo Argentino",
    "Andreani",
    "Brubank",
    "Ualá",
    "Naranja X",
)
_BRANDS_CS = ("AFIP", "ARCA", "SAT", "DIAN", "SUNAT", "SII", "OCA", "BBVA", "ANSES", "ARBA", "AGIP")
_BRAND_CI_RE = re.compile(r"\b(" + "|".join(re.escape(b) for b in _BRANDS_CI) + r")\b", re.IGNORECASE)
_BRAND_CS_RE = re.compile(r"\b(" + "|".join(_BRANDS_CS) + r")\b")

_CLICKFIX_KEYS = frozenset(
    {
        "ps_invoke",
        "ps_iex",
        "ps_iwr",
        "ps_encoded",
        "mshta_remote",
        "cmd_exec",
        "curl_url",
        "finger",
        "ps_downloadstring",
        "ps_webclient",
        "conhost_headless",
        "msiexec_remote",
        "rundll32_abuse",
        "regsvr32_squiblydoo",
        "certutil_download",
        "bitsadmin",
        "ps_hidden",
        "ps_bypass",
    }
)
_HTML_IN_FOREIGN = frozenset(
    {
        "html",
        "body",
        "div",
        "iframe",
        "form",
        "input",
        "script",
        "a",
        "span",
        "p",
        "img",
        "button",
        "embed",
        "object",
    }
)
# fallback AJAX de Internet Explorer (jQuery 1.x): no es Windows Script Host fuera de un .hta
_IE_AJAX_KEYS = frozenset({"com_activex", "com_xmlhttp"})
# cómo se obtuvo una capa: un literal escrito tal cual con innerHTML/document.write NO está codificado
_SINK_PLAIN = "document.write/innerHTML"
_SINK_ESCAPED = "document.write/innerHTML con escapes"
_RASTER_DATA = (
    "data:image/png",
    "data:image/jpeg",
    "data:image/jpg",
    "data:image/gif",
    "data:image/webp",
    "data:image/bmp",
)
_REF_ATTRS = frozenset({"href", "src", "xlink:href", "action", "formaction", "data", "background", "poster"})


@dataclass
class FormInfo:
    action: str
    method: str
    layer: int
    has_password: bool = False
    has_email_field: bool = False


@dataclass
class HtmlFacts:
    root_tag: str | None = None
    forms: list[FormInfo] = field(default_factory=list)
    password_inputs: int = 0
    input_values: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    script_chars: int = 0
    script_srcs: list[str] = field(default_factory=list)
    event_handlers: list[str] = field(default_factory=list)
    js_urls: list[str] = field(default_factory=list)
    refs: list[tuple[str, str, str, bool]] = field(
        default_factory=list
    )  # (tag, atributo, valor, tiene download)
    meta_refresh: list[str] = field(default_factory=list)
    hta: bool = False
    svg_scripts: int = 0
    svg_foreign: int = 0
    svg_foreign_html: bool = False
    svg_handlers: int = 0
    svg_active_hrefs: int = 0
    visible: list[str] = field(default_factory=list)
    visible_chars: int = 0
    title: str = ""
    decoded: list[tuple[str, int]] = field(default_factory=list)  # (cómo, profundidad)
    decoded_strings: list[str] = field(default_factory=list)
    decoded_chars: int = 0
    tags: int = 0
    truncated: bool = False

    def corpus(self) -> str:
        parts = self.scripts + self.event_handlers + self.js_urls
        return "\n".join(parts)[:MAX_SCRIPT_CHARS]

    def visible_text(self) -> str:
        return " ".join(self.visible)


class _Collector(HTMLParser):
    """Recolector tolerante: junta formularios, scripts, links y texto visible (con topes)."""

    def __init__(self, facts: HtmlFacts, layer: int) -> None:
        super().__init__(convert_charrefs=True)
        self.f = facts
        self.layer = layer
        self._script: list[str] | None = None
        self._script_len = 0
        self._forms: list[FormInfo] = []
        self._svg = 0
        self._foreign = 0
        self._in_title = False
        self._in_style = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        f = self.f
        f.tags += 1
        if f.tags > MAX_TAGS:
            f.truncated = True
            return
        local = tag.rsplit(":", 1)[-1]
        if f.root_tag is None and self.layer == 0:
            f.root_tag = local
        a: dict[str, str] = {}
        for k, v in attrs:
            if k not in a:
                a[k] = v or ""
        if local == "svg":
            self._svg += 1
        if tag == "hta:application":
            f.hta = True
        if local == "script":
            self._script = []
            self._script_len = 0
            if a.get("src") and len(f.script_srcs) < MAX_LIST:
                f.script_srcs.append(a["src"][:2000])
            if self._svg:
                f.svg_scripts += 1
        elif local == "style":
            self._in_style += 1
        elif local == "title":
            self._in_title = True
        elif local == "form":
            form = FormInfo(
                action=a.get("action", "").strip(), method=a.get("method", "get").lower(), layer=self.layer
            )
            if len(f.forms) < MAX_LIST:
                f.forms.append(form)
            self._forms.append(form)
        elif local in ("input", "button"):
            typ = a.get("type", "text").strip().lower()
            form = self._forms[-1] if self._forms else None
            if typ == "password":
                f.password_inputs += 1
                if form:
                    form.has_password = True
            hint = " ".join(
                (a.get("name", ""), a.get("id", ""), a.get("placeholder", ""), a.get("autocomplete", ""))
            ).lower()
            if form and (
                typ == "email" or "mail" in hint or "correo" in hint or "usuario" in hint or "user" in hint
            ):
                form.has_email_field = True
            if a.get("formaction") and form is not None and not form.action:
                form.action = a["formaction"].strip()
            val = a.get("value", "")
            if val and len(f.input_values) < 500:
                f.input_values.append(val[:2000])
        elif local == "meta" and a.get("http-equiv", "").strip().lower() == "refresh":
            m = _META_REFRESH_URL_RE.search(a.get("content", ""))
            if m and len(f.meta_refresh) < 50:
                f.meta_refresh.append(m.group(1))
        elif local == "foreignobject":
            self._foreign += 1
            if self._svg:
                f.svg_foreign += 1
        elif self._foreign and local in _HTML_IN_FOREIGN:
            f.svg_foreign_html = True

        has_download = "download" in a
        for k, v in a.items():
            if k.startswith("on") and v:
                if f.script_chars < MAX_SCRIPT_CHARS and len(f.event_handlers) < MAX_LIST:
                    f.event_handlers.append(v[:100_000])
                    f.script_chars += min(len(v), 100_000)
                if self._svg:
                    f.svg_handlers += 1
            elif k in _REF_ATTRS and v:
                low = v.lstrip()[:40].lower()
                if len(f.refs) < MAX_LIST:
                    f.refs.append((local, k, v, has_download))
                if low.startswith("javascript:"):
                    if len(f.js_urls) < MAX_LIST:
                        f.js_urls.append(urllib.parse.unquote(v.lstrip()[11:100_000]))
                    if self._svg:
                        f.svg_active_hrefs += 1
                elif (
                    low.startswith("data:")
                    and self._svg
                    and not low.startswith(_RASTER_DATA)
                    and local != "image"
                ):
                    f.svg_active_hrefs += 1

    def handle_endtag(self, tag: str) -> None:
        local = tag.rsplit(":", 1)[-1]
        if local == "script" and self._script is not None:
            text = "".join(self._script)
            if text.strip() and len(self.f.scripts) < MAX_LIST:
                self.f.scripts.append(text)
            self._script = None
        elif local == "style" and self._in_style:
            self._in_style -= 1
        elif local == "title":
            self._in_title = False
        elif local == "form" and self._forms:
            self._forms.pop()
        elif local == "svg" and self._svg:
            self._svg -= 1
        elif local == "foreignobject" and self._foreign:
            self._foreign -= 1

    def handle_data(self, data: str) -> None:
        f = self.f
        if self._script is not None:
            room = MAX_SCRIPT_CHARS - f.script_chars
            if room <= 0:
                f.truncated = True
                return
            chunk = data[:room]
            self._script.append(chunk)
            f.script_chars += len(chunk)
            return
        if self._in_style:
            return
        if self._in_title:
            f.title = (f.title + data)[:500]
            return
        if f.visible_chars < MAX_VISIBLE_CHARS and data.strip():
            chunk = data[: MAX_VISIBLE_CHARS - f.visible_chars]
            f.visible.append(chunk)
            f.visible_chars += len(chunk)


def _parse_into(facts: HtmlFacts, text: str, layer: int) -> None:
    if len(text) > MAX_PARSE_CHARS:
        facts.truncated = True
    col = _Collector(facts, layer)
    try:
        col.feed(text[:MAX_PARSE_CHARS])
        col.close()
    except Exception as exc:  # noqa: BLE001 - HTML hostil: lo que se juntó hasta acá sirve igual
        log.debug("HTMLParser falló en la capa %d: %s", layer, type(exc).__name__)
        facts.truncated = True
    if col._script is not None:  # <script> sin cerrar
        text_ = "".join(col._script)
        if text_.strip():
            facts.scripts.append(text_)


def _string_literal(js: str, start: int, quote: str) -> str | None:
    """Contenido de un literal JS que empieza en `start` (tras la comilla), respetando escapes. Acotado."""
    limit = min(len(js), start + MAX_LITERAL_CHARS)
    pos = start
    while pos < limit:
        end = js.find(quote, pos, limit)
        if end < 0:
            return None
        backslashes = 0
        k = end - 1
        while k >= start and js[k] == "\\":
            backslashes += 1
            k -= 1
        if backslashes % 2 == 0:
            return js[start:end]
        pos = end + 1
    return None


def _literals(js: str, prefix_re: re.Pattern[str]) -> list[str]:
    out: list[str] = []
    for m in prefix_re.finditer(js):
        lit = _string_literal(js, m.end(), m.group(1))
        if lit is not None:
            out.append(lit)
        if len(out) >= MAX_LITERALS:
            break
    return out


def _unquote_js(lit: str) -> str:
    if "\\x" in lit or "\\u" in lit:
        lit = ind.unescape_js(lit)
    return lit.replace("\\'", "'").replace('\\"', '"').replace("\\/", "/").replace("\\n", "\n")


def _decoded_strings_from_js(js: str) -> list[tuple[str, str]]:
    """[(cómo, texto)] decodificados de atob/unescape/fromCharCode/escapes y strings que se escriben como HTML."""
    out: list[tuple[str, str]] = []
    for lit in _literals(js, _ATOB_PREFIX_RE):
        raw = ind.b64_decode(lit, 4 * 1024 * 1024)
        txt = ind.bytes_to_text(raw) if raw else None
        if txt:
            out.append(("atob", txt))
    for lit in _literals(js, _UNESCAPE_PREFIX_RE):
        decoded = urllib.parse.unquote(_unquote_js(lit))
        if decoded != lit:  # sin %XX ni \xNN no se decodificó nada
            out.append(("unescape", decoded))
    for txt in ind.charcode_texts(js):
        out.append(("String.fromCharCode", txt))
        if len(out) > 64:
            break
    for lit in _literals(js, _HTML_SINK_PREFIX_RE):
        if len(lit) >= 20:
            how = _SINK_ESCAPED if ("\\x" in lit or "\\u" in lit) else _SINK_PLAIN
            out.append((how, _unquote_js(lit)))
    if len(ind.JS_ESCAPE_RE.findall(js[:200_000])) >= 30:
        out.append(("escapes \\xNN", ind.unescape_js(js)))
    return out


def _analyze_layers(text: str) -> HtmlFacts:
    facts = HtmlFacts()
    queue: list[tuple[str, int, str, str]] = [(text, 0, "original", "html")]
    seen: set[int] = set()
    processed = 0
    while queue and processed < MAX_LAYERS:
        content, depth, how, kind = queue.pop(0)
        processed += 1
        n_scripts, n_handlers, n_js = len(facts.scripts), len(facts.event_handlers), len(facts.js_urls)
        if kind == "html":
            _parse_into(facts, content, depth)
            new_js = "\n".join(
                facts.scripts[n_scripts:] + facts.event_handlers[n_handlers:] + facts.js_urls[n_js:]
            )
        else:
            new_js = content
        if depth >= MAX_DEPTH or not new_js:
            continue
        for dhow, decoded in _decoded_strings_from_js(new_js[:MAX_SCRIPT_CHARS]):
            if not decoded or len(decoded) < 4:
                continue
            h = hash(decoded)
            if h in seen:
                continue
            seen.add(h)
            if facts.decoded_chars + len(decoded) > MAX_DECODED_CHARS:
                facts.truncated = True
                break
            facts.decoded_chars += len(decoded)
            if len(facts.decoded_strings) < 200:
                facts.decoded_strings.append(decoded[:4000])
            if _HTML_TAG_RE.search(decoded[:100_000]):
                facts.decoded.append((dhow, depth + 1))
                queue.append((decoded, depth + 1, dhow, "html"))
            elif len(decoded) >= 20 and ind.printable_ratio(decoded[:4096]) >= 0.9:
                facts.decoded.append((dhow, depth + 1))
                facts.scripts.append(decoded)
                queue.append((decoded, depth + 1, dhow, "js"))
    return facts


def _is_external(url: str) -> bool:
    u = url.strip().lower()
    return u.startswith(("http://", "https://", "//", "ftp://"))


def _host(url: str) -> str:
    u = url.strip()
    if u.startswith("//"):
        u = "http:" + u
    try:
        host = urllib.parse.urlsplit(u).hostname or ""
    except ValueError:
        host = ""
    return host.replace(".", "[.]")


def _mask_email(email: str) -> str:
    local, _, domain = email.partition("@")
    return f"{local[:1]}***@{domain}"


@dataclass(slots=True)
class _Payload:
    kind: str
    how: str
    size: int
    source: str


class HtmlAnalyzer(ArtifactAnalyzer):
    name: ClassVar[str] = "html"

    def accepts(self, artifact: Artifact) -> bool:
        t = artifact.detected_type or ""
        if t in ("html", "svg", "script/hta"):
            return True
        if t == "xml":
            head, _ = ind.decode_text((artifact.data or b"")[:8192], 8192)
            return bool(_SVG_ROOT_RE.match(head))
        return False

    async def analyze(self, ctx: AnalysisContext, artifact: Artifact) -> list[Finding]:
        recipients = {a.lower() for a in (ctx.message.to + ctx.message.cc) if a}
        return await asyncio.to_thread(self._analyze_sync, artifact, recipients)

    # ------------------------------------------------------------------ síncrono (en thread)
    def _analyze_sync(self, artifact: Artifact, recipients: set[str]) -> list[Finding]:
        data = artifact.data or b""
        text, truncated = ind.decode_text(data, MAX_HTML_BYTES)
        declared_hta = artifact.detected_type == "script/hta" or artifact.extension == "hta"
        if not text.strip():
            if declared_hta:
                # .hta vacío o no extraído (listing_only, cifrado): el tipo en sí ya es la señal
                f = self._hta(artifact, HtmlFacts())
                f.evidence["nota"] = (
                    "no se pudo leer el contenido (posiblemente excede los límites o está cifrado)"
                )
                return [f]
            return []
        facts = _analyze_layers(text)
        facts.truncated = facts.truncated or truncated
        corpus = facts.corpus()
        is_hta = declared_hta or facts.hta
        is_svg = artifact.detected_type in ("svg", "xml") or facts.root_tag == "svg"
        where = "aplicación HTML (.hta)" if is_hta else "imagen SVG" if is_svg else "archivo HTML"

        findings: list[Finding] = []
        add = findings.append
        if is_hta:
            add(self._hta(artifact, facts))
        if is_svg:
            f = self._svg(artifact, facts)
            if f:
                add(f)
        findings.extend(self._smuggling(artifact, facts, text, corpus))
        findings.extend(self._phishing(artifact, facts, text, corpus, recipients))
        f = self._redirect(artifact, facts, corpus)
        if f:
            add(f)
        f = self._obfuscation(artifact, facts, corpus)
        if f:
            add(f)

        # indicadores de scripts sobre el JS (y valores de inputs, donde ClickFix a veces esconde el comando)
        clipboard = bool(_CLIPBOARD_RE.search(corpus))
        scan_src = "\n".join([corpus, *facts.input_values[:200]])
        if clipboard:
            scan_src += "\n" + facts.visible_text()
        if scan_src.strip():
            result = ind.scan_text(
                scan_src,
                profile="script" if is_hta else "html",
                assume=("wsh",) if is_hta else (),
                max_depth=2,
            )
            scan_findings = ind.findings_from_scan(
                result, analyzer=self.name, prefix="html", artifact_id=artifact.id, where=where
            )
            # la ofuscación del HTML se evalúa con métricas propias (html.obfuscated_script) y los payloads
            # embebidos ya los reporta el análisis de smuggling: no contar dos veces la misma evidencia
            skip = {"html.obfuscation"}
            if any(x.rule in ("html.smuggling_payload", "html.embedded_payload") for x in findings):
                skip.add("html.embedded_pe")
            if not is_hta and {k for k in result.hits if k.startswith("com_")} <= _IE_AJAX_KEYS:
                skip.add("html.com_objects")
            findings.extend(x for x in scan_findings if x.rule not in skip)
            if clipboard:
                cmd_hits = [
                    h
                    for h in result.hits.values()
                    if h.key in _CLICKFIX_KEYS
                    or h.group in ("lolbin", "powershell_encoded", "powershell_stealth")
                ]
                if cmd_hits:
                    add(self._clickfix(artifact, facts, cmd_hits))
        if facts.truncated:
            for fnd in findings:
                fnd.evidence.setdefault("nota", "archivo muy grande o complejo: se revisó solo una parte")
        return findings

    # ------------------------------------------------------------------ HTA / SVG
    def _hta(self, artifact: Artifact, facts: HtmlFacts) -> Finding:
        return Finding(
            analyzer=self.name,
            rule="html.hta",
            title="Aplicación HTML (.hta) adjunta",
            description=(
                "Un archivo .hta parece una página web, pero Windows lo ejecuta como un programa con permisos "
                "completos sobre la computadora (puede descargar e instalar cualquier cosa). No hay motivo comercial "
                "para recibirlo por mail."
            ),
            category=FindingCategory.SUSPICIOUS_FILE,
            severity=Severity.HIGH,
            score=70,
            artifact_id=artifact.id,
            evidence={"scripts": len(facts.scripts), "etiqueta_hta": facts.hta},
        )

    def _svg(self, artifact: Artifact, facts: HtmlFacts) -> Finding | None:
        reasons = []
        if facts.svg_scripts:
            reasons.append(f"{facts.svg_scripts} bloque(s) <script>")
        if facts.svg_foreign_html:
            reasons.append("<foreignObject> con HTML embebido")
        if facts.svg_handlers:
            reasons.append(f"{facts.svg_handlers} atributo(s) de evento (onload, onclick…)")
        if facts.svg_active_hrefs:
            reasons.append("links javascript:/data: activos")
        if not reasons:
            return None
        return Finding(
            analyzer=self.name,
            rule="html.svg_active_content",
            title="Imagen SVG con código ejecutable",
            description=(
                "Este archivo se presenta como una imagen (SVG), pero contiene código o páginas web embebidas. Una "
                "imagen real no necesita nada de eso: es una técnica muy usada en 2024-2025 para colar páginas de "
                "phishing o descargas maliciosas que se abren en el navegador."
            ),
            category=FindingCategory.SUSPICIOUS_FILE,
            severity=Severity.HIGH,
            score=70,
            artifact_id=artifact.id,
            evidence={"senales": reasons},
        )

    # ------------------------------------------------------------------ smuggling
    def _payload_candidates(
        self, facts: HtmlFacts, text: str, corpus: str
    ) -> tuple[list[_Payload], bool, bool]:
        """Busca y decodifica payloads. Devuelve (payloads peligrosos, hay datos codificados, smuggling por data: URI)."""
        payloads: list[_Payload] = []
        has_encoded = False
        data_uri_smuggling = False
        probes = 0

        def probe(raw: bytes | None, how: str, source: str) -> None:
            nonlocal probes
            probes += 1
            if not raw:
                return
            kind = ind.sniff_magic(raw)
            if kind == "gzip":
                inflated = ind.inflate(raw[: 4 * 1024 * 1024], gzip=True)
                if inflated:
                    kind = ind.sniff_magic(inflated[: ind.ISO_PROBE_BYTES])
                    how = f"gzip+{how}"
            if kind in ind.DANGEROUS_PAYLOADS and kind != "gzip" and len(payloads) < 8:
                payloads.append(_Payload(kind=kind, how=how, size=len(raw), source=source))

        # 1) data: URIs
        for tag, attr, value, has_dl in facts.refs:
            v = value.strip()
            if v[:5].lower() != "data:":
                continue
            header, _, payload = v.partition(",")
            mime = header[5:].split(";", 1)[0].strip().lower()
            if mime.startswith("image/") and mime != "image/svg+xml":
                continue
            raw = (
                ind.b64_decode(payload, ind.ISO_PROBE_BYTES)
                if ";base64" in header.lower()
                else urllib.parse.unquote_to_bytes(payload[: ind.ISO_PROBE_BYTES * 3])
            )
            if len(payload) >= 100 and (
                has_dl or (tag in ("a", "iframe", "embed", "object") and mime.startswith("application/"))
            ):
                data_uri_smuggling = True
                has_encoded = True
            probe(raw, "data: URI", f"<{tag} {attr}>")
            if probes >= MAX_PAYLOAD_CANDIDATES:
                break

        # 2) base64 grandes en el JS (con arreglos/concatenaciones unidos) y en todo el documento
        joined = _JOIN_ARRAY_RE.sub("", ind.normalize(corpus)) if corpus else ""
        seen: set[str] = set()
        for source, hay in (("script", joined), ("documento", text)):
            for m in ind.iter_base64_runs(hay, SMUGGLING_MIN_B64, limit=MAX_PAYLOAD_CANDIDATES):
                blob = m.group(0)
                key = blob[:64]
                if key in seen:
                    continue
                seen.add(key)
                head = ind.b64_decode(blob[:64], 48) or b""
                if head[:4] in (b"\x89PNG", b"GIF8") or head[:3] == b"\xff\xd8\xff" or head[:4] == b"RIFF":
                    continue  # imagen embebida
                if source == "script":
                    has_encoded = True
                probe(ind.b64_decode(blob, ind.ISO_PROBE_BYTES), "base64", source)
                probe(ind.b64_decode(blob[::-1].lstrip("="), ind.ISO_PROBE_BYTES), "base64 invertido", source)
                if probes >= MAX_PAYLOAD_CANDIDATES * 2:
                    break

        # 3) hex y arreglos de bytes en el JS
        for count, m in enumerate(ind.HEX_RUN_RE.finditer(joined)):
            if count >= 8:
                break
            if len(m.group(0)) >= SMUGGLING_MIN_B64:
                has_encoded = True
                try:
                    probe(bytes.fromhex(m.group(0)[: 2 * ind.ISO_PROBE_BYTES]), "hex", "script")
                except ValueError:
                    pass
        for count, m in enumerate(ind.BYTE_ARRAY_RE.finditer(joined)):
            if count >= 8:
                break
            vals = ind.parse_int_list(m.group(0), ind.ISO_PROBE_BYTES)
            if len(vals) >= 256 and all(0 <= v <= 255 for v in vals):
                has_encoded = True
                probe(bytes(vals), "arreglo de bytes", "script")
        return payloads, has_encoded, data_uri_smuggling

    def _smuggling(self, artifact: Artifact, facts: HtmlFacts, text: str, corpus: str) -> list[Finding]:
        sinks = sorted(
            {m.group(0).strip("( ").lower() for m in _SINK_RE.finditer(corpus[:MAX_SCRIPT_CHARS])}
        )[:6]
        triggers = sorted(
            {m.group(0).strip("( ").lower() for m in _TRIGGER_RE.finditer(corpus[:MAX_SCRIPT_CHARS])}
        )[:6]
        data_prims = bool(_DATA_PRIM_RE.search(corpus))
        js_smuggling = bool(sinks) and bool(triggers)
        payloads, has_encoded, data_uri_smuggling = self._payload_candidates(facts, text, corpus)
        technique = cap_tech = ind.cap_list(sinks + triggers, 6)
        if data_uri_smuggling:
            cap_tech = technique + ["link data: con descarga"]

        if payloads:
            evidence = {
                "contenido": ind.cap_list(ind.PAYLOAD_LABELS.get(p.kind, p.kind) for p in payloads),
                "codificacion": ind.cap_list(p.how for p in payloads),
                "tamano_decodificado_aprox": max(p.size for p in payloads),
            }
            if js_smuggling or data_uri_smuggling:
                evidence["tecnica"] = cap_tech
                return [
                    Finding(
                        analyzer=self.name,
                        rule="html.smuggling_payload",
                        title="La página arma y descarga un archivo peligroso (HTML smuggling)",
                        description=(
                            "Este archivo HTML trae escondido, codificado como texto, "
                            f"{ind.PAYLOAD_LABELS.get(payloads[0].kind, 'un archivo')} y al abrirlo lo arma y lo descarga "
                            "solo en la computadora. Así se esquivan los filtros del correo: es una técnica de "
                            "entrega de malware muy conocida."
                        ),
                        category=FindingCategory.SUSPICIOUS_FILE,
                        severity=Severity.HIGH,
                        score=85,
                        artifact_id=artifact.id,
                        evidence=evidence,
                    )
                ]
            return [
                Finding(
                    analyzer=self.name,
                    rule="html.embedded_payload",
                    title="El HTML esconde un archivo peligroso",
                    description=(
                        "Dentro de este archivo HTML hay "
                        f"{ind.PAYLOAD_LABELS.get(payloads[0].kind, 'un archivo')} codificado como texto. Un documento "
                        "web legítimo no necesita traer programas escondidos."
                    ),
                    category=FindingCategory.SUSPICIOUS_FILE,
                    severity=Severity.HIGH,
                    score=70,
                    artifact_id=artifact.id,
                    evidence=evidence,
                )
            ]
        if (js_smuggling and (has_encoded or data_prims)) or data_uri_smuggling:
            return [
                Finding(
                    analyzer=self.name,
                    rule="html.smuggling",
                    title="La página arma y descarga un archivo escondido (HTML smuggling)",
                    description=(
                        "Este archivo HTML contiene datos codificados que, al abrirlo, convierte en un archivo y lo "
                        "descarga automáticamente. No se pudo identificar qué archivo es (puede estar cifrado), pero "
                        "la técnica en sí es típica de la entrega de malware."
                    ),
                    category=FindingCategory.SUSPICIOUS_FILE,
                    severity=Severity.HIGH,
                    score=65,
                    artifact_id=artifact.id,
                    evidence={"tecnica": cap_tech, "datos_codificados": has_encoded},
                )
            ]
        if js_smuggling:
            return [
                Finding(
                    analyzer=self.name,
                    rule="html.download_trigger",
                    title="La página genera una descarga automática",
                    description=(
                        "Este archivo HTML crea un archivo en el navegador y lo descarga sin que lo pidas. Puede ser "
                        "legítimo (una exportación), pero en un adjunto de mail conviene desconfiar."
                    ),
                    category=FindingCategory.SUSPICIOUS_FILE,
                    severity=Severity.MEDIUM,
                    score=35,
                    artifact_id=artifact.id,
                    evidence={"tecnica": technique},
                )
            ]
        return []

    # ------------------------------------------------------------------ phishing
    def _phishing(
        self, artifact: Artifact, facts: HtmlFacts, text: str, corpus: str, recipients: set[str]
    ) -> list[Finding]:
        js_password = bool(_JS_PASSWORD_RE.search(corpus)) or any(
            _JS_PASSWORD_RE.search(s) for s in facts.decoded_strings[:200]
        )
        has_password = facts.password_inputs > 0 or js_password
        decoded_blob = "\n".join(facts.decoded_strings)
        hay = "\n".join((corpus[: 4 * 1024 * 1024], decoded_blob, text[: 4 * 1024 * 1024]))
        services = ind.cap_list(m.group(0).lower() for m in _EXFIL_SERVICES_RE.finditer(hay))
        geo = ind.cap_list(m.group(0).lower() for m in _GEO_RE.finditer(hay))

        external_actions = [
            fm.action for fm in facts.forms if _is_external(fm.action) and (fm.has_password or js_password)
        ]
        network = bool(_NETWORK_RE.search(corpus))
        external_literals = [
            m.group(1)
            for m in _URL_LITERAL_RE.finditer(corpus[: 4 * 1024 * 1024])
            if _is_external(m.group(1))
        ][:50]
        js_exfil = network and (
            bool(external_literals) or bool(services) or bool(re.search(r"https?://", decoded_blob))
        )

        brand_src = " ".join((facts.title, facts.visible_text()[:200_000], decoded_blob[:200_000]))
        brands = ind.cap_list(
            [m.group(1) for m in _BRAND_CI_RE.finditer(brand_src)]
            + [m.group(1) for m in _BRAND_CS_RE.finditer(brand_src)],
            5,
        )

        emails_src = facts.input_values[:500] + facts.decoded_strings[:200]
        found_emails: list[str] = []
        for s in emails_src:
            found_emails.extend(m.group(0).lower() for m in _EMAIL_RE.finditer(s[:20_000]))
        for m in _EMAIL_RE.finditer(corpus[: 1024 * 1024]):
            found_emails.append(m.group(0).lower())
            if len(found_emails) > 200:
                break
        victim = [e for e in found_emails if e in recipients]
        prefilled_input = any(_EMAIL_RE.search(v) for v in facts.input_values[:500])

        findings: list[Finding] = []
        destinations = ind.cap_list(
            [_host(u) or ind.clean_snippet(u, 60) for u in external_actions + external_literals[:5]]
            + services,
            6,
        )
        if has_password and (external_actions or js_exfil or services):
            score = 70
            reasons = []
            if external_actions:
                reasons.append("el formulario envía los datos a un servidor externo")
            if js_exfil:
                reasons.append("un script envía los datos por Internet")
            if services:
                reasons.append(
                    "usa servicios de terceros para recibir las contraseñas (Telegram, webhooks, formularios)"
                )
                score += 5
            if brands:
                score += 5
            if victim or prefilled_input:
                score += 5
            evidence: dict = {"motivos": reasons, "destinos": destinations}
            if brands:
                evidence["marcas_imitadas"] = brands
            if victim:
                evidence["mail_precargado"] = ind.cap_list(_mask_email(e) for e in victim)
            elif prefilled_input:
                evidence["mail_precargado"] = "sí (de otra dirección)"
            if geo:
                evidence["geolocaliza_a_la_victima"] = geo
            brand_txt = f" (imita a {', '.join(brands[:2])})" if brands else ""
            findings.append(
                Finding(
                    analyzer=self.name,
                    rule="html.credential_phishing",
                    title=f"Página falsa para robar contraseñas{brand_txt}",
                    description=(
                        "Este adjunto es una página de inicio de sesión falsa: pide usuario y contraseña y los manda "
                        "a un servidor del atacante. Ninguna empresa real te pide iniciar sesión desde un archivo "
                        "adjunto. Si alguien ya escribió su contraseña ahí, hay que cambiarla de inmediato."
                    ),
                    category=FindingCategory.PHISHING,
                    severity=Severity.HIGH,
                    score=min(score, 85),
                    artifact_id=artifact.id,
                    evidence=evidence,
                )
            )
        elif has_password:
            ev: dict = {"campos_de_contrasena": facts.password_inputs or "creados por script"}
            if brands:
                ev["marcas_imitadas"] = brands
            findings.append(
                Finding(
                    analyzer=self.name,
                    rule="html.password_form",
                    title="Formulario de contraseña dentro de un adjunto",
                    description=(
                        "Este archivo HTML pide una contraseña. Los servicios reales nunca piden iniciar sesión "
                        "desde un archivo adjunto: no escribas tus datos ahí."
                    ),
                    category=FindingCategory.PHISHING,
                    severity=Severity.MEDIUM,
                    score=45 if brands else 40,
                    artifact_id=artifact.id,
                    evidence=ev,
                )
            )
        elif services and network:
            findings.append(
                Finding(
                    analyzer=self.name,
                    rule="html.exfil_channel",
                    title="La página envía datos a un canal del atacante",
                    description=(
                        "Este archivo HTML manda información a servicios como bots de Telegram o webhooks, típicos "
                        "de los kits de phishing para recibir datos robados."
                    ),
                    category=FindingCategory.PHISHING,
                    severity=Severity.HIGH,
                    score=65,
                    artifact_id=artifact.id,
                    evidence={"destinos": services, **({"geolocaliza_a_la_victima": geo} if geo else {})},
                )
            )
        return findings

    # ------------------------------------------------------------------ redirecciones / ofuscación
    def _redirect(self, artifact: Artifact, facts: HtmlFacts, corpus: str) -> Finding | None:
        targets: list[str] = [u for u in facts.meta_refresh if _is_external(u)]
        how: list[str] = ["meta refresh"] if targets else []
        js_targets = []
        for m in _JS_REDIRECT_RE.finditer(corpus[:MAX_SCRIPT_CHARS]):
            url = m.group(2) or m.group(4) or m.group(6)
            if url:
                js_targets.append(url)
            if len(js_targets) >= 10:
                break
        if js_targets:
            how.append("JavaScript (window.location)")
            targets.extend(js_targets)
        dynamic = bool(_JS_REDIRECT_DYN_RE.search(corpus))
        if dynamic:
            how.append("JavaScript con destino codificado")
        if not targets and not dynamic:
            return None
        return Finding(
            analyzer=self.name,
            rule="html.redirect",
            title="El adjunto redirige a un sitio externo",
            description=(
                "Al abrir este archivo, el navegador salta automáticamente a otra página de Internet. Es una forma "
                "común de llevar a la víctima a un sitio de phishing sin que el link aparezca en el mail."
            ),
            category=FindingCategory.PHISHING,
            severity=Severity.MEDIUM,
            score=45 if dynamic else 40,
            artifact_id=artifact.id,
            evidence={
                "metodo": how,
                "destinos": ind.cap_list(_host(u) or ind.clean_snippet(u, 80) for u in targets)
                or ["(codificado)"],
            },
        )

    def _obfuscation(self, artifact: Artifact, facts: HtmlFacts, corpus: str) -> Finding | None:
        if not corpus.strip():
            return None
        strong = ind.cap_list(
            ind.clean_snippet(m.group(0), 60) for m in _STRONG_OBF_RE.finditer(corpus[:MAX_SCRIPT_CHARS])
        )
        metrics = [
            label
            for key, label in ind.obfuscation_metrics(corpus)
            if key not in ("long_line", "entropy", "base64_blob")
        ]
        encoded = [d for d in facts.decoded if d[0] != _SINK_PLAIN]
        if encoded:
            metrics.append(f"{len(encoded)} capa(s) de código codificado ({encoded[0][0]})")
        if not strong and not metrics:
            return None
        if strong:
            score, sev = 60, Severity.HIGH
        elif len(metrics) >= 2:
            score, sev = 45, Severity.MEDIUM
        else:
            score, sev = 35, Severity.MEDIUM
        return Finding(
            analyzer=self.name,
            rule="html.obfuscated_script",
            title="Código JavaScript ofuscado",
            description=(
                "El archivo contiene código escrito a propósito para que no se pueda leer (codificado, partido en "
                "pedazos o armado letra por letra). Las páginas de phishing lo usan para esconder el formulario o "
                "la descarga a los filtros de seguridad."
            ),
            category=FindingCategory.SUSPICIOUS_FILE,
            severity=sev,
            score=score,
            artifact_id=artifact.id,
            evidence={"tecnicas": strong, "senales": ind.cap_list(metrics)},
        )

    def _clickfix(self, artifact: Artifact, facts: HtmlFacts, hits: list[ind.IndicatorHit]) -> Finding:
        instructions = _CLICKFIX_TEXT_RE.search(facts.visible_text()[:200_000] + " " + facts.title)
        evidence: dict = {
            "comando": next((h.snippet for h in hits if h.snippet), ""),
            "indicadores": ind.cap_list(h.label for h in hits),
        }
        if instructions:
            evidence["instrucciones"] = ind.clean_snippet(instructions.group(0), 60)
        return Finding(
            analyzer=self.name,
            rule="html.clickfix",
            title="Página que te pide pegar un comando en Windows (ClickFix)",
            description=(
                "La página copia en secreto un comando al portapapeles y después pide 'verificar que sos humano' "
                "apretando Windows+R y pegando. Ese comando instala un virus. Nunca pegues en Ejecutar algo que te "
                "pida una página web."
            ),
            category=FindingCategory.SUSPICIOUS_FILE,
            severity=Severity.HIGH,
            score=80,
            artifact_id=artifact.id,
            evidence=evidence,
        )
