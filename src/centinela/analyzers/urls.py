"""Analizador de links (ParsedMessage.urls). NUNCA visita las URLs: todo es análisis del texto del link.

Detecta: hosts IP (incluidas formas ofuscadas decimal/hex/octal), dominios IDN con alfabetos mezclados,
imitaciones de los dominios de la empresa y de marcas (bancos, AFIP/ARCA, Microsoft, Mercado Pago...),
links engañosos (el texto muestra un dominio y el link lleva a otro), esquemas peligrosos (javascript:,
search-ms:, ms-msdt:, file:/UNC...), descargas directas de archivos riesgosos (con agravante si están en
servicios gratuitos muy abusados), acortadores, el truco "https://microsoft.com@evil.tld", hosts muy
largos y puertos no estándar.

Los links reescritos por filtros de seguridad (Microsoft Safe Links, Proofpoint, Google, Barracuda...) se
"desenvuelven" para analizar el destino real. Si un link de seguimiento lleva otra URL completa como
parámetro (redirección abierta), esa URL también se analiza.

Configuración:
- `general.trusted_domains` (socios/ESP de confianza): se excluyen SOLO de señales débiles (acortador, host
  largo, puerto raro, hosting gratuito, usuario@ no engañoso), bajan el puntaje de descargas como un sitio
  conocido, y un link de seguimiento o destino de confianza no cuenta como "link engañoso" (igual que los
  ESP conocidos). Nunca se excluyen de imitaciones, homógrafos, IPs ni esquemas peligrosos.
- `analyzers.extra_brands`: marcas propias del rubro que se suman a las imitaciones de marcas.

Agrupación: un hallazgo por cada (regla, artifact), con la lista de dominios (hasta 20) y hasta 5 URLs de
ejemplo en `evidence`. NO se usa `Finding.dedupe_key` para separar por dominio a propósito: el scoring
combina hallazgos con noisy-OR, así que 5 acortadores en un newsletter sumarían como 5 señales distintas.
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, unquote, urlsplit

from centinela.analyzers._lookalike import (
    DomainInfo,
    LookalikeDetector,
    domain_info,
    host_in_domains,
    is_mixed_script,
    is_private_ip,
    is_well_known,
    is_whole_script_confusable,
    normalize_domains,
    registrable_domain,
)
from centinela.analyzers.base import MessageAnalyzer
from centinela.core.models import Finding, FindingCategory, Severity

if TYPE_CHECKING:
    from collections.abc import Iterable

    from centinela.analyzers.base import AnalysisContext
    from centinela.core.models import ExtractedUrl

log = logging.getLogger(__name__)

NAME = "urls"
_MAX_URLS = 500
_MAX_URL_LEN = 4096
_MAX_EMBEDDED = 2
_MAX_UNWRAP = 3
_EVIDENCE_URL_LEN = 300

_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]{0,31}):")
_HOSTLIKE_RE = re.compile(r"^[a-z0-9\-]{1,63}(?:\.[a-z0-9\-]{1,63}){1,10}(?:[:/?#]|$)", re.I)
_SKIP_SCHEMES = frozenset(
    {"mailto", "tel", "sms", "cid", "callto", "mid", "about", "news", "fax", "geo", "whatsapp"}
)

_DANGEROUS_SCHEMES: dict[str, str] = {
    "javascript": "ejecuta código dentro del navegador o del programa de correo",
    "vbscript": "ejecuta código VBScript en Windows",
    "data": "trae una página web o archivo completo escondido dentro del propio link",
    "file": "abre un archivo de una carpeta de red; además puede filtrar la contraseña de Windows al servidor del atacante",
    "smb": "abre una carpeta de red externa; puede filtrar la contraseña de Windows",
    "unc": "abre una carpeta de red externa (\\\\servidor\\carpeta); puede filtrar la contraseña de Windows",
    "search-ms": "abre una búsqueda de Windows que muestra archivos remotos del atacante como si fueran locales",
    "search": "abre una búsqueda de Windows que muestra archivos remotos del atacante como si fueran locales",
    "ms-search": "abre una búsqueda de Windows que muestra archivos remotos del atacante como si fueran locales",
    "ms-msdt": "abre la herramienta de diagnóstico de Windows (vulnerabilidad 'Follina', usada para ejecutar código)",
    "ms-officecmd": "abre Office con parámetros manipulados (vulnerabilidad conocida)",
    "ms-appinstaller": "instala una aplicación directamente desde internet (método usado por malware)",
    "ms-its": "abre un archivo de ayuda compilado (CHM) que puede ejecutar código",
    "mk": "abre un archivo de ayuda compilado (CHM) que puede ejecutar código",
    "its": "abre un archivo de ayuda compilado (CHM) que puede ejecutar código",
    "hcp": "abre el Centro de ayuda de Windows (vulnerabilidad conocida)",
    "shell": "abre carpetas o programas de Windows",
    "itms-services": "instala una aplicación en iPhone por fuera de la App Store",
    "jar": "abre un archivo Java desde internet",
}

# Extensiones riesgosas para una descarga directa.
_RISKY_DL_EXEC = frozenset(
    "exe scr js jse vbs vbe hta ps1 bat cmd msi lnk jar wsf cpl appx appxbundle msix msixbundle pif xll reg apk".split()
)
_RISKY_DL_ARCHIVE = frozenset("zip rar 7z iso img vhd vhdx one".split())
_RISKY_DL = _RISKY_DL_EXEC | _RISKY_DL_ARCHIVE
_FILENAME_PARAMS = frozenset(
    {"file", "filename", "fn", "f", "name", "attachment", "download", "archivo", "nombre", "path"}
)


def _p_dropbox(host: str, path: str, query: str) -> bool:
    q = query.lower()
    return "dl=1" in q or "raw=1" in q


def _p_github(host: str, path: str, query: str) -> bool:
    return "/releases/download/" in path or "/raw/" in path


def _p_gitlab(host: str, path: str, query: str) -> bool:
    return "/-/raw/" in path or "/raw/" in path


def _p_bitbucket(host: str, path: str, query: str) -> bool:
    return "/downloads/" in path or "/raw/" in path


def _p_pastebin(host: str, path: str, query: str) -> bool:
    return path.startswith("/raw")


def _p_pasteee(host: str, path: str, query: str) -> bool:
    return path.startswith("/r/")


def _p_s3(host: str, path: str, query: str) -> bool:
    return host.startswith("s3.") or ".s3." in host or ".s3-" in host or host.startswith("s3-")


def _p_gdrive(host: str, path: str, query: str) -> bool:
    return "export=download" in query.lower() or path.startswith("/uc")


def _p_gdocs(host: str, path: str, query: str) -> bool:
    return "export=download" in query.lower()


_Pred = Callable[[str, str, str], bool] | None

# (sufijo de host, predicado de path/query o None, nombre del servicio, "hosting gratuito" para el LOW genérico)
_ABUSED_HOSTS: tuple[tuple[str, _Pred, str, bool], ...] = (
    ("cdn.discordapp.com", None, "Discord", True),
    ("media.discordapp.net", None, "Discord", True),
    ("transfer.sh", None, "transfer.sh", True),
    ("mediafire.com", None, "MediaFire", True),
    ("mega.nz", None, "MEGA", True),
    ("mega.io", None, "MEGA", True),
    ("dl.dropboxusercontent.com", None, "Dropbox", False),
    ("dropboxusercontent.com", None, "Dropbox", False),
    ("dropbox.com", _p_dropbox, "Dropbox", False),
    ("raw.githubusercontent.com", None, "GitHub", False),
    ("objects.githubusercontent.com", None, "GitHub", False),
    ("codeload.github.com", None, "GitHub", False),
    ("github.com", _p_github, "GitHub", False),
    ("gitlab.com", _p_gitlab, "GitLab", False),
    ("bitbucket.org", _p_bitbucket, "Bitbucket", False),
    ("pastebin.com", _p_pastebin, "Pastebin", True),
    ("paste.ee", _p_pasteee, "paste.ee", True),
    ("ngrok.io", None, "ngrok", True),
    ("ngrok-free.app", None, "ngrok", True),
    ("ngrok.app", None, "ngrok", True),
    ("ngrok-free.dev", None, "ngrok", True),
    ("ngrok.dev", None, "ngrok", True),
    ("trycloudflare.com", None, "Cloudflare Tunnel", True),
    ("workers.dev", None, "Cloudflare Workers", True),
    ("pages.dev", None, "Cloudflare Pages", True),
    ("r2.dev", None, "Cloudflare R2", True),
    ("firebasestorage.googleapis.com", None, "Firebase", True),
    ("firebaseapp.com", None, "Firebase", True),
    ("web.app", None, "Firebase", True),
    ("glitch.me", None, "Glitch", True),
    ("ipfs.io", None, "IPFS", True),
    ("dweb.link", None, "IPFS", True),
    ("cloudflare-ipfs.com", None, "IPFS", True),
    ("pinata.cloud", None, "IPFS", True),
    ("w3s.link", None, "IPFS", True),
    ("nftstorage.link", None, "IPFS", True),
    ("fleek.co", None, "IPFS", True),
    ("telegra.ph", None, "Telegraph", True),
    ("4shared.com", None, "4shared", True),
    ("gofile.io", None, "Gofile", True),
    ("file.io", None, "file.io", True),
    ("anonfiles.com", None, "AnonFiles", True),
    ("catbox.moe", None, "Catbox", True),
    ("sendspace.com", None, "SendSpace", True),
    ("filebin.net", None, "Filebin", True),
    ("temp.sh", None, "temp.sh", True),
    ("tmpfiles.org", None, "tmpfiles", True),
    ("pixeldrain.com", None, "Pixeldrain", True),
    ("krakenfiles.com", None, "KrakenFiles", True),
    ("blob.core.windows.net", None, "Azure Blob Storage", False),
    ("storage.googleapis.com", None, "Google Cloud Storage", False),
    ("amazonaws.com", _p_s3, "Amazon S3", False),
    ("digitaloceanspaces.com", None, "DigitalOcean Spaces", False),
    ("backblazeb2.com", None, "Backblaze", False),
    ("drive.usercontent.google.com", None, "Google Drive", False),
    ("drive.google.com", _p_gdrive, "Google Drive", False),
    ("docs.google.com", _p_gdocs, "Google Drive", False),
)

_SHORTENERS = frozenset(
    {
        "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "v.gd", "buff.ly", "rebrand.ly",
        "cutt.ly", "cutt.us", "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "tiny.one", "s.id", "bit.do", "qrco.de",
        "acortar.link", "acortaurl.com", "shorturl.asia", "x.gd", "urlz.fr", "surl.li", "u.to", "clck.ru",
        "shrtco.de", "lnkd.in", "1url.cz", "short.gy", "bl.ink", "soo.gd", "tr.im", "t2m.io", "smarturl.it",
        "hyperurl.co", "urlr.me", "goo.su", "kutt.it", "shorte.st", "adf.ly", "ouo.io", "spoo.me", "l.ead.me",
        "qr.net", "trib.al", "shorturl.gg", "ln.run", "chilp.it", "tinu.be", "rotf.lol", "tny.im",
    }
)  # fmt: skip

# Plataformas de envío masivo / seguimiento de clics: el destino real no se puede conocer.
_TRACKERS = frozenset(
    {
        "list-manage.com", "mailchimp.com", "sendgrid.net", "mandrillapp.com", "hubspotlinks.com", "hubspot.com",
        "hs-sites.com", "rs6.net", "createsend.com", "createsend1.com", "cmail19.com", "cmail20.com", "awstrack.me",
        "sparkpostmail.com", "mjt.lu", "sendibt2.com", "sendibt3.com", "sendibm1.com", "brevo.com", "mlsend.com",
        "mailerlite.com", "klclick.com", "klclick1.com", "klclick2.com", "klclick3.com", "klaviyomail.com",
        "substack.com", "beehiiv.com", "convertkit-mail.com", "convertkit-mail2.com", "ck.page", "exacttarget.com",
        "emarsys.net", "fromdoppler.com", "embluemail.com", "envialosimple.com", "icommkt.com", "mimecast.com",
        "mimecastprotect.com", "mailgun.org", "mailgun.net", "salesforce.com", "pardot.com", "mktoweb.com",
        "mkt.com", "aweber.com", "getresponse.com", "gr8.com", "acemlna.com", "activehosted.com", "constantcontact.com",
        "zohocampaigns.com", "e2ma.net", "linkedin.com", "facebook.com", "instagram.com", "perfit.com.ar",
        "mailrelay-i.com", "mailjet.com", "intercom-mail.com", "customeriomail.com", "postmarkapp.com",
    }
)  # fmt: skip

_FILEISH_TLDS = frozenset(
    {"zip", "mov", "py", "sh", "pl", "rs", "md", "ps", "so", "ai", "pdf", "doc", "xls", "exe"}
)
_SAFE_PORTS = {"http": {80, 443}, "https": {443, 80}, "ftp": {21}, "ftps": {990, 21}}


# --------------------------------------------------------------------------- estructuras


@dataclass
class _Parsed:
    url: str
    scheme: str
    host: str
    info: DomainInfo
    port: int | None
    userinfo: str
    path: str
    query: str


@dataclass
class _Hit:
    rule: str
    score: int
    severity: Severity
    category: FindingCategory
    title: str
    description: str
    domain: str
    url: str
    detail: dict[str, object] = field(default_factory=dict)


@dataclass
class _Group:
    rule: str
    artifact_id: str | None
    best: _Hit
    domains: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    details: list[dict[str, object]] = field(default_factory=list)


# --------------------------------------------------------------------------- parseo


def _clean(url: str) -> str:
    s = (url or "")[:_MAX_URL_LEN].strip().strip("<>\"' ")
    # los navegadores ignoran tabs y saltos de línea dentro de las URLs ("java\tscript:")
    return "".join(ch for ch in s if ch not in "\t\r\n\x00")


def _scheme_of(s: str) -> str | None:
    m = _SCHEME_RE.match(s)
    return m.group(1).lower() if m else None


def _parse_http(s: str) -> _Parsed | None:
    scheme = _scheme_of(s)
    if scheme not in ("http", "https", "ftp", "ftps"):
        return None
    rest = s[len(scheme) + 1 :]
    if scheme in ("http", "https"):
        rest = rest.replace("\\", "/")  # WHATWG: en http(s) "\" es "/" (truco "https://banco.com\@evil.tld")
    norm = f"{scheme}://{rest.lstrip('/')}"
    try:
        parts = urlsplit(norm)
        host = parts.hostname or ""
    except ValueError:
        return None
    try:
        port = parts.port
    except ValueError:
        port = None
    host = unquote(host)
    info = domain_info(host)
    if info is None:
        return None
    netloc = parts.netloc
    userinfo = netloc.rpartition("@")[0] if "@" in netloc else ""
    return _Parsed(
        norm, scheme, host, info, port, unquote(userinfo)[:200], parts.path[:2048], parts.query[:4096]
    )


def _query_params(query: str) -> list[tuple[str, str]]:
    try:
        return parse_qsl(query[:4096], keep_blank_values=False, max_num_fields=100)
    except ValueError:
        return []


def _unwrap(p: _Parsed) -> str | None:
    """Destino real de links reescritos por filtros de seguridad o redirectores conocidos."""
    host = p.info.host
    path = p.path

    def q(*names: str) -> str | None:
        for k, v in _query_params(p.query):
            if k.lower() in names and v:
                return v
        return None

    inner: str | None = None
    if host.endswith("safelinks.protection.outlook.com") or host.endswith(
        "safelinks.protection.office365.us"
    ):
        inner = q("url")
    elif host == "urldefense.proofpoint.com" and path.startswith("/v2/url"):
        u = q("u")
        inner = unquote(u.replace("-", "%").replace("_", "/")) if u else None
    elif host == "urldefense.com" and path.startswith("/v3/__"):
        body = p.url.split("/v3/__", 1)[1]
        inner = body.split("__;", 1)[0]
    elif p.info.label == "google" and path == "/url":
        inner = q("q", "url")
    elif host.endswith("linkprotect.cudasvc.com") and path.startswith("/url"):
        inner = q("a")
    elif host.endswith("trendmicro.com") and "clicktime" in path:
        inner = q("url")
    elif host in ("l.facebook.com", "lm.facebook.com", "l.instagram.com") and path == "/l.php":
        inner = q("u")
    elif host == "www.youtube.com" and path == "/redirect":
        inner = q("q")
    elif host == "slack-redir.net" and path == "/link":
        inner = q("url")
    if inner and _scheme_of(inner.strip()):
        return _clean(inner)
    return None


def _embedded_urls(p: _Parsed) -> list[str]:
    """URLs completas pasadas como parámetro (redirecciones abiertas, links de seguimiento)."""
    out: list[str] = []
    for _k, v in _query_params(p.query):
        vv = v.strip()
        if vv[:8].lower().startswith(("http://", "https://")):
            out.append(_clean(vv))
            if len(out) >= _MAX_EMBEDDED:
                break
    return out


def _display_domain(text: str | None) -> str | None:
    """Dominio que el texto visible de un link 'promete' (ej. 'www.bancogalicia.com.ar' o una URL)."""
    if not text:
        return None
    for tok in re.split(r"[\s<>\"'()\[\]{},;|]+", text[:500])[:50]:
        t = tok.strip().strip(".:!?").lower()
        if not t or "@" in t.split("/", 1)[0]:
            continue
        explicit = False
        m = _SCHEME_RE.match(t)
        if m:
            if m.group(1) not in ("http", "https"):
                continue
            t = t[len(m.group(1)) + 1 :].lstrip("/")
            explicit = True
        host = re.split(r"[/?#:]", t, maxsplit=1)[0].strip(".")
        if "." not in host or len(host) > 253:
            continue
        if host.startswith("www."):
            explicit = True
        if not all(c.isalnum() or c in ".-" for c in host):
            continue
        info = domain_info(host)
        if info is None or (not info.registrable and not info.is_ip):
            continue
        if info.is_ip and not (explicit or (host.count(".") == 3 and info.registrable == host)):
            continue  # "1.234" o fechas "10.5.2024" no son IPs que el texto "prometa"
        if info.suffix.rsplit(".", 1)[-1] in _FILEISH_TLDS and not explicit:
            continue
        return host
    return None


def _host_matches(host: str, suffix: str) -> bool:
    return host == suffix or host.endswith("." + suffix)


def _abused_service(p: _Parsed) -> tuple[str, bool] | None:
    host = p.info.host
    if "/ipfs/" in p.path:
        return "IPFS", True
    for suffix, pred, name, free in _ABUSED_HOSTS:
        if _host_matches(host, suffix) and (pred is None or pred(host, p.path, p.query)):
            return name, free
    return None


def _is_file_host(host: str) -> bool:
    """Servicio donde cualquiera sube archivos (aunque la URL no sea de descarga directa)."""
    return any(_host_matches(host, suffix) for suffix, _pred, _name, _free in _ABUSED_HOSTS)


def _download_ext(p: _Parsed) -> tuple[str, str] | None:
    """(extensión, nombre de archivo) si el link baja un archivo riesgoso."""
    last = unquote(p.path).rsplit("/", 1)[-1].strip().rstrip(".")
    if "." in last:
        ext = last.rsplit(".", 1)[-1].lower()
        if ext in _RISKY_DL:
            return ext, last[:200]
    for k, v in _query_params(p.query):
        if k.lower() in _FILENAME_PARAMS and "." in v:
            name = v.rsplit("/", 1)[-1].strip().rstrip(".")
            ext = name.rsplit(".", 1)[-1].lower()
            if ext in _RISKY_DL:
                return ext, name[:200]
    return None


def _short(url: str) -> str:
    return url if len(url) <= _EVIDENCE_URL_LEN else url[: _EVIDENCE_URL_LEN - 3] + "..."


# --------------------------------------------------------------------------- reglas por URL


def _hit(rule: str, score: int, severity: Severity, title: str, description: str, domain: str, url: str,
         category: FindingCategory = FindingCategory.PHISHING, **detail: object) -> _Hit:  # fmt: skip
    return _Hit(rule, score, severity, category, title, description, domain, _short(url), dict(detail))


def _check_scheme(s: str, scheme: str) -> _Hit | None:
    if scheme == "data":
        mime = s[5:64].split(",", 1)[0].split(";", 1)[0].strip().lower()
        if mime.startswith("image/") and "svg" not in mime:
            return None
        reason = _DANGEROUS_SCHEMES["data"] + (f" ({mime})" if mime else "")
    elif scheme in _DANGEROUS_SCHEMES:
        reason = _DANGEROUS_SCHEMES[scheme]
    else:
        return None
    return _hit(
        "url.dangerous_scheme",
        75,
        Severity.HIGH,
        f"Link peligroso de tipo '{scheme}:'",
        f"Este link no abre una página web normal: {reason}. Un mail legítimo prácticamente nunca usa este "
        "tipo de link. No hacer clic.",
        f"{scheme}:",
        s,
        scheme=scheme,
    )


def _checks_http(p: _Parsed, det: LookalikeDetector, trusted: frozenset[str] = frozenset()) -> list[_Hit]:
    hits: list[_Hit] = []
    info = p.info
    host_disp = info.unicode_host
    reg = info.registrable or info.host
    company = det.is_company(info.host)
    # dominio de confianza (config): se trata como un sitio conocido SOLO para las señales débiles
    trusted_host = not info.is_ip and host_in_domains(info.host, trusted)
    well_known = company or trusted_host or is_well_known(info.host)

    # truco usuario@host (la variante no engañosa es débil: no aplica a dominios de confianza)
    user = p.userinfo.split(":", 1)[0] if p.userinfo else ""
    deceptive = bool(user) and (
        "." in user or user.lower().startswith("www") or det.match(user.split("/", 1)[0]) is not None
    )
    if p.userinfo and (deceptive or not trusted_host):
        hits.append(
            _hit(
                "url.userinfo_trick",
                70 if deceptive else 15,
                Severity.HIGH if deceptive else Severity.LOW,
                f"Link con engaño en la dirección ('{user[:60]}@{host_disp}')",
                f"La dirección empieza con '{user[:60]}' para parecer legítima, pero todo lo que está antes de la "
                f"'@' se ignora: el navegador en realidad va a {host_disp}."
                if deceptive
                else f"El link incluye un usuario ('{user[:60]}') antes del sitio {host_disp}; es poco común en mails.",
                reg,
                p.url,
                user=user[:100],
            )
        )

    # host IP
    if info.is_ip:
        if not (is_private_ip(info.registrable) and not info.ip_obfuscated):
            obf = info.ip_obfuscated
            hits.append(
                _hit(
                    "url.ip_literal",
                    50 if obf else 35,
                    Severity.MEDIUM,
                    f"Link a una dirección IP en vez de un sitio con nombre ({info.registrable})",
                    "Los sitios legítimos usan nombres (como empresa.com). Un link directo a una dirección "
                    "numérica suele apuntar a un servidor improvisado de un atacante"
                    + (
                        f"; además está escrita de forma ofuscada ('{p.host[:60]}') para que no se reconozca."
                        if obf
                        else "."
                    ),
                    info.registrable,
                    p.url,
                    ip=info.registrable,
                    obfuscated=obf,
                )
            )
    else:
        # IDN con alfabetos mezclados / homógrafos completos
        if info.is_idn:
            bad = [
                lab
                for lab in info.unicode_host.split(".")
                if not lab.isascii() and (is_mixed_script(lab) or is_whole_script_confusable(lab))
            ]
            if bad:
                hits.append(
                    _hit(
                        "url.idn_homograph",
                        70,
                        Severity.HIGH,
                        f"Link con letras de otro alfabeto que imitan a las normales ({host_disp})",
                        f"El dominio {host_disp} (en realidad '{info.host}') usa letras de otros alfabetos (por "
                        "ejemplo cirílico) que se ven idénticas a las latinas. Es una técnica para imitar sitios "
                        "conocidos de forma casi imposible de notar a simple vista.",
                        reg,
                        p.url,
                        ascii_host=info.host,
                    )
                )

        # imitaciones
        lk = det.company_match(info.host)
        if lk:
            hits.append(
                _hit(
                    "url.lookalike_domain",
                    65 if lk.kind == "subdomain" else 70,
                    Severity.HIGH,
                    f"Link a un dominio parecido al de la empresa ({lk.domain})",
                    f"El link lleva a {lk.domain}, que se parece a {lk.target} pero no es el mismo: {lk.explanation}. "
                    "Suele usarse para robar contraseñas con una página que imita a la de la empresa.",
                    reg,
                    p.url,
                    imitates=lk.target,
                    kind=lk.kind,
                )
            )
        else:
            lk = det.brand_match(info.host)
            if lk:
                hits.append(
                    _hit(
                        "url.lookalike_brand",
                        65 if lk.kind == "subdomain" else 70,
                        Severity.HIGH,
                        f"Link a un sitio que imita a {lk.target} ({lk.domain})",
                        f"El link lleva a {lk.domain}, que no es de {lk.target} ({lk.target_domain}): {lk.explanation}. "
                        "Es la forma típica de robar usuarios y contraseñas (de home banking, AFIP, Microsoft 365...).",
                        reg,
                        p.url,
                        imitates=lk.target,
                        kind=lk.kind,
                    )
                )

    # descargas directas de archivos riesgosos
    dl = _download_ext(p)
    abused = _abused_service(p)
    if dl:
        ext, fname = dl
        if abused:
            score, sev = 65, Severity.HIGH
        elif well_known and not _is_file_host(info.host):
            score, sev = (30, Severity.MEDIUM) if ext in _RISKY_DL_EXEC else (10, Severity.LOW)
        else:
            score, sev = 45, Severity.MEDIUM
        where = f" desde {abused[0]}, un servicio gratuito muy usado para distribuir virus" if abused else ""
        hits.append(
            _hit(
                "url.risky_download",
                score,
                sev,
                f"Link que descarga un archivo riesgoso (.{ext})",
                f"Al hacer clic se descarga '{fname}'{where}. Los archivos .{ext} pueden instalar programas "
                "maliciosos (robo de contraseñas, control remoto, ransomware). Bajar archivos así por un link "
                "evita los controles de adjuntos del correo.",
                reg,
                p.url,
                category=FindingCategory.SUSPICIOUS_FILE,
                extension=ext,
                filename=fname,
                service=abused[0] if abused else None,
            )
        )
    elif abused and abused[1] and not trusted_host:
        hits.append(
            _hit(
                "url.free_hosting",
                15,
                Severity.LOW,
                f"Link a un servicio de alojamiento gratuito ({abused[0]})",
                f"El link apunta a {abused[0]}, un servicio donde cualquiera publica páginas o archivos en minutos. "
                "Es muy usado para páginas falsas de inicio de sesión y para distribuir virus.",
                reg,
                p.url,
                service=abused[0],
            )
        )

    # señales débiles (no aplican a dominios propios o muy conocidos)
    if not well_known and not info.is_ip:
        if reg in _SHORTENERS or info.host in _SHORTENERS:
            hits.append(
                _hit(
                    "url.shortener",
                    10,
                    Severity.LOW,
                    f"Link acortado ({info.host})",
                    "Los acortadores de links esconden el destino real; no se puede saber a dónde lleva sin abrirlo.",
                    reg,
                    p.url,
                )
            )
        n_sub = len([x for x in info.subdomain.split(".") if x]) if info.subdomain else 0
        if len(info.host) > 75 or n_sub >= 5 or info.label.count("-") >= 4:
            hits.append(
                _hit(
                    "url.long_hostname",
                    10,
                    Severity.LOW,
                    f"Dirección de sitio inusualmente larga ({host_disp[:80]})",
                    "La dirección del sitio es muy larga o tiene muchas partes; es un recurso para que en el "
                    "celular solo se vea el principio (que suele imitar a un sitio conocido).",
                    reg,
                    p.url,
                    host_length=len(info.host),
                    subdomains=n_sub,
                )
            )
    if p.port is not None and p.port not in _SAFE_PORTS.get(p.scheme, set()):
        private = info.is_ip and is_private_ip(info.registrable)
        if not well_known and not private:
            hits.append(
                _hit(
                    "url.nonstandard_port",
                    20,
                    Severity.MEDIUM,
                    f"Link a un puerto no habitual ({host_disp}:{p.port})",
                    "Los sitios web normales no necesitan indicar un 'puerto' en la dirección. Suele indicar un "
                    "servidor improvisado o un equipo comprometido.",
                    reg,
                    p.url,
                    port=p.port,
                )
            )
    return hits


def _check_deceptive(display: str | None, original: _Parsed | None, final: _Parsed, det: LookalikeDetector,
                     trusted: frozenset[str] = frozenset()) -> _Hit | None:  # fmt: skip
    disp = _display_domain(display)
    if not disp:
        return None
    real = final.info.host
    if det.same_entity(disp, real):
        return None
    orig_reg = registrable_domain(original.info.host) if original else ""
    if original is not None and orig_reg in _TRACKERS:
        return None  # link de seguimiento de una plataforma de mailing: el destino real no se conoce
    if registrable_domain(real) in _TRACKERS:
        return None
    if host_in_domains(real, trusted) or (
        original is not None and host_in_domains(original.info.host, trusted)
    ):
        return None  # seguimiento de un ESP de confianza (config) o destino de confianza: igual que _TRACKERS
    shortener = registrable_domain(real) in _SHORTENERS or real in _SHORTENERS
    return _hit(
        "url.deceptive_link",
        40 if shortener else 65,
        Severity.MEDIUM if shortener else Severity.HIGH,
        f"El texto del link muestra '{disp}' pero lleva a {final.info.unicode_host}",
        f"En el mail se ve '{disp}', pero al hacer clic se abre {final.info.unicode_host}. "
        + (
            "El destino real queda escondido detrás de un acortador."
            if shortener
            else "Es un engaño clásico de phishing: mostrar un sitio conocido y llevar a otro."
        ),
        registrable_domain(real) or real,
        final.url,
        display=(display or "")[:200],
        display_domain=disp,
        real_domain=real,
    )


def _analyze_one(
    u: ExtractedUrl, det: LookalikeDetector, trusted: frozenset[str] = frozenset()
) -> list[_Hit]:
    s = _clean(u.url)
    if not s:
        return []
    if s.startswith("\\\\"):
        return [h for h in [_check_scheme(s, "unc")] if h]
    scheme = _scheme_of(s)
    if scheme is not None and "." in scheme and scheme not in _DANGEROUS_SCHEMES and _HOSTLIKE_RE.match(s):
        scheme = None  # "www.ejemplo.com:8080/x": es un host con puerto, no un esquema
    if scheme is None:
        if s.startswith("//"):
            s = "https:" + s
        elif s.lower().startswith("www.") or _HOSTLIKE_RE.match(s):
            s = "http://" + s
        else:
            return []  # relativa / ancla
        scheme = _scheme_of(s)
    if scheme in _SKIP_SCHEMES:
        return []
    danger = _check_scheme(s, scheme or "")
    if danger:
        return [danger]
    original = _parse_http(s)
    if original is None:
        return []

    # desenvolver Safe Links / Proofpoint / redirectores
    final = original
    wrappers: list[str] = []
    for _ in range(_MAX_UNWRAP):
        inner = _unwrap(final)
        if not inner:
            break
        wrappers.append(final.info.host)
        inner_scheme = _scheme_of(inner)
        if inner_scheme in _SKIP_SCHEMES:
            return []
        danger = _check_scheme(inner, inner_scheme or "")
        if danger:
            return [danger]
        nxt = _parse_http(inner)
        if nxt is None:
            break
        final = nxt

    hits = _checks_http(final, det, trusted)
    dec = _check_deceptive(u.display_text, original, final, det, trusted)
    if dec:
        hits.append(dec)
    for emb in _embedded_urls(final):
        es = _scheme_of(emb)
        danger = _check_scheme(emb, es or "")
        if danger:
            hits.append(danger)
            continue
        ep = _parse_http(emb)
        if ep is not None and ep.info.host != final.info.host:
            for h in _checks_http(ep, det, trusted):
                h.detail["embedded_in"] = _short(final.url)
                hits.append(h)
    if wrappers:
        for h in hits:
            h.detail.setdefault("unwrapped_from", wrappers[0])
    return hits


def analyze_urls(
    urls: list[ExtractedUrl],
    company_domains: list[str],
    *,
    trusted_domains: Iterable[str] = (),
    extra_brands: Iterable[str] = (),
) -> list[Finding]:
    """Versión sincrónica (CPU) del análisis de links."""
    det = LookalikeDetector(company_domains, extra_brands=extra_brands)
    trusted = normalize_domains(trusted_domains)
    groups: dict[tuple[str, str | None], _Group] = {}
    seen_urls: set[tuple[str, str | None, str | None]] = set()
    for u in urls[:_MAX_URLS]:
        art = u.source.split(":", 1)[1][:200] if u.source.startswith("artifact:") else None
        key = (u.url[:_MAX_URL_LEN], u.display_text, art)
        if key in seen_urls:
            continue
        seen_urls.add(key)
        try:
            hits = _analyze_one(u, det, trusted)
        except Exception as exc:  # noqa: BLE001 - una URL hostil no debe tumbar el análisis del resto
            # solo el tipo: el mensaje de la excepción podría incluir la URL (tokens personales)
            log.debug("no se pudo analizar una URL: %s", type(exc).__name__)
            continue
        for h in hits:
            g = groups.get((h.rule, art))
            if g is None:
                g = groups[(h.rule, art)] = _Group(h.rule, art, h)
            elif h.score > g.best.score:
                g.best = h
            if h.domain and h.domain not in g.domains and len(g.domains) < 20:
                g.domains.append(h.domain)
            if h.url not in g.urls and len(g.urls) < 5:
                g.urls.append(h.url)
            if h.detail and len(g.details) < 5:
                g.details.append({"domain": h.domain, **{k: v for k, v in h.detail.items() if v is not None}})

    findings: list[Finding] = []
    for g in groups.values():
        b = g.best
        extra = len(g.domains) - 1
        title = b.title + (f" (y {extra} dominio{'s' if extra > 1 else ''} más)" if extra > 0 else "")
        findings.append(
            Finding(
                analyzer=NAME,
                rule=g.rule,
                title=title[:300],
                description=b.description,
                category=b.category,
                severity=b.severity,
                score=max(0, min(100, b.score)),
                artifact_id=g.artifact_id,
                evidence={"domains": g.domains, "urls": g.urls, "details": g.details},
            )
        )
    return findings


class UrlAnalyzer(MessageAnalyzer):
    """Analiza los links del mail (cuerpo y adjuntos) sin visitarlos."""

    name = NAME

    async def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        urls = list(ctx.message.urls or [])
        if not urls:
            return []
        s = ctx.settings
        return await asyncio.to_thread(
            analyze_urls,
            urls,
            list(s.general.company_domains),
            trusted_domains=list(s.general.trusted_domains),
            extra_brands=list(s.analyzers.extra_brands),
        )
