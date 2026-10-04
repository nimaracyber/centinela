"""Helpers compartidos para detectar dominios "parecidos" (typosquatting, homógrafos, marcas en subdominios).

Lo usan `headers` (remitente, Reply-To) y `urls` (links). Todo es OFFLINE:
- `tldextract` se usa con el snapshot de la Public Suffix List que viene empaquetado
  (`suffix_list_urls=()`, `cache_dir=None`): nunca hace pedidos de red ni escribe en disco.
- No se resuelve DNS ni se visita ningún dominio.

Conceptos:
- *registrable*: el dominio que alguien compra ("empresa.com.ar" en "mail.empresa.com.ar").
- *etiqueta*: la parte registrable sin el sufijo público ("empresa").
- *esqueleto* (skeleton): versión "visual" de un texto, donde caracteres que se ven iguales se
  reducen al mismo (Cirílico "а" -> "a", "rn" -> "m", "0" -> "o", "1"/"i" -> "l"...). Dos dominios con
  el mismo esqueleto se ven idénticos para una persona aunque sean distintos para la computadora.

Configuración que se usa acá:
- `general.trusted_domains` (`normalize_domains` + `host_in_domains`): dominios de socios/ESP de confianza.
  Los analizadores los excluyen SOLO de heurísticas débiles (nunca de imitaciones, firmas ni reputación).
- `analyzers.extra_brands` (`parse_extra_brands`): marcas propias del rubro que se suman a `BRANDS`.
  Formato de cada entrada: un dominio ("bancoregional.com.ar") o "Nombre visible: dominio1, dominio2"
  (también vale "=" como separador). Las entradas sin un dominio válido se ignoran (sin el dominio real
  de la marca no hay forma de no marcarla a ella misma como imitación).

Defensas: todos los textos se truncan (host <= 255, etiqueta <= 63), los resultados se cachean con
`lru_cache` acotado y la distancia de edición corta temprano. Nada de regex con backtracking.
"""

from __future__ import annotations

import functools
import ipaddress
import logging
import re
import threading
import unicodedata
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

import tldextract

log = logging.getLogger(__name__)

# --------------------------------------------------------------------------- tldextract offline

_EXTRACTOR: tldextract.TLDExtract | None = None
_EXTRACTOR_LOCK = threading.Lock()


def _extractor() -> tldextract.TLDExtract:
    """TLDExtract con la PSL empaquetada: sin red, sin caché en disco. Thread-safe (se usa en to_thread)."""
    global _EXTRACTOR
    if _EXTRACTOR is None:
        with _EXTRACTOR_LOCK:
            if _EXTRACTOR is None:
                ext = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, fallback_to_snapshot=True)
                ext("example.com")  # fuerza la carga del snapshot dentro del lock
                _EXTRACTOR = ext
    return _EXTRACTOR


# --------------------------------------------------------------------------- normalización de hosts

_MAX_HOST = 255
_MAX_LABEL = 63
_DOTS = str.maketrans({"。": ".", "．": ".", "｡": "."})  # puntos "ideográficos" que IDNA acepta


@dataclass(frozen=True, slots=True)
class DomainInfo:
    host: str  # host ASCII (punycode), minúsculas, sin punto final
    unicode_host: str  # el mismo host en Unicode (para mostrar / comparar homógrafos)
    subdomain: str  # ASCII ("mail" en "mail.empresa.com")
    label: str  # etiqueta registrable ASCII ("empresa" o "xn--...")
    unicode_label: str
    suffix: str  # sufijo público ("com.ar"); "" si no se reconoce
    registrable: str  # "empresa.com.ar"; para IPs, la IP; "" si no hay sufijo público conocido
    is_ip: bool = False
    ip_obfuscated: bool = False  # IP escrita en decimal/hex/octal o abreviada (http://3232235777/)

    @property
    def is_idn(self) -> bool:
        return self.host != self.unicode_host or "xn--" in self.host


def normalize_host(host: str) -> tuple[str, str] | None:
    """Devuelve (host_ascii, host_unicode) o None si no hay host utilizable."""
    if not host:
        return None
    host = host.strip()[: _MAX_HOST * 2].translate(_DOTS)
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    host = unicodedata.normalize("NFKC", host).lower().strip(".")
    if not host:
        return None
    if ":" in host:  # IPv6 literal: no tiene etiquetas DNS
        return host[:_MAX_HOST], host[:_MAX_HOST]
    ascii_labels: list[str] = []
    uni_labels: list[str] = []
    for raw in host.split(".")[-127:]:
        lab = raw[:_MAX_LABEL]
        if lab.isascii():
            ascii_labels.append(lab)
            if lab.startswith("xn--"):
                try:
                    uni = lab[4:].encode("ascii").decode("punycode").lower()
                except (UnicodeError, ValueError):
                    uni = lab
                uni_labels.append(uni)
            else:
                uni_labels.append(lab)
        else:
            try:
                enc = "xn--" + lab.encode("punycode").decode("ascii")
            except (UnicodeError, ValueError):
                enc = "xn--invalid"
            ascii_labels.append(enc[:_MAX_LABEL])
            uni_labels.append(lab)
    return ".".join(ascii_labels)[:_MAX_HOST], ".".join(uni_labels)[:_MAX_HOST]


def parse_ipv4_whatwg(host: str) -> tuple[str, bool] | None:
    """Parsea un host como IPv4 igual que un navegador (WHATWG URL): acepta 3232235777, 0xC0A80101,
    0300.0250.1.1, 192.168.1 ... Devuelve (ip_canónica, ofuscada) o None si no es una IPv4."""
    parts = host.split(".")
    if len(parts) > 1 and parts[-1] == "":
        parts.pop()
    if not parts or len(parts) > 4:
        return None
    nums: list[int] = []
    obfuscated = len(parts) != 4
    for p in parts:
        if not p or len(p) > 34 or not p.isascii():
            return None
        try:
            if p[:2] in ("0x", "0X"):
                n = int(p[2:], 16) if len(p) > 2 else 0
                obfuscated = True
            elif len(p) > 1 and p[0] == "0":
                n = int(p, 8)
                obfuscated = True
            elif p.isdigit():
                n = int(p)
            else:
                return None
        except ValueError:
            return None
        nums.append(n)
    if any(n > 255 for n in nums[:-1]) or nums[-1] >= 256 ** (5 - len(nums)):
        return None
    value = nums[-1]
    for i, n in enumerate(nums[:-1]):
        value += n * 256 ** (3 - i)
    return str(ipaddress.IPv4Address(value)), obfuscated


def domain_info(host: str | None) -> DomainInfo | None:
    """Descompone un host (o el dominio de un mail) en sus partes. Cacheado (clave acotada)."""
    if not host:
        return None
    return _domain_info(host[: _MAX_HOST + 8])


@functools.lru_cache(maxsize=8192)
def _domain_info(host: str) -> DomainInfo | None:
    norm = normalize_host(host)
    if norm is None:
        return None
    ascii_host, uni_host = norm
    v4 = parse_ipv4_whatwg(ascii_host)
    if v4 is not None:
        ip, obf = v4
        return DomainInfo(ascii_host, uni_host, "", "", "", "", ip, is_ip=True, ip_obfuscated=obf)
    if ":" in ascii_host:
        try:
            ip6 = ipaddress.IPv6Address(ascii_host.split("%", 1)[0])
        except ValueError:
            return None
        return DomainInfo(ascii_host, uni_host, "", "", "", "", str(ip6), is_ip=True)
    ext = _extractor()(ascii_host)
    label, suffix, sub = ext.domain, ext.suffix, ext.subdomain
    registrable = f"{label}.{suffix}" if label and suffix else ""
    uni_labels = uni_host.split(".")
    n_suffix = len(suffix.split(".")) if suffix else 0
    uni_label = uni_labels[-(n_suffix + 1)] if label and len(uni_labels) > n_suffix else label
    return DomainInfo(ascii_host, uni_host, sub, label, uni_label, suffix, registrable)


def registrable_domain(host: str | None) -> str:
    """'mail.empresa.com.ar' -> 'empresa.com.ar'. Para hosts sin sufijo público conocido devuelve el host."""
    if not host:
        return ""
    info = domain_info(host)
    if info is None:
        return ""
    return info.registrable or info.host


def email_domain(addr: str | None) -> str:
    """Dominio (minúsculas) de una dirección de mail, o ''."""
    if not addr or "@" not in addr:
        return ""
    dom = addr.strip().strip("<>").rsplit("@", 1)[1].strip().strip(">").strip(".").lower()
    return dom[:_MAX_HOST]


# --------------------------------------------------------------------------- listas de dominios de configuración

_MAX_CONFIG_DOMAINS = 500


def normalize_domains(domains: Iterable[str] | None) -> frozenset[str]:
    """Normaliza una lista de dominios de la configuración ("@Proveedor.com", "*.esp.net", "x.com.") a hosts
    ASCII en minúsculas. Se descartan IPs, nombres de una sola etiqueta y sufijos públicos sueltos ("com.ar"):
    confiar en "com.ar" sería confiar en medio internet."""
    return _normalize_domains(tuple(d for d in (domains or ()) if isinstance(d, str))[:_MAX_CONFIG_DOMAINS])


@functools.lru_cache(maxsize=64)
def _normalize_domains(domains: tuple[str, ...]) -> frozenset[str]:
    out: set[str] = set()
    for raw in domains:
        d = raw.strip().lower().lstrip("@").removeprefix("*.").strip(".")
        if not d or len(d) > _MAX_HOST:
            continue
        info = domain_info(d)
        if info is None or info.is_ip or not info.registrable:
            continue
        out.add(info.host)
    return frozenset(out)


def host_in_domains(host: str | None, domains: frozenset[str]) -> bool:
    """True si `host` es uno de `domains` o un subdominio (comparación por etiquetas completas)."""
    if not host or not domains:
        return False
    norm = normalize_host(host[: _MAX_HOST * 2])
    if norm is None:
        return False
    labels = norm[0].split(".")
    return any(".".join(labels[i:]) in domains for i in range(len(labels)))


# Redes de intranet (RFC 1918, loopback, link-local, ULA). No se usa `is_private` de ipaddress porque también
# incluye rangos de documentación y otros que en un link de un mail NO son "la red de la oficina".
_INTRANET_NETS = tuple(
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "::1/128",
              "fc00::/7", "fe80::/10")
)  # fmt: skip


def is_private_ip(ip: str) -> bool:
    """True si la IP es de una red interna (intranet / equipo local)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr.version == n.version and addr in n for n in _INTRANET_NETS)


# ccTLDs que en la práctica se venden como genéricos (".co", ".io", ".me"...): no cuentan como "variante de país".
_GENERIC_CC = frozenset("co cc ws me io ai tv to ly gg la st nu tk ml ga cf gq sh so su ac cx fm im".split())


def _is_cc_suffix(suffix: str) -> bool:
    """True si el sufijo es de un país ("com.ar", "ar", "co.uk", "mx"), excluyendo ccTLDs usados como genéricos."""
    if not suffix:
        return False
    parts = suffix.split(".")
    last = parts[-1]
    if not (len(last) == 2 and last.isalpha() and last.isascii()):
        return False
    return len(parts) > 1 or last not in _GENERIC_CC


# --------------------------------------------------------------------------- esqueleto visual

# Caracteres que se ven como letras latinas (subconjunto práctico de Unicode UTS #39 confusables).
_CONFUSABLES: dict[str, str] = {
    # Cirílico
    "а": "a", "в": "b", "ь": "b", "с": "c", "ԁ": "d", "е": "e", "ё": "e", "һ": "h", "і": "l", "ї": "l",
    "ј": "j", "к": "k", "ӏ": "l", "м": "m", "п": "n", "о": "o", "р": "p", "ԛ": "q", "г": "r", "ѕ": "s",
    "т": "t", "у": "y", "ү": "y", "х": "x", "ԝ": "w", "ɡ": "g",
    # Griego
    "α": "a", "β": "b", "ϲ": "c", "ε": "e", "η": "n", "ι": "l", "κ": "k", "ν": "v", "ο": "o", "ρ": "p",
    "τ": "t", "υ": "u", "χ": "x", "ω": "w", "γ": "y",
    # Armenio
    "օ": "o", "ս": "u", "ց": "g", "հ": "h", "ո": "n", "զ": "q",
    # Latín extendido y símbolos
    "ı": "l", "ɩ": "l", "ł": "l", "ɑ": "a", "đ": "d", "ø": "o", "ħ": "h",
    # dígitos / signos que se confunden con letras
    "0": "o", "1": "l", "|": "l", "i": "l",
}  # fmt: skip
_CONFUSABLE_TABLE = str.maketrans(_CONFUSABLES)
_MULTI = (("rn", "m"), ("vv", "w"), ("cl", "d"))


def skeleton(text: str) -> str:
    """Esqueleto visual: minúsculas, sin acentos, confusables -> latín, rn->m, vv->w, cl->d, 0->o, 1/i->l."""
    return _skeleton(text[:256])


@functools.lru_cache(maxsize=16384)
def _skeleton(text: str) -> str:
    s = unicodedata.normalize("NFKC", text).lower()
    s = "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))
    s = s.translate(_CONFUSABLE_TABLE)
    for a, b in _MULTI:
        s = s.replace(a, b)
    return s


def edit_distance(a: str, b: str, limit: int) -> int:
    """Distancia de Damerau (OSA: inserción, borrado, sustitución, transposición) con corte en `limit`.
    Devuelve limit+1 si se pasa. Entradas acotadas a 64 caracteres."""
    a, b = a[:64], b[:64]
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    if a == b:
        return 0
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        best = cur[0]
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            v = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                v = min(v, prev2[j - 2] + 1)
            cur[j] = v
            best = min(best, v)
        if best > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1] if prev[-1] <= limit else limit + 1


# --------------------------------------------------------------------------- scripts (alfabetos)

_CONFUSABLE_SCRIPTS = frozenset({"LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE", "COPTIC", "GEORGIAN"})


def label_scripts(label: str) -> set[str]:
    """Alfabetos de las letras de una etiqueta ('LATIN', 'CYRILLIC', ...). Dígitos y guiones no cuentan."""
    out: set[str] = set()
    for ch in unicodedata.normalize("NFKC", label[:_MAX_LABEL]):
        if not unicodedata.category(ch).startswith("L"):
            continue
        name = unicodedata.name(ch, "")
        if not name:
            continue
        first = name.split(" ", 1)[0]
        if first == "CJK":
            out.add("CJK")
        elif first in ("FULLWIDTH", "HALFWIDTH", "MODIFIER", "MATHEMATICAL", "SMALL"):
            continue
        else:
            out.add(first)
    return out


def is_mixed_script(label: str) -> bool:
    """True si mezcla alfabetos confundibles (ej. latín + cirílico en 'pаypal')."""
    return len(label_scripts(label) & _CONFUSABLE_SCRIPTS) >= 2


def is_whole_script_confusable(label: str) -> bool:
    """True si la etiqueta está toda en un alfabeto no latino pero se ve idéntica a texto latino
    (ej. 'аррӏе' escrito entero en cirílico)."""
    scripts = label_scripts(label)
    if len(scripts) != 1 or scripts <= {"LATIN"} or not scripts <= _CONFUSABLE_SCRIPTS:
        return False
    sk = skeleton(label)
    return bool(sk) and all(c.isascii() and (c.isalnum() or c == "-") for c in sk)


# --------------------------------------------------------------------------- marcas

_CTX_GENERIC = frozenset(
    "banco bank banca banking homebanking online seguridad security alerta alertas alert aviso avisos "
    "notificacion notificaciones notification notifications servicio servicios service atencion cliente "
    "clientes customer soporte support cuenta cuentas account tarjeta tarjetas team equipo admin "
    "administrador noreply no-reply informa info sistema sistemas help ayuda verificacion verification "
    "oficial official mesa helpdesk".split()
)
_CTX_DELIVERY = frozenset(
    "envio envios entrega entregas paquete paquetes pedido pedidos delivery shipping shipment tracking "
    "seguimiento logistica courier express encomienda encomiendas correo".split()
)
_CTX_FISCAL = frozenset(
    "agencia recaudacion fiscal impuesto impuestos tributaria tributario tributos aduana afip contribuyente "
    "contribuyentes fisco".split()
)
_CONTEXTS = {"generic": _CTX_GENERIC, "delivery": _CTX_GENERIC | _CTX_DELIVERY, "fiscal": _CTX_FISCAL}


@dataclass(frozen=True)
class Brand:
    """Marca que los atacantes suelen imitar.

    keys: etiquetas distintivas ("mercadopago"): se buscan homógrafos, typos, cambio de TLD y agregados.
    weak_keys: palabras genéricas ("office", "galicia", "macro"): solo homógrafos y agregados con palabras
               de anzuelo ("office365-login"), nunca typos ni cambio de TLD (demasiados falsos positivos).
    legit: dominios registrables de la marca. cc_ok: la marca usa variantes por país (google.com.ar).
    display / display_weak: frases (normalizadas, sin acentos) que en el nombre visible del remitente
               afirman ser la marca; las "weak" además requieren una palabra de contexto.
    """

    name: str
    keys: tuple[str, ...]
    legit: tuple[str, ...]
    weak_keys: tuple[str, ...] = ()
    cc_ok: bool = False
    display: tuple[str, ...] = ()
    display_weak: tuple[str, ...] = ()
    context: str = "generic"


BRANDS: tuple[Brand, ...] = (
    Brand(
        "Microsoft",
        keys=("microsoft", "microsoftonline", "office365", "microsoft365", "onedrive", "sharepoint", "hotmail"),
        weak_keys=("office", "outlook", "teams"),
        legit=(
            "microsoft.com", "microsoftonline.com", "microsoftonline-p.com", "microsoft365.com", "office.com",
            "office.net", "office365.com", "outlook.com", "live.com", "live.net", "hotmail.com", "msn.com",
            "onedrive.com", "1drv.ms", "sharepoint.com", "sharepointonline.com", "onenote.com", "onenote.net",
            "windows.com", "windowsupdate.com", "azure.com", "msauth.net", "msftauth.net", "msauthimages.net",
            "msecnd.net", "msocdn.com", "aka.ms", "bing.com", "skype.com", "xbox.com", "microsoftstore.com",
            "dynamics.com", "powerbi.com", "visualstudio.com", "cloud.microsoft", "static.microsoft",
            "office365.us", "outlook.office365.com",
        ),
        cc_ok=True,
        display=("microsoft", "office 365", "office365", "microsoft 365", "onedrive", "one drive", "sharepoint",
                 "share point", "hotmail"),
        display_weak=("outlook", "office", "teams", "exchange"),
    ),
    Brand(
        "Google",
        keys=("google", "gmail", "googlemail"),
        legit=(
            "google.com", "gmail.com", "googlemail.com", "googleapis.com", "gstatic.com", "googleadservices.com",
            "googlesyndication.com", "google-analytics.com", "googletagmanager.com", "doubleclick.net",
            "youtube.com", "youtu.be", "goo.gl", "g.co", "forms.gle", "googlegroups.com", "withgoogle.com",
            "googlevideo.com", "ggpht.com", "googleblog.com", "google.dev",
        ),
        cc_ok=True,
        display=("google", "gmail", "google drive", "google workspace"),
    ),
    Brand("DocuSign", keys=("docusign",), legit=("docusign.com", "docusign.net"), display=("docusign",)),
    Brand(
        "Dropbox",
        keys=("dropbox",),
        legit=("dropbox.com", "dropboxmail.com", "dropboxstatic.com", "dropboxapi.com", "db.tt"),
        display=("dropbox",),
    ),
    Brand("WeTransfer", keys=("wetransfer",), legit=("wetransfer.com", "we.tl"), display=("wetransfer", "we transfer")),
    Brand(
        "Adobe",
        keys=("adobe", "adobesign", "acrobat"),
        legit=("adobe.com", "adobe.io", "adobelogin.com", "adobesign.com", "echosign.com", "acrobat.com",
               "typekit.net", "adobecc.com", "adobe.ly"),
        display=("adobe", "acrobat", "adobe sign"),
    ),
    Brand("PayPal", keys=("paypal",), legit=("paypal.com", "paypal.me", "paypalobjects.com"), cc_ok=True,
          display=("paypal", "pay pal")),
    Brand(
        "Apple",
        keys=("icloud", "itunes", "appleid"),
        weak_keys=("apple",),
        legit=("apple.com", "icloud.com", "me.com", "mac.com", "itunes.com", "apple.news", "mzstatic.com",
               "cdn-apple.com", "apple.co"),
        display=("apple", "icloud", "itunes", "apple id", "app store"),
    ),
    Brand("DHL", keys=("dhl",), legit=("dhl.com", "dhl.de", "dpdhl.com"), cc_ok=True, display=("dhl",),
          context="delivery"),
    Brand("FedEx", keys=("fedex",), legit=("fedex.com",), cc_ok=True, display=("fedex", "fed ex"), context="delivery"),
    Brand("UPS", keys=(), weak_keys=("ups",), legit=("ups.com",), cc_ok=True, display_weak=("ups",),
          context="delivery"),
    Brand(
        "Mercado Pago",
        keys=("mercadopago",),
        legit=("mercadopago.com", "mercadolibre.com", "mercadolivre.com.br", "mlstatic.com"),
        cc_ok=True,
        display=("mercado pago", "mercadopago"),
    ),
    Brand(
        "Mercado Libre",
        keys=("mercadolibre", "mercadolivre"),
        legit=("mercadolibre.com", "mercadolivre.com.br", "mercadopago.com", "mlstatic.com", "mercadoshops.com"),
        cc_ok=True,
        display=("mercado libre", "mercadolibre", "mercado livre"),
    ),
    Brand("AFIP", keys=("afip",), legit=("afip.gob.ar", "afip.gov.ar"), display=("afip",), context="fiscal"),
    Brand("ARCA", keys=(), weak_keys=("arca",), legit=("arca.gob.ar",), display_weak=("arca",), context="fiscal"),
    Brand(
        "Banco Galicia",
        keys=("bancogalicia",),
        weak_keys=("galicia",),
        legit=("bancogalicia.com", "bancogalicia.com.ar", "galicia.ar"),
        display=("banco galicia",),
        display_weak=("galicia",),
    ),
    Brand(
        "Santander",
        keys=("santander", "santanderrio", "bancosantander"),
        legit=("santander.com", "santander.com.ar", "santanderrio.com.ar", "santander.com.mx", "santander.com.br",
               "santander.cl", "santander.co.uk", "bancosantander.es", "gruposantander.com"),
        cc_ok=True,
        display=("banco santander", "santander rio"),
        display_weak=("santander",),
    ),
    Brand("BBVA", keys=("bbva", "bbvafrances"), legit=("bbva.com", "bbva.com.ar", "bbva.mx", "bbva.es"), cc_ok=True,
          display=("bbva",)),
    Brand("Banco Macro", keys=("bancomacro",), weak_keys=("macro",), legit=("macro.com.ar", "bancomacro.com"),
          display=("banco macro",), display_weak=("macro",)),
    Brand("Banco Nación", keys=("banconacion",), weak_keys=("bna",), legit=("bna.com.ar",),
          display=("banco nacion", "banco de la nacion")),
    Brand("Banco Provincia", keys=("bancoprovincia", "bapro"), legit=("bancoprovincia.com.ar", "bapro.com.ar"),
          display=("banco provincia", "banco de la provincia", "bapro")),
    Brand("ICBC", keys=("icbc",), legit=("icbc.com.ar", "icbc.com.cn", "icbc.com"), cc_ok=True, display=("icbc",)),
    Brand("HSBC", keys=("hsbc",), legit=("hsbc.com", "hsbc.com.ar", "hsbc.com.mx", "hsbc.co.uk"), cc_ok=True,
          display=("hsbc",)),
    Brand("Itaú", keys=("itau",), legit=("itau.com.br", "itau.com", "itau.com.ar", "itau.com.uy", "itau.cl"),
          cc_ok=True, display=("itau",)),
    Brand("Bradesco", keys=("bradesco",), legit=("bradesco.com.br", "bradesco.com"), cc_ok=True, display=("bradesco",)),
    Brand("Bancolombia", keys=("bancolombia",), legit=("bancolombia.com", "bancolombia.com.co", "grupobancolombia.com"),
          display=("bancolombia",)),
    Brand("Banorte", keys=("banorte",), legit=("banorte.com", "banorte.com.mx"), display=("banorte",)),
    Brand("BCI", keys=(), weak_keys=("bci",), legit=("bci.cl",), display=("banco bci",), display_weak=("bci",)),
    Brand("Correo Argentino", keys=("correoargentino",), legit=("correoargentino.com.ar",),
          display=("correo argentino",), context="delivery"),
    Brand("Andreani", keys=("andreani",), legit=("andreani.com", "andreani.com.ar"), cc_ok=True, display=("andreani",),
          context="delivery"),
    Brand("OCA", keys=(), weak_keys=("oca",), legit=("oca.com.ar",), display_weak=("oca",), context="delivery"),
    # --- extras relevantes en LatAm (bancos digitales, fiscos, correos)
    Brand("Naranja X", keys=("naranjax",), legit=("naranjax.com", "naranja.com"), display=("naranja x",)),
    Brand("Ualá", keys=("uala",), legit=("uala.com.ar", "uala.com.mx", "uala.com.co"), display=("uala",)),
    Brand("Brubank", keys=("brubank",), legit=("brubank.com",), display=("brubank",)),
    Brand("Banco Ciudad", keys=("bancociudad",), legit=("bancociudad.com.ar",), display=("banco ciudad",)),
    Brand("Credicoop", keys=("credicoop", "bancocredicoop"), legit=("bancocredicoop.coop",), display=("credicoop",)),
    Brand("Supervielle", keys=("supervielle",), legit=("supervielle.com.ar",), display=("supervielle",)),
    Brand("Banco Patagonia", keys=("bancopatagonia",), legit=("bancopatagonia.com.ar",), display=("banco patagonia",)),
    Brand("Nubank", keys=("nubank",), legit=("nubank.com.br", "nu.com.mx", "nubank.com"), display=("nubank",)),
    Brand("Citibanamex", keys=("banamex", "citibanamex"), legit=("banamex.com", "citibanamex.com"),
          display=("banamex", "citibanamex")),
    Brand("SAT", keys=(), weak_keys=("sat",), legit=("sat.gob.mx",), display_weak=("sat",), context="fiscal"),
    Brand("DIAN", keys=(), weak_keys=("dian",), legit=("dian.gov.co",), display_weak=("dian",), context="fiscal"),
    Brand("SUNAT", keys=("sunat",), legit=("sunat.gob.pe",), display=("sunat",), context="fiscal"),
    Brand("Correios", keys=("correios",), legit=("correios.com.br",), display=("correios",), context="delivery"),
    Brand("WhatsApp", keys=("whatsapp",), legit=("whatsapp.com", "whatsapp.net", "wa.me"), display=("whatsapp",)),
    Brand(
        "Amazon",
        keys=("amazon",),
        legit=("amazon.com", "amazon.com.br", "amazon.com.mx", "amazonses.com", "media-amazon.com",
               "ssl-images-amazon.com", "a2z.com", "amazon.jobs", "amzn.to"),
        cc_ok=True,
        display=("amazon",),
    ),
    Brand(
        "Meta / Facebook",
        keys=("facebook", "instagram", "facebookmail"),
        legit=("facebook.com", "fb.com", "facebookmail.com", "meta.com", "instagram.com", "fbcdn.net", "fb.me"),
        display=("facebook", "instagram", "meta business", "meta for business"),
    ),
)  # fmt: skip

# Dominios donde cualquiera crea subdominios o publica contenido propio: que la marca dueña sea legítima
# NO hace legítimo lo que hay ahí ("microsoft-login.web.app", "docusign.sharepoint.com").
USER_CONTENT_DOMAINS = frozenset(
    {
        "windows.net", "azurewebsites.net", "azureedge.net", "cloudapp.net", "azurefd.net", "sharepoint.com",
        "web.app", "firebaseapp.com", "appspot.com", "blogspot.com", "googleusercontent.com", "github.io",
        "githubusercontent.com", "amazonaws.com", "cloudfront.net", "netlify.app", "vercel.app", "herokuapp.com",
        "workers.dev", "pages.dev", "r2.dev", "glitch.me", "ngrok.io", "ngrok-free.app", "ngrok.app",
        "trycloudflare.com", "wixsite.com", "weebly.com", "godaddysites.com", "square.site", "webflow.io",
        "notion.site", "framer.app", "onrender.com", "repl.co", "replit.dev", "translate.goog", "myshopify.com",
        "dropboxusercontent.com", "000webhostapp.com", "surge.sh", "fly.dev", "digitaloceanspaces.com",
        "backblazeb2.com", "ipfs.io", "dweb.link", "telegra.ph", "wordpress.com", "sites.google.com",
    }
)  # fmt: skip

# Plataformas SaaS donde el subdominio es el nombre del cliente ("mercadolibre.custhelp.com"): no se marca
# "marca en subdominio" ahí (demasiados falsos positivos de mesas de ayuda legítimas).
SAAS_TENANT_DOMAINS = frozenset(
    {
        "zendesk.com", "freshdesk.com", "custhelp.com", "salesforce.com", "force.com", "my.site.com", "okta.com",
        "atlassian.net", "service-now.com", "servicenow.com", "hubspot.com", "hs-sites.com", "typeform.com",
        "zoom.us", "webex.com", "gotomeeting.com", "bamboohr.com", "workday.com", "myworkdayjobs.com",
        "sendgrid.net", "list-manage.com", "mailchimp.com", "exacttarget.com", "createsend.com", "mcsv.net",
    }
)  # fmt: skip

FREEMAIL_DOMAINS = frozenset(
    {
        "gmail.com", "googlemail.com", "outlook.com", "outlook.es", "outlook.com.ar", "hotmail.com",
        "hotmail.com.ar", "hotmail.es", "hotmail.co.uk", "live.com", "live.com.ar", "live.com.mx", "live.cl",
        "msn.com", "yahoo.com", "yahoo.com.ar", "yahoo.com.mx", "yahoo.com.br", "yahoo.es", "ymail.com",
        "rocketmail.com", "icloud.com", "me.com", "mac.com", "aol.com", "protonmail.com", "proton.me", "pm.me",
        "gmx.com", "gmx.net", "gmx.de", "mail.com", "zoho.com", "zohomail.com", "yandex.com", "yandex.ru",
        "mail.ru", "tutanota.com", "tuta.io", "fibertel.com.ar", "speedy.com.ar", "arnet.com.ar", "uol.com.br",
        "bol.com.br", "terra.com.br", "ig.com.br", "qq.com", "163.com", "hushmail.com", "inbox.com",
        "web.de", "t-online.de", "libero.it", "orange.fr", "laposte.net", "free.fr", "seznam.cz",
    }
)  # fmt: skip
_FREEMAIL_LABELS = frozenset({"gmail", "hotmail", "yahoo", "outlook"})

# Plataformas legítimas muy comunes (además de las marcas): se usan SOLO para bajar heurísticas débiles.
_COMMON_LEGIT = frozenset(
    {
        "linkedin.com", "lnkd.in", "twitter.com", "x.com", "t.co", "zoom.us", "zoom.com", "slack.com",
        "github.com", "gitlab.com", "atlassian.com", "atlassian.net", "salesforce.com", "hubspot.com",
        "mailchimp.com", "list-manage.com", "sendgrid.net", "tiktok.com", "pinterest.com", "vimeo.com",
        "spotify.com", "wikipedia.org", "mercadoshops.com.ar", "tiendanube.com", "nuvemshop.com.br",
        "cloudflare.com", "akamai.net", "akamaized.net", "office.net", "wa.me", "whatsapp.com",
        "calendly.com", "canva.com", "notion.so", "trello.com", "asana.com", "monday.com", "stripe.com",
        "shopify.com", "wordpress.org", "w3.org", "schema.org", "gravatar.com", "typeform.com",
    }
)  # fmt: skip
_GOV_SUFFIXES = (
    "gob.ar", "gov.ar", "gob.mx", "gov.br", "gov.co", "gob.pe", "gob.cl", "gub.uy", "gob.ec", "gob.bo", "gov.py",
    "gob.ve", "gob.es", "gov",
)  # fmt: skip

# Palabras "de anzuelo" que los atacantes pegan a una marca ("microsoft-login", "afipnotificaciones").
_LURE_WORDS = (
    "login logon signin sign secure security seguridad seguro verify verification verificacion verificar "
    "validar validacion account accounts cuenta cuentas update updates actualizar actualizacion support soporte "
    "help ayuda service services servicio servicios online web www app apps mail email correo portal auth sso "
    "id my mi mis pay pago pagos payment payments factura facturas facturacion billing invoice invoices cobro "
    "cobros cliente clientes customer customers team teams office outlook drive docs doc file files share "
    "shared sharing download downloads descarga descargas cloud net home homebanking banking bank banco wallet "
    "alert alerts alerta alertas notify notificacion notificaciones notification info tracking track "
    "seguimiento envio envios delivery express paquete store shop tienda ar arg mx br cl co pe uy py bo ec ve "
    "es us la latam sa srl sas group grupo corp inc admin rrhh hr it 365 o365 global center centro access "
    "acceso reset password clave recovery recupero confirm confirmar unlock desbloqueo oauth token sms gob gov "
    "tramite tramites legal official oficial new nuevo nueva dashboard panel cuit cbu mp ml digital empresas "
    "personas"
).split()
_LURE_SK = frozenset(skeleton(w) for w in _LURE_WORDS)

# Etiquetas legítimas que quedan a 1 typo de una marca (evitar falsos positivos conocidos).
_BENIGN_NEAR_MISSES = frozenset(
    {"paypay", "goggle", "goggles", "googly", "adobo", "appel", "cloud", "tunes", "email", "mail", "outlet",
     "naranjas", "naranjo", "correio", "correos", "unbank", "andreoni"}
)  # fmt: skip


_BrandIndex = tuple[tuple[Brand, tuple[tuple[str, str, bool], ...]], ...]


def _index_brands(brands: Iterable[Brand]) -> _BrandIndex:
    """Por marca: (clave, esqueleto, es_débil) precalculados."""
    out = []
    for b in brands:
        keys = tuple((k, skeleton(k), False) for k in b.keys) + tuple(
            (k, skeleton(k), True) for k in b.weak_keys
        )
        out.append((b, keys))
    return tuple(out)


@functools.lru_cache(maxsize=1)
def _brand_index() -> _BrandIndex:
    return _index_brands(BRANDS)


# --------------------------------------------------------------------------- marcas extra (configuración)

_MAX_EXTRA_BRANDS = 50
_MAX_EXTRA_ENTRY = 300
_MAX_EXTRA_DOMAINS = 10
_STRONG_KEY_MIN = 5  # claves más cortas: solo homógrafos y agregados con anzuelo (como las "weak_keys")
_DISPLAY_LABEL_MIN = 6  # la etiqueta del dominio solo cuenta como "nombre visible" si es distintiva
_EXTRA_SPLIT_RE = re.compile(r"[\s,;|]+")
_URL_SCHEME_RE = re.compile(r"(?i)\bhttps?://")


def _parse_extra_entry(entry: str) -> Brand | None:
    text = _URL_SCHEME_RE.sub("", entry.strip()[:_MAX_EXTRA_ENTRY])
    if not text:
        return None
    name = ""
    domains_part = text
    for sep in (":", "="):
        if sep in text:
            name, _, domains_part = text.partition(sep)
            name = " ".join(name.split())
            break
    legit: list[str] = []
    labels: list[str] = []
    for tok in _EXTRA_SPLIT_RE.split(domains_part)[: _MAX_EXTRA_DOMAINS * 3]:
        tok = tok.split("/", 1)[0].strip().lower().lstrip("@").removeprefix("*.").strip(".")
        if not tok or "." not in tok:
            continue
        info = domain_info(tok)
        if info is None or info.is_ip or not info.registrable or info.registrable in legit:
            continue
        legit.append(info.registrable)
        if info.unicode_label and info.unicode_label not in labels:
            labels.append(info.unicode_label)
        if len(legit) >= _MAX_EXTRA_DOMAINS:
            break
    if not legit:
        return None
    norm_name = _norm_words(name) if name else ""
    joined = norm_name.replace(" ", "")
    candidates = labels + ([joined] if joined and joined.isascii() and joined.isalnum() else [])
    keys = tuple(dict.fromkeys(k for k in candidates if len(k) >= _STRONG_KEY_MIN))
    weak = tuple(dict.fromkeys(k for k in candidates if 3 <= len(k) < _STRONG_KEY_MIN and k not in keys))
    display = tuple(
        dict.fromkeys(
            ([norm_name] if len(norm_name) >= 4 else [])
            + [lab for lab in labels if len(lab) >= _DISPLAY_LABEL_MIN and lab.isascii()]
        )
    )
    if not keys and not weak:
        return None
    return Brand(name=name or legit[0], keys=keys, legit=tuple(legit), weak_keys=weak, display=display)


@functools.lru_cache(maxsize=32)
def _parse_extra_brands(entries: tuple[str, ...]) -> tuple[Brand, ...]:
    out: list[Brand] = []
    ignored = 0
    for entry in entries[:_MAX_EXTRA_BRANDS]:
        brand = _parse_extra_entry(entry)
        if brand is None:
            ignored += 1
        else:
            out.append(brand)
    if ignored:
        # se loguea una sola vez por configuración (lru_cache): es config, no datos del mail
        log.warning(
            "analyzers.extra_brands: %d entrada(s) ignorada(s); usar un dominio ('marca.com.ar') o "
            "'Nombre: dominio1, dominio2'",
            ignored,
        )
    return tuple(out)


def parse_extra_brands(entries: Iterable[str] | None) -> tuple[Brand, ...]:
    """Marcas de `analyzers.extra_brands` (ver docstring del módulo para el formato)."""
    return _parse_extra_brands(tuple(e for e in (entries or ()) if isinstance(e, str)))


@functools.lru_cache(maxsize=32)
def _extra_brand_index(entries: tuple[str, ...]) -> tuple[tuple[Brand, ...], _BrandIndex]:
    extras = _parse_extra_brands(entries)
    return BRANDS + extras, _brand_index() + _index_brands(extras)


@functools.lru_cache(maxsize=1)
def _all_brand_legit() -> frozenset[str]:
    return frozenset(d for b in BRANDS for d in b.legit)


def brand_owns(brand: Brand, info: DomainInfo) -> bool:
    """True si el dominio es de la marca (lista legítima o variante de país cuando la marca las usa)."""
    if not info.registrable:
        return False
    if info.registrable in brand.legit:
        return True
    if brand.cc_ok and _is_cc_suffix(info.suffix):
        return info.label in brand.keys or any(info.label == d.split(".", 1)[0] for d in brand.legit)
    return False


def brands_owning(host: str) -> list[Brand]:
    info = domain_info(host)
    if info is None or info.is_ip:
        return []
    return [b for b in BRANDS if brand_owns(b, info)]


def is_freemail(host: str) -> bool:
    reg = registrable_domain(host)
    if not reg:
        return False
    if reg in FREEMAIL_DOMAINS:
        return True
    info = domain_info(reg)
    return bool(info and info.label in _FREEMAIL_LABELS and _is_cc_suffix(info.suffix))


def is_user_content(host: str) -> bool:
    info = domain_info(host)
    if info is None:
        return False
    if info.registrable in USER_CONTENT_DOMAINS:
        return True
    return any(
        info.host == d or info.host.endswith("." + d) for d in USER_CONTENT_DOMAINS if d.count(".") > 1
    )


def is_well_known(host: str) -> bool:
    """Dominio legítimo muy conocido (marca, plataforma común o gobierno). Solo para heurísticas débiles."""
    info = domain_info(host)
    if info is None or info.is_ip or not info.registrable or is_user_content(host):
        return False
    if info.registrable in _COMMON_LEGIT or info.registrable in _all_brand_legit():
        return True
    if any(info.suffix == s or info.suffix.endswith("." + s) for s in _GOV_SUFFIXES):
        return True
    return bool(brands_owning(host))


def _norm_words(text: str) -> str:
    """Minúsculas, sin acentos, todo lo que no es letra/dígito -> espacio, espacios colapsados."""
    s = unicodedata.normalize("NFKC", text[:512]).lower()
    s = "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))
    s = "".join(c if c.isalnum() else " " for c in s)
    return " ".join(s.split())


def brands_in_text(text: str, brands: Sequence[Brand] | None = None) -> list[Brand]:
    """Marcas que un texto (nombre visible del remitente) afirma ser. Coincidencia por palabra completa.
    `brands`: lista a usar (por defecto `BRANDS`; `LookalikeDetector.brands` incluye las extra)."""
    norm = f" {_norm_words(text)} "
    if not norm.strip():
        return []
    words = set(norm.split())
    found: list[Brand] = []
    for b in BRANDS if brands is None else brands:
        if any(f" {p} " in norm for p in b.display):
            found.append(b)
            continue
        if b.display_weak and any(f" {p} " in norm for p in b.display_weak):
            ctx = _CONTEXTS.get(b.context, _CTX_GENERIC)
            if words & ctx:
                found.append(b)
    return found


# --------------------------------------------------------------------------- detector

_KIND_TEXT = {
    "homoglyph": "usa letras o números que se ven iguales (por ejemplo 'rn' en vez de 'm', '0' en vez de 'o')",
    "punycode": "usa caracteres de otro alfabeto (por ejemplo cirílico) que se ven idénticos a los latinos",
    "typo": "tiene una o dos letras cambiadas, agregadas o quitadas",
    "tld_swap": "tiene el mismo nombre pero otra terminación (por ejemplo .com.ar en vez de .com)",
    "affix": "le agrega palabras al nombre real (por ejemplo '-pagos' o 'login')",
    "subdomain": "pone el nombre real al principio de un dominio que es de otra persona",
}


@dataclass(frozen=True)
class LookalikeMatch:
    domain: str  # dominio sospechoso (registrable, en Unicode si es IDN)
    target: str  # a quién imita: "empresa.com" o "Mercado Pago"
    target_domain: str  # dominio legítimo de referencia
    kind: str  # homoglyph | punycode | typo | tld_swap | affix | subdomain
    is_brand: bool

    @property
    def explanation(self) -> str:
        return _KIND_TEXT.get(self.kind, "se parece al dominio real")


def _typo_limit(n: int, is_company: bool) -> int:
    if is_company:
        return 0 if n <= 4 else 1 if n <= 6 else 2
    return 0 if n <= 5 else 1 if n <= 8 else 2


def _affix_match(sk_label: str, sk_key: str, need_lure: bool) -> bool:
    """La clave aparece en la etiqueta con un 'agregado' delimitado (guion, número o palabra de anzuelo)."""
    if len(sk_key) < 3 or sk_key == sk_label:
        return False
    start = sk_label.find(sk_key)
    tries = 0
    while start != -1 and tries < 4:
        tries += 1
        left, right = sk_label[:start], sk_label[start + len(sk_key) :]
        lseg = left.rsplit("-", 1)[-1] if left else ""
        rseg = right.split("-", 1)[0] if right else ""
        left_ok = not left or left.endswith("-") or lseg in _LURE_SK or lseg.isdigit()
        right_ok = not right or right.startswith("-") or rseg in _LURE_SK or rseg.isdigit()
        if left_ok and right_ok and (left or right):
            others = [t for t in "".join(c if c.isalpha() else " " for c in f"{left} {right}").split() if t]
            if not need_lure or any(t in _LURE_SK for t in others):
                return True
        start = sk_label.find(sk_key, start + 1)
    return False


def _match_key(
    info: DomainInfo, key: str, sk_key: str, *, weak: bool, is_company: bool, cc_ok: bool
) -> str | None:
    label, ulabel = info.label, info.unicode_label
    if not label:
        return None
    sk_label = skeleton(ulabel)
    if ulabel == key:
        if weak or (cc_ok and _is_cc_suffix(info.suffix)):
            return None
        return "tld_swap"
    if sk_label == sk_key:
        return "punycode" if (label.startswith("xn--") or not ulabel.isascii()) else "homoglyph"
    if not weak and label not in _BENIGN_NEAR_MISSES:
        lim = _typo_limit(len(sk_key), is_company)
        if lim and edit_distance(sk_label, sk_key, lim) <= lim:
            return "typo"
    if (is_company and len(sk_key) >= 4) or not is_company:
        if _affix_match(sk_label, sk_key, need_lure=not is_company or weak):
            return "affix"
    return None


def _subdomain_tokens(sub: str) -> set[str]:
    out: set[str] = set()
    for lab in sub.split(".")[-12:]:
        if not lab:
            continue
        uni = lab
        if lab.startswith("xn--"):
            try:
                uni = lab[4:].encode("ascii").decode("punycode")
            except (UnicodeError, ValueError):
                uni = lab
        sk = skeleton(uni)
        out.add(sk)
        out.add(sk.replace("-", ""))
        out.update(p for p in sk.split("-") if p)
    return out


class LookalikeDetector:
    """Detecta dominios que imitan a los dominios de la empresa o a marcas conocidas.

    `brands`: reemplaza la lista de marcas (tests); `extra_brands`: entradas de `analyzers.extra_brands`
    que se SUMAN a `BRANDS` (ver `parse_extra_brands`)."""

    def __init__(
        self,
        company_domains: Iterable[str] = (),
        brands: Sequence[Brand] | None = None,
        *,
        extra_brands: Iterable[str] = (),
    ) -> None:
        regs: list[DomainInfo] = []
        for d in company_domains:
            d = (d or "").strip().lower().lstrip("@").removeprefix("*.").strip(".")
            info = domain_info(d) if d else None
            if info and info.registrable and not info.is_ip:
                regs.append(domain_info(info.registrable) or info)
        self.company: tuple[DomainInfo, ...] = tuple({r.registrable: r for r in regs}.values())
        self.company_regs = frozenset(r.registrable for r in self.company)
        self._company_keys = tuple((c, skeleton(c.unicode_label)) for c in self.company)
        extras = tuple(e for e in (extra_brands or ()) if isinstance(e, str))
        if brands is not None:
            self.brands: tuple[Brand, ...] = tuple(brands)
            self._brands = _index_brands(self.brands)
        elif extras:
            self.brands, self._brands = _extra_brand_index(extras)
        else:
            self.brands, self._brands = BRANDS, _brand_index()

    # ---- pertenencia
    def is_company(self, host: str | None) -> bool:
        return bool(host) and registrable_domain(host) in self.company_regs

    def same_entity(self, a: str, b: str) -> bool:
        """Mismo dueño: mismo registrable, ambos de la empresa, o ambos de la misma marca."""
        ra, rb = registrable_domain(a), registrable_domain(b)
        if not ra or not rb:
            return False
        if ra == rb or (ra in self.company_regs and rb in self.company_regs):
            return True
        ia, ib = domain_info(ra), domain_info(rb)
        if ia is None or ib is None:
            return False
        return any(brand_owns(br, ia) and brand_owns(br, ib) for br in self.brands)

    def brands_in_text(self, text: str) -> list[Brand]:
        """`brands_in_text` con las marcas de este detector (incluye las extra de la configuración)."""
        return brands_in_text(text, self.brands)

    # ---- detección
    def company_match(self, host: str | None) -> LookalikeMatch | None:
        if not host or not self.company:
            return None
        info = domain_info(host)
        if info is None or info.is_ip or not info.registrable or info.registrable in self.company_regs:
            return None
        for comp, sk_key in self._company_keys:
            kind = _match_key(info, comp.unicode_label, sk_key, weak=False, is_company=True, cc_ok=False)
            if kind:
                return LookalikeMatch(self._display(info), comp.registrable, comp.registrable, kind, False)
        sub = self._subdomain_company(info)
        if sub:
            return sub
        return None

    def brand_match(self, host: str | None) -> LookalikeMatch | None:
        if not host:
            return None
        info = domain_info(host)
        if info is None or info.is_ip or not info.registrable or info.registrable in self.company_regs:
            return None
        owned = info.registrable in _all_brand_legit() or any(brand_owns(b, info) for b, _ in self._brands)
        if not owned:
            for brand, keys in self._brands:
                for key, sk_key, weak in keys:
                    kind = _match_key(info, key, sk_key, weak=weak, is_company=False, cc_ok=brand.cc_ok)
                    if kind:
                        return LookalikeMatch(self._display(info), brand.name, brand.legit[0], kind, True)
        return self._subdomain_brand(info)

    def match(self, host: str | None) -> LookalikeMatch | None:
        return self.company_match(host) or self.brand_match(host)

    # ---- internos
    @staticmethod
    def _display(info: DomainInfo) -> str:
        if info.label != info.unicode_label:
            return f"{info.unicode_label}.{info.suffix} ({info.registrable})"
        return info.registrable

    def _subdomain_company(self, info: DomainInfo) -> LookalikeMatch | None:
        # "empresa.sharepoint.com", "empresa.myshopify.com", "empresa.zendesk.com" suelen ser de la propia
        # empresa: solo se marca cuando el dominio de abajo NO es una plataforma conocida.
        if (
            not info.subdomain
            or info.registrable in SAAS_TENANT_DOMAINS
            or info.registrable in USER_CONTENT_DOMAINS
            or is_well_known(info.registrable)
        ):
            return None
        tokens = _subdomain_tokens(info.subdomain)
        for comp, sk_key in self._company_keys:
            if len(sk_key) >= 4 and sk_key in tokens:
                return LookalikeMatch(info.host, comp.registrable, comp.registrable, "subdomain", False)
        return None

    def _subdomain_brand(self, info: DomainInfo) -> LookalikeMatch | None:
        if not info.subdomain or info.registrable in SAAS_TENANT_DOMAINS:
            return None
        tokens = _subdomain_tokens(info.subdomain)
        for brand, keys in self._brands:
            if brand_owns(brand, info):
                continue
            for _key, sk_key, weak in keys:
                if len(sk_key) < 3:
                    continue
                if not weak and sk_key in tokens:
                    return LookalikeMatch(info.host, brand.name, brand.legit[0], "subdomain", True)
                if any(_affix_match(t, sk_key, need_lure=True) for t in tokens if t != sk_key):
                    return LookalikeMatch(info.host, brand.name, brand.legit[0], "subdomain", True)
        return None


__all__ = [
    "BRANDS",
    "FREEMAIL_DOMAINS",
    "Brand",
    "DomainInfo",
    "LookalikeDetector",
    "LookalikeMatch",
    "brand_owns",
    "brands_in_text",
    "brands_owning",
    "domain_info",
    "edit_distance",
    "email_domain",
    "host_in_domains",
    "is_freemail",
    "is_mixed_script",
    "is_private_ip",
    "is_user_content",
    "is_well_known",
    "is_whole_script_confusable",
    "label_scripts",
    "normalize_domains",
    "normalize_host",
    "parse_extra_brands",
    "parse_ipv4_whatwg",
    "registrable_domain",
    "skeleton",
]
