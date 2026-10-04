"""Analizador de encabezados: autenticación del remitente (SPF/DKIM/DMARC), suplantación y lookalikes.

Qué encabezado de autenticación se usa
--------------------------------------
Cualquiera puede escribir un `Authentication-Results` falso dentro del mail antes de enviarlo. El único
confiable es el que agrega el proveedor que RECIBIÓ el mail (Gmail, Microsoft 365, el servidor propio), y
ese siempre queda ARRIBA de todo. Por eso:

1. Se usa solo el `Authentication-Results` más alto (más los que estén pegados inmediatamente debajo con el
   mismo authserv-id, porque algunos proveedores parten el resultado en varias líneas).
2. Si no hay ninguno, se usa el `ARC-Authentication-Results` de instancia más alta (i=N mayor), que es el
   que agregó el último intermediario que selló la cadena ARC.
3. Para SPF, si no salió de lo anterior, se usa el `Received-SPF` más alto.

Limitación conocida: si el servidor que recibe NO agrega `Authentication-Results` (algunos hostings
cPanel), el header más alto puede venir del atacante. En ese caso solo se pierden detecciones
(un "pass" falso), nunca se generan falsos positivos.

Con `general.trusted_authserv_ids` configurado (ej: ["mx.google.com", "*.prod.outlook.com"]) la regla es
más estricta: solo se usa el `Authentication-Results` (o `ARC-Authentication-Results`) más alto cuyo
authserv-id coincide con la lista ("*.dominio" = cualquier subdominio). Received-SPF no se usa (no trae
authserv-id). Si ninguno coincide se informa "no hay resultados de autenticación confiables" (INFO).
Ojo: Microsoft 365 escribe su Authentication-Results SIN authserv-id; ahí sirve su ARC
("mx.microsoft.com") o dejar la lista vacía.

`general.trusted_domains` (socios/proveedores/ESP): se excluyen de las señales DÉBILES del remitente
(SPF softfail, DKIM/compauth fallido, Return-Path distinto, Reply-To hacia ese dominio). Nunca de la
suplantación del dominio propio, de DMARC/SPF fail ni de las imitaciones de dominios.
"""

from __future__ import annotations

import asyncio
import logging
import re
import unicodedata
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from centinela.analyzers._lookalike import (
    LookalikeDetector,
    LookalikeMatch,
    brand_owns,
    domain_info,
    email_domain,
    host_in_domains,
    is_freemail,
    is_well_known,
    normalize_domains,
    registrable_domain,
)
from centinela.analyzers.base import MessageAnalyzer
from centinela.core.models import Finding, FindingCategory, Severity

if TYPE_CHECKING:
    from collections.abc import Iterable

    from centinela.analyzers.base import AnalysisContext
    from centinela.core.config import Settings
    from centinela.core.models import ParsedMessage

log = logging.getLogger(__name__)

NAME = "headers"
_MAX_HEADER = 16_384
_MAX_HEADERS = 1_000
_MAX_AUTH_HEADERS = 50  # Authentication-Results que se examinan buscando un authserv-id confiable
_AUTH_HEADER_NAMES = ("authentication-results", "arc-authentication-results")

_KNOWN_METHODS = frozenset(
    {"spf", "dkim", "dmarc", "arc", "compauth", "bimi", "iprev", "auth", "dkim-atps", "sender-id", "dkim-adsp",
     "smime", "rrvs", "vbr", "x-dkim", "domainkeys"}
)  # fmt: skip
_SPF_VALUES = frozenset(
    {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror", "hardfail", "policy"}
)
_DMARC_POLICY_RE = re.compile(r"dmarc\s*=\s*fail\b[^;]{0,400}?\bp\s*=\s*(none|quarantine|reject)\b", re.I)
_ARC_INSTANCE_RE = re.compile(r"^\s*i\s*=\s*(\d{1,3})\s*$")

# Plataformas de envío masivo: es normal que el Return-Path sea de ellas.
_ESP_DOMAINS = frozenset(
    {
        "amazonses.com", "sendgrid.net", "mcsv.net", "mcdlv.net", "rsgsv.net", "mailchimpapp.net", "mandrillapp.com",
        "sparkpostmail.com", "mailgun.org", "mailgun.net", "postmarkapp.com", "mktomail.com", "exacttarget.com",
        "cmail19.com", "cmail20.com", "createsend.com", "mailjet.com", "sendinblue.com", "brevo.com",
        "sender-sib.com", "mlsend.com", "hubspotemail.net", "hubspotstarter.net", "fromdoppler.com",
        "embluemail.com", "envialosimple.com", "icommarketing.com", "zohomail.com", "zeptomail.com",
        "salesforce.com", "intercom-mail.com", "customeriomail.com", "constantcontact.com", "rs6.net",
        "elasticemail.com", "smtp2go.com", "mailersend.net", "perfit.com.ar", "mailrelay-i.com",
    }
)  # fmt: skip

_VIA_RE = re.compile(
    r"(?<![a-z])(via|vía|por medio de|on behalf of|en nombre de|a traves de|a través de)(?![a-z])", re.I
)
_EMAIL_IN_TEXT = re.compile(r"[a-z0-9._%+\-]{1,64}@((?:[a-z0-9\-]{1,63}\.){1,6}[a-z0-9\-]{2,63})", re.I)
_DOMAIN_IN_TEXT = re.compile(
    r"(?<![a-z0-9@._\-])((?:www\.)?(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.){1,6}[a-z]{2,24})(?![a-z0-9\-])",
    re.I,
)
# TLDs que también son extensiones de archivo: "factura.zip" en un nombre no es un dominio salvo "www."
_FILEISH_TLDS = frozenset(
    {"zip", "mov", "py", "sh", "pl", "rs", "md", "ps", "so", "ai", "pdf", "doc", "xls", "exe"}
)
_LEGAL_SUFFIXES = frozenset(
    "sa s a srl s r l sas sacif saic sh ltda ltd inc llc corp sl spa de cv sapi gmbh".split()
)


# --------------------------------------------------------------------------- parseo de Authentication-Results


@dataclass
class AuthResults:
    """Resultado de autenticación consolidado (minúsculas)."""

    source: str  # "authentication-results" | "arc-authentication-results" | "received-spf"
    authserv_id: str | None = None
    spf: str | None = None
    spf_source: str | None = None
    dkim: str | None = None
    dmarc: str | None = None
    dmarc_policy: str | None = None  # none | quarantine | reject (si se pudo saber)
    compauth: str | None = None
    header_from: str | None = None
    smtp_mailfrom: str | None = None
    dkim_domains: list[str] = field(default_factory=list)
    instance: int = 0  # i= de ARC

    def evidence(self) -> dict[str, object]:
        ev: dict[str, object] = {"source": self.source}
        for k in (
            "authserv_id",
            "spf",
            "dkim",
            "dmarc",
            "dmarc_policy",
            "compauth",
            "header_from",
            "smtp_mailfrom",
        ):
            v = getattr(self, k)
            if v:
                ev[k] = v
        if self.dkim_domains:
            ev["dkim_domains"] = self.dkim_domains[:5]
        return ev


def strip_comments(value: str) -> str:
    """Quita comentarios RFC 5322 "(...)" (anidados, con escapes), respetando strings entre comillas."""
    out: list[str] = []
    depth = 0
    quoted = False
    i, n = 0, len(value)
    while i < n:
        ch = value[i]
        if ch == "\\" and i + 1 < n:
            if depth == 0:
                out.append(value[i : i + 2])
            i += 2
            continue
        if quoted:
            out.append(ch)
            if ch == '"':
                quoted = False
        elif ch == "(":
            depth += 1
        elif ch == ")" and depth > 0:
            depth -= 1
            if depth == 0:
                out.append(" ")
        elif depth == 0:
            if ch == '"':
                quoted = True
            out.append(ch)
        i += 1
    return "".join(out)


def parse_authentication_results(value: str, *, source: str = "authentication-results") -> AuthResults:
    """Parsea un Authentication-Results (RFC 8601) tolerando formatos de Gmail, Microsoft 365 y otros.

    Microsoft omite el authserv-id ("spf=pass ...; dkim=none ...; dmarc=fail action=none header.from=x").
    ARC-Authentication-Results empieza con "i=N;".
    """
    raw = (value or "")[:_MAX_HEADER]
    res = AuthResults(source=source)
    pol = _DMARC_POLICY_RE.search(raw)
    text = strip_comments(raw)
    segments = [s.strip() for s in text.split(";")][:64]
    if segments and source == "arc-authentication-results":
        m = _ARC_INSTANCE_RE.match(segments[0])
        if m:
            res.instance = int(m.group(1))
            segments = segments[1:]
    if segments and "=" not in segments[0]:
        words = segments[0].split()
        res.authserv_id = words[0].lower()[:255] if words else None
        segments = segments[1:]

    results: list[tuple[str, str, dict[str, str]]] = []
    for seg in segments:
        for tok in seg.split()[:64]:
            if "=" not in tok:
                continue
            k, _, v = tok.partition("=")
            k = k.strip().lower()
            v = v.strip().strip('"').lower()[:255]
            method = k.split("/", 1)[0]
            if method in _KNOWN_METHODS and "." not in k:
                results.append((method, v, {}))
            elif results:
                results[-1][2].setdefault(k, v)
        if len(results) > 64:
            break

    dkim_vals: list[str] = []
    for method, val, props in results:
        if method == "spf" and res.spf is None:
            res.spf = val
            res.spf_source = source
            res.smtp_mailfrom = props.get("smtp.mailfrom") or res.smtp_mailfrom
        elif method == "dkim":
            dkim_vals.append(val)
            d = props.get("header.d") or (props.get("header.i") or "").lstrip("@").rsplit("@", 1)[-1]
            if d and d not in res.dkim_domains:
                res.dkim_domains.append(d)
        elif method == "dmarc" and res.dmarc is None:
            res.dmarc = val
            res.header_from = props.get("header.from")
            action = props.get("action") or props.get("policy.applied-disposition")
            if action in ("none", "quarantine", "reject"):
                res.dmarc_policy = action
            elif action in ("oreject", "pct.quarantine", "pct.reject"):
                res.dmarc_policy = "reject" if "reject" in action else "quarantine"
        elif method == "compauth" and res.compauth is None:
            res.compauth = val
    if pol and not res.dmarc_policy:
        res.dmarc_policy = pol.group(1).lower()
    if dkim_vals:
        res.dkim = "pass" if "pass" in dkim_vals else "fail" if "fail" in dkim_vals else dkim_vals[0]
    return res


def parse_received_spf(value: str) -> str | None:
    """'Received-SPF: SoftFail (protection.outlook.com: ...) ...' -> 'softfail'."""
    text = strip_comments((value or "")[:_MAX_HEADER]).strip()
    if not text:
        return None
    word = text.split(None, 1)[0].lower().rstrip(";")
    return word if word in _SPF_VALUES else None


def _merge_adjacent(headers: list[tuple[str, str]], first: int, primary: AuthResults) -> AuthResults:
    """Suma los Authentication-Results pegados debajo con el mismo authserv-id (resultado partido en varios)."""
    j = first + 1
    while j < len(headers) and j - first <= 4 and headers[j][0].lower() == "authentication-results":
        nxt = parse_authentication_results(headers[j][1])
        if not primary.authserv_id or nxt.authserv_id != primary.authserv_id:
            break
        primary.spf = primary.spf or nxt.spf
        primary.dmarc = primary.dmarc or nxt.dmarc
        primary.dmarc_policy = primary.dmarc_policy or nxt.dmarc_policy
        primary.compauth = primary.compauth or nxt.compauth
        primary.header_from = primary.header_from or nxt.header_from
        primary.smtp_mailfrom = primary.smtp_mailfrom or nxt.smtp_mailfrom
        if nxt.dkim:
            primary.dkim = "pass" if "pass" in (primary.dkim, nxt.dkim) else primary.dkim or nxt.dkim
        primary.dkim_domains.extend(d for d in nxt.dkim_domains if d not in primary.dkim_domains)
        j += 1
    return primary


def normalize_authserv_ids(ids: Iterable[str] | None) -> tuple[str, ...]:
    """Patrones de `general.trusted_authserv_ids` en minúsculas ("*.dominio" = cualquier subdominio)."""
    out: list[str] = []
    for raw in ids or ():
        if not isinstance(raw, str):
            continue
        p = raw.strip().lower().rstrip(".")[:255]
        if not p or p == "*" or p == "*.":
            continue  # "*" confiaría en cualquiera: equivale a no configurar nada
        if p not in out:
            out.append(p)
    return tuple(out[:100])


def authserv_id_trusted(authserv_id: str | None, patterns: tuple[str, ...]) -> bool:
    if not authserv_id or not patterns:
        return False
    a = authserv_id.strip().lower().rstrip(".")
    for p in patterns:
        if p.startswith("*."):
            if a.endswith(p[1:]) and len(a) > len(p) - 1:
                return True
        elif a == p:
            return True
    return False


def _authserv_id_of(value: str, *, arc: bool) -> str | None:
    """authserv-id de un (ARC-)Authentication-Results sin parsear todo el header (barato)."""
    segments = strip_comments((value or "")[:1024]).split(";")
    if arc and segments and _ARC_INSTANCE_RE.match(segments[0]):
        segments = segments[1:]
    if not segments or "=" in segments[0]:
        return None
    words = segments[0].split()
    return words[0].lower()[:255] if words else None


def _collect_trusted(headers: list[tuple[str, str]], patterns: tuple[str, ...]) -> AuthResults | None:
    """El (ARC-)Authentication-Results más alto con un authserv-id de la lista de confiables."""
    seen = 0
    for i, (k, v) in enumerate(headers):
        name = k.lower()
        if name not in _AUTH_HEADER_NAMES:
            continue
        seen += 1
        if seen > _MAX_AUTH_HEADERS:
            break
        arc = name == "arc-authentication-results"
        if not authserv_id_trusted(_authserv_id_of(v, arc=arc), patterns):
            continue
        if arc:
            return parse_authentication_results(v, source="arc-authentication-results")
        return _merge_adjacent(headers, i, parse_authentication_results(v))
    return None


def auth_authserv_ids(msg: ParsedMessage, limit: int = 5) -> list[str]:
    """authserv-id de los (ARC-)Authentication-Results presentes (para la evidencia), sin repetir."""
    out: list[str] = []
    seen = 0
    for k, v in msg.headers[:_MAX_HEADERS]:
        name = k.lower()
        if name not in _AUTH_HEADER_NAMES:
            continue
        seen += 1
        if seen > _MAX_AUTH_HEADERS:
            break
        aid = _authserv_id_of(v, arc=name == "arc-authentication-results") or "(sin authserv-id)"
        aid = aid[:100]
        if aid not in out:
            out.append(aid)
            if len(out) >= limit:
                break
    return out


def collect_auth(msg: ParsedMessage, trusted_authserv_ids: Iterable[str] | None = None) -> AuthResults | None:
    """Elige y consolida los resultados de autenticación confiables (ver docstring del módulo)."""
    headers = msg.headers[:_MAX_HEADERS]
    patterns = normalize_authserv_ids(trusted_authserv_ids)
    if patterns:
        return _collect_trusted(headers, patterns)
    primary: AuthResults | None = None
    first = next((i for i, (k, _) in enumerate(headers) if k.lower() == "authentication-results"), None)
    if first is not None:
        primary = _merge_adjacent(headers, first, parse_authentication_results(headers[first][1]))
    else:
        arcs = [
            parse_authentication_results(v, source="arc-authentication-results")
            for k, v in headers
            if k.lower() == "arc-authentication-results"
        ][:20]
        if arcs:
            primary = max(arcs, key=lambda a: a.instance)

    rspf_raw = next((v for k, v in headers if k.lower() == "received-spf"), None)
    rspf = parse_received_spf(rspf_raw) if rspf_raw else None
    if primary is None and rspf:
        primary = AuthResults(source="received-spf", spf=rspf, spf_source="received-spf")
    elif primary is not None and primary.spf is None and rspf:
        primary.spf = rspf
        primary.spf_source = "received-spf"
    return primary


# --------------------------------------------------------------------------- helpers


def _finding(rule: str, title: str, description: str, category: FindingCategory, severity: Severity, score: int,
             evidence: dict[str, object] | None = None) -> Finding:  # fmt: skip
    return Finding(
        analyzer=NAME,
        rule=rule,
        title=title[:300],
        description=description,
        category=category,
        severity=severity,
        score=max(0, min(100, score)),
        evidence=evidence or {},
    )


def _norm_words(text: str) -> str:
    s = unicodedata.normalize("NFKC", text[:512]).lower()
    s = "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))
    return " ".join("".join(c if c.isalnum() else " " for c in s).split())


def _domains_in_display(display: str) -> list[tuple[str, bool]]:
    """Dominios que aparecen en el nombre visible: [(dominio, venía_como_email)]."""
    out: list[tuple[str, bool]] = []
    seen: set[str] = set()
    text = display[:256]
    for m in _EMAIL_IN_TEXT.finditer(text):
        dom = m.group(1).lower().strip(".")
        if dom not in seen:
            seen.add(dom)
            out.append((dom, True))
    rest = _EMAIL_IN_TEXT.sub(" ", text)
    for m in _DOMAIN_IN_TEXT.finditer(rest):
        dom = m.group(1).lower().strip(".")
        tld = dom.rsplit(".", 1)[-1]
        if tld in _FILEISH_TLDS and not dom.startswith("www."):
            continue
        if dom not in seen:
            seen.add(dom)
            out.append((dom, False))
    return out[:5]


def _company_names(settings: Settings, det: LookalikeDetector) -> list[str]:
    names: list[str] = []
    cname = _norm_words(settings.general.company_name or "")
    if cname and cname != "mi empresa":
        words = [w for w in cname.split() if w not in _LEGAL_SUFFIXES]
        core = " ".join(words)
        if len(core) >= 4:
            names.append(core)
    for c in det.company:
        lab = _norm_words(c.unicode_label)
        if len(lab) >= 5 and lab not in names:
            names.append(lab)
    return names


def _is_esp(dom: str) -> bool:
    reg = registrable_domain(dom)
    return reg in _ESP_DOMAINS or is_well_known(dom)


# --------------------------------------------------------------------------- reglas


def _auth_findings(
    auth: AuthResults | None,
    from_dom: str,
    det: LookalikeDetector,
    *,
    trusted_doms: frozenset[str] = frozenset(),
    untrusted_ids: list[str] | None = None,
    trusted_ids: tuple[str, ...] = (),
) -> list[Finding]:
    if auth is None and untrusted_ids:
        # hay resultados, pero los escribió un servidor que no está en trusted_authserv_ids
        return [
            _finding(
                "headers.no_trusted_auth_results",
                "No hay resultados de autenticación confiables",
                "El mail trae encabezados de verificación del remitente (SPF/DKIM/DMARC), pero ninguno lo agregó "
                "un servidor de la lista de confiables de la configuración ('trusted_authserv_ids'). Como "
                "cualquiera puede escribir esos encabezados antes de mandar el mail, no se tuvieron en cuenta "
                "y no se puede confirmar quién lo envió. Si cambiaste de proveedor de correo, revisá esa lista.",
                FindingCategory.SPOOFING,
                Severity.INFO,
                0,
                {"authserv_ids_found": untrusted_ids[:5], "trusted_authserv_ids": list(trusted_ids[:10])},
            )
        ]
    if auth is None or not (auth.spf or auth.dkim or auth.dmarc or auth.compauth):
        return [
            _finding(
                "headers.no_auth_results",
                "No hay resultados de verificación del remitente",
                "El mail no trae los encabezados con los que el proveedor de correo verifica si el remitente es "
                "auténtico (SPF/DKIM/DMARC). No es peligroso en sí, pero no se puede confirmar quién lo mandó.",
                FindingCategory.SPOOFING,
                Severity.INFO,
                0,
            )
        ]
    out: list[Finding] = []
    ev = auth.evidence()
    if from_dom:
        ev["from_domain"] = from_dom
    dmarc = auth.dmarc or ""
    spf = "fail" if auth.spf == "hardfail" else (auth.spf or "")
    dkim = auth.dkim or ""
    dmarc_pass = dmarc in ("pass", "bestguesspass")
    own = det.is_company(from_dom)

    own_spoof = own and (
        dmarc == "fail"
        or (
            dmarc in ("", "none", "temperror", "permerror") and spf in ("fail", "softfail") and dkim != "pass"
        )
    )
    if own_spoof:
        out.append(
            _finding(
                "headers.own_domain_spoof",
                f"Mail que se hace pasar por la propia empresa ({from_dom})",
                f"El mail dice venir de {from_dom}, que es un dominio de la empresa, pero el servidor que lo "
                "recibió comprobó que NO salió de los servidores autorizados de la empresa (falló la "
                "verificación SPF/DMARC). Es la técnica típica para pedir transferencias o datos haciéndose pasar "
                "por un jefe o un compañero. Ante cualquier pedido de dinero o datos, confirmarlo por teléfono.",
                FindingCategory.SPOOFING,
                Severity.HIGH,
                70,
                ev,
            )
        )
        return out
    if dmarc == "fail":
        weak_policy = auth.dmarc_policy == "none"
        out.append(
            _finding(
                "headers.dmarc_fail",
                f"El remitente no pasó la verificación DMARC ({from_dom or 'dominio desconocido'})",
                "El dominio del remitente publica una regla (DMARC) para comprobar que sus mails son auténticos, "
                "y este mail no la cumple. Puede ser una suplantación del remitente o un error de configuración "
                "de quien envía. Desconfiar de pedidos de pago, cambios de datos o links de inicio de sesión."
                + (" (El dominio tiene la política en modo 'solo monitorear'.)" if weak_policy else ""),
                FindingCategory.SPOOFING,
                Severity.MEDIUM,
                30 if weak_policy else 40,
                ev,
            )
        )
        return out  # SPF/DKIM ya están contemplados dentro de DMARC: no se suman de nuevo
    # socio/ESP de confianza: las señales débiles (softfail, DKIM/compauth) suelen ser mala configuración suya
    from_trusted = host_in_domains(from_dom, trusted_doms)
    mailfrom_trusted = host_in_domains(email_domain(auth.smtp_mailfrom) or auth.smtp_mailfrom, trusted_doms)
    weak_ok = not (from_trusted or mailfrom_trusted)
    if not dmarc_pass:
        if spf == "fail":
            out.append(
                _finding(
                    "headers.spf_fail",
                    "El servidor que envió el mail no está autorizado por el dominio (SPF)",
                    f"El dominio {auth.smtp_mailfrom or from_dom or ''} declara qué servidores pueden mandar sus "
                    "mails y este mail salió de uno que no está en la lista. Suele pasar con mails falsificados "
                    "(y a veces con reenvíos automáticos).",
                    FindingCategory.SPOOFING,
                    Severity.MEDIUM,
                    30,
                    ev,
                )
            )
        elif spf == "softfail" and weak_ok:
            out.append(
                _finding(
                    "headers.spf_softfail",
                    "El dominio no reconoce del todo al servidor que envió el mail (SPF softfail)",
                    "El dominio del remitente indica que este servidor 'probablemente' no está autorizado a mandar "
                    "sus mails. Es una señal débil de suplantación.",
                    FindingCategory.SPOOFING,
                    Severity.LOW,
                    10,
                    ev,
                )
            )
        if dkim == "fail" and not from_trusted:
            out.append(
                _finding(
                    "headers.dkim_fail",
                    "La firma digital del mail (DKIM) no es válida",
                    "El mail tiene una firma digital que no coincide: pudo haber sido modificado en el camino o "
                    "falsificado. A veces lo causan listas de correo que alteran el mensaje.",
                    FindingCategory.SPOOFING,
                    Severity.LOW,
                    15,
                    ev,
                )
            )
        if auth.compauth == "fail" and not from_trusted:
            out.append(
                _finding(
                    "headers.compauth_fail",
                    "Microsoft no pudo verificar al remitente (compauth)",
                    "La verificación combinada de Microsoft 365 indica que el remitente no es quien dice ser.",
                    FindingCategory.SPOOFING,
                    Severity.LOW,
                    15,
                    ev,
                )
            )
    return out


def _display_findings(
    msg: ParsedMessage, settings: Settings, det: LookalikeDetector, from_dom: str
) -> list[Finding]:
    out: list[Finding] = []
    display = (msg.from_display or "").strip()[:256]
    if not display or not from_dom:
        return out
    from_info = domain_info(from_dom)
    freemail = is_freemail(from_dom)
    platform = is_well_known(from_dom) and not freemail
    via = bool(_VIA_RE.search(display))
    own = det.is_company(from_dom)

    # 1) el nombre visible muestra otro mail / dominio
    shown_bad: list[tuple[str, bool]] = []
    for dom, as_email in _domains_in_display(display):
        info = domain_info(dom)
        if info is None or not info.registrable:
            continue
        if det.same_entity(dom, from_dom) or (platform and via):
            continue
        shown_bad.append((dom, as_email))
    if shown_bad:
        dom, as_email = shown_bad[0]
        strong = as_email or det.is_company(dom) or is_well_known(dom)
        out.append(
            _finding(
                "headers.display_name_spoof",
                f"El nombre del remitente muestra '{dom}' pero el mail viene de {from_dom}",
                f"En el nombre visible aparece {'la dirección' if as_email else 'el dominio'} '{dom}', pero el mail "
                f"en realidad lo envió una cuenta de {from_dom}. Es un truco para que en el celular o en Outlook se "
                "vea una dirección conocida y la persona no mire la dirección real.",
                FindingCategory.SPOOFING,
                Severity.HIGH if strong else Severity.MEDIUM,
                65 if strong else 45,
                {
                    "display_name": display,
                    "shown_domains": [d for d, _ in shown_bad],
                    "from_domain": from_dom,
                },
            )
        )

    # 2) el nombre visible dice ser una marca conocida
    if not own and from_info is not None:
        claimed = [
            b
            for b in det.brands_in_text(display)
            if not (brand_owns(b, from_info) and not freemail) and not (platform and via)
        ]
        if claimed:
            names = ", ".join(b.name for b in claimed[:3])
            out.append(
                _finding(
                    "headers.display_name_brand",
                    f"El remitente dice ser {names} pero escribe desde {from_dom}",
                    f"{claimed[0].name} no envía sus mails desde {from_dom}"
                    + (" (una casilla gratuita que cualquiera puede crear)" if freemail else "")
                    + ". Usar el nombre de una empresa conocida en el remitente es la forma más común de phishing. "
                    "No hacer clic en links ni abrir adjuntos; ante la duda, entrar al sitio oficial escribiendo "
                    "la dirección a mano.",
                    FindingCategory.SPOOFING,
                    Severity.HIGH if freemail else Severity.MEDIUM,
                    60 if freemail else 45,
                    {
                        "display_name": display,
                        "brands": [b.name for b in claimed[:5]],
                        "from_domain": from_dom,
                    },
                )
            )

    # 3) el nombre visible usa el nombre de la empresa desde afuera
    if not own and not (platform and via):
        norm = f" {_norm_words(display)} "
        hits = [n for n in _company_names(settings, det) if f" {n} " in norm]
        if hits:
            out.append(
                _finding(
                    "headers.display_name_company",
                    f"Alguien usa el nombre de la empresa desde una casilla externa ({from_dom})",
                    f"El nombre visible menciona a la empresa ('{hits[0]}'), pero el mail viene de {from_dom}, que no "
                    "es un dominio de la empresa"
                    + (" sino una casilla gratuita" if freemail else "")
                    + ". Así se hacen los fraudes de 'mail del jefe' (BEC): verificar por otro medio antes de "
                    "pagar o enviar información.",
                    FindingCategory.SPOOFING,
                    Severity.HIGH if freemail else Severity.MEDIUM,
                    60 if freemail else 40,
                    {"display_name": display, "company_match": hits[0], "from_domain": from_dom},
                )
            )
    return out


def _reply_to_findings(
    msg: ParsedMessage, det: LookalikeDetector, from_dom: str, trusted_doms: frozenset[str] = frozenset()
) -> list[Finding]:
    if not from_dom or not msg.reply_to:
        return []
    if is_well_known(from_dom) and not is_freemail(from_dom):
        return []  # Google Forms, calendarios, DocuSign...: el Reply-To es la persona que usó la plataforma
    for rt in msg.reply_to[:5]:
        rt_dom = email_domain(rt)
        if not rt_dom or det.same_entity(rt_dom, from_dom) or host_in_domains(rt_dom, trusted_doms):
            continue
        free = is_freemail(rt_dom)
        look = det.match(rt_dom)
        if not (free or look):
            continue
        own = det.is_company(from_dom)
        reason = "una casilla gratuita" if free else f"un dominio que imita a {look.target}" if look else ""
        return [
            _finding(
                "headers.reply_to_mismatch",
                f"Las respuestas irían a otra dirección ({rt_dom})",
                f"El mail dice venir de {from_dom}, pero si se responde, la respuesta va a {rt_dom} ({reason}). "
                "Es típico del fraude por mail a empresas (BEC): el atacante quiere que la conversación siga con "
                "él, por ejemplo para pedir un pago a otra cuenta.",
                FindingCategory.SPOOFING,
                Severity.MEDIUM,
                45 if own else 35,
                {"from_domain": from_dom, "reply_to": rt[:254], "reply_to_freemail": free},
            )
        ]
    return []


def _return_path_findings(msg: ParsedMessage, det: LookalikeDetector, from_dom: str, auth: AuthResults | None,
                          trusted_doms: frozenset[str] = frozenset()) -> list[Finding]:  # fmt: skip
    rp_dom = email_domain(msg.return_path)
    if not rp_dom or not from_dom or det.same_entity(rp_dom, from_dom):
        return []
    if auth is not None and auth.dmarc in ("pass", "bestguesspass"):
        return []
    if _is_esp(rp_dom) or host_in_domains(rp_dom, trusted_doms) or host_in_domains(from_dom, trusted_doms):
        return []  # señal débil: no aplica a ESP conocidos ni a dominios de confianza
    return [
        _finding(
            "headers.return_path_mismatch",
            "El remitente técnico es de otro dominio",
            f"La dirección de rebote (Return-Path) es de {rp_dom}, distinta del remitente visible ({from_dom}). "
            "Es común en mails masivos, pero también en suplantaciones.",
            FindingCategory.SPOOFING,
            Severity.LOW,
            10,
            {"return_path_domain": rp_dom, "from_domain": from_dom},
        )
    ]


def _lookalike_findings(msg: ParsedMessage, det: LookalikeDetector, from_dom: str) -> list[Finding]:
    candidates: list[tuple[str, str]] = []
    if from_dom:
        candidates.append(("From", from_dom))
    candidates += [("Reply-To", email_domain(r)) for r in msg.reply_to[:5]]
    sender = msg.header("sender")
    if sender:
        candidates.append(("Sender", email_domain(sender)))
    if msg.return_path:
        candidates.append(("Return-Path", email_domain(msg.return_path)))

    company: list[tuple[str, LookalikeMatch]] = []
    brand: list[tuple[str, LookalikeMatch]] = []
    seen: set[tuple[str, str]] = set()
    for hdr, dom in candidates:
        if not dom:
            continue
        m = det.company_match(dom)
        if m and (hdr, m.domain) not in seen:
            seen.add((hdr, m.domain))
            company.append((hdr, m))
            continue
        if hdr in ("From", "Reply-To"):
            b = det.brand_match(dom)
            if b and (hdr, b.domain) not in seen:
                seen.add((hdr, b.domain))
                brand.append((hdr, b))

    out: list[Finding] = []
    if company:
        hdr, m = company[0]
        out.append(
            _finding(
                "headers.lookalike_domain",
                f"Dominio parecido al de la empresa: {m.domain}",
                f"El {hdr} usa {m.domain}, que se parece a {m.target} pero no es el mismo: {m.explanation}. "
                "Se usa para que un mail falso parezca interno o de alguien de confianza. Si este dominio también "
                "es de la empresa, agregarlo a 'company_domains' en la configuración.",
                FindingCategory.SPOOFING,
                Severity.HIGH,
                70,
                {
                    "matches": [
                        {"header": h, "domain": x.domain, "imitates": x.target, "kind": x.kind}
                        for h, x in company
                    ]
                },
            )
        )
    if brand:
        hdr, m = brand[0]
        out.append(
            _finding(
                "headers.lookalike_brand",
                f"Dominio que imita a {m.target}: {m.domain}",
                f"El {hdr} usa {m.domain}, que imita a {m.target} ({m.target_domain}): {m.explanation}. "
                f"{m.target} no usa ese dominio; es una técnica típica de phishing.",
                FindingCategory.SPOOFING,
                Severity.HIGH,
                65,
                {
                    "matches": [
                        {"header": h, "domain": x.domain, "imitates": x.target, "kind": x.kind}
                        for h, x in brand
                    ]
                },
            )
        )
    return out


def analyze_message_headers(msg: ParsedMessage, settings: Settings) -> list[Finding]:
    """Versión sincrónica (CPU) del análisis de encabezados."""
    det = LookalikeDetector(settings.general.company_domains, extra_brands=settings.analyzers.extra_brands)
    trusted_doms = normalize_domains(settings.general.trusted_domains)
    trusted_ids = normalize_authserv_ids(settings.general.trusted_authserv_ids)
    from_dom = email_domain(msg.from_addr)
    auth = collect_auth(msg, trusted_ids)
    untrusted_ids = auth_authserv_ids(msg) if trusted_ids and auth is None else None
    findings: list[Finding] = []
    findings += _auth_findings(
        auth, from_dom, det, trusted_doms=trusted_doms, untrusted_ids=untrusted_ids, trusted_ids=trusted_ids
    )
    findings += _display_findings(msg, settings, det, from_dom)
    findings += _reply_to_findings(msg, det, from_dom, trusted_doms)
    findings += _return_path_findings(msg, det, from_dom, auth, trusted_doms)
    findings += _lookalike_findings(msg, det, from_dom)
    return findings


class HeaderAnalyzer(MessageAnalyzer):
    """SPF/DKIM/DMARC, suplantación del nombre visible, Reply-To engañoso y dominios parecidos."""

    name = NAME

    async def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        return await asyncio.to_thread(analyze_message_headers, ctx.message, ctx.settings)
