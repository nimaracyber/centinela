"""Analizador de contenido: señuelos típicos en asunto y cuerpo (español, portugués e inglés).

Busca frases de facturas/pagos, pedidos de credenciales, urgencia, fraude de "cambio de cuenta bancaria"
(BEC), pretextos de fraude del CEO ("estoy en una reunión", tarjetas de regalo) y el patrón
"adjunto comprimido/cifrado + la contraseña en el texto" (técnica para que el antivirus no lo revise).

Las coincidencias son por palabra completa, sin importar mayúsculas ni acentos, y se eliminan los
caracteres invisibles (zero-width, soft hyphen) que los atacantes intercalan para esquivar filtros.
Las señales de texto por sí solas puntúan bajo: solo suben cuando se combinan con adjuntos riesgosos.
"Adjunto con contraseña" = un comprimido adjunto, cualquier artifact `encrypted` (no se pudo abrir) o un
comprimido `password_protected` en cualquier nivel (aunque se haya abierto con la clave del mail: la
técnica de evasión es la misma). Nunca se guarda el cuerpo del mail: la evidencia son solo las frases
detectadas (y la contraseña enmascarada).
"""

from __future__ import annotations

import asyncio
import logging
import re
import unicodedata
from collections.abc import Iterable
from html.parser import HTMLParser
from typing import TYPE_CHECKING

from centinela.analyzers.base import MessageAnalyzer
from centinela.core.models import Finding, FindingCategory, Severity

if TYPE_CHECKING:
    from centinela.analyzers.base import AnalysisContext
    from centinela.core.models import Artifact, ParsedMessage

log = logging.getLogger(__name__)

NAME = "content"
_MAX_HTML = 2_000_000
_MAX_TEXT = 300_000
_MAX_PHRASES = 8

_ARCHIVE_TYPES = frozenset(
    {"zip", "jar", "7z", "rar", "gzip", "bzip2", "xz", "tar", "cab", "iso", "udf", "vhd", "vhdx", "img"}
)
_ARCHIVE_EXTS = frozenset(
    {
        "zip",
        "rar",
        "7z",
        "gz",
        "tgz",
        "bz2",
        "xz",
        "tar",
        "cab",
        "iso",
        "img",
        "vhd",
        "vhdx",
        "arj",
        "lzh",
        "ace",
        "z",
    }
)
_RISKY_TYPES = _ARCHIVE_TYPES | frozenset(
    {"pe", "msi", "lnk", "html", "svg", "onenote", "chm", "url_shortcut", "iqy", "slk", "reg", "elf", "macho"}
)
_RISKY_EXTS = _ARCHIVE_EXTS | frozenset(
    "exe scr com pif cpl msi js jse vbs vbe wsf wsh hta ps1 bat cmd lnk one chm html htm shtml svg xhtml url iqy slk reg jar".split()
)


# --------------------------------------------------------------------------- HTML -> texto


class _Stop(Exception):
    pass


class _TextExtractor(HTMLParser):
    _SKIP = frozenset({"script", "style", "head", "title", "noscript", "template"})
    _BLOCK = frozenset(
        {"p", "div", "br", "li", "tr", "td", "th", "h1", "h2", "h3", "h4", "h5", "h6", "table", "section",
         "article", "blockquote", "ul", "ol", "hr", "header", "footer", "center"}
    )  # fmt: skip

    def __init__(self, limit: int) -> None:
        super().__init__(convert_charrefs=True)
        self._parts: list[str] = []
        self._size = 0
        self._skip = 0
        self._limit = limit

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self._SKIP:
            self._skip += 1
        elif tag in self._BLOCK:
            self._parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIP:
            self._skip = max(0, self._skip - 1)
        elif tag in self._BLOCK:
            self._parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self._skip:
            return
        self._parts.append(data)
        self._size += len(data)
        if self._size > self._limit:
            raise _Stop

    def text(self) -> str:
        return "".join(self._parts)[: self._limit]


def html_to_text(html: str, limit: int = _MAX_TEXT) -> str:
    """Convierte HTML a texto plano (sin scripts/estilos). Lineal y tolerante a HTML roto."""
    if not html:
        return ""
    parser = _TextExtractor(limit)
    try:
        parser.feed(html[:_MAX_HTML])
        parser.close()
    except _Stop:
        pass
    except Exception as exc:  # noqa: BLE001 - HTML hostil: nos quedamos con lo que se pudo extraer
        log.debug("html_to_text: HTML inválido (%s)", type(exc).__name__)  # nunca el contenido del mail
    return parser.text()


def normalize_text(text: str) -> str:
    """Minúsculas, sin acentos ni caracteres invisibles, espacios colapsados (saltos de línea se conservan)."""
    s = text[:_MAX_TEXT]
    if not s.isascii():
        s = unicodedata.normalize("NFKC", s)
        s = "".join(
            c
            for c in unicodedata.normalize("NFKD", s)
            if not unicodedata.combining(c) and unicodedata.category(c) != "Cf"
        )
    s = s.lower()
    s = re.sub(r"[^\S\n]+", " ", s)
    return re.sub(r" ?\n[\s]*", "\n", s)


# --------------------------------------------------------------------------- diccionarios


def _phrases_re(phrases: Iterable[str]) -> re.Pattern[str]:
    alts = sorted({re.escape(p).replace(r"\ ", " ") for p in phrases}, key=len, reverse=True)
    return re.compile(r"(?<![a-z0-9])(?:" + "|".join(alts) + r")(?![a-z0-9])")


_INVOICE = _phrases_re(
    """
factura|facturas|factura electronica|factura adjunta|facturacion|comprobante|comprobantes|comprobante de pago
comprobante de transferencia|transferencia bancaria|transferencia realizada|orden de compra|orden de pago|cotizacion
presupuesto|remito|aviso de pago|nota de credito|nota de debito|recibo de pago|pago pendiente|pagos pendientes
saldo pendiente|saldo deudor|deuda pendiente|estado de cuenta|resumen de cuenta|afip|arca|carta documento|embargo
citacion|notificacion judicial|cedula de notificacion|intimacion|multa|multas|infraccion|boleto|nota fiscal
fatura|faturas|comprovante|comprovante de pagamento|pedido de compra|cotacao|orcamento|boleto bancario|segunda via
nf-e|danfe|intimacao|nota fiscal eletronica|invoice|invoices|payment receipt|proof of payment|remittance advice
purchase order|wire transfer|payment advice|quotation|overdue payment|outstanding balance|statement of account
payment confirmation|bank transfer
""".replace("\n", "|")
    .strip("|")
    .split("|")
)

_CREDENTIAL = _phrases_re(
    """
buzon lleno|buzon esta lleno|buzon de correo esta lleno|su buzon ha alcanzado|casilla llena|casilla esta llena
mailbox is full|mailbox full|mailbox is almost full|caixa de correio cheia|caixa postal cheia|caixa de entrada cheia
cuota de almacenamiento|storage quota|almacenamiento lleno|almacenamiento esta lleno|limite de almacenamiento
storage limit|storage is full|actualice sus datos|actualiza tus datos|actualizar sus datos|actualizar tus datos
actualice su informacion|actualice su cuenta|update your information|update your account|update your details
atualize seus dados|atualizar seus dados|sesion suspendida|sesion expirada|cuenta suspendida|cuenta bloqueada
cuenta sera suspendida|cuenta sera bloqueada|cuenta sera cerrada|cuenta sera desactivada|cuenta deshabilitada
acceso suspendido|acceso restringido|inicio de sesion inusual|actividad inusual|actividad sospechosa
acceso no autorizado|mensajes retenidos|mensajes pendientes de entrega|correos retenidos|correos pendientes
account suspended|account has been suspended|account will be suspended|account locked|unusual sign-in
unusual sign in activity|unusual activity|suspicious activity|unauthorized access|pending messages
messages on hold|held messages|conta suspensa|conta bloqueada|atividade incomum|atividade suspeita
acesso nao autorizado|verifique sua conta|confirme sua identidade|confirme su identidad|confirmar su identidad
confirma tu identidad|verify your identity|confirm your identity|verify your account|validate your account
confirm your account|reactivate your account|reactive su cuenta|ingrese sus credenciales|ingrese su contrasena
ingresa tu contrasena|enter your password|sign in to view|log in to view|le han compartido un documento
shared a document with you|shared a file with you|compartio un archivo con usted|ha compartido un archivo con usted
""".replace("\n", "|")
    .strip("|")
    .split("|")
)
_CREDENTIAL_RE = (
    re.compile(
        r"(?<![a-z0-9])(?:verifi\w{1,6}|valid\w{1,6}|confirm\w{1,6}|reactiv\w{1,6}) (?:su|tu|sus|tus|la|el|your|sua|seu) "
        r"(?:cuenta|identidad|correo|buzon|usuario|account|identity|mailbox|email|e-mail|conta|identidade)(?![a-z0-9])"
    ),
    re.compile(
        r"(?<![a-z0-9])(?:contrasena|clave|password|senha)s?(?: [a-z0-9]{1,15}){0,3}? "
        r"(?:expira|expirara|ha expirado|expiro|vence|vencera|ha vencido|vencio|caduca|caducara|ha caducado|caduco"
        r"|expire|expires|will expire|has expired|expired|expirou|vai expirar)(?![a-z0-9])"
    ),
)

_URGENCY = _phrases_re(
    """
urgente|urgencia|inmediato|inmediata|inmediatamente|de inmediato|dentro de las 24 horas|en las proximas 24 horas
dentro de las 48 horas|en las proximas 48 horas|ultimo aviso|ultima notificacion|ultima advertencia|ultimo recordatorio
accion requerida|se requiere accion|accion inmediata|respuesta inmediata|hoy mismo|a la brevedad|de lo contrario
sera suspendida|sera eliminada|sera bloqueada|sera cancelada|evitar la suspension|evite la suspension
evitar el bloqueo|vence hoy|urgent|immediately|immediate action|action required|within 24 hours|within 48 hours
final notice|final warning|last reminder|as soon as possible|asap|will be suspended|will be deleted|will be closed
imediatamente|imediato|acao necessaria|dentro de 24 horas|sera suspensa
""".replace("\n", "|")
    .strip("|")
    .split("|")
)

_BANK_TERMS = (
    r"(?:cbu|cvu|alias|cuenta bancaria|cuentas bancarias|datos bancarios|numero de cuenta|clabe|iban|swift"
    r"|bank account|bank details|banking details|bank information|banking information|wire instructions"
    r"|payment instructions|conta bancaria|dados bancarios|chave pix)"
)
_BANK_CHANGE_RE = (
    re.compile(
        r"(?<![a-z0-9])(?:nuev[oa]s?|cambi\w{0,5}|actualiz\w{0,6}|modific\w{0,6}|new|updated|changed?|nov[oa]s?"
        r"|alterad[oa]s?|alteracao|mudanca)"
        r"(?: (?:de|del|la|el|los|las|nuestr[oa]s?|mi|mis|su|sus|our|my|the|of|in|to|a|en|dos|da|do|nossa|nosso|minha)){0,4} "
        + _BANK_TERMS
        + r"(?![a-z0-9])"
    ),
    re.compile(
        r"(?<![a-z0-9])"
        + _BANK_TERMS
        + r"(?: [a-z]{1,15}){0,3}? (?:nuev[oa]s?|actualizad[oa]s?|modificad[oa]s?|cambi[oa]\w{0,4}|has changed"
        r"|have changed|changed|updated|alterad[oa]s?|mudou)(?![a-z0-9])"
    ),
)

_PRETEXT = _phrases_re(
    """
estoy en una reunion|estoy en reunion|estoy reunido|estoy reunida|estoy en una conferencia|no puedo atender llamadas
no puedo hablar|no puedo atender|no me llames|solo por mail|solo por correo|necesito un favor|necesito que me hagas un favor
podes hacerme un favor|puedes hacerme un favor|me podes hacer un favor|me puedes hacer un favor|me haces un favor
estas disponible|estas en la oficina|tenes un minuto|tienes un minuto|mantenelo en reserva
mantenlo en reserva|mantengalo en reserva|no comentes con nadie|necesito que realices una transferencia
necesito que hagas una transferencia|realizar un pago urgente|i'm in a meeting|im in a meeting|i am in a meeting
are you available|are you at your desk|quick favor|i need a favor|do me a favor|keep this confidential
estou em uma reuniao|estou em reuniao|voce esta disponivel|preciso de um favor
""".replace("\n", "|")
    .strip("|")
    .split("|")
)
_GIFT = _phrases_re(
    """
tarjetas de regalo|tarjeta de regalo|gift card|gift cards|giftcard|giftcards|tarjetas de google play
tarjetas google play|tarjetas itunes|tarjetas de itunes|tarjetas de apple|tarjetas steam|tarjetas de steam
tarjetas amazon|cartao presente|cartoes presente|vale presente|google play cards|itunes cards|steam cards|amazon cards
""".replace("\n", "|")
    .strip("|")
    .split("|")
)

_PW_KEYWORD = r"(?:contrasena|contrasenas|clave|password|passwd|pass|pwd|senha|codigo|pin)"
_PW_FILLER = (
    r"(?: (?:del|de|para|do|da|of|for|to|the|el|la|los|las|este|esta|archivo|archivos|adjunto|adjuntos|documento"
    r"|documentos|zip|rar|pdf|file|files|attachment|attachments|arquivo|anexo|anexos|abrir|apertura|open|it)){0,6}"
)
_PW_VALUE = r"[\"'«“]?([a-z0-9@#$%&*_.!\-]{3,32})"
_PW_STRICT_RE = re.compile(
    r"(?<![a-z0-9])"
    + _PW_KEYWORD
    + _PW_FILLER
    + r"(?: ?[:=] ?| (?:es|is|e|seria|sera|son|sao)(?: ?[:=])? )"
    + _PW_VALUE
)
_PW_LOOSE_RE = re.compile(
    r"(?<![a-z0-9])" + _PW_KEYWORD + _PW_FILLER + r" (?=[a-z@#$%&*_.!\-]*\d)" + _PW_VALUE
)
_PW_MENTION_RE = re.compile(
    r"(?<![a-z0-9])(?:(?:protegid[oa]s?|encriptad[oa]s?|cifrad[oa]s?|bloquead[oa]s?) (?:con|por|mediante) "
    r"(?:una )?(?:contrasena|clave|password|senha)|password[ -]protected|protected (?:with|by) (?:a )?password"
    r"|protegid[oa]s? (?:com|por) senha|com senha|zip con (?:contrasena|clave))(?![a-z0-9])"
)
_PW_VALUE_STOPWORDS = frozenset(
    "incorrecta incorrecto invalida valida segura seguro temporal nueva nuevo personal requerida necesaria obligatoria "
    "expira vence caduca fiscal token incorrect invalid required expired secreta secreto".split()
)


def _find(pattern: re.Pattern[str], text: str, limit: int = _MAX_PHRASES) -> list[str]:
    out: list[str] = []
    for m in pattern.finditer(text):
        p = m.group(0).strip()
        if p not in out:
            out.append(p)
            if len(out) >= limit:
                break
    return out


def _password_hint(text: str) -> tuple[str | None, bool]:
    """(contraseña enmascarada o None, se menciona 'protegido con contraseña')."""
    for rx in (_PW_STRICT_RE, _PW_LOOSE_RE):
        for m in rx.finditer(text):
            val = m.group(1).strip(".-!")
            if len(val) >= 3 and val not in _PW_VALUE_STOPWORDS:
                return val[0] + "*" * (len(val) - 1), True
    return None, bool(_PW_MENTION_RE.search(text))


# --------------------------------------------------------------------------- reglas


def _finding(rule: str, title: str, description: str, category: FindingCategory, severity: Severity, score: int,
             evidence: dict[str, object]) -> Finding:  # fmt: skip
    return Finding(
        analyzer=NAME,
        rule=rule,
        title=title,
        description=description,
        category=category,
        severity=severity,
        score=max(0, min(100, score)),
        evidence=evidence,
    )


def _sev(score: int) -> Severity:
    if score <= 0:
        return Severity.INFO
    if score < 25:
        return Severity.LOW
    if score < 60:
        return Severity.MEDIUM
    return Severity.HIGH


def _is_archive(a: Artifact) -> bool:
    return a.detected_type in _ARCHIVE_TYPES or a.extension in _ARCHIVE_EXTS


def _is_risky(a: Artifact) -> bool:
    return (
        a.detected_type in _RISKY_TYPES or a.detected_type.startswith("script/") or a.extension in _RISKY_EXTS
    )


def _is_protected(a: Artifact) -> bool:
    """Tenía contraseña: `encrypted` (no se pudo abrir, cualquier tipo) o un comprimido con
    `password_protected` aunque se haya abierto (por ejemplo con la clave del mail: igual es la técnica de
    evasión). Un PDF/Office abierto con clave no cuenta acá: lo evalúan sus analizadores."""
    return a.encrypted or (a.password_protected and _is_archive(a))


def analyze_content(msg: ParsedMessage) -> list[Finding]:
    """Versión sincrónica (CPU) del análisis de contenido."""
    subject = normalize_text(msg.subject or "")
    body_parts = [msg.body_text or ""]
    if msg.body_html and len((msg.body_text or "").strip()) < 200:
        body_parts.append(html_to_text(msg.body_html))
    elif msg.body_html:
        body_parts.append(html_to_text(msg.body_html, limit=_MAX_TEXT // 2))
    body = normalize_text("\n".join(body_parts))
    text = f"{subject}\n{body}"

    attachments = [a for a in msg.artifacts if a.depth == 0]
    risky_att = [a for a in attachments if _is_risky(a)]
    protected = [a for a in msg.artifacts if _is_protected(a)]
    protected_ids = {a.id for a in protected}
    archive_or_encrypted = protected + [
        a for a in attachments if _is_archive(a) and a.id not in protected_ids
    ]

    inv = _find(_INVOICE, text)
    cred = _find(_CREDENTIAL, text) + [p for rx in _CREDENTIAL_RE for p in _find(rx, text, 3)]
    urg = _find(_URGENCY, text)
    bank = [p for rx in _BANK_CHANGE_RE for p in _find(rx, text, 4)]
    pretext = _find(_PRETEXT, text)
    gift = _find(_GIFT, text)
    pw_masked, pw_present = _password_hint(text)

    def ev(phrases: list[str], **extra: object) -> dict[str, object]:
        in_subject = any(p in subject for p in phrases)
        return {"phrases": phrases[:_MAX_PHRASES], "in_subject": in_subject, **extra}

    out: list[Finding] = []
    if pw_present and attachments:
        names = [a.filename or a.id for a in (archive_or_encrypted or attachments)][:5]
        if archive_or_encrypted:
            out.append(
                _finding(
                    "content.password_protected_lure",
                    "Adjunto comprimido o cifrado con la contraseña en el mismo mail",
                    "El mail trae un archivo protegido con contraseña y la contraseña para abrirlo está escrita en "
                    "el texto. Los atacantes lo hacen para que los antivirus no puedan revisar el contenido. "
                    "Un proveedor legítimo rara vez lo necesita: no abrirlo sin confirmar con el remitente por "
                    "otro medio.",
                    FindingCategory.SUSPICIOUS_FILE,
                    Severity.HIGH,
                    65,
                    {
                        "attachments": names,
                        "password_hint": pw_masked,
                        "encrypted": any(a.encrypted for a in msg.artifacts),
                        "password_protected": [a.filename or a.id for a in protected][:5],
                    },
                )
            )
        else:
            out.append(
                _finding(
                    "content.password_hint",
                    "El mail incluye una contraseña para abrir un adjunto",
                    "El texto da una contraseña para abrir un archivo adjunto. Puede ser legítimo (recibos de "
                    "sueldo, resúmenes), pero también se usa para esconder contenido malicioso de los antivirus.",
                    FindingCategory.SUSPICIOUS_FILE,
                    Severity.LOW,
                    15,
                    {"attachments": names, "password_hint": pw_masked},
                )
            )

    if bank:
        score = 45 + (5 if urg else 0)
        out.append(
            _finding(
                "content.bec_bank_change",
                "El mail informa un cambio de cuenta bancaria",
                "El mensaje avisa sobre nuevos datos bancarios (CBU/CVU/alias o cuenta). Es el fraude más costoso "
                "para las PyMEs: alguien se hace pasar por un proveedor o cliente para que le paguen a su cuenta. "
                "Antes de transferir, confirmar el cambio por teléfono a un número ya conocido (no al que figura en "
                "el mail).",
                FindingCategory.PHISHING,
                _sev(score),
                score,
                ev(bank, urgency=urg[:3]),
            )
        )

    if pretext or gift:
        # una sola frase ("¿estás disponible?") es muy común en mails normales; dos señales juntas no
        score = 40 if (pretext and gift) or len(pretext) >= 2 else 15 if gift else 10
        score += 5 if urg else 0
        phrases = pretext + gift
        out.append(
            _finding(
                "content.bec_lure",
                "El mail usa frases típicas del fraude del 'jefe que pide un favor'",
                "Frases como 'estoy en una reunión, necesito un favor' o pedidos de tarjetas de regalo son el "
                "guion clásico de quien se hace pasar por un directivo para obtener pagos o compras. Confirmar "
                "siempre en persona o por teléfono.",
                FindingCategory.PHISHING,
                _sev(score),
                score,
                ev(phrases, urgency=urg[:3]),
            )
        )

    if cred:
        score = 15 + (10 if urg else 0) + (5 if msg.urls else 0)
        if any(
            a.detected_type in ("html", "svg") or a.extension in ("html", "htm", "svg", "shtml")
            for a in attachments
        ):
            score += 10
        score = min(score, 40)
        out.append(
            _finding(
                "content.credential_lure",
                "El mail pide verificar la cuenta o ingresar la contraseña",
                "El texto usa frases típicas de robo de contraseñas ('verifique su cuenta', 'su buzón está lleno', "
                "'su contraseña expira'). Los servicios reales no piden la contraseña por mail: ante la duda, "
                "entrar al sitio escribiendo la dirección a mano, nunca desde el link.",
                FindingCategory.PHISHING,
                _sev(score),
                score,
                ev(cred, urgency=urg[:3]),
            )
        )

    if inv:
        score = 30 if risky_att else 15 if attachments else 10
        score += 5 if urg else 0
        out.append(
            _finding(
                "content.invoice_lure",
                "El mail habla de facturas, pagos o trámites",
                "El asunto o el texto mencionan facturas, comprobantes, pagos u organismos (AFIP/ARCA, juzgados). "
                "Es el tema más usado para lograr que se abra un adjunto con virus. Por sí solo no es grave; "
                "importa si el remitente es desconocido o el adjunto es comprimido o ejecutable.",
                FindingCategory.PHISHING,
                _sev(score),
                score,
                ev(inv, urgency=urg[:3], risky_attachments=[a.filename or a.id for a in risky_att][:5]),
            )
        )

    if urg and not out:
        out.append(
            _finding(
                "content.urgency",
                "El mail presiona con urgencia",
                "El texto apura a actuar ('urgente', 'dentro de las 24 horas', 'último aviso'). La urgencia es "
                "una táctica para que no se revise con calma; por sí sola es una señal débil.",
                FindingCategory.PHISHING,
                Severity.LOW,
                5,
                ev(urg),
            )
        )
    return out


class ContentAnalyzer(MessageAnalyzer):
    """Señuelos en asunto y cuerpo: facturas, credenciales, urgencia, BEC y contraseñas de adjuntos."""

    name = NAME

    async def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        return await asyncio.to_thread(analyze_content, ctx.message)
