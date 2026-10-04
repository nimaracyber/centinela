"""Arma el contenido de las alertas a partir de un AnalysisResult.

`build_alert(result, settings)` devuelve un `Alert` con todo lo que un canal necesita: nivel, título,
resumen en lenguaje llano, "Qué hacer" adaptado a los hallazgos, datos clave del mail, link al
dashboard y campos para máquinas. Los renderers (`to_text`, `to_telegram_html`, `to_markdown`,
`to_html_email`, `to_cef`) producen cada formato respetando sus límites de tamaño.

Reglas de seguridad de este módulo:
- NUNCA se incluye contenido de adjuntos, cuerpo del mail ni secretos: solo metadatos (nombre, tipo,
  SHA-256, familia, hallazgos). La `evidence` de los hallazgos solo se usa para extraer URLs, que se
  muestran "desactivadas".
- Todo texto que controla el atacante (asunto, remitente, nombres de archivo, títulos de hallazgos...)
  se sanea: se eliminan caracteres de control, se hacen visibles los trucos bidi (RLO: "fdp.exe" que se
  ve como "exe.pdf") y se desactivan URLs y dominios (hxxps://ejemplo[.]com) para que nadie pueda hacer
  clic desde la alerta.
- Cada renderer escapa según su formato (HTML, mrkdwn de Slack, markdown de Discord, CEF).
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta, timezone
from functools import lru_cache
from typing import TYPE_CHECKING, Any, Literal

from centinela import __version__
from centinela.core.models import FindingCategory, Severity, VerdictLevel

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Sequence
    from datetime import tzinfo

    from centinela.core.config import Settings
    from centinela.core.models import AnalysisResult, ArtifactSummary, Finding

__all__ = [
    "DETAIL_STEPS",
    "Alert",
    "AttachmentFact",
    "Detail",
    "FindingFact",
    "build_alert",
    "cef_escape_extension",
    "cef_escape_header",
    "clean_text",
    "defang_email",
    "defang_text",
    "defang_url",
    "escape_discord",
    "escape_html",
    "escape_slack",
    "format_local_datetime",
    "truncate",
    "utf16_len",
]

# --------------------------------------------------------------------------- límites

TEXT_MAX_CHARS = 3500
TELEGRAM_MAX_CHARS = 4096  # Telegram cuenta en unidades UTF-16; medimos el HTML completo (conservador)
MARKDOWN_MAX_CHARS = 3000  # tope de un bloque "section" de Slack
TOP_FINDINGS = 5
MAX_ATTACHMENTS = 8
MAX_URLS = 5
MAX_FAMILIES = 8
MAX_RECIPIENTS = 5
MAX_MACHINE_FINDINGS = 100
MAX_MACHINE_ARTIFACTS = 200

SUBJECT_MAX = 200
SUMMARY_MAX = 900
SENDER_MAX = 200
FINDING_TITLE_MAX = 180
FINDING_DESC_MAX = 300
FILENAME_MAX = 120
URL_MAX = 160
FAMILY_MAX = 60

CEF_VENDOR = "Centinela"
CEF_PRODUCT = "Centinela"

# --------------------------------------------------------------------------- niveles

_LEVELS: dict[str, tuple[str, str, str]] = {
    # nivel: (emoji, adjetivo, plantilla del título)
    "malicious": ("🔴", "malicioso", "Mail malicioso detectado en {mb}"),
    "suspicious": ("🟠", "sospechoso", "Mail sospechoso detectado en {mb}"),
    "error": ("⚠️", "no analizado", "No se pudo analizar por completo un mail en {mb}"),
    "clean": ("🟢", "sin amenazas", "Mail sin amenazas detectadas en {mb}"),
}
_DEFAULT_SUMMARY = {
    "malicious": "Este mail tiene características claras de ser un ataque. No lo abras.",
    "suspicious": "Este mail tiene señales de ser peligroso. Tratalo con cuidado.",
    "error": "Centinela no pudo analizar este mail por completo.",
    "clean": "Centinela no encontró amenazas en este mail.",
}
LEVEL_COLORS = {"malicious": "#B91C1C", "suspicious": "#C2410C", "error": "#4B5563", "clean": "#15803D"}
LEVEL_COLOR_INT = {"malicious": 0xB91C1C, "suspicious": 0xC2410C, "error": 0x4B5563, "clean": 0x15803D}

_SEVERITY_LABELS = {
    Severity.CRITICAL: "Crítica",
    Severity.HIGH: "Alta",
    Severity.MEDIUM: "Media",
    Severity.LOW: "Baja",
    Severity.INFO: "Info",
}

# --------------------------------------------------------------------------- tipos de archivo

_TYPE_LABELS = {
    "pe": "programa de Windows",
    "elf": "programa de Linux",
    "macho": "programa de macOS",
    "msi": "instalador de Windows (MSI)",
    "ole": "documento de Office (formato antiguo)",
    "ooxml": "documento de Office",
    "rtf": "documento RTF",
    "pdf": "PDF",
    "onenote": "nota de OneNote",
    "chm": "ayuda de Windows (CHM)",
    "zip": "archivo comprimido ZIP",
    "jar": "programa Java (JAR)",
    "7z": "archivo comprimido 7-Zip",
    "rar": "archivo comprimido RAR",
    "gzip": "archivo comprimido GZIP",
    "bzip2": "archivo comprimido BZIP2",
    "xz": "archivo comprimido XZ",
    "tar": "archivo TAR",
    "cab": "archivo CAB",
    "iso": "imagen de disco (ISO)",
    "udf": "imagen de disco (UDF)",
    "vhd": "disco virtual (VHD)",
    "vhdx": "disco virtual (VHDX)",
    "img": "imagen de disco (IMG)",
    "lnk": "acceso directo de Windows",
    "eml": "mail adjunto",
    "html": "página web (HTML)",
    "svg": "imagen SVG (puede tener código)",
    "xml": "archivo XML",
    "url_shortcut": "acceso directo a internet (.url)",
    "iqy": "consulta web de Excel (.iqy)",
    "slk": "planilla SYLK (.slk)",
    "reg": "archivo de registro de Windows (.reg)",
    "settingcontent": "acceso a configuración de Windows",
    "library-ms": "biblioteca de Windows (.library-ms)",
    "search-ms": "búsqueda de Windows (.search-ms)",
    "text": "texto",
    "unknown": "tipo desconocido",
}
_SCRIPT_LABELS = {
    "js": "JavaScript",
    "vbs": "VBScript",
    "ps1": "PowerShell",
    "bat": "por lotes (BAT/CMD)",
    "wsf": "WSF",
    "hta": "HTA",
    "vba": "macro VBA",
    "python": "Python",
    "sh": "de shell",
}


def type_label(detected_type: str) -> str:
    """Nombre en castellano llano de un `Artifact.detected_type`."""
    t = (detected_type or "unknown").strip().lower()
    if t in _TYPE_LABELS:
        return _TYPE_LABELS[t]
    if t.startswith("script/"):
        return "script " + _SCRIPT_LABELS.get(t[7:], t[7:] or "")
    if t.startswith("image/"):
        return "imagen"
    return clean_text(t, 40) or "tipo desconocido"


# --------------------------------------------------------------------------- saneamiento

_BIDI_CHARS = frozenset("\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
_LINE_BREAKS = frozenset("\n\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029")
_SPACES_RE = re.compile(r"[ \t]{2,}")
_BLANKS_RE = re.compile(r"\n{3,}")


def truncate(text: str, max_len: int) -> str:
    """Recorta a `max_len` caracteres agregando "…" si hizo falta."""
    if max_len <= 0:
        return ""
    if len(text) <= max_len:
        return text
    if max_len == 1:
        return "…"
    return text[: max_len - 1].rstrip() + "…"


def clean_text(value: object, max_len: int, *, multiline: bool = False) -> str:
    """Sanea texto controlado por el atacante.

    - quita caracteres de control/formato (incluye zero-width) y surrogates sueltos,
    - hace visibles los controles bidi (U+202E RLO etc.) como "[U+202E]",
    - colapsa espacios; saltos de línea solo si `multiline`,
    - recorta a `max_len`.
    """
    if value is None:
        return ""
    s = str(value)
    hard = max_len * 4 + 64  # cota previa: nunca procesar textos gigantes
    if len(s) > hard:
        s = s[:hard]
    s = s.replace("\r\n", "\n")
    out: list[str] = []
    for ch in s:
        if ch in _BIDI_CHARS:
            out.append(f"[U+{ord(ch):04X}]")
        elif ch in _LINE_BREAKS:
            out.append("\n" if multiline else " ")
        elif ch == "\t":
            out.append(" ")
        elif unicodedata.category(ch) in ("Cc", "Cf", "Cs"):
            continue
        else:
            out.append(ch)
    s = _SPACES_RE.sub(" ", "".join(out))
    if multiline:
        s = _BLANKS_RE.sub("\n\n", "\n".join(line.strip() for line in s.split("\n")))
    return truncate(s.strip(), max_len)


# --------------------------------------------------------------------------- defang

_SCHEMES = {"http": "hxxp", "https": "hxxps", "ftp": "fxp", "ftps": "fxps"}
_SCHEME_RE = re.compile(r"(?i)\b(https?|ftps?)(?=:)")
_URL_RE = re.compile(r"(?i)\b(?:https?|ftps?)://[^\s<>\"'`]{1,4096}")
# nombres de host "pelados" (sin esquema): labels separados por punto y un TLD alfabético o punycode
_HOST_RE = re.compile(r"(?i)(?:[\w-]{1,63}\.){1,30}(?:xn--[a-z0-9-]{1,59}|[a-z]{2,24})\b")
# TLDs que los clientes de chat/mail convierten en link. Se excluyen a propósito .zip/.mov (también son
# extensiones de archivo y desfigurarían nombres de adjuntos).
_TLDS = frozenset(
    """
    com net org info biz io co me ly app dev xyz top online site shop store tech live life club icu cyou
    buzz fun click link work today world space website press host pw cc tk ml ga cf gq ru su ua kz by cn
    br ar mx cl pe uy py bo ec ve cr gt hn sv ni pa do cu pr es pt us uk de fr it nl eu ch be at pl cz ro
    hu gr tr ir in jp kr hk tw sg my id th vn ph au nz ca za ng ke eg ma gov edu mil int name pro mobi
    asia tel travel jobs vip win bid loan men mom lol ink one zone email support help services solutions
    digital network systems cloud ai gg tv fm am to ws la so st sh ac im is li lt lv ee fi se no dk ie
    rest bar today group global company agency center finance financial bank money pay cash credit
    login account accounts secure security verify update download docs page best top news blog
    """.split()
)


def _defang_scheme(m: re.Match[str]) -> str:
    return _SCHEMES.get(m.group(1).lower(), m.group(1))


def defang_url(url: str, max_len: int | None = URL_MAX) -> str:
    """`https://a.example.com/x` -> `hxxps://a[.]example[.]com/x` (+ saneado y recorte)."""
    s = clean_text(url, 4096)
    s = _SCHEME_RE.sub(_defang_scheme, s)
    s = s.replace(".", "[.]")
    return truncate(s, max_len) if max_len else s


def _defang_host(m: re.Match[str]) -> str:
    s = m.group(0)
    labels = s.split(".")
    if labels[0].lower() == "www":
        return "[.]".join(labels)
    # el último label que sea un TLD conocido (con al menos un label antes) define el dominio
    for i in range(len(labels) - 1, 0, -1):
        if labels[i].lower() in _TLDS or labels[i].lower().startswith("xn--"):
            tail = "".join("." + lab for lab in labels[i + 1 :])
            return "[.]".join(labels[: i + 1]) + tail
    return s


def defang_text(text: str) -> str:
    """Desactiva URLs y dominios dentro de un texto libre (que ya debería estar saneado)."""
    if not text:
        return text
    text = _URL_RE.sub(lambda m: defang_url(m.group(0), None), text)
    text = _SCHEME_RE.sub(_defang_scheme, text)
    return _HOST_RE.sub(_defang_host, text)


def defang_email(addr: str | None, max_len: int = 254) -> str:
    """`juan@proveedor.com` -> `juan@proveedor[.]com`."""
    s = clean_text(addr, max_len)
    if "@" in s:
        local, _, domain = s.rpartition("@")
        return f"{defang_text(local)}@{domain.replace('.', '[.]')}"
    return defang_text(s)


def _safe_text(value: object, max_len: int) -> str:
    """Saneado + defang + recorte: para cualquier texto que venga del mail o de los hallazgos."""
    return truncate(defang_text(clean_text(value, max_len)), max_len + 40)


# --------------------------------------------------------------------------- escapes por formato


def escape_html(text: str) -> str:
    """Escape para HTML (mail y Telegram). Telegram solo admite &lt; &gt; &amp; &quot; con nombre."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def escape_slack(text: str) -> str:
    """Slack mrkdwn: escapar & < > evita menciones (<!channel>) y links inyectados."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


_DISCORD_SPECIAL_RE = re.compile(r"([\\*_~`|>#\[\]<@])")
_DISCORD_LINE_START_RE = re.compile(r"(?m)^(\s*)([-+])")


def escape_discord(text: str) -> str:
    """Markdown de Discord: escapa con barra invertida lo que forma formato, links, citas o menciones
    (Discord muestra el carácter sin la barra)."""
    return _DISCORD_LINE_START_RE.sub(r"\1\\\2", _DISCORD_SPECIAL_RE.sub(r"\\\1", text))


def cef_escape_header(value: object) -> str:
    """Campos del header CEF: escapar barra invertida y pipe; sin saltos de línea."""
    s = clean_text(value, 512)
    return s.replace("\\", "\\\\").replace("|", "\\|")


def cef_escape_extension(value: object, max_len: int = 1023) -> str:
    """Valores de extensión CEF: escapar barra invertida, igual y saltos de línea (\\n, \\r)."""
    s = clean_text(value, max_len, multiline=True)
    return s.replace("\\", "\\\\").replace("=", "\\=").replace("\r", "\\r").replace("\n", "\\n")


def utf16_len(text: str) -> int:
    """Largo en unidades UTF-16 (como cuenta Telegram)."""
    return len(text.encode("utf-16-le")) // 2


# --------------------------------------------------------------------------- fechas

# zonas sin horario de verano: respaldo si el sistema no tiene la base tzdata (ej: Windows sin tzdata)
_FIXED_OFFSETS_H = {
    "America/Montevideo": -3,
    "America/Sao_Paulo": -3,
    "America/Asuncion": -3,
    "America/Bogota": -5,
    "America/Lima": -5,
    "America/Guayaquil": -5,
    "America/Panama": -5,
    "America/Cancun": -5,
    "America/Caracas": -4,
    "America/La_Paz": -4,
    "America/Santo_Domingo": -4,
    "America/Puerto_Rico": -4,
    "America/Mexico_City": -6,
    "America/Monterrey": -6,
    "America/Merida": -6,
    "America/Guatemala": -6,
    "America/Costa_Rica": -6,
    "America/El_Salvador": -6,
    "America/Tegucigalpa": -6,
    "America/Managua": -6,
    "UTC": 0,
    "Etc/UTC": 0,
}


@lru_cache(maxsize=32)
def _tz(name: str) -> tzinfo:
    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo(name)
    except (ImportError, KeyError, ValueError, OSError):
        pass
    if name.startswith(("America/Argentina/", "America/Buenos_Aires")):
        return timezone(timedelta(hours=-3))
    offset = _FIXED_OFFSETS_H.get(name)
    if offset is not None:
        return timezone(timedelta(hours=offset))
    return UTC


def format_local_datetime(dt: datetime | None, tz_name: str) -> str:
    """`03/10/2026 14:32 (UTC-03:00)` en la zona horaria configurada."""
    if dt is None:
        return "(sin fecha)"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    local = dt.astimezone(_tz(tz_name or "UTC"))
    total = int((local.utcoffset() or timedelta(0)).total_seconds())
    if total == 0:
        suffix = "UTC"
    else:
        sign = "-" if total < 0 else "+"
        total = abs(total)
        suffix = f"UTC{sign}{total // 3600:02d}:{(total % 3600) // 60:02d}"
    return f"{local:%d/%m/%Y %H:%M} ({suffix})"


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


# --------------------------------------------------------------------------- perfil de amenaza

_STEALERS = frozenset(
    """
    lumma lummac lummac2 redline vidar raccoon stealc rhadamanthys agenttesla formbook xloader snake
    snakekeylogger 404keylogger masslogger lokibot loki azorult risepro meduza atomic amos metastealer
    mystic aurora erbium phemedrone strela acrstealer darkcloud hawkeye pony arkei mars vipkeylogger
    purelogs whitesnake blackguard stealerium echelon danabot ursnif gozi
    """.split()
)
_RATS = frozenset(
    """
    asyncrat remcos njrat bladabindi quasar quasarrat dcrat darkcrystal darkcomet nanocore xworm warzone
    avemaria netwire netsupport netsupportmanager plugx gh0st venomrat orcus bitrat sectoprat arechclient2
    parallax adwind jrat strrat houdini wshrat revengerat limerat sparkrat cobaltstrike sliver havoc
    meterpreter bruteratel
    """.split()
)
_RANSOMWARE = frozenset(
    """
    lockbit lockbit3 conti ryuk blackcat alphv akira phobos stop djvu medusa medusalocker play royal
    blacksuit blackbasta babuk makop dharma crysis mallox targetcompany rhysida 8base hive clop cl0p revil
    sodinokibi maze egregor wannacry qilin agenda ransomhub hunters inc incransom cactus bianlian trigona
    nokoyawa blackbyte lorenz ragnarlocker avoslocker lockergoga gandcrab cerber locky magniber fog
    interlock lynx safepay dragonforce termite embargo globeimposter chaos xorist
    """.split()
)
_LOADERS = frozenset(
    """
    guloader cloudeye smokeloader emotet heodo qakbot qbot icedid bokbot bumblebee pikabot latrodectus
    darkgate socgholish gootloader hijackloader idatloader privateloader amadey systembc dbatloader
    modiloader bazarloader trickbot matanbuchus oyster ssload lobshot rugmi purecrypter pureloader
    donutloader buerloader zloader hancitor dridex ghostpulse
    """.split()
)
# troyanos bancarios muy activos en Latinoamérica
_BANKERS = frozenset(
    """
    grandoreiro mekotio casbaneiro metamorfo mispadu ursa javali guildma astaroth bbtok amavaldo vadokrist
    ousaban zumanek numando lampion chaes coyote pixpirate brata danabot ursnif gozi dridex zeus
    """.split()
)
_BEC_TEXT = ("cbu", "cvu", "cuenta bancaria", "datos bancarios", "cambio de cuenta", "nueva cuenta", "iban")


def _norm_family(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _tokens(text: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", text.lower()) if t}


@dataclass(frozen=True)
class _Profile:
    malware: bool = False
    stealer: bool = False
    rat: bool = False
    ransomware: bool = False
    loader: bool = False
    banker: bool = False
    macro: bool = False
    bec: bool = False
    phishing: bool = False
    spoofing: bool = False


def _family_profile(family: str) -> dict[str, bool]:
    n = _norm_family(family)
    if not n:
        return {}
    flags = {
        "stealer": n in _STEALERS or "stealer" in n or "keylog" in n,
        "rat": n in _RATS or n.endswith("rat"),
        "ransomware": n in _RANSOMWARE or "ransom" in n or n.endswith("locker"),
        "loader": n in _LOADERS or n.endswith("loader"),
        "banker": n in _BANKERS or "banker" in n,
    }
    return {k: v for k, v in flags.items() if v}


def _profile(findings: Sequence[Finding], families: Sequence[str]) -> _Profile:
    flags: dict[str, bool] = {}
    for fam in families:
        flags.update(_family_profile(fam))
    if families:
        flags["malware"] = True
    for f in findings:
        if f.score <= 0 and f.severity <= Severity.INFO:
            continue
        rule_tokens = _tokens(f.rule)
        if f.malware_family:
            flags.update(_family_profile(f.malware_family))
        text = (clean_text(f.title, 300) + " " + clean_text(f.description, 600)).lower()
        cat = f.category
        if cat in (FindingCategory.MALWARE, FindingCategory.REPUTATION, FindingCategory.SUSPICIOUS_FILE):
            flags["malware"] = True
        if rule_tokens & {"stealer", "infostealer", "keylogger", "stealers"}:
            flags["stealer"] = True
        if rule_tokens & {"rat", "backdoor"} or "acceso remoto" in text:
            flags["rat"] = True
        if any("ransom" in t for t in rule_tokens) or "ransomware" in text:
            flags["ransomware"] = True
        if rule_tokens & {"loader", "downloader", "dropper"}:
            flags["loader"] = True
        if rule_tokens & {"banker", "bankingtrojan"}:
            flags["banker"] = True
        if rule_tokens & {"vba", "macro", "macros", "xlm", "autoexec", "autoopen", "vbaproject"}:
            flags["macro"] = True
        is_bec = bool(
            rule_tokens & {"bec", "cbu", "cvu", "iban", "wire", "ceofraud"}
            or {"bank", "change"} <= rule_tokens
            or {"payment", "change"} <= rule_tokens
            or any(k in text for k in _BEC_TEXT)
        )
        if is_bec:
            flags["bec"] = True
        # phishing de credenciales (un fraude de pago/BEC suele venir con categoría PHISHING: no es lo mismo)
        if (cat == FindingCategory.PHISHING and not is_bec) or rule_tokens & {
            "phish",
            "phishing",
            "credential",
            "credentials",
            "harvest",
            "harvesting",
        }:
            flags["phishing"] = True
        # suplantación del REMITENTE (un link a un dominio parecido es phishing, no esto)
        if cat == FindingCategory.SPOOFING or rule_tokens & {
            "spoof",
            "spoofing",
            "impersonation",
            "displayname",
        }:
            flags["spoofing"] = True
    return _Profile(**flags)


def _recommendations(level: str, p: _Profile, has_attachments: bool, has_urls: bool) -> list[str]:
    """Pasos concretos, para alguien no técnico, según lo que se encontró."""
    if level == "error":
        return [
            "Centinela no pudo revisar este mail por completo: tratalo con cuidado y no abras adjuntos "
            "que no esperabas.",
            "Si el problema se repite, avisá a quien administra Centinela.",
        ]
    if level not in ("malicious", "suspicious"):
        return []
    malicious = level == "malicious"
    recs: list[str] = []
    if has_attachments and has_urls:
        recs.append("No abras los adjuntos ni hagas clic en los links de este mail.")
    elif has_attachments:
        recs.append("No abras los adjuntos de este mail.")
    elif has_urls:
        recs.append("No hagas clic en los links de este mail.")
    else:
        recs.append("No respondas este mail ni sigas sus instrucciones.")
    if p.macro:
        recs.append(
            "Si abriste el documento, NO toques «Habilitar edición» ni «Habilitar contenido»: las macros "
            "son la forma en que se instala el virus."
        )
    if p.bec:
        recs.append(
            "Si el mail pide cambiar la cuenta bancaria (CBU/CVU/alias) o pagar con urgencia: antes de "
            "pagar, verificá llamando por teléfono a un número que ya tengas agendado (nunca al que figura "
            "en el mail)."
        )
    if malicious:
        recs.append("Borrá el mail (y después vaciá la papelera). Centinela no lo borra: solo te avisa.")
    else:
        recs.append(
            "Si no esperabas este mail, borralo. Ante la duda, consultá con soporte antes de abrir nada."
        )
    infection_risk = p.malware or p.stealer or p.rat or p.ransomware or p.loader or p.banker or p.macro
    if infection_risk and (has_attachments or has_urls):
        if malicious:
            recs.append(
                "Si ya abriste el adjunto o el link: desconectá esa PC de la red (sacá el cable y apagá el "
                "Wi-Fi), no la sigas usando y avisá a soporte técnico enseguida."
            )
        else:
            recs.append(
                "Si ya lo abriste y la PC hace cosas raras, desconectala de la red (cable y Wi-Fi) y avisá a "
                "soporte técnico."
            )
    if p.stealer or p.banker:
        recs.append(
            "Este tipo de virus roba contraseñas: si se abrió el adjunto, cambiá las contraseñas (mail, home "
            "banking, redes y sistemas de la empresa) desde OTRO dispositivo, no desde esa PC, y cerrá las "
            "sesiones abiertas en todos lados."
        )
    if p.banker:
        recs.append("Si usaste el home banking desde esa PC, avisá a tu banco.")
    if p.rat:
        recs.append(
            "Este tipo de virus permite controlar la PC a distancia: si se abrió, no uses esa PC (y menos "
            "para el banco) hasta que la revise soporte."
        )
    if p.ransomware:
        recs.append(
            "Si ves archivos con nombres raros o un aviso pidiendo rescate: desconectá la PC de la red, no "
            "pagues y avisá a soporte. Verificá que las copias de seguridad estén a salvo."
        )
    if p.loader and not (p.rat or p.ransomware):
        recs.append(
            "Este tipo de virus descarga otros más peligrosos (como ransomware): si se abrió, que soporte "
            "revise la PC cuanto antes."
        )
    if p.phishing:
        recs.append(
            "Si ingresaste tu usuario y contraseña en ese link: cambiá la contraseña ahora mismo y activá la "
            "verificación en dos pasos."
        )
    if p.spoofing and not p.bec:
        recs.append(
            "El remitente puede estar falsificado: no confíes en el nombre que aparece. Si conocés a esa "
            "persona, confirmá por otro medio (teléfono o WhatsApp)."
        )
    return recs[:9]


def _recipient_tips(level: str, p: _Profile, has_attachments: bool, has_urls: bool) -> list[str]:
    """Variante suave del "Qué hacer" para el destinatario original del mail."""
    tips: list[str] = []
    if has_attachments and has_urls:
        tips.append("No abras los adjuntos ni hagas clic en los links de ese mail.")
    elif has_attachments:
        tips.append("No abras los adjuntos de ese mail.")
    elif has_urls:
        tips.append("No hagas clic en los links de ese mail.")
    tips.append("No respondas ni reenvíes el mail.")
    if p.bec:
        tips.append(
            "Si pide cambiar datos bancarios o hacer un pago urgente, confirmalo por teléfono con un número "
            "que ya tengas (no el del mail)."
        )
    if p.macro:
        tips.append("Si abriste el documento, no habilites macros ni «contenido».")
    tips.append(
        "Si ya lo abriste, hiciste clic o escribiste tu contraseña, avisá enseguida a soporte técnico. No "
        "pasa nada por avisar: cuanto antes, mejor."
    )
    tips.append(
        "Si no lo esperabas, borralo." if level == "malicious" else "Si no lo esperabas, podés borrarlo."
    )
    return tips


# --------------------------------------------------------------------------- estructuras


@dataclass(frozen=True, eq=False)
class AttachmentFact:
    """Un adjunto (o archivo interno de un contenedor) con hallazgos relevantes."""

    artifact_id: str
    display_name: str  # "factura.zip › factura.pdf.exe" (saneado)
    detected_type: str
    type_label: str
    sha256: str
    size: int
    encrypted: bool
    severity: Severity
    families: tuple[str, ...] = ()


@dataclass(frozen=True, eq=False)
class FindingFact:
    rule: str
    title: str
    description: str
    severity: Severity
    severity_label: str
    score: int
    category: str
    artifact: str | None = None
    family: str | None = None


@dataclass(frozen=True)
class Detail:
    """Nivel de detalle: se reduce paso a paso cuando el mensaje no entra en el límite del canal."""

    findings: int = TOP_FINDINGS
    attachments: int = MAX_ATTACHMENTS
    urls: int = MAX_URLS
    recipients: int = MAX_RECIPIENTS
    recommendations: int = 9
    descriptions: bool = True


DETAIL_STEPS = (
    Detail(),
    Detail(descriptions=False),
    Detail(descriptions=False, urls=3, attachments=4, recipients=3),
    Detail(descriptions=False, urls=2, attachments=2, findings=3, recipients=2),
    Detail(descriptions=False, urls=1, attachments=1, findings=2, recipients=1, recommendations=5),
)

# Modelo intermedio de documento: los renderers lo traducen a cada formato.
# Segmento: (estilo, texto) con estilo "t" (texto), "b" (negrita), "c" (código) o "br" (salto dentro del ítem).
Seg = tuple[str, str]
Line = tuple[Seg, ...]
Flavor = Literal["slack", "discord"]


def _t(text: str) -> Line:
    return (("t", text),)


@dataclass(frozen=True, eq=False)
class Alert:
    """Todo lo necesario para alertar sobre un resultado. Textos ya saneados y con URLs desactivadas."""

    level: str  # "malicious" | "suspicious" | "error" | "clean"
    emoji: str
    level_label: str  # "malicioso" | "sospechoso"...
    title: str
    summary: str
    recommendations: tuple[str, ...]
    recipient_tips: tuple[str, ...]
    sender: str
    sender_address: str | None  # dirección cruda (para máquinas), no se muestra a humanos
    recipients: tuple[str, ...]
    mailbox: str
    subject: str
    date: str
    score: int
    attachments: tuple[AttachmentFact, ...]
    families: tuple[str, ...]
    findings: tuple[FindingFact, ...]
    total_findings: int
    urls: tuple[str, ...]  # ya desactivadas
    dashboard_url: str | None
    rule: str
    result_id: str
    company_name: str
    received_at: datetime
    analyzed_at: datetime
    machine: dict[str, Any]

    # ------------------------------------------------------------------ helpers

    @property
    def color(self) -> str:
        return LEVEL_COLORS.get(self.level, LEVEL_COLORS["suspicious"])

    @property
    def color_int(self) -> int:
        return LEVEL_COLOR_INT.get(self.level, LEVEL_COLOR_INT["suspicious"])

    @property
    def headline(self) -> str:
        return f"{self.emoji} {self.title}"

    def recipients_line(self, limit: int = MAX_RECIPIENTS) -> str:
        if not self.recipients:
            return self.mailbox
        shown = list(self.recipients[:limit])
        rest = len(self.recipients) - len(shown)
        return ", ".join(shown) + (f" y {rest} más" if rest > 0 else "")

    def email_subject(self, max_subject: int = 80) -> str:
        """Asunto del mail de alerta: `[Centinela] 🔴 Mail malicioso: <asunto truncado>`."""
        subj = truncate(self.subject, max_subject)
        if self.level == "error":
            return f"[Centinela] {self.emoji} No se pudo analizar un mail: {subj}"
        return f"[Centinela] {self.emoji} Mail {self.level_label}: {subj}"

    def recipient_email_subject(self, max_subject: int = 60) -> str:
        return f"[Centinela] {self.emoji} Cuidado con este mail: {truncate(self.subject, max_subject)}"

    def fact_pairs(self, d: Detail | None = None) -> list[tuple[str, str]]:
        d = d or Detail()
        return [
            ("De", self.sender),
            ("Para", self.recipients_line(d.recipients)),
            ("Asunto", self.subject),
            ("Fecha", self.date),
            ("Riesgo", f"{self.score}/100 ({self.level_label})"),
        ]

    def attachment_line(self, a: AttachmentFact) -> str:
        enc = ", con contraseña" if a.encrypted else ""
        return f"{a.display_name} — {a.type_label}{enc}"

    def finding_line(self, f: FindingFact) -> str:
        where = f" ({f.artifact})" if f.artifact else ""
        return f"{f.title}{where}"

    def findings_heading(self, shown: int) -> str:
        if self.total_findings > shown:
            return f"Qué encontramos ({shown} de {self.total_findings})"
        return "Qué encontramos"

    def families_heading(self) -> str:
        return "Familia de malware" if len(self.families) == 1 else "Familias de malware"

    # ------------------------------------------------------------------ documento intermedio

    def _blocks(self, d: Detail) -> tuple[list[tuple], list[tuple]]:
        """(cuerpo, cola). La cola (link + pie) se preserva siempre al recortar."""
        body: list[tuple] = [("title", self.headline), ("para", _t(self.summary))]
        recs = self.recommendations[: d.recommendations]
        if recs:
            body += [("heading", "Qué hacer"), ("list", tuple(_t(r) for r in recs), True)]
        body += [("heading", "Datos del mail"), ("facts", tuple((k, _t(v)) for k, v in self.fact_pairs(d)))]
        atts = self.attachments[: d.attachments]
        if atts:
            items = []
            for a in atts:
                items.append(
                    (
                        ("b", a.display_name),
                        ("t", f" — {a.type_label}{', con contraseña' if a.encrypted else ''}"),
                        ("br", ""),
                        ("t", "SHA-256: "),
                        ("c", a.sha256 or "(sin hash)"),
                    )
                )
            rest = len(self.attachments) - len(atts)
            if rest > 0:
                items.append(_t(f"(y {rest} más en el panel)"))
            body += [("heading", "Adjuntos peligrosos"), ("list", tuple(items), False)]
        if self.families:
            body.append(("kv", self.families_heading(), (("b", ", ".join(self.families)),)))
        fnds = self.findings[: d.findings]
        if fnds:
            items = []
            for f in fnds:
                segs: list[Seg] = [("b", f"[{f.severity_label}]"), ("t", " " + self.finding_line(f))]
                if d.descriptions and f.description:
                    segs += [("br", ""), ("t", f.description)]
                items.append(tuple(segs))
            body += [("heading", self.findings_heading(len(fnds))), ("list", tuple(items), False)]
        urls = self.urls[: d.urls]
        if urls:
            body += [
                ("heading", "Links sospechosos (no hacer clic)"),
                ("list", tuple((("c", u),) for u in urls), False),
            ]
        tail: list[tuple] = []
        if self.dashboard_url:
            tail.append(("link", "Ver el detalle en el panel de Centinela", self.dashboard_url))
        tail.append(("footer", "Aviso automático de Centinela. El mail no fue borrado ni movido."))
        return body, tail

    def _recipient_blocks(self) -> tuple[list[tuple], list[tuple]]:
        company = self.company_name or "tu empresa"
        if self.level in ("malicious", "suspicious"):
            intro = (
                f"El sistema de seguridad del correo de {company} (Centinela) detectó que un mail que "
                f"recibiste parece {self.level_label}."
            )
        else:
            intro = (
                f"El sistema de seguridad del correo de {company} (Centinela) revisó un mail que recibiste."
            )
        body: list[tuple] = [
            ("title", f"{self.emoji} Cuidado con un mail que recibiste"),
            ("para", _t("Hola:")),
            ("para", _t(intro)),
            ("para", _t(self.summary)),
            ("heading", "El mail"),
            ("facts", (("De", _t(self.sender)), ("Asunto", _t(self.subject)), ("Fecha", _t(self.date)))),
        ]
        if self.recipient_tips:
            body += [("heading", "Qué hacer"), ("list", tuple(_t(r) for r in self.recipient_tips), True)]
        tail = [("footer", "Este aviso es automático. Centinela no borró ni movió el mail.")]
        return body, tail

    # ------------------------------------------------------------------ texto plano

    def to_text(self, max_len: int = TEXT_MAX_CHARS) -> str:
        """Texto plano (SMS-like, cuerpo de mail, fallback de Telegram). Nunca supera `max_len`."""
        return _fit(lambda d: self._blocks(d), _render_text_lines, len, max_len)

    def to_recipient_text(self) -> str:
        body, tail = self._recipient_blocks()
        return "\n".join(_render_text_lines(body) + _render_text_lines(tail))

    # ------------------------------------------------------------------ Telegram

    def to_telegram_html(self, max_len: int = TELEGRAM_MAX_CHARS) -> str:
        """HTML de Telegram (parse_mode=HTML): solo <b>, <code>, <a>; todo lo demás escapado."""
        return _fit(lambda d: self._blocks(d), _render_telegram_lines, utf16_len, max_len)

    # ------------------------------------------------------------------ Slack / Discord

    def to_markdown(
        self, flavor: Flavor = "slack", *, max_len: int = MARKDOWN_MAX_CHARS, include_title: bool = True
    ) -> str:
        """mrkdwn de Slack (`flavor="slack"`) o markdown de Discord (`flavor="discord"`)."""

        def blocks(d: Detail) -> tuple[list[tuple], list[tuple]]:
            body, tail = self._blocks(d)
            if not include_title:
                body = [b for b in body if b[0] != "title"]
            return body, tail

        return _fit(blocks, lambda bl: _render_md_lines(bl, flavor), len, max_len)

    def markdown_parts(self, flavor: Flavor, d: Detail | None = None) -> dict[str, str]:
        """Piezas sueltas en markdown para armar bloques/embeds (Slack, Discord)."""
        d = d or Detail()
        bold = "*" if flavor == "slack" else "**"
        esc = escape_slack if flavor == "slack" else escape_discord
        parts: dict[str, str] = {"summary": esc(self.summary)}
        recs = self.recommendations[: d.recommendations]
        if recs:
            parts["recommendations"] = "\n".join(f"{i}. {esc(r)}" for i, r in enumerate(recs, 1))
        atts = self.attachments[: d.attachments]
        if atts:
            lines = [
                f"• {bold}{esc(a.display_name)}{bold} — {esc(a.type_label)}"
                f"{esc(', con contraseña') if a.encrypted else ''}\n   SHA-256: `{a.sha256 or '-'}`"
                for a in atts
            ]
            rest = len(self.attachments) - len(atts)
            if rest > 0:
                lines.append(esc(f"(y {rest} más en el panel)"))
            parts["attachments"] = "\n".join(lines)
        if self.families:
            parts["families"] = esc(", ".join(self.families))
        fnds = self.findings[: d.findings]
        if fnds:
            lines = []
            for f in fnds:
                line = f"• {bold}{esc(f.severity_label)}{bold} · {esc(self.finding_line(f))}"
                if d.descriptions and f.description:
                    line += "\n   " + esc(f.description)
                lines.append(line)
            parts["findings"] = "\n".join(lines)
        urls = self.urls[: d.urls]
        if urls:
            parts["urls"] = "\n".join(f"• `{_md_code(u, flavor)}`" for u in urls)
        return parts

    # ------------------------------------------------------------------ mail HTML

    def to_html_email(self) -> str:
        """HTML simple con CSS inline y tablas (Outlook-friendly). Todo escapado."""
        body, tail = self._blocks(Detail())
        return _render_html_document(self, body, tail, preheader=self.summary)

    def to_recipient_html(self) -> str:
        body, tail = self._recipient_blocks()
        return _render_html_document(self, body, tail, preheader=self.summary)

    # ------------------------------------------------------------------ CEF

    def cef_severity(self) -> int:
        tenth = round(self.score / 10)
        if self.level == "malicious":
            return max(8, min(10, tenth))
        if self.level == "suspicious":
            return max(5, min(7, tenth))
        if self.level == "error":
            return 3
        return max(0, min(3, tenth))

    def to_cef(self, scale: float = 1.0) -> str:
        """`CEF:0|Centinela|Centinela|<ver>|<regla>|<nombre>|<sev 0-10>|<extensiones>`.

        `scale` < 1 achica los campos largos (para entrar en un datagrama UDP).
        """

        def lim(n: int) -> int:
            return max(16, int(n * scale))

        m = self.machine
        msg = m["message"]
        ext: list[tuple[str, object, int]] = [
            ("rt", int(self.analyzed_at.timestamp() * 1000), 20),
            ("start", int(self.received_at.timestamp() * 1000), 20),
            ("externalId", self.result_id, 64),
            ("cat", self.level, 32),
            ("act", "alert", 16),
            ("deviceDirection", 0, 2),
            ("suser", msg.get("from") or "", lim(254)),
            ("duser", ",".join(msg.get("to") or []), lim(500)),
            ("msg", self.summary, lim(600)),
        ]
        # campos "custom" de CEF: el label solo va si hay valor
        custom: list[tuple[str, str, object, int]] = [
            ("cs1", "subject", msg.get("subject") or "", lim(300)),
            ("cs2", "malwareFamilies", ",".join(self.families), lim(300)),
            ("cs3", "messageId", msg.get("message_id") or "", lim(250)),
            ("cs4", "dashboardUrl", self.dashboard_url or "", lim(300)),
            ("cs5", "rules", ",".join(f.rule for f in self.findings), lim(400)),
            ("cs6", "mailbox", self.mailbox, lim(254)),
            ("cn1", "score", self.score, 4),
            ("cn2", "findingCount", self.total_findings, 8),
        ]
        for key, label, value, n in custom:
            if value not in ("", None):
                ext += [(f"{key}Label", label, 32), (key, value, n)]
        if self.attachments:
            a = self.attachments[0]
            ext += [
                ("fname", a.display_name, lim(255)),
                ("fileHash", a.sha256, 128),
                ("fileType", a.detected_type, 32),
                ("fsize", a.size, 20),
            ]
        if self.urls:
            ext.append(("request", self.urls[0], lim(300)))
        extension = " ".join(f"{k}={cef_escape_extension(v, n)}" for k, v, n in ext if v not in ("", None))
        header = "|".join(
            [
                "CEF:0",
                cef_escape_header(CEF_VENDOR),
                cef_escape_header(CEF_PRODUCT),
                cef_escape_header(__version__),
                cef_escape_header(self.rule),
                cef_escape_header(self.title),
                str(self.cef_severity()),
            ]
        )
        return f"{header}|{extension}"


def _code_safe(text: str) -> str:
    return text.replace("`", "'")


# --------------------------------------------------------------------------- renderers


def _seg_text(line: Line, *, br: str = "\n   ") -> str:
    return "".join(br if style == "br" else text for style, text in line)


def _render_text_lines(blocks: Iterable[tuple]) -> list[str]:
    out: list[str] = []
    for blk in blocks:
        kind = blk[0]
        if kind == "title":
            out.append(blk[1])
        elif kind == "para":
            out += ["", _seg_text(blk[1])]
        elif kind == "heading":
            out += ["", blk[1].upper()]
        elif kind == "list":
            for i, item in enumerate(blk[1], 1):
                prefix = f"{i}. " if blk[2] else "- "
                out += (prefix + _seg_text(item)).split("\n")
        elif kind == "facts":
            out += [f"{k}: {_seg_text(v)}" for k, v in blk[1]]
        elif kind == "kv":
            out += ["", f"{blk[1].upper()}: {_seg_text(blk[2])}"]
        elif kind == "link":
            out += ["", f"{blk[1]}: {blk[2]}"]
        elif kind == "footer":
            out += ["", f"— {blk[1]}"]
    return out


def _tg_segs(line: Line) -> str:
    parts = []
    for style, text in line:
        if style == "b":
            parts.append(f"<b>{escape_html(text)}</b>")
        elif style == "c":
            parts.append(f"<code>{escape_html(text)}</code>")
        elif style == "br":
            parts.append("\n   ")
        else:
            parts.append(escape_html(text))
    return "".join(parts)


def _render_telegram_lines(blocks: Iterable[tuple]) -> list[str]:
    """Cada línea física queda con sus etiquetas balanceadas: se puede recortar por líneas."""
    out: list[str] = []
    for blk in blocks:
        kind = blk[0]
        if kind == "title":
            out.append(f"<b>{escape_html(blk[1])}</b>")
        elif kind == "para":
            out += ["", _tg_segs(blk[1])]
        elif kind == "heading":
            out += ["", f"<b>{escape_html(blk[1])}</b>"]
        elif kind == "list":
            for i, item in enumerate(blk[1], 1):
                prefix = f"{i}. " if blk[2] else "• "
                out += (prefix + _tg_segs(item)).split("\n")
        elif kind == "facts":
            out += [f"<b>{escape_html(k)}:</b> {_tg_segs(v)}" for k, v in blk[1]]
        elif kind == "kv":
            out += ["", f"<b>{escape_html(blk[1])}:</b> {_tg_segs(blk[2])}"]
        elif kind == "link":
            out += ["", f'🔎 <a href="{escape_html(blk[2])}">{escape_html(blk[1])}</a>']
        elif kind == "footer":
            out += ["", f"<i>{escape_html(blk[1])}</i>"]
    return out


def _md_segs(line: Line, flavor: Flavor) -> str:
    esc = escape_slack if flavor == "slack" else escape_discord
    bold = "*" if flavor == "slack" else "**"
    parts = []
    for style, text in line:
        if style == "b":
            parts.append(f"{bold}{esc(text)}{bold}")
        elif style == "c":
            parts.append(f"`{_md_code(text, flavor)}`")
        elif style == "br":
            parts.append("\n   ")
        else:
            parts.append(esc(text))
    return "".join(parts)


def _md_code(text: str, flavor: Flavor) -> str:
    """Contenido de un `code span`: sin backticks; en Slack además & < > escapados (obligatorio)."""
    s = _code_safe(text)
    return escape_slack(s) if flavor == "slack" else s


def _render_md_lines(blocks: Iterable[tuple], flavor: Flavor) -> list[str]:
    esc = escape_slack if flavor == "slack" else escape_discord
    bold = "*" if flavor == "slack" else "**"
    out: list[str] = []
    for blk in blocks:
        kind = blk[0]
        if kind == "title":
            out.append(f"{bold}{esc(blk[1])}{bold}")
        elif kind == "para":
            out += ["", _md_segs(blk[1], flavor)]
        elif kind == "heading":
            out += ["", f"{bold}{esc(blk[1])}{bold}"]
        elif kind == "list":
            for i, item in enumerate(blk[1], 1):
                prefix = f"{i}. " if blk[2] else "• "
                out += (prefix + _md_segs(item, flavor)).split("\n")
        elif kind == "facts":
            out += [f"{bold}{esc(k)}:{bold} {_md_segs(v, flavor)}" for k, v in blk[1]]
        elif kind == "kv":
            out += ["", f"{bold}{esc(blk[1])}:{bold} {_md_segs(blk[2], flavor)}"]
        elif kind == "link":
            label, url = blk[1], blk[2]
            if flavor == "slack":
                out += ["", f"<{url}|{escape_slack(label)}>"]
            else:
                out += ["", f"[{escape_discord(label)}]({url})"]
        elif kind == "footer":
            out += ["", f"_{esc(blk[1])}_"]
    return out


def _fit(
    make_blocks: Callable[[Detail], tuple[list[tuple], list[tuple]]],
    render: Callable[[list[tuple]], list[str]],
    measure: Callable[[str], int],
    limit: int,
) -> str:
    """Renderiza bajando el nivel de detalle hasta entrar en `limit`; último recurso: recorta líneas
    del final del cuerpo preservando la cola (link al dashboard + pie)."""
    body_lines: list[str] = []
    tail_lines: list[str] = []
    for d in DETAIL_STEPS:
        body, tail = make_blocks(d)
        body_lines, tail_lines = render(body), render(tail)
        text = "\n".join(body_lines + tail_lines)
        if measure(text) <= limit:
            return text
    marker = "…"
    while body_lines:
        text = "\n".join([*body_lines, marker, *tail_lines])
        if measure(text) <= limit:
            return text
        body_lines.pop()
    text = "\n".join(tail_lines)
    # cola sola demasiado larga (no debería pasar con los topes de campos): recorte crudo
    return text if measure(text) <= limit else truncate(text, max(1, limit // 2))


def _render_html_document(alert: Alert, body: list[tuple], tail: list[tuple], *, preheader: str) -> str:
    font = "font-family:Arial,Helvetica,sans-serif;"
    color = alert.color
    parts: list[str] = []
    for blk in body:
        kind = blk[0]
        if kind == "title":
            continue  # va en la franja de color
        if kind == "para":
            parts.append(
                f'<p style="margin:0 0 12px 0;{font}font-size:15px;line-height:1.5;">{_html_segs(blk[1])}</p>'
            )
        elif kind == "heading":
            parts.append(
                f'<p style="margin:20px 0 8px 0;{font}font-size:16px;font-weight:bold;color:#111827;">'
                f"{escape_html(blk[1])}</p>"
            )
        elif kind == "list":
            tag = "ol" if blk[2] else "ul"
            items = "".join(
                f'<li style="margin:0 0 8px 0;{font}font-size:15px;line-height:1.5;">{_html_segs(item)}</li>'
                for item in blk[1]
            )
            parts.append(f'<{tag} style="margin:0 0 8px 0;padding:0 0 0 22px;">{items}</{tag}>')
        elif kind == "kv":
            parts.append(
                f'<p style="margin:20px 0 8px 0;{font}font-size:15px;line-height:1.5;">'
                f"<b>{escape_html(blk[1])}:</b> {_html_segs(blk[2])}</p>"
            )
        elif kind == "facts":
            rows = "".join(
                f'<tr><td valign="top" style="padding:4px 12px 4px 0;{font}font-size:14px;color:#6B7280;'
                f'white-space:nowrap;">{escape_html(k)}</td><td style="padding:4px 0;{font}font-size:14px;'
                f'color:#111827;word-break:break-word;">{_html_segs(v)}</td></tr>'
                for k, v in blk[1]
            )
            parts.append(
                f'<table role="presentation" cellpadding="0" cellspacing="0" border="0" '
                f'style="border-collapse:collapse;">{rows}</table>'
            )
    tail_parts: list[str] = []
    for blk in tail:
        if blk[0] == "link":
            tail_parts.append(
                '<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:20px 0 0 0;">'
                f'<tr><td bgcolor="#1D4ED8" style="background-color:#1D4ED8;border-radius:4px;">'
                f'<a href="{escape_html(blk[2])}" style="display:inline-block;padding:10px 18px;{font}'
                f'font-size:15px;font-weight:bold;color:#FFFFFF;text-decoration:none;">{escape_html(blk[1])}</a>'
                "</td></tr></table>"
            )
        elif blk[0] == "footer":
            tail_parts.append(
                f'<p style="margin:24px 0 0 0;{font}font-size:12px;color:#6B7280;">{escape_html(blk[1])}</p>'
            )
    title = body[0][1] if body and body[0][0] == "title" else alert.headline
    return (
        '<!DOCTYPE html>\n<html lang="es"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{escape_html(title)}</title></head>"
        '<body style="margin:0;padding:0;background-color:#F3F4F6;">'
        f'<div style="display:none;max-height:0;overflow:hidden;mso-hide:all;">{escape_html(truncate(preheader, 140))}</div>'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
        'style="background-color:#F3F4F6;"><tr><td align="center" style="padding:16px;">'
        '<table role="presentation" width="640" cellpadding="0" cellspacing="0" border="0" '
        'style="width:100%;max-width:640px;background-color:#FFFFFF;border:1px solid #E5E7EB;">'
        f'<tr><td bgcolor="{color}" style="background-color:{color};padding:16px 20px;{font}font-size:20px;'
        f'font-weight:bold;color:#FFFFFF;">{escape_html(title)}</td></tr>'
        f'<tr><td style="padding:20px;{font}color:#111827;">{"".join(parts)}{"".join(tail_parts)}</td></tr>'
        "</table></td></tr></table></body></html>"
    )


def _html_segs(line: Line) -> str:
    parts = []
    for style, text in line:
        if style == "b":
            parts.append(f"<b>{escape_html(text)}</b>")
        elif style == "c":
            parts.append(
                "<span style=\"font-family:Consolas,'Courier New',monospace;font-size:13px;"
                f'word-break:break-all;">{escape_html(text)}</span>'
            )
        elif style == "br":
            parts.append("<br>")
        else:
            parts.append(escape_html(text))
    return "".join(parts)


# --------------------------------------------------------------------------- build_alert

_URL_KEYS = frozenset(
    {"url", "urls", "href", "link", "links", "target", "final_url", "redirect", "redirects"}
)
_URL_VALUE_RE = re.compile(r"(?i)^(?:https?|ftps?)://\S{1,4096}$")


def _evidence_urls(findings: Iterable[Finding], limit: int) -> list[str]:
    """URLs mencionadas en la evidencia de hallazgos relevantes (las sospechosas), desactivadas."""
    out: list[str] = []
    seen: set[str] = set()
    for f in findings:
        ev = f.evidence if isinstance(f.evidence, dict) else {}
        for key, value in list(ev.items())[:50]:
            values = value if isinstance(value, (list, tuple)) else [value]
            for v in list(values)[:20]:
                if not isinstance(v, str):
                    continue
                s = v.strip()
                if not (
                    _URL_VALUE_RE.match(s) or (str(key).lower() in _URL_KEYS and "." in s and " " not in s)
                ):
                    continue
                d = defang_url(s, URL_MAX)
                if d and d not in seen:
                    seen.add(d)
                    out.append(d)
                    if len(out) >= limit:
                        return out
    return out


def _artifact_path(art_id: str, by_id: dict[str, ArtifactSummary]) -> str:
    names: list[str] = []
    cur: str | None = art_id
    seen: set[str] = set()
    while cur and cur not in seen and len(names) < 8:
        seen.add(cur)
        a = by_id.get(cur)
        if a is None:
            names.append(cur)
            break
        names.append(a.filename or a.id)
        cur = a.parent_id
    names.reverse()
    return " › ".join(clean_text(n, FILENAME_MAX) for n in names)


def _dashboard_url(settings: Settings, result_id: str) -> str | None:
    base = (settings.actions.alerts.dashboard_base_url or "").strip()
    if not base:
        return None
    if len(base) > 500 or not re.match(r"(?i)^https?://[^\s/?#\"'<>`]+[^\s\"'<>`]*$", base):
        return None
    return f"{base.rstrip('/')}/messages/{result_id}"


def _level_value(level: object) -> str:
    try:
        return VerdictLevel(level).value
    except ValueError:
        return "suspicious"


def build_alert(result: AnalysisResult, settings: Settings) -> Alert:
    """Arma el `Alert` de un resultado. No hace I/O; seguro ante datos hostiles."""
    level = _level_value(result.verdict.level)
    emoji, label, title_tpl = _LEVELS.get(level, _LEVELS["suspicious"])
    mailbox = (
        clean_text(result.ref.mailbox or (result.to[0] if result.to else ""), 120) or "el buzón monitoreado"
    )
    title = title_tpl.format(mb=mailbox)

    ordered = sorted(result.findings, key=lambda f: (-int(f.severity), -int(f.score)))
    relevant = [f for f in ordered if f.score > 0 or f.severity > Severity.INFO]
    by_id = {a.id: a for a in result.artifacts}

    # familias: del veredicto y de los hallazgos, sin repetir
    families: list[str] = []
    seen_fam: set[str] = set()
    for fam in [*result.verdict.malware_families, *(f.malware_family for f in relevant if f.malware_family)]:
        c = clean_text(fam, FAMILY_MAX)
        if c and c.lower() not in seen_fam:
            seen_fam.add(c.lower())
            families.append(c)

    # adjuntos con hallazgos relevantes (orden: el de mayor severidad primero)
    attachments: list[AttachmentFact] = []
    att_index: dict[str, int] = {}
    for f in relevant:
        aid = f.artifact_id
        if not aid:
            continue
        if aid in att_index:
            a_fact = attachments[att_index[aid]]
            if f.malware_family:
                fam = clean_text(f.malware_family, FAMILY_MAX)
                if fam and fam not in a_fact.families:
                    attachments[att_index[aid]] = replace(a_fact, families=(*a_fact.families, fam))
            continue
        a = by_id.get(aid)
        att_index[aid] = len(attachments)
        attachments.append(
            AttachmentFact(
                artifact_id=aid,
                display_name=_artifact_path(aid, by_id),
                detected_type=clean_text(a.detected_type if a else "unknown", 40),
                type_label=type_label(a.detected_type if a else "unknown"),
                sha256=(a.sha256 if a and re.fullmatch(r"[0-9a-fA-F]{64}", a.sha256 or "") else "").lower(),
                size=int(a.size) if a else 0,
                encrypted=bool(a.encrypted) if a else False,
                severity=Severity(f.severity),
                families=(clean_text(f.malware_family, FAMILY_MAX),) if f.malware_family else (),
            )
        )

    findings = tuple(
        FindingFact(
            rule=clean_text(f.rule, 120),
            title=_safe_text(f.title, FINDING_TITLE_MAX),
            description=_safe_text(f.description, FINDING_DESC_MAX),
            severity=Severity(f.severity),
            severity_label=_SEVERITY_LABELS.get(Severity(f.severity), "Info"),
            score=int(f.score),
            category=FindingCategory(f.category).value,
            artifact=_artifact_path(f.artifact_id, by_id) if f.artifact_id else None,
            family=clean_text(f.malware_family, FAMILY_MAX) or None,
        )
        for f in relevant[:TOP_FINDINGS]
    )
    rule = findings[0].rule if findings else f"centinela.verdict.{level}"

    urls = _evidence_urls(relevant, MAX_URLS)
    profile = _profile(relevant, families)
    # adjuntos "de verdad" (no cuentan las imágenes de firma/logos)
    has_attachments = bool(attachments) or any(
        a.depth == 0 and not (a.detected_type or "").startswith("image/") for a in result.artifacts
    )
    has_urls = bool(urls) or profile.phishing

    # remitente: nombre visible + dirección, ambos desactivados
    addr = clean_text(result.from_addr, 254)
    disp = _safe_text(result.from_display, 80)
    if addr and disp and disp.lower() != addr.lower():
        sender = f"{disp} <{defang_email(addr)}>"
    elif addr:
        sender = defang_email(addr)
    else:
        sender = disp or "(remitente desconocido)"
    sender = truncate(sender, SENDER_MAX + 40)

    recipients = tuple(c for c in (clean_text(a, 120) for a in result.to[:50]) if c)
    subject = _safe_text(result.subject, SUBJECT_MAX) or "(sin asunto)"
    summary = _safe_text(result.verdict.summary, SUMMARY_MAX) or _DEFAULT_SUMMARY.get(level, "")
    result_id = str(result.id)
    dashboard = _dashboard_url(settings, result_id)
    recs = _recommendations(level, profile, has_attachments, has_urls)
    tips = _recipient_tips(level, profile, has_attachments, has_urls)

    machine = _machine_payload(
        result,
        level=level,
        title=title,
        summary=summary,
        rule=rule,
        families=families,
        recommendations=recs,
        attachments=attachments,
        urls=urls,
        dashboard=dashboard,
        subject=subject,
        ordered=ordered,
    )
    return Alert(
        level=level,
        emoji=emoji,
        level_label=label,
        title=title,
        summary=summary,
        recommendations=tuple(recs),
        recipient_tips=tuple(tips),
        sender=sender,
        sender_address=addr or None,
        recipients=recipients,
        mailbox=mailbox,
        subject=subject,
        date=format_local_datetime(result.received_at, settings.general.timezone),
        score=int(result.verdict.score),
        attachments=tuple(attachments),
        families=tuple(families[:MAX_FAMILIES]),
        findings=findings,
        total_findings=len(relevant),
        urls=tuple(urls),
        dashboard_url=dashboard,
        rule=rule,
        result_id=result_id,
        company_name=clean_text(settings.general.company_name, 80),
        received_at=result.received_at
        if result.received_at.tzinfo
        else result.received_at.replace(tzinfo=UTC),
        analyzed_at=result.analyzed_at
        if result.analyzed_at.tzinfo
        else result.analyzed_at.replace(tzinfo=UTC),
        machine=machine,
    )


def _machine_payload(
    result: AnalysisResult,
    *,
    level: str,
    title: str,
    summary: str,
    rule: str,
    families: list[str],
    recommendations: list[str],
    attachments: list[AttachmentFact],
    urls: list[str],
    dashboard: str | None,
    subject: str,
    ordered: list[Finding],
) -> dict[str, Any]:
    """Campos para máquinas (webhook JSON, SIEM). Sin cuerpo, sin contenido de adjuntos, sin evidencia."""
    artifacts = []
    for a in result.artifacts[:MAX_MACHINE_ARTIFACTS]:
        d = a.model_dump(mode="json")
        for k in ("id", "filename", "declared_content_type", "extraction_note", "parent_id", "detected_type"):
            if d.get(k) is not None:
                d[k] = clean_text(d[k], 300)
        artifacts.append(d)
    findings = [
        {
            "analyzer": clean_text(f.analyzer, 60),
            "rule": clean_text(f.rule, 120),
            "title": _safe_text(f.title, FINDING_TITLE_MAX),
            "description": _safe_text(f.description, FINDING_DESC_MAX),
            "category": FindingCategory(f.category).value,
            "severity": Severity(f.severity).name.lower(),
            "severity_level": int(f.severity),
            "score": int(f.score),
            "artifact_id": clean_text(f.artifact_id, 300) or None,
            "malware_family": clean_text(f.malware_family, FAMILY_MAX) or None,
        }
        for f in ordered[:MAX_MACHINE_FINDINGS]
    ]
    return {
        "schema": "centinela.alert/v1",
        "id": str(result.id),
        "level": level,
        "score": int(result.verdict.score),
        "rule": rule,
        "title": title,
        "summary": summary,
        "recommendations": list(recommendations),
        "families": families[:MAX_FAMILIES],
        "dashboard_url": dashboard,
        "message": {
            "connector": clean_text(result.ref.connector, 64),
            "mailbox": clean_text(result.ref.mailbox, 254),
            "remote_id": clean_text(result.ref.remote_id, 300),
            "folder": clean_text(result.ref.folder, 200) or None,
            "message_id": clean_text(result.message_id, 300) or None,
            "subject": subject,
            "from": clean_text(result.from_addr, 254) or None,
            "from_display": _safe_text(result.from_display, 120) or None,
            "to": [c for c in (clean_text(a, 254) for a in result.to[:50]) if c],
            "received_at": _iso(result.received_at),
            "size": int(result.size),
        },
        "analysis": {
            "analyzed_at": _iso(result.analyzed_at),
            "duration_ms": int(result.duration_ms),
            "errors": len(result.errors),
            "verdict": {
                "level": level,
                "score": int(result.verdict.score),
                "summary": summary,
                "malware_families": families[:MAX_FAMILIES],
            },
        },
        "dangerous_attachments": [
            {
                "id": clean_text(a.artifact_id, 300),
                "path": a.display_name,
                "detected_type": a.detected_type,
                "sha256": a.sha256 or None,
                "size": a.size,
                "encrypted": a.encrypted,
                "max_severity": a.severity.name.lower(),
                "families": list(a.families),
            }
            for a in attachments[:MAX_MACHINE_ARTIFACTS]
        ],
        "findings": findings,
        "findings_total": len(result.findings),
        "artifacts": artifacts,
        "artifacts_total": len(result.artifacts),
        "urls_defanged": list(urls),
    }
