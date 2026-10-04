"""Reputación: SHA-256 de archivos en MalwareBazaar / VirusTotal y URLs en URLhaus.

Privacidad (regla de oro de Centinela):
- los ARCHIVOS nunca salen de la empresa: a MalwareBazaar y VirusTotal solo se les manda el SHA-256,
  y solo si `privacy.hash_lookups` y `analyzers.reputation.enabled` están activos;
- las URLs solo se consultan si `privacy.url_lookups` está activo (pueden llevar tokens personales):
  se les saca el fragmento (#...) y nunca se consultan URLs internas (IPs privadas, localhost,
  dominios propios de la empresa).

Robustez:
- resultados positivos y negativos se cachean en `ctx.cache` (positivos `cache_ttl_hours`, negativos
  `negative_cache_ttl_hours`, más corto, para detectar campañas nuevas que los servicios incorporan horas
  después; 0 = no cachear los negativos);
- VirusTotal gratis permite 4 consultas/minuto (`virustotal_requests_per_minute`, subirlo con una key
  premium; 0 = no consultar VT): un token bucket compartido por proceso decide; si no hay cupo en unos
  segundos se saltea con una nota INFO (nunca se frena el análisis del mail);
- nunca se consulta un hash vacío: las entradas "solo listadas" (`listing_only`, sin contenido) y los
  artifacts sin SHA-256 válido (o con el SHA-256 de un archivo vacío) se saltean;
- errores de red / cuotas / credenciales se convierten en notas INFO, no tumban el análisis;
- respuestas con tamaño máximo, timeouts en todo, nunca se loguean las API keys.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
import re
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from centinela.analyzers.base import ArtifactAnalyzer, MessageAnalyzer
from centinela.core.models import Finding, FindingCategory, Severity

if TYPE_CHECKING:
    from centinela.analyzers.base import AnalysisContext
    from centinela.core.cache import Cache
    from centinela.core.config import ReputationConfig, Settings
    from centinela.core.models import Artifact, ExtractedUrl

log = logging.getLogger(__name__)

MB_API_URL = "https://mb-api.abuse.ch/api/v1/"
VT_FILE_URL = "https://www.virustotal.com/api/v3/files/{sha256}"
URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/url/"

_USER_AGENT = "Centinela/0.1 (+self-hosted email security)"
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024  # un reporte de VT de un archivo popular puede pesar varios MB
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()  # nunca se consulta: "archivo vacío" no es un archivo
_CACHE_VERSION = 1
_VT_COOLDOWN_S = 60.0
_MAX_VT_RPM = 10_000
_MAX_URL_LEN = 2048
_SEEN_KEY = "reputation.sha256_seen"
_NOTED_KEY = "reputation.notes_emitted"


# --------------------------------------------------------------------------- familias


_FAMILY_ALIASES: dict[str, str] = {
    # RATs
    "asyncrat": "AsyncRAT",
    "dcrat": "DCRat",
    "darkcrystal": "DCRat",
    "darkcrystalrat": "DCRat",
    "quasar": "QuasarRAT",
    "quasarrat": "QuasarRAT",
    "njrat": "njRAT",
    "bladabindi": "njRAT",
    "remcos": "Remcos",
    "remcosrat": "Remcos",
    "xworm": "XWorm",
    "nanocore": "NanoCore",
    "warzone": "Warzone RAT",
    "warzonerat": "Warzone RAT",
    "avemaria": "Warzone RAT",
    "venomrat": "VenomRAT",
    "netsupport": "NetSupport RAT",
    "netsupportrat": "NetSupport RAT",
    "netsupportmanager": "NetSupport RAT",
    "netsupportmanagerrat": "NetSupport RAT",
    "darkcomet": "DarkComet",
    "netwire": "NetWire",
    "parallax": "Parallax RAT",
    "wshrat": "WSH RAT",
    "houdini": "Houdini",
    "strrat": "STRRAT",
    "adwind": "Adwind",
    "jrat": "Adwind",
    "orcus": "Orcus RAT",
    "valleyrat": "ValleyRAT",
    "darkgate": "DarkGate",
    # stealers / keyloggers
    "agenttesla": "AgentTesla",
    "negasteal": "AgentTesla",
    "formbook": "FormBook",
    "xloader": "XLoader",
    "lumma": "Lumma Stealer",
    "lummac": "Lumma Stealer",
    "lummac2": "Lumma Stealer",
    "redline": "RedLine Stealer",
    "metastealer": "META Stealer",
    "vidar": "Vidar",
    "stealc": "StealC",
    "snakekeylogger": "Snake Keylogger",
    "404keylogger": "Snake Keylogger",
    "raccoon": "Raccoon Stealer",
    "recordbreaker": "Raccoon Stealer",
    "rhadamanthys": "Rhadamanthys",
    "lokibot": "LokiBot",
    "masslogger": "MassLogger",
    "hawkeye": "HawkEye",
    "azorult": "Azorult",
    "purelogs": "PureLogs Stealer",
    "strela": "Strela Stealer",
    "blustealer": "BluStealer",
    # loaders / bots
    "guloader": "GuLoader",
    "cloudeye": "GuLoader",
    "dbatloader": "DBatLoader",
    "modiloader": "DBatLoader",
    "purecrypter": "PureCrypter",
    "smokeloader": "SmokeLoader",
    "amadey": "Amadey",
    "privateloader": "PrivateLoader",
    "emotet": "Emotet",
    "qakbot": "QakBot",
    "qbot": "QakBot",
    "icedid": "IcedID",
    "bumblebee": "Bumblebee",
    "pikabot": "Pikabot",
    "latrodectus": "Latrodectus",
    "zloader": "ZLoader",
    "ursnif": "Ursnif",
    "gozi": "Ursnif",
    "trickbot": "TrickBot",
    "cobaltstrike": "Cobalt Strike",
    # ransomware
    "lockbit": "LockBit",
    "blackcat": "BlackCat",
    "alphv": "BlackCat",
    "akira": "Akira",
    "conti": "Conti",
    "phobos": "Phobos",
    "djvu": "STOP/Djvu",
    "andromeda": "Andromeda",
    "gamarue": "Andromeda",
    # test
    "eicar": "EICAR-Test-File",
}

# nombres "genéricos" de motores antivirus que no identifican una familia real
_GENERIC_NAMES = frozenset(
    {
        "generic",
        "gen",
        "genericrxaa",
        "agent",
        "kryptik",
        "zusy",
        "razy",
        "tiggre",
        "bulz",
        "ulise",
        "barys",
        "johnnie",
        "midie",
        "lazy",
        "tedy",
        "jaik",
        "mikey",
        "fragtor",
        "ursu",
        "doina",
        "strictor",
        "cerbu",
        "malware",
        "trojan",
        "heur",
        "heuristic",
        "variant",
        "suspicious",
        "packed",
        "packer",
        "crypt",
        "cryptor",
        "crypter",
        "obfuscated",
        "wacatac",
        "sabsik",
        "casdet",
        "msil",
        "win32",
        "win64",
        "w32",
        "w64",
        "dropper",
        "downloader",
        "injector",
        "script",
        "unsafe",
        "artemis",
        "malicious",
        "confidence",
        "presenoker",
        "occamy",
        "tnega",
        "phonzy",
        "skeeyah",
        "convagent",
        "spyware",
        "ransom",
        "ransomware",
        "backdoor",
        "worm",
        "virus",
        "exploit",
        "pua",
        "pup",
        "adware",
        "riskware",
        "hacktool",
        "tool",
        "stealer",
        "infostealer",
        "passwordstealer",
        "psw",
        "rat",
        "remoteadmin",
        "loader",
        "bot",
        "miner",
        "coinminer",
        "autoit",
        "vbs",
        "js",
        "html",
        "pdf",
        "doc",
        "xls",
        "rtf",
        "lnk",
        "powershell",
        "nsis",
        "ole",
        "macro",
        "dotnet",
        "vb",
        "delphi",
        "rozena",
        "shellcode",
        "keylogger",
        "spy",
        "banker",
        "phishing",
        "unknown",
        "none",
        "null",
        "other",
        "multi",
        "win",
        "andr",
        "unix",
        "osx",
        "email",
        "txt",
        "img",
        "java",
        "trojanspy",
        "trojandownloader",
        "trojandropper",
        "behaveslike",
        "aipm",
        "smalldownloader",
        "vbinject",
        "msilheracles",
        "heracles",
        "ai",
        "test",
        "eicartest",
    }
)

_FAMILY_SUFFIXES = ("stealer", "rat", "loader", "bot", "keylogger", "ransomware", "ransom", "trojan")
_PLATFORM_PREFIX_RE = re.compile(r"^(?:win|elf|osx|apk|jar|js|ps1|vbs|py)\.(?=[A-Za-z0-9])", re.IGNORECASE)


def _family_key(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def known_family(name: str | None) -> str | None:
    """Nombre canónico SOLO si `name` es un alias conocido (no inventa familias)."""
    if not name:
        return None
    key = _family_key(str(name))[:80]
    if not key:
        return None
    if key in _FAMILY_ALIASES:
        return _FAMILY_ALIASES[key]
    for suffix in _FAMILY_SUFFIXES:
        if key.endswith(suffix) and key[: -len(suffix)] in _FAMILY_ALIASES:
            return _FAMILY_ALIASES[key[: -len(suffix)]]
    return None


def canonical_family(name: str | None) -> str | None:
    """Normaliza el nombre de una familia de malware ("RemcosRAT", "win.remcos", "remcos" -> "Remcos").

    Devuelve None para nombres genéricos de antivirus ("Generic", "Agent", "Kryptik"...). Un nombre
    desconocido pero plausible se devuelve limpio (sin sufijos numéricos de firma).
    """
    if not name:
        return None
    raw = str(name).strip()
    if not raw or len(raw) > 100:
        return None
    raw = _PLATFORM_PREFIX_RE.sub("", raw)  # ids estilo Malpedia: "win.remcos" -> "remcos"
    known = known_family(raw)
    if known:
        return known
    key = _family_key(raw)
    if len(key) < 3 or key.isdigit() or key in _GENERIC_NAMES:
        return None
    cleaned = re.sub(r"[-_.]?\d{4,}(?:-\d+)?$", "", raw).strip(" .-_/")
    if not cleaned or _family_key(cleaned) in _GENERIC_NAMES or not re.search(r"[A-Za-z]{3}", cleaned):
        return None
    return cleaned[:64]


def _family_from_vt(attrs: dict[str, Any]) -> tuple[str | None, str | None]:
    """(familia canónica, label crudo) a partir de popular_threat_classification de VirusTotal."""
    ptc = attrs.get("popular_threat_classification")
    if not isinstance(ptc, dict):
        return None, None
    label = ptc.get("suggested_threat_label")
    label = label[:120] if isinstance(label, str) else None
    candidates: list[str] = []
    if label:
        rest = label.split(".", 1)[1] if "." in label else label
        candidates.extend(p for p in rest.split("/") if p)
    names = ptc.get("popular_threat_name")
    if isinstance(names, list):
        for item in names[:5]:
            if isinstance(item, dict) and isinstance(item.get("value"), str):
                candidates.append(item["value"])
    for cand in candidates:
        fam = canonical_family(cand)
        if fam:
            return fam, label
    return None, label


# --------------------------------------------------------------------------- rate limit


class TokenBucket:
    """Token bucket sin locks (asyncio es monohilo): `acquire` nunca espera más de `max_wait_s`.

    Si el próximo token llega dentro de `max_wait_s`, lo reserva (tokens puede quedar negativo) y
    duerme hasta entonces; si no, devuelve False de inmediato.
    """

    def __init__(self, rate_per_minute: float, capacity: float, clock=time.monotonic) -> None:
        self.rate = rate_per_minute / 60.0
        self.capacity = float(capacity)
        self.tokens = float(capacity)
        self._clock = clock
        self._ts = clock()

    def _refill(self) -> None:
        now = self._clock()
        elapsed = max(0.0, now - self._ts)
        self._ts = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)

    def try_acquire(self) -> bool:
        self._refill()
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False

    async def acquire(self, max_wait_s: float) -> bool:
        if self.try_acquire():
            return True
        wait = (1.0 - self.tokens) / self.rate if self.rate > 0 else float("inf")
        if wait > max_wait_s:
            return False
        self.tokens -= 1.0  # reserva
        try:
            await asyncio.sleep(wait)
        except asyncio.CancelledError:
            self.tokens += 1.0
            raise
        return True

    def reset(self) -> None:
        self.tokens = self.capacity
        self._ts = self._clock()


@dataclass
class _ServiceState:
    cooldown_until: float = 0.0
    auth_error_logged: bool = False

    def cooling_down(self) -> bool:
        return time.monotonic() < self.cooldown_until

    def start_cooldown(self, seconds: float) -> None:
        self.cooldown_until = max(self.cooldown_until, time.monotonic() + seconds)


# compartidos por todo el proceso (la cuota de VirusTotal es por API key, no por mail)
VT_BUCKET = TokenBucket(rate_per_minute=4, capacity=4)  # cuota gratuita (el default de la configuración)
_VT_BUCKETS: dict[int, TokenBucket] = {4: VT_BUCKET}
_STATES: dict[str, _ServiceState] = {
    "malwarebazaar": _ServiceState(),
    "virustotal": _ServiceState(),
    "urlhaus": _ServiceState(),
}


def vt_bucket_for(requests_per_minute: int) -> TokenBucket:
    """Bucket de VirusTotal compartido por proceso para una cuota dada (`virustotal_requests_per_minute`).
    0 o negativo = sin cupo (nunca se consulta VT)."""
    rpm = max(0, min(_MAX_VT_RPM, int(requests_per_minute)))
    bucket = _VT_BUCKETS.get(rpm)
    if bucket is None:
        bucket = _VT_BUCKETS[rpm] = TokenBucket(rate_per_minute=rpm, capacity=rpm)
    return bucket


def reset_rate_limits() -> None:
    """Para tests y para recargar configuración: vacía cooldowns y llena los buckets de VT."""
    for bucket in _VT_BUCKETS.values():
        bucket.reset()
    for state in _STATES.values():
        state.cooldown_until = 0.0
        state.auth_error_logged = False


# --------------------------------------------------------------------------- HTTP / caché


class _LookupError(Exception):
    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind  # "network" | "timeout" | "too_large" | "invalid" | "auth" | "rate_limited" | "http"


async def _fetch_json(
    http: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    headers: dict[str, str],
    data: dict[str, str] | None = None,
    timeout_s: float,
) -> tuple[int, Any]:
    """Hace el request leyendo como máximo _MAX_RESPONSE_BYTES. Devuelve (status, json | None)."""
    try:
        async with asyncio.timeout(timeout_s * 2 + 1):
            async with http.stream(
                method, url, headers={"User-Agent": _USER_AGENT, **headers}, data=data, timeout=timeout_s
            ) as resp:
                body = bytearray()
                async for chunk in resp.aiter_bytes():
                    body += chunk
                    if len(body) > _MAX_RESPONSE_BYTES:
                        raise _LookupError("too_large", "respuesta demasiado grande")
                status = resp.status_code
    except _LookupError:
        raise
    except (httpx.TimeoutException, TimeoutError) as exc:
        raise _LookupError("timeout", "tiempo de espera agotado") from exc
    except httpx.HTTPError as exc:
        raise _LookupError("network", f"error de red: {type(exc).__name__}") from exc
    if not body:
        return status, None
    try:
        return status, json.loads(bytes(body))
    except ValueError:
        return status, None


async def _cache_get(cache: Cache, key: str) -> dict[str, Any] | None:
    try:
        raw = await cache.get(key)
    except Exception:  # noqa: BLE001 - un caché caído no debe frenar el análisis
        log.warning("no se pudo leer el caché de reputación", exc_info=True)
        return None
    if not raw:
        return None
    try:
        value = json.loads(raw)
    except ValueError:
        return None
    if (
        not isinstance(value, dict)
        or value.get("v") != _CACHE_VERSION
        or not isinstance(value.get("found"), bool)
    ):
        return None
    return value


def _cache_ttl(found: bool, cfg: ReputationConfig) -> int:
    """TTL en segundos (0 = no cachear). Un negativo nunca dura más que un positivo."""
    positive = max(60, int(cfg.cache_ttl_hours) * 3600)
    if found:
        return positive
    hours = int(cfg.negative_cache_ttl_hours)
    if hours <= 0:
        return 0
    return min(positive, max(60, hours * 3600))


async def _cache_set(cache: Cache, key: str, value: dict[str, Any], cfg: ReputationConfig) -> None:
    ttl = _cache_ttl(bool(value.get("found")), cfg)
    if ttl <= 0:
        return
    try:
        await cache.set(key, json.dumps({"v": _CACHE_VERSION, **value}, ensure_ascii=False), ttl)
    except Exception:  # noqa: BLE001
        log.warning("no se pudo guardar en el caché de reputación", exc_info=True)


def _str(value: Any, limit: int) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()[:limit]
    return None


def _str_list(value: Any, *, max_items: int = 15, limit: int = 64) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        s = _str(item, limit)
        if s and s not in out:
            out.append(s)
        if len(out) >= max_items:
            break
    return out


def _secret(value: Any) -> str | None:
    if value is None:
        return None
    raw = value.get_secret_value() if hasattr(value, "get_secret_value") else str(value)
    raw = raw.strip()
    return raw or None


def _note(
    analyzer: str, rule: str, title: str, description: str, *, artifact_id: str | None, **evidence: Any
) -> Finding:
    return Finding(
        analyzer=analyzer,
        rule=rule,
        title=title,
        description=description,
        category=FindingCategory.POLICY,
        severity=Severity.INFO,
        score=0,
        artifact_id=artifact_id,
        evidence=evidence,
    )


# --------------------------------------------------------------------------- parsers de respuestas


_MB_AUTH_STATUSES = frozenset(
    {"no_api_key", "unknown_auth_key", "user_blacklisted", "unauthorized", "auth_failed"}
)
_MB_NOT_FOUND = frozenset({"hash_not_found", "no_results"})


def _parse_malwarebazaar(status: int, payload: Any) -> dict[str, Any]:
    if status in (401, 403):
        raise _LookupError("auth", f"credenciales rechazadas (HTTP {status})")
    if status == 429:
        raise _LookupError("rate_limited", "cuota excedida (HTTP 429)")
    if status != 200:
        raise _LookupError("http", f"HTTP {status}")
    if not isinstance(payload, dict):
        raise _LookupError("invalid", "respuesta inválida")
    qs = payload.get("query_status")
    if qs in _MB_NOT_FOUND:
        return {"found": False}
    if qs in _MB_AUTH_STATUSES:
        raise _LookupError("auth", f"credenciales rechazadas ({qs})")
    if qs != "ok":
        raise _LookupError("invalid", f"estado inesperado: {str(qs)[:40]}")
    data = payload.get("data")
    entry = data[0] if isinstance(data, list) and data and isinstance(data[0], dict) else None
    if entry is None:
        raise _LookupError("invalid", "respuesta sin datos")
    signature = _str(entry.get("signature"), 80)
    tags = _str_list(entry.get("tags"))
    family = canonical_family(signature)
    if not family:
        for tag in tags:
            family = known_family(tag)
            if family:
                break
    return {
        "found": True,
        "signature": signature,
        "family": family,
        "tags": tags,
        "first_seen": _str(entry.get("first_seen"), 32),
        "file_type": _str(entry.get("file_type"), 24),
    }


def _parse_virustotal(status: int, payload: Any) -> dict[str, Any]:
    if status == 404:
        return {"found": False}
    if status in (401, 403):
        raise _LookupError("auth", f"credenciales rechazadas (HTTP {status})")
    if status == 429:
        raise _LookupError("rate_limited", "cuota excedida (HTTP 429)")
    if status != 200:
        raise _LookupError("http", f"HTTP {status}")
    attrs = None
    if isinstance(payload, dict) and isinstance(payload.get("data"), dict):
        attrs = payload["data"].get("attributes")
    if not isinstance(attrs, dict):
        raise _LookupError("invalid", "respuesta inválida")
    stats = attrs.get("last_analysis_stats")
    stats = stats if isinstance(stats, dict) else {}

    def _int(key: str) -> int:
        v = stats.get(key)
        return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else 0

    total = sum(_int(k) for k in stats if isinstance(k, str))
    family, label = _family_from_vt(attrs)
    return {
        "found": True,
        "malicious": _int("malicious"),
        "suspicious": _int("suspicious"),
        "total": total,
        "label": label,
        "family": family,
    }


def _parse_urlhaus(status: int, payload: Any) -> dict[str, Any]:
    if status in (401, 403):
        raise _LookupError("auth", f"credenciales rechazadas (HTTP {status})")
    if status == 429:
        raise _LookupError("rate_limited", "cuota excedida (HTTP 429)")
    if status != 200:
        raise _LookupError("http", f"HTTP {status}")
    if not isinstance(payload, dict):
        raise _LookupError("invalid", "respuesta inválida")
    qs = payload.get("query_status")
    if qs in ("no_results", "invalid_url"):
        return {"found": False}
    if qs in _MB_AUTH_STATUSES:
        raise _LookupError("auth", f"credenciales rechazadas ({qs})")
    if qs != "ok":
        raise _LookupError("invalid", f"estado inesperado: {str(qs)[:40]}")
    signatures: list[str] = []
    payloads = payload.get("payloads")
    if isinstance(payloads, list):
        for item in payloads[:100]:
            if isinstance(item, dict):
                fam = canonical_family(_str(item.get("signature"), 80))
                if fam and fam not in signatures:
                    signatures.append(fam)
            if len(signatures) >= 5:
                break
    return {
        "found": True,
        "url_status": _str(payload.get("url_status"), 16) or "unknown",
        "threat": _str(payload.get("threat"), 40) or "",
        "tags": _str_list(payload.get("tags"), max_items=10),
        "families": signatures,
        "reference": _str(payload.get("urlhaus_reference"), 200),
        "date_added": _str(payload.get("date_added"), 32),
    }


# --------------------------------------------------------------------------- analizador de archivos


@dataclass
class _Outcome:
    findings: list[Finding]
    hit: bool = False


class ReputationAnalyzer(ArtifactAnalyzer):
    """Busca el SHA-256 de cada archivo en MalwareBazaar y VirusTotal (nunca sube el archivo)."""

    name = "reputation"
    vt_max_wait_s: float = 2.0  # espera máxima por un token de VirusTotal antes de saltear

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.vt_bucket = vt_bucket_for(settings.analyzers.reputation.virustotal_requests_per_minute)

    @classmethod
    def enabled(cls, settings: Settings) -> bool:
        return super().enabled(settings) and settings.analyzers.reputation.enabled

    def _keys(self, settings: Settings) -> tuple[str | None, str | None]:
        cfg = settings.analyzers.reputation
        # virustotal_requests_per_minute <= 0: VirusTotal desactivado aunque haya key
        vt_key = _secret(cfg.virustotal_api_key) if int(cfg.virustotal_requests_per_minute) > 0 else None
        return _secret(cfg.malwarebazaar_api_key), vt_key

    def _active(self, settings: Settings) -> bool:
        if not (settings.privacy.hash_lookups and settings.analyzers.reputation.enabled):
            return False
        mb_key, vt_key = self._keys(settings)
        return bool(mb_key or vt_key)

    def accepts(self, artifact: Artifact) -> bool:
        if not self._active(self.settings):
            return False
        if artifact.listing_only:  # entrada solo listada: no hay contenido ni hash que consultar
            return False
        sha = (artifact.sha256 or "").lower()
        if not _SHA256_RE.fullmatch(sha) or sha == _EMPTY_SHA256:
            return False
        size = artifact.size or len(artifact.data)
        if size <= 0:
            return False
        dtype = (artifact.detected_type or "").lower()
        if dtype.startswith("image/"):
            return False
        return not (dtype == "text" and size < 1024)

    async def analyze(self, ctx: AnalysisContext, artifact: Artifact) -> list[Finding]:
        settings = ctx.settings
        if not self._active(settings) or not self.accepts(artifact):
            return []
        sha = artifact.sha256.lower()
        seen = ctx.extra.setdefault(_SEEN_KEY, set())
        if not isinstance(seen, set):
            seen = set()
            ctx.extra[_SEEN_KEY] = seen
        if sha in seen:  # mismo archivo repetido en el mail: una sola consulta
            return []
        seen.add(sha)

        mb_key, vt_key = self._keys(settings)
        findings: list[Finding] = []
        mb_hit = False
        if mb_key:
            outcome = await self._malwarebazaar(ctx, sha, artifact.id, mb_key)
            findings.extend(outcome.findings)
            mb_hit = outcome.hit
        if vt_key and not mb_hit:  # si MalwareBazaar ya lo conoce no gastamos cuota de VT
            findings.extend(await self._virustotal(ctx, sha, artifact.id, vt_key))
        return findings

    # ----------------------------------------------------------------- MalwareBazaar

    async def _malwarebazaar(self, ctx: AnalysisContext, sha: str, artifact_id: str, key: str) -> _Outcome:
        cfg = ctx.settings.analyzers.reputation
        cache_key = f"rep:mb:{sha}"
        result = await _cache_get(ctx.cache, cache_key)
        cached = result is not None
        if result is None:
            state = _STATES["malwarebazaar"]
            if state.cooling_down():
                return _Outcome(self._service_notes(ctx, "malwarebazaar", "rate_limited", artifact_id))
            try:
                status, payload = await _fetch_json(
                    ctx.http,
                    "POST",
                    MB_API_URL,
                    headers={"Auth-Key": key, "Accept": "application/json"},
                    data={"query": "get_info", "hash": sha},
                    timeout_s=cfg.timeout_s,
                )
                result = _parse_malwarebazaar(status, payload)
            except _LookupError as exc:
                self._handle_error("malwarebazaar", exc)
                return _Outcome(self._service_notes(ctx, "malwarebazaar", exc.kind, artifact_id, str(exc)))
            await _cache_set(ctx.cache, cache_key, result, cfg)

        if not result.get("found"):
            return _Outcome([])
        family = result.get("family")
        fam_txt = f" de la familia {family}" if family else ""
        return _Outcome(
            [
                Finding(
                    analyzer=self.name,
                    rule="rep.malwarebazaar",
                    title=f"Archivo conocido como malware{f' ({family})' if family else ''}",
                    description=(
                        f"Este archivo es idéntico a una muestra de malware{fam_txt} registrada en la base "
                        "pública MalwareBazaar (abuse.ch). Se comparó solo su huella digital (SHA-256): el "
                        "archivo no salió de la empresa. No lo abras y avisá a quien maneje la seguridad."
                    ),
                    category=FindingCategory.REPUTATION,
                    severity=Severity.CRITICAL,
                    score=98,
                    artifact_id=artifact_id,
                    malware_family=family,
                    evidence={
                        "service": "malwarebazaar",
                        "sha256": sha,
                        "signature": result.get("signature"),
                        "tags": result.get("tags") or [],
                        "first_seen": result.get("first_seen"),
                        "file_type": result.get("file_type"),
                        "link": f"https://bazaar.abuse.ch/sample/{sha}/",
                        "cached": cached,
                    },
                )
            ],
            hit=True,
        )

    # ----------------------------------------------------------------- VirusTotal

    async def _virustotal(self, ctx: AnalysisContext, sha: str, artifact_id: str, key: str) -> list[Finding]:
        cfg = ctx.settings.analyzers.reputation
        cache_key = f"rep:vt:{sha}"
        result = await _cache_get(ctx.cache, cache_key)
        cached = result is not None
        if result is None:
            state = _STATES["virustotal"]
            if state.cooling_down() or not await self.vt_bucket.acquire(self.vt_max_wait_s):
                return self._service_notes(ctx, "virustotal", "rate_limited", artifact_id)
            try:
                status, payload = await _fetch_json(
                    ctx.http,
                    "GET",
                    VT_FILE_URL.format(sha256=sha),
                    headers={"x-apikey": key, "Accept": "application/json"},
                    timeout_s=cfg.timeout_s,
                )
                result = _parse_virustotal(status, payload)
            except _LookupError as exc:
                self._handle_error("virustotal", exc)
                return self._service_notes(ctx, "virustotal", exc.kind, artifact_id, str(exc))
            await _cache_set(ctx.cache, cache_key, result, cfg)

        if not result.get("found"):
            return []
        malicious = int(result.get("malicious") or 0)
        total = int(result.get("total") or 0)
        family = result.get("family")
        evidence = {
            "service": "virustotal",
            "sha256": sha,
            "malicious": malicious,
            "suspicious": int(result.get("suspicious") or 0),
            "total": total,
            "label": result.get("label"),
            "link": f"https://www.virustotal.com/gui/file/{sha}",
            "cached": cached,
        }
        ratio = f"{malicious} de {total}" if total else str(malicious)
        if malicious >= 5:
            return [
                Finding(
                    analyzer=self.name,
                    rule="rep.virustotal",
                    title=f"VirusTotal: {ratio} antivirus lo marcan como malicioso"
                    + (f" ({family})" if family else ""),
                    description=(
                        f"{ratio} motores antivirus de VirusTotal identifican este archivo como malicioso"
                        + (f" (familia {family})" if family else "")
                        + ". Se consultó solo su huella digital (SHA-256): el archivo no salió de la "
                        "empresa. No lo abras."
                    ),
                    category=FindingCategory.REPUTATION,
                    severity=Severity.CRITICAL,
                    score=95,
                    artifact_id=artifact_id,
                    malware_family=family,
                    evidence=evidence,
                )
            ]
        if malicious >= 2:
            return [
                Finding(
                    analyzer=self.name,
                    rule="rep.virustotal.low_detections",
                    title=f"VirusTotal: {ratio} antivirus lo marcan como malicioso",
                    description=(
                        "Unos pocos antivirus de VirusTotal marcan este archivo como malicioso. Puede ser un "
                        "falso positivo o malware nuevo que todavía pocos detectan: tratalo con cuidado."
                    ),
                    category=FindingCategory.REPUTATION,
                    severity=Severity.MEDIUM,
                    score=40,
                    artifact_id=artifact_id,
                    malware_family=family,
                    evidence=evidence,
                )
            ]
        return [
            Finding(
                analyzer=self.name,
                rule="rep.virustotal.clean",
                title="VirusTotal: el archivo es conocido y no está marcado como malicioso",
                description=(
                    "VirusTotal ya conocía este archivo y prácticamente ningún antivirus lo marca como "
                    "malicioso. Es solo contexto: no garantiza que sea seguro."
                ),
                category=FindingCategory.REPUTATION,
                severity=Severity.INFO,
                score=0,
                artifact_id=artifact_id,
                evidence=evidence,
            )
        ]

    # ----------------------------------------------------------------- errores

    def _handle_error(self, service: str, exc: _LookupError) -> None:
        state = _STATES[service]
        if exc.kind == "rate_limited":
            state.start_cooldown(_VT_COOLDOWN_S)
            log.warning("reputación: %s devolvió cuota excedida; se pausa %ss", service, int(_VT_COOLDOWN_S))
        elif exc.kind == "auth":
            state.start_cooldown(300.0)
            if not state.auth_error_logged:
                state.auth_error_logged = True
                log.error("reputación: %s rechazó la API key configurada (%s)", service, exc)
        else:
            log.warning("reputación: no se pudo consultar %s: %s", service, exc)

    def _service_notes(
        self, ctx: AnalysisContext, service: str, kind: str, artifact_id: str, detail: str | None = None
    ) -> list[Finding]:
        """Nota INFO de servicio no consultado: una sola por mail y por (servicio, motivo)."""
        noted = ctx.extra.setdefault(_NOTED_KEY, set())
        if not isinstance(noted, set) or (service, kind) in noted:
            return []
        noted.add((service, kind))
        return [self._service_note(service, kind, artifact_id, detail)]

    def _service_note(self, service: str, kind: str, artifact_id: str, detail: str | None = None) -> Finding:
        pretty = {"malwarebazaar": "MalwareBazaar", "virustotal": "VirusTotal"}.get(service, service)
        if kind == "rate_limited":
            return _note(
                self.name,
                f"rep.{service}.rate_limited",
                f"{pretty}: consulta salteada por límite de uso",
                f"No se consultó {pretty} para este archivo porque se alcanzó el límite de consultas del "
                "plan gratuito. El resto del análisis no se ve afectado.",
                artifact_id=artifact_id,
                service=service,
            )
        return _note(
            self.name,
            f"rep.{service}.error",
            f"{pretty}: no se pudo consultar",
            f"No se pudo consultar la reputación del archivo en {pretty} ({detail or kind}). El resto del "
            "análisis no se ve afectado.",
            artifact_id=artifact_id,
            service=service,
            error=kind,
        )


# --------------------------------------------------------------------------- analizador de URLs


def _is_internal_host(host: str, company_domains: list[str]) -> bool:
    host = host.strip(".").lower()
    if not host or host == "localhost" or host.endswith((".localhost", ".local", ".internal", ".lan")):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        return not ip.is_global
    if "." not in host:  # nombre de una sola etiqueta: intranet
        return True
    for dom in company_domains:
        dom = dom.strip(".").lower()
        if dom and (host == dom or host.endswith("." + dom)):
            return True
    return False


def _normalize_lookup_url(url: str, company_domains: list[str]) -> str | None:
    url = (url or "").strip()
    if not url or len(url) > _MAX_URL_LEN or any(c in url for c in "\r\n\t "):
        return None
    try:
        parts = urlsplit(url)
        host = parts.hostname
        port = parts.port
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not host:
        return None
    if _is_internal_host(host, company_domains):
        return None
    # nunca mandar usuario:contraseña@ embebidos en la URL
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc += f":{port}"
    # el fragmento (#...) nunca viaja al servidor y suele llevar tokens: no se manda a URLhaus
    return urlunsplit((parts.scheme.lower(), netloc, parts.path, parts.query, ""))


def _artifact_from_source(source: str) -> str | None:
    if source.startswith("artifact:"):
        return source.split(":", 1)[1] or None
    return None


@dataclass
class _UrlLookup:
    url: str
    source: str
    result: dict[str, Any] | None = None
    error: str | None = None


class UrlReputationAnalyzer(MessageAnalyzer):
    """Consulta las URLs del mail en URLhaus (solo si `privacy.url_lookups`)."""

    name = "url_reputation"
    max_urls_per_message: int = 20
    concurrency: int = 4

    @classmethod
    def enabled(cls, settings: Settings) -> bool:
        return super().enabled(settings) and settings.analyzers.reputation.enabled

    @staticmethod
    def _key(settings: Settings) -> str | None:
        return _secret(settings.analyzers.reputation.urlhaus_api_key)

    def _active(self, settings: Settings) -> bool:
        return bool(
            settings.privacy.url_lookups and settings.analyzers.reputation.enabled and self._key(settings)
        )

    def _select(self, urls: list[ExtractedUrl], company_domains: list[str]) -> list[tuple[str, str]]:
        selected: list[tuple[str, str]] = []
        seen: set[str] = set()
        for u in urls:
            norm = _normalize_lookup_url(u.url, company_domains)
            if norm is None or norm in seen:
                continue
            seen.add(norm)
            selected.append((norm, u.source or ""))
            if len(selected) >= self.max_urls_per_message:
                break
        return selected

    async def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        settings = ctx.settings
        if not self._active(settings):
            return []
        key = self._key(settings)
        assert key is not None
        targets = self._select(ctx.message.urls, settings.general.company_domains)
        if not targets:
            return []
        sem = asyncio.Semaphore(max(1, self.concurrency))
        lookups = await asyncio.gather(*(self._lookup(ctx, url, source, key, sem) for url, source in targets))
        return self._findings(lookups)

    async def _lookup(
        self, ctx: AnalysisContext, url: str, source: str, key: str, sem: asyncio.Semaphore
    ) -> _UrlLookup:
        cfg = ctx.settings.analyzers.reputation
        out = _UrlLookup(url=url, source=source)
        cache_key = "rep:urlhaus:" + hashlib.sha256(url.encode("utf-8", "surrogatepass")).hexdigest()
        cached = await _cache_get(ctx.cache, cache_key)
        if cached is not None:
            out.result = cached
            return out
        state = _STATES["urlhaus"]
        if state.cooling_down():
            out.error = "rate_limited"
            return out
        async with sem:
            try:
                status, payload = await _fetch_json(
                    ctx.http,
                    "POST",
                    URLHAUS_API_URL,
                    headers={"Auth-Key": key, "Accept": "application/json"},
                    data={"url": url},
                    timeout_s=cfg.timeout_s,
                )
                out.result = _parse_urlhaus(status, payload)
            except _LookupError as exc:
                out.error = exc.kind
                if exc.kind == "rate_limited":
                    state.start_cooldown(_VT_COOLDOWN_S)
                elif exc.kind == "auth":
                    state.start_cooldown(300.0)
                    if not state.auth_error_logged:
                        state.auth_error_logged = True
                        log.error("reputación: URLhaus rechazó la API key configurada (%s)", exc)
                else:
                    log.warning("reputación: no se pudo consultar URLhaus: %s", exc)
                return out
        await _cache_set(ctx.cache, cache_key, out.result, cfg)
        return out

    def _findings(self, lookups: list[_UrlLookup]) -> list[Finding]:
        groups: dict[str | None, list[_UrlLookup]] = {}
        errors: dict[str, int] = {}
        for lk in lookups:
            if lk.error:
                errors[lk.error] = errors.get(lk.error, 0) + 1
            elif lk.result and lk.result.get("found"):
                groups.setdefault(_artifact_from_source(lk.source), []).append(lk)

        findings: list[Finding] = []
        for artifact_id, items in groups.items():
            malware = [i for i in items if "phish" not in str(i.result.get("threat", "")).lower()]
            category = FindingCategory.MALWARE if malware else FindingCategory.PHISHING
            online = any(i.result.get("url_status") in ("online", "offline") for i in items)
            families: list[str] = []
            for i in items:
                for fam in i.result.get("families") or []:
                    if fam not in families:
                        families.append(fam)
            family = families[0] if families else None
            if category == FindingCategory.MALWARE:
                title = "Link a un sitio que distribuye malware (URLhaus)"
                desc = (
                    "El mail contiene un link registrado en URLhaus (abuse.ch) como sitio que distribuye "
                    "programas maliciosos"
                    + (f" ({family})" if family else "")
                    + ". No hagas clic: si alguien ya lo abrió, avisá a quien maneje la seguridad."
                )
            else:
                title = "Link de phishing conocido (URLhaus)"
                desc = (
                    "El mail contiene un link registrado en URLhaus (abuse.ch) como sitio malicioso. "
                    "No hagas clic ni ingreses usuario o contraseña."
                )
            findings.append(
                Finding(
                    analyzer=self.name,
                    rule="rep.urlhaus",
                    title=title,
                    description=desc,
                    category=category,
                    severity=Severity.HIGH,
                    score=85 if online else 75,
                    artifact_id=artifact_id,
                    malware_family=family,
                    evidence={
                        "service": "urlhaus",
                        "count": len(items),
                        "urls": [
                            {
                                "url": i.url[:200],
                                "url_status": i.result.get("url_status"),
                                "threat": i.result.get("threat"),
                                "tags": i.result.get("tags") or [],
                                "reference": i.result.get("reference"),
                            }
                            for i in items[:10]
                        ],
                    },
                )
            )
        if errors:
            findings.append(
                _note(
                    self.name,
                    "rep.urlhaus.error",
                    "URLhaus: no se pudieron consultar algunos links",
                    "No se pudo verificar la reputación de algunos links del mail en URLhaus. El resto del "
                    "análisis no se ve afectado.",
                    artifact_id=None,
                    service="urlhaus",
                    errors=errors,
                )
            )
        return findings


__all__ = [
    "MB_API_URL",
    "URLHAUS_API_URL",
    "VT_BUCKET",
    "VT_FILE_URL",
    "ReputationAnalyzer",
    "TokenBucket",
    "UrlReputationAnalyzer",
    "canonical_family",
    "known_family",
    "reset_rate_limits",
    "vt_bucket_for",
]
