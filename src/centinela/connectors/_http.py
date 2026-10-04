"""Helper HTTP asíncrono compartido por los conectores cloud (Gmail API, Microsoft Graph, Pub/Sub).

Qué resuelve:
- Reintentos con backoff exponencial + jitter ante errores de red, 408/429/5xx (y lo que el llamador
  marque como reintentable, ej. el 403 `rateLimitExceeded` de Gmail), respetando `Retry-After`
  (segundos o fecha HTTP) con un tope.
- 401: pide un token nuevo (forzando refresh) UNA vez y reintenta.
- Lectura del cuerpo SIEMPRE con tope de bytes (streaming): una respuesta gigante u hostil no puede
  agotar la memoria. Superar el tope levanta `ResponseTooLarge` sin reintentar.
- Timeout por intento (conexión/lectura) y timeout total por intento (anti "slowloris").
- Esperas interrumpibles por el `stop` del conector.
- Nunca loguea tokens, query strings ni cuerpos: solo método, host+path y status.
"""

from __future__ import annotations

import asyncio
import email.utils
import json
import logging
import random
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import httpx

from centinela import __version__
from centinela.core.models import VerdictLevel

if TYPE_CHECKING:
    from centinela.core.config import TagConfig

log = logging.getLogger(__name__)

USER_AGENT = f"centinela/{__version__} (+passive mail security; httpx)"

DEFAULT_TIMEOUT = httpx.Timeout(connect=10.0, read=60.0, write=30.0, pool=15.0)
DEFAULT_MAX_BODY = 16 * 1024 * 1024  # respuestas JSON de API: nunca deberían acercarse a esto
RETRY_STATUSES: frozenset[int] = frozenset({408, 429, 500, 502, 503, 504})

TokenFn = Callable[[bool], Awaitable[str]]
"""`await token(force_refresh)` -> access token (bearer)."""

RetryPredicate = Callable[["HttpResponse"], bool]


class HttpError(Exception):
    """Error HTTP/red no recuperable (o reintentos agotados). El mensaje no incluye secretos."""

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        url: str | None = None,
        code: str | None = None,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.url = url
        self.code = code
        self.retry_after = retry_after


class ResponseTooLarge(HttpError):
    """El cuerpo de la respuesta superó el tope de bytes permitido.

    `size` es el Content-Length declarado, o None si no se conoce (solo se sabe que supera el tope).
    """

    def __init__(self, message: str, *, size: int | None = None, **kwargs: Any) -> None:
        super().__init__(message, **kwargs)
        self.size = size


class Stopped(Exception):
    """Se activó el `stop` del conector mientras se esperaba para reintentar (señal, no error)."""


@dataclass
class RetryPolicy:
    max_attempts: int = 5
    base_delay: float = 1.0
    max_delay: float = 60.0
    max_retry_after: float = 300.0  # nunca esperar más que esto por un Retry-After
    retry_statuses: frozenset[int] = field(default_factory=lambda: RETRY_STATUSES)


DEFAULT_POLICY = RetryPolicy()


@dataclass
class HttpResponse:
    status_code: int
    headers: httpx.Headers
    content: bytes
    url: str  # saneada: esquema + host + path, sin query

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300

    def json(self) -> Any:
        if not self.content:
            return {}
        try:
            return json.loads(self.content)
        except (ValueError, UnicodeDecodeError) as exc:
            raise HttpError(
                f"respuesta no es JSON válido ({self.status_code} {self.url})",
                status=self.status_code,
                url=self.url,
            ) from exc

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")

    def error_code(self) -> str | None:
        """Código de error de la API: Graph `error.code`, Google `error.errors[0].reason` / `error.status`."""
        try:
            data = json.loads(self.content) if self.content else None
        except (ValueError, UnicodeDecodeError):
            return None
        if not isinstance(data, dict):
            return None
        err = data.get("error")
        if isinstance(err, str):  # OAuth: {"error": "invalid_grant"}
            return err
        if not isinstance(err, dict):
            return None
        errors = err.get("errors")
        if isinstance(errors, list) and errors and isinstance(errors[0], dict) and errors[0].get("reason"):
            return str(errors[0]["reason"])
        for key in ("code", "status"):
            v = err.get(key)
            if isinstance(v, str) and v:
                return v
        return None

    def error_message(self, limit: int = 300) -> str:
        """Mensaje de error de la API, recortado (para logs/diagnóstico; nunca contiene el token)."""
        try:
            data = json.loads(self.content) if self.content else None
        except (ValueError, UnicodeDecodeError):
            data = None
        msg = ""
        if isinstance(data, dict):
            err = data.get("error")
            if isinstance(err, dict):
                msg = str(err.get("message") or "")
            elif isinstance(err, str):
                msg = str(data.get("error_description") or err)
        return msg[:limit]

    def raise_for_status(self, context: str = "") -> HttpResponse:
        if self.ok:
            return self
        code = self.error_code()
        detail = self.error_message()
        prefix = f"{context}: " if context else ""
        raise HttpError(
            f"{prefix}HTTP {self.status_code} en {self.url}"
            + (f" ({code})" if code else "")
            + (f": {detail}" if detail else ""),
            status=self.status_code,
            url=self.url,
            code=code,
            retry_after=parse_retry_after(self.headers.get("retry-after")),
        )


def safe_url(url: str | httpx.URL) -> str:
    """URL sin query ni fragmento (las query strings pueden llevar tokens de delta o filtros con PII)."""
    parts = urlsplit(str(url))
    return f"{parts.scheme}://{parts.netloc}{parts.path}"


def parse_retry_after(value: str | None, *, now: float | None = None) -> float | None:
    """`Retry-After` en segundos (entero/decimal) o fecha HTTP. None si falta o es inválido."""
    if value is None:
        return None
    value = value.strip()
    if not value or len(value) > 64:
        return None
    try:
        secs = float(value)
    except ValueError:
        try:
            dt = email.utils.parsedate_to_datetime(value)
        except (TypeError, ValueError, IndexError):
            return None
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        ref = time.time() if now is None else now
        secs = dt.timestamp() - ref
    if secs != secs or secs < 0:  # NaN o negativo
        return 0.0
    return secs


def backoff_delay(
    attempt: int, *, base: float = 1.0, cap: float = 60.0, rng: Callable[[], float] = random.random
) -> float:
    """Backoff exponencial con jitter ("equal jitter"): entre 50% y 100% de min(cap, base*2^attempt)."""
    attempt = max(0, min(attempt, 30))
    ceiling = min(cap, base * (2**attempt))
    return ceiling / 2 + rng() * ceiling / 2


class Backoff:
    """Backoff con estado para loops de conectores (reconexión con tope)."""

    def __init__(self, base: float = 1.0, cap: float = 300.0) -> None:
        self.base = base
        self.cap = cap
        self.attempt = 0

    def next(self) -> float:
        d = backoff_delay(self.attempt, base=self.base, cap=self.cap)
        self.attempt += 1
        return d

    def reset(self) -> None:
        self.attempt = 0


async def sleep_or_stop(seconds: float, stop: asyncio.Event | None = None) -> bool:
    """Duerme `seconds` o hasta que `stop` se active. Devuelve True si se activó `stop`."""
    seconds = max(0.0, seconds)
    if stop is None:
        await asyncio.sleep(seconds)
        return False
    if stop.is_set():
        return True
    try:
        await asyncio.wait_for(stop.wait(), timeout=seconds)
    except TimeoutError:
        return False
    return True


# Indirección para que los tests puedan registrar/acortar las esperas sin dormir de verdad.
_sleep = sleep_or_stop


def _retry_after_seconds(resp: HttpResponse) -> float | None:
    ra = parse_retry_after(resp.headers.get("retry-after"))
    if ra is None:
        # algunos servicios de Microsoft mandan x-ms-retry-after-ms
        raw = resp.headers.get("x-ms-retry-after-ms")
        if raw:
            try:
                ra = max(0.0, float(raw) / 1000.0)
            except ValueError:
                ra = None
    return ra


async def _send_once(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    params: Mapping[str, Any] | None,
    headers: dict[str, str],
    json_body: Any,
    content: bytes | None,
    timeouts: httpx.Timeout,
    max_body: int,
    total_timeout: float,
) -> HttpResponse:
    async with asyncio.timeout(total_timeout):
        req = client.build_request(
            method, url, params=params, headers=headers, json=json_body, content=content, timeout=timeouts
        )
        resp = await client.send(req, stream=True)
        try:
            surl = safe_url(resp.request.url)
            declared = resp.headers.get("content-length")
            if declared and declared.isdigit() and int(declared) > max_body:
                raise ResponseTooLarge(
                    f"respuesta demasiado grande ({declared} bytes > {max_body}) en {surl}",
                    size=int(declared),
                    status=resp.status_code,
                    url=surl,
                )
            buf = bytearray()
            async for chunk in resp.aiter_bytes():
                buf += chunk
                if len(buf) > max_body:
                    raise ResponseTooLarge(
                        f"respuesta demasiado grande (> {max_body} bytes) en {surl}",
                        status=resp.status_code,
                        url=surl,
                    )
            return HttpResponse(
                status_code=resp.status_code, headers=resp.headers, content=bytes(buf), url=surl
            )
        finally:
            await resp.aclose()


async def request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    params: Mapping[str, Any] | None = None,
    headers: Mapping[str, str] | None = None,
    json: Any = None,  # mismo nombre que en httpx
    content: bytes | None = None,
    token: TokenFn | None = None,
    timeouts: httpx.Timeout | None = None,
    total_timeout: float = 180.0,
    max_body: int = DEFAULT_MAX_BODY,
    policy: RetryPolicy = DEFAULT_POLICY,
    retry_if: RetryPredicate | None = None,
    stop: asyncio.Event | None = None,
) -> HttpResponse:
    """Hace el request con reintentos. Devuelve la respuesta final (2xx o error no reintentable).

    Levanta `HttpError` si se agotan los reintentos por red/429/5xx, `ResponseTooLarge` si el cuerpo
    supera `max_body`, y `Stopped` si `stop` se activa durante una espera de reintento.
    """
    hdrs: dict[str, str] = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    surl = safe_url(url)
    refreshed = False
    use_refreshed = False
    attempt = 0
    last_exc: BaseException | None = None
    while True:
        if stop is not None and stop.is_set():
            raise Stopped()
        if token is not None and not use_refreshed:
            hdrs["Authorization"] = f"Bearer {await token(False)}"
        use_refreshed = False
        delay: float | None = None
        try:
            resp = await _send_once(
                client,
                method,
                url,
                params=params,
                headers=hdrs,
                json_body=json,
                content=content,
                timeouts=timeouts or DEFAULT_TIMEOUT,
                max_body=max_body,
                total_timeout=total_timeout,
            )
        except ResponseTooLarge:
            raise
        except (httpx.TransportError, TimeoutError) as exc:
            last_exc = exc
            log.debug(
                "HTTP %s %s: error de red %s (intento %d)", method, surl, type(exc).__name__, attempt + 1
            )
            delay = backoff_delay(attempt, base=policy.base_delay, cap=policy.max_delay)
        else:
            log.debug("HTTP %s %s -> %d", method, resp.url, resp.status_code)
            if resp.status_code == 401 and token is not None and not refreshed:
                refreshed = True
                use_refreshed = True
                hdrs["Authorization"] = f"Bearer {await token(True)}"
                continue
            retryable = resp.status_code in policy.retry_statuses or (retry_if is not None and retry_if(resp))
            if not retryable:
                return resp
            ra = _retry_after_seconds(resp)
            if attempt + 1 >= policy.max_attempts:
                raise HttpError(
                    f"HTTP {resp.status_code} en {resp.url} tras {attempt + 1} intentos"
                    + (f" ({resp.error_code()})" if resp.error_code() else ""),
                    status=resp.status_code,
                    url=resp.url,
                    code=resp.error_code(),
                    retry_after=ra,
                )
            if ra is not None:
                delay = min(ra, policy.max_retry_after)
            else:
                delay = backoff_delay(attempt, base=policy.base_delay, cap=policy.max_delay)
            log.info("HTTP %s %s -> %d; reintento en %.1fs", method, resp.url, resp.status_code, delay)
        attempt += 1
        if attempt >= policy.max_attempts:
            raise HttpError(
                f"error de red en {surl} tras {attempt} intentos: {type(last_exc).__name__}", url=surl
            ) from last_exc
        if await _sleep(delay, stop):
            raise Stopped()


def new_client(*, max_connections: int = 10) -> httpx.AsyncClient:
    """Cliente HTTP para un conector: sin cookies persistentes, sin seguir redirects, con límites."""
    return httpx.AsyncClient(
        timeout=DEFAULT_TIMEOUT,
        follow_redirects=False,
        limits=httpx.Limits(max_connections=max_connections, max_keepalive_connections=max_connections),
        headers={"User-Agent": USER_AGENT},
    )


def utc_from_ms(ms: Any) -> datetime | None:
    """Epoch en milisegundos (int o string, como `internalDate` de Gmail) -> datetime UTC."""
    try:
        value = int(ms)
    except (TypeError, ValueError):
        return None
    if value <= 0 or value > 32503680000000:  # año 3000: valor basura
        return None
    return datetime.fromtimestamp(value / 1000, tz=UTC)


def parse_iso8601(value: Any) -> datetime | None:
    """ISO 8601 (Graph: `2026-10-03T12:00:00Z`) -> datetime UTC con tz. None si es inválido."""
    if not isinstance(value, str) or not value or len(value) > 64:
        return None
    v = value.strip()
    if v.endswith(("Z", "z")):
        v = v[:-1] + "+00:00"
    dot = v.find(".")
    if dot != -1:  # .NET/Graph puede mandar 7 decimales: recortar a microsegundos
        end = dot + 1
        while end < len(v) and v[end].isdigit():
            end += 1
        v = v[: dot + 1] + v[dot + 1 : end][:6] + v[end:]
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def iso_utc(dt: datetime) -> str:
    """datetime -> `YYYY-MM-DDTHH:MM:SSZ` (formato que Graph acepta en $filter)."""
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- utilidades de conectores cloud


class RecentIds:
    """Conjunto acotado (LRU) de ids ya entregados, para no re-descargar el mismo mail en ráfagas."""

    def __init__(self, maxlen: int = 5000) -> None:
        self._d: OrderedDict[str, None] = OrderedDict()
        self._maxlen = maxlen

    def __contains__(self, key: object) -> bool:
        return key in self._d

    def add(self, key: str) -> None:
        self._d[key] = None
        self._d.move_to_end(key)
        while len(self._d) > self._maxlen:
            self._d.popitem(last=False)

    def __len__(self) -> int:
        return len(self._d)


def label_for_level(level: VerdictLevel, tag: TagConfig) -> str | None:
    """Nombre del label/categoría a aplicar según el veredicto y la config (None = no etiquetar)."""
    if level == VerdictLevel.MALICIOUS:
        return tag.label_malicious
    if level == VerdictLevel.SUSPICIOUS and tag.min_level == "suspicious":
        return tag.label_suspicious
    return None


async def shutdown_tasks(tasks: list[asyncio.Task[Any]], grace: float) -> None:
    """Da `grace` segundos para que las tareas terminen solas (ven `stop`) y cancela el resto."""
    if not tasks:
        return
    _done, pending = await asyncio.wait(tasks, timeout=grace)
    for t in pending:
        t.cancel()
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, Exception):
            log.debug("tarea de conector terminó con error: %r", r)


async def wait_any(stop: asyncio.Event, wake: asyncio.Event | None, seconds: float) -> None:
    """Espera a que se active `stop` o `wake`, o hasta `seconds` segundos (lo primero)."""
    if stop.is_set() or (wake is not None and wake.is_set()):
        return
    waiters = {asyncio.ensure_future(stop.wait())}
    if wake is not None:
        waiters.add(asyncio.ensure_future(wake.wait()))
    try:
        await asyncio.wait(waiters, timeout=max(0.0, seconds), return_when=asyncio.FIRST_COMPLETED)
    finally:
        for w in waiters:
            w.cancel()
        await asyncio.gather(*waiters, return_exceptions=True)


def dedup_casefold(items: list[str]) -> list[str]:
    """Quita vacíos y repetidos (sin distinguir mayúsculas), preservando el orden."""
    seen: set[str] = set()
    out: list[str] = []
    for it in items:
        s = (it or "").strip()
        if s and s.lower() not in seen:
            seen.add(s.lower())
            out.append(s)
    return out


__all__ = [
    "DEFAULT_MAX_BODY",
    "DEFAULT_POLICY",
    "DEFAULT_TIMEOUT",
    "Backoff",
    "HttpError",
    "HttpResponse",
    "RecentIds",
    "ResponseTooLarge",
    "RetryPolicy",
    "Stopped",
    "TokenFn",
    "backoff_delay",
    "dedup_casefold",
    "iso_utc",
    "label_for_level",
    "new_client",
    "parse_iso8601",
    "parse_retry_after",
    "request",
    "safe_url",
    "shutdown_tasks",
    "sleep_or_stop",
    "utc_from_ms",
    "wait_any",
]
