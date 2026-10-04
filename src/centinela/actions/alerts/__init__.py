"""Canales de alerta: email, Telegram, webhook (JSON/Slack/Teams/Discord/Google Chat) y syslog (CEF).

`build_channels(settings, http)` instancia los canales habilitados según `actions.alerts.channels`
(registro por `type` de la config). Los módulos de cada canal se importan de forma diferida: un canal
roto o con una dependencia faltante no impide que funcionen los demás.

También expone utilidades compartidas por los canales:
- `AlertDeliveryError` / `AlertRateLimitedError`: excepciones cuyo mensaje NUNCA contiene secretos
  (tokens, URLs de webhook, contraseñas). `retry_after` (segundos) indica cuándo reintentar ante un 429
  y `retryable=False` marca errores que no se arreglan reintentando (credenciales, chat inexistente).
- `register_secret()`: agrega un secreto al filtro que lo tapa en los logs de httpx (httpx loguea la URL
  completa de cada request en INFO, y en Telegram el token va en la URL).
"""

from __future__ import annotations

import importlib
import logging
import math
import threading
from typing import TYPE_CHECKING, Any

from centinela.actions.alerts.base import AlertChannel

if TYPE_CHECKING:
    from collections.abc import Iterable

    import httpx

    from centinela.core.config import Settings

__all__ = [
    "CHANNEL_TYPES",
    "AlertChannel",
    "AlertDeliveryError",
    "AlertRateLimitedError",
    "build_channels",
    "channel_class",
    "describe_exception",
    "meets_min_level",
    "parse_retry_after",
    "redact",
    "register_secret",
]

log = logging.getLogger(__name__)

# tipo de config -> "módulo:Clase" (import diferido)
CHANNEL_TYPES: dict[str, str] = {
    "email": "centinela.actions.alerts.email:EmailChannel",
    "telegram": "centinela.actions.alerts.telegram:TelegramChannel",
    "webhook": "centinela.actions.alerts.webhook:WebhookChannel",
    "syslog": "centinela.actions.alerts.syslog:SyslogChannel",
}

_LEVEL_RANK = {"clean": 0, "error": 1, "suspicious": 2, "malicious": 3}


class AlertDeliveryError(RuntimeError):
    """No se pudo entregar una alerta. El mensaje es apto para logs (sin secretos)."""

    def __init__(
        self,
        message: str,
        *,
        channel: str | None = None,
        status: int | None = None,
        retry_after: float | None = None,
        retryable: bool = True,
    ) -> None:
        super().__init__(message)
        self.channel = channel
        self.status = status
        self.retry_after = retry_after
        self.retryable = retryable


class AlertRateLimitedError(AlertDeliveryError):
    """El servicio respondió 429: reintentar después de `retry_after` segundos."""


def meets_min_level(level: object, min_level: str) -> bool:
    """True si un veredicto (`VerdictLevel` o str) alcanza el `min_level` de un canal."""
    value = getattr(level, "value", level)
    if value not in ("suspicious", "malicious"):
        return False
    return _LEVEL_RANK.get(str(value), 0) >= _LEVEL_RANK.get(min_level, 2)


# --------------------------------------------------------------------------- secretos


def redact(text: str, secrets: Iterable[str | None]) -> str:
    """Reemplaza cada secreto (de 6+ caracteres) por "***"."""
    for s in secrets:
        if s and len(s) >= 6 and s in text:
            text = text.replace(s, "***")
    return text


class _RedactingFilter(logging.Filter):
    """Filtro de logging que tapa secretos registrados en los mensajes ya formateados."""

    def __init__(self) -> None:
        super().__init__("centinela-redact")
        self._secrets: frozenset[str] = frozenset()
        self._lock = threading.Lock()

    def add(self, secret: str) -> None:
        with self._lock:
            self._secrets = self._secrets | {secret}

    def filter(self, record: logging.LogRecord) -> bool:
        secrets = self._secrets
        if not secrets:
            return True
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001 - un log mal formado no debe romper nada
            return True
        red = redact(msg, secrets)
        if red != msg:
            record.msg = red
            record.args = None
        return True


_FILTER = _RedactingFilter()
_FILTERED_LOGGERS = ("httpx", "httpcore")
_installed = False


def register_secret(secret: str | None) -> None:
    """Registra un secreto para taparlo en los logs de httpx (idempotente, thread-safe)."""
    global _installed
    if not secret or len(secret) < 6:
        return
    _FILTER.add(secret)
    if not _installed:
        for name in _FILTERED_LOGGERS:
            lg = logging.getLogger(name)
            if _FILTER not in lg.filters:
                lg.addFilter(_FILTER)
        _installed = True


def describe_exception(exc: BaseException, secrets: Iterable[str | None] = ()) -> str:
    """Descripción corta y sin secretos de una excepción (para mensajes de error)."""
    text = str(exc).strip().replace("\n", " ")[:200]
    text = redact(text, list(secrets))
    return f"{type(exc).__name__}: {text}" if text else type(exc).__name__


def parse_retry_after(*candidates: object, default: float = 30.0) -> float:
    """Primer valor numérico válido (segundos) entre los candidatos (`retry_after` del JSON, header
    `Retry-After`...). Acotado a 1 hora; `default` si ninguno sirve."""
    for c in candidates:
        if c is None or isinstance(c, bool):
            continue
        try:
            value = float(c)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            continue
        if math.isfinite(value) and value >= 0:
            return min(value, 3600.0)
    return default


# --------------------------------------------------------------------------- registro


def channel_class(type_: str) -> type[AlertChannel]:
    """Clase del canal para un `type` de config. KeyError si el tipo no existe."""
    target = CHANNEL_TYPES[type_]
    module_name, _, class_name = target.partition(":")
    module = importlib.import_module(module_name)
    cls = getattr(module, class_name)
    if not (isinstance(cls, type) and issubclass(cls, AlertChannel)):
        raise TypeError(f"{target} no es un AlertChannel")
    return cls


def build_channels(settings: Settings, http: httpx.AsyncClient) -> list[AlertChannel]:
    """Instancia los canales habilitados. Un canal mal configurado se informa en el log y se omite."""
    channels: list[AlertChannel] = []
    seen: set[str] = set()
    for cfg in settings.actions.alerts.channels:
        cfg_any: Any = cfg
        if not getattr(cfg_any, "enabled", True):
            continue
        type_ = getattr(cfg_any, "type", "?")
        name = getattr(cfg_any, "name", "?")
        try:
            cls = channel_class(type_)
            channel = cls(cfg_any, settings, http)
        except Exception as exc:  # noqa: BLE001 - un canal roto no debe dejar sin alertas a los demás
            log.error("canal de alerta %r (%s) omitido: %s", name, type_, describe_exception(exc))
            continue
        if name in seen:
            log.warning("hay más de un canal de alerta llamado %r: conviene usar nombres únicos", name)
        seen.add(name)
        channels.append(channel)
    return channels
