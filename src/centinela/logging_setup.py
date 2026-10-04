"""Configuración de logging (JSON o texto plano) con redacción de secretos.

- `setup_logging(settings)`: configura el logger raíz según `general.log_level` / `general.log_json`.
  Es idempotente: reemplaza solo los handlers que instaló Centinela (no toca los de pytest, uvicorn, etc.).
- `RedactingFilter`: filtro de logging que tapa cosas con pinta de secreto (contraseñas, tokens,
  headers Authorization, API keys, tokens de bot de Telegram, credenciales en URLs, webhooks...).
- `redact(text)`: la misma redacción como función, para usar en mensajes de error que salen por la API
  o el health-check.

Todas las regex son lineales (cuantificadores acotados, sin anidamiento) para que un mensaje de log
hostil no pueda colgar el proceso (ReDoS). Además cada registro se recorta a `MAX_RECORD_CHARS`
para no volcar cuerpos de mail completos ni payloads gigantes.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from centinela.core.config import GeneralConfig, Settings

REDACTED = "[REDACTADO]"
MAX_RECORD_CHARS = 16_000
_MARK = "_centinela_handler"

# Nombres de clave que indican un secreto (en key=value, JSON, query strings, headers).
_SENSITIVE_NAMES = (
    r"password|passwd|passphrase|pwd|secret|token|api[_-]?key|apikey|auth[_-]?key|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|credential|cookie|session[_-]?id|signature|x-api-key|hmac"
)

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Bloques de clave privada PEM (acotado para no ser cuadrático).
    (
        re.compile(
            r"-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----[\s\S]{0,12000}?-----END [A-Z ]{0,40}PRIVATE KEY-----"
        ),
        REDACTED,
    ),
    # Credenciales embebidas en URLs: scheme://usuario:clave@host  (postgres, redis, amqp, imap...).
    (
        re.compile(r"(\b[a-zA-Z][a-zA-Z0-9+.\-]{1,20}://[^\s:/@]{0,256}:)[^\s@/]{1,256}@"),
        r"\1" + REDACTED + "@",
    ),
    # Headers Authorization / Proxy-Authorization (cualquier esquema).
    (
        re.compile(
            r"(?i)\b((?:proxy-)?authorization[\"']?\s{0,5}[:=]\s{0,5}[\"']?)(?:(bearer|basic|digest|token|negotiate|ntlm)\s{1,5})?[^\s,;\"']{1,4096}"
        ),
        r"\1\2 " + REDACTED,
    ),
    # Bearer <token> suelto.
    (re.compile(r"(?i)\b(bearer)\s{1,5}[A-Za-z0-9\-._~+/]{8,4096}=*"), r"\1 " + REDACTED),
    # SMTP AUTH PLAIN/LOGIN/XOAUTH2 en base64.
    (
        re.compile(r"(?i)\b(AUTH\s{1,5}(?:PLAIN|LOGIN|XOAUTH2)\s{1,5})[A-Za-z0-9+/=]{8,8192}"),
        r"\1" + REDACTED,
    ),
    # Token de bot de Telegram (también dentro de https://api.telegram.org/bot<token>/...).
    (re.compile(r"(?<=bot)\d{5,12}:[A-Za-z0-9_\-]{30,64}"), REDACTED),
    (re.compile(r"\b\d{5,12}:[A-Za-z0-9_\-]{30,64}\b"), REDACTED),
    # Webhooks que son secretos en sí mismos (Slack, Discord, Teams, Google Chat).
    (
        re.compile(r"(?i)(hooks\.slack\.com/(?:services|workflows|triggers)/)[A-Za-z0-9/_\-]{1,512}"),
        r"\1" + REDACTED,
    ),
    (re.compile(r"(?i)(discord(?:app)?\.com/api/webhooks/)[A-Za-z0-9/_\-]{1,512}"), r"\1" + REDACTED),
    (re.compile(r"(?i)(\.webhook\.office\.com/)[^\s\"'<>]{1,2048}"), r"\1" + REDACTED),
    (re.compile(r"(?i)(\.logic\.azure\.com[^\s\"'<>?]{0,512}\?)[^\s\"'<>]{1,2048}"), r"\1" + REDACTED),
    (
        re.compile(r"(?i)(chat\.googleapis\.com/v1/spaces/[^\s/]{1,128}/messages\?)[^\s\"'<>]{1,2048}"),
        r"\1" + REDACTED,
    ),
    # Formatos conocidos de tokens.
    (
        re.compile(r"\beyJ[A-Za-z0-9_\-]{8,4096}\.eyJ[A-Za-z0-9_\-]{8,8192}\.[A-Za-z0-9_\-]{8,4096}"),
        REDACTED,
    ),  # JWT
    (re.compile(r"\bya29\.[0-9A-Za-z_\-]{10,4096}"), REDACTED),  # Google OAuth access token
    (re.compile(r"\b1//[0-9A-Za-z_\-]{20,1024}"), REDACTED),  # Google refresh token
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}"), REDACTED),  # Google API key
    (re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,256}"), REDACTED),  # Slack
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,255}"), REDACTED),  # GitHub
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), REDACTED),  # AWS access key id
    (re.compile(r"\bEwB[A-Za-z0-9+/=_\-]{40,8192}"), REDACTED),  # tokens MSA (Outlook.com)
    # clave=valor / "clave": "valor" / ?clave=valor para nombres que indican secreto
    # (el prefijo de la clave, ej. "client_" en client_secret, queda fuera del match y se conserva).
    (
        re.compile(
            r"(?i)((?:" + _SENSITIVE_NAMES + r")[\w.\-]{0,40}[\"']?\s{0,5}[:=]\s{0,5}[\"']?)"
            r"(?!\[REDACTADO\])[^\s\"'&,;}\]]{1,4096}"
        ),
        r"\1" + REDACTED,
    ),
]

_SECRET_KEY_RE = re.compile(r"(?i)" + _SENSITIVE_NAMES + r"|authorization")


def redact(text: str, *, limit: int = MAX_RECORD_CHARS) -> str:
    """Devuelve `text` con los secretos tapados y recortado a `limit` caracteres."""
    if not text:
        return text
    if limit and len(text) > limit:
        text = text[:limit] + f"... [truncado, {len(text) - limit} caracteres más]"
    for pattern, repl in _PATTERNS:
        text = pattern.sub(repl, text)
    return text


def _redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, bytes):
        return f"<{len(value)} bytes>"  # nunca volcar bytes crudos (pueden ser partes de un mail)
    if isinstance(value, int | float | bool) or value is None:
        return value
    return redact(repr(value), limit=2000)


class RedactingFilter(logging.Filter):
    """Filtro que tapa secretos en el mensaje (ya formateado con sus args) y en los `extra`."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 - un log mal formateado no debe romper nada
            message = f"{record.msg!r} (args no formateables)"
        record.msg = redact(message)
        record.args = None
        for key, value in list(record.__dict__.items()):
            if key in _STD_ATTRS or key.startswith("_"):
                continue
            if _SECRET_KEY_RE.search(key):
                record.__dict__[key] = REDACTED
            else:
                record.__dict__[key] = _redact_value(value)
        return True


_STD_ATTRS = frozenset(
    {
        "name",
        "msg",
        "args",
        "levelname",
        "levelno",
        "pathname",
        "filename",
        "module",
        "exc_info",
        "exc_text",
        "stack_info",
        "lineno",
        "funcName",
        "created",
        "msecs",
        "relativeCreated",
        "thread",
        "threadName",
        "processName",
        "process",
        "taskName",
        "message",
        "asctime",
    }
)


class PlainFormatter(logging.Formatter):
    def __init__(self) -> None:
        super().__init__("%(asctime)s %(levelname)-7s %(name)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

    def format(self, record: logging.LogRecord) -> str:
        # redactar también el traceback (se arma en format(), después de los filtros)
        return redact(super().format(record), limit=MAX_RECORD_CHARS * 2)


class JsonFormatter(logging.Formatter):
    """Una línea JSON por registro: ts, level, logger, msg, exc, + campos `extra`."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": redact(record.getMessage()),
        }
        if record.exc_info:
            payload["exc"] = redact(self.formatException(record.exc_info), limit=MAX_RECORD_CHARS)
        elif record.exc_text:
            payload["exc"] = redact(record.exc_text, limit=MAX_RECORD_CHARS)
        if record.stack_info:
            payload["stack"] = redact(self.formatStack(record.stack_info), limit=MAX_RECORD_CHARS)
        for key, value in record.__dict__.items():
            if key in _STD_ATTRS or key.startswith("_") or key in payload:
                continue
            payload[key] = REDACTED if _SECRET_KEY_RE.search(key) else _redact_value(value)
        return json.dumps(payload, ensure_ascii=False, default=str)


# Librerías ruidosas o que pueden loguear URLs/tokens a nivel INFO/DEBUG.
_QUIET_LOGGERS = {
    "httpx": logging.WARNING,  # loguea URLs completas (la de Telegram lleva el token del bot)
    "httpcore": logging.WARNING,
    "hpack": logging.WARNING,
    "msal": logging.WARNING,  # en DEBUG vuelca tokens
    "urllib3": logging.WARNING,
    "google": logging.WARNING,
    "googleapiclient": logging.WARNING,
    "google_auth_httplib2": logging.WARNING,
    "imapclient": logging.WARNING,
    "aiosqlite": logging.WARNING,
    "sqlalchemy.engine": logging.WARNING,
    "asyncio": logging.WARNING,
    "multipart": logging.WARNING,
    "python_multipart": logging.WARNING,
}


def _level(value: str | int | None) -> int:
    if isinstance(value, int):
        return value
    lvl = logging.getLevelName(str(value or "INFO").strip().upper())
    return lvl if isinstance(lvl, int) else logging.INFO


def setup_logging(
    config: Settings | GeneralConfig | None = None,
    *,
    level: str | int | None = None,
    json_format: bool | None = None,
    stream: Any = None,
) -> logging.Handler:
    """Configura el logger raíz. Devuelve el handler instalado (útil en tests)."""
    general = getattr(config, "general", config)
    lvl = _level(level if level is not None else getattr(general, "log_level", "INFO"))
    as_json = json_format if json_format is not None else bool(getattr(general, "log_json", True))

    root = logging.getLogger()
    for h in list(root.handlers):
        if getattr(h, _MARK, False):
            root.removeHandler(h)
            h.close()

    handler = logging.StreamHandler(stream or sys.stderr)
    setattr(handler, _MARK, True)
    handler.setFormatter(JsonFormatter() if as_json else PlainFormatter())
    handler.addFilter(RedactingFilter())
    root.addHandler(handler)
    root.setLevel(lvl)

    for name, quiet in _QUIET_LOGGERS.items():
        logger = logging.getLogger(name)
        if lvl > logging.DEBUG or name in {"httpx", "httpcore", "msal"}:
            logger.setLevel(max(quiet, lvl))
    # uvicorn (lo arranca la CLI con log_config=None) propaga al raíz y pasa por el mismo filtro
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logging.getLogger(name).propagate = True
    return handler


__all__ = ["REDACTED", "JsonFormatter", "PlainFormatter", "RedactingFilter", "redact", "setup_logging"]
