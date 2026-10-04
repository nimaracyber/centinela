"""Alertas por Telegram (Bot API `sendMessage` con parse_mode=HTML).

El token del bot va en la URL (https://api.telegram.org/bot<token>/sendMessage), así que:
- nunca se incluye en mensajes de excepción ni de log (se tapa con `redact`),
- se registra en el filtro de logs de httpx (que loguea la URL de cada request en INFO),
- las excepciones de httpx se re-lanzan sin encadenar (`from None`) para que un traceback no lo filtre.

Ante un 429 se lanza `AlertRateLimitedError` con `retry_after` (segundos) tomado de
`parameters.retry_after`. Si Telegram rechaza el HTML ("can't parse entities"), se reintenta UNA vez el
mismo contenido como texto plano.

`message_thread_id` (opcional): manda la alerta a un tema ("topic") de un supergrupo con temas, por
ejemplo uno llamado "Seguridad", en lugar del tema general.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any

import httpx

from centinela.actions.alerts import (
    AlertDeliveryError,
    AlertRateLimitedError,
    describe_exception,
    parse_retry_after,
    redact,
    register_secret,
)
from centinela.actions.alerts.base import AlertChannel
from centinela.actions.alerts.format import TELEGRAM_MAX_CHARS, build_alert

if TYPE_CHECKING:
    from centinela.core.config import Settings, TelegramAlertConfig
    from centinela.core.models import AnalysisResult

log = logging.getLogger(__name__)

# el token no puede tener nada que altere la URL (/, ?, #, espacios, %...)
_TOKEN_RE = re.compile(r"[A-Za-z0-9:_-]{10,200}")
_CHAT_ID_RE = re.compile(r"-?\d{1,20}|@[A-Za-z][A-Za-z0-9_]{3,64}")


class TelegramChannel(AlertChannel):
    type = "telegram"
    api_base = "https://api.telegram.org"
    timeout = httpx.Timeout(15.0, connect=10.0)

    def __init__(self, config: TelegramAlertConfig, settings: Settings, http: httpx.AsyncClient) -> None:
        super().__init__(config, settings, http)
        token = config.bot_token.get_secret_value().strip()
        if not _TOKEN_RE.fullmatch(token):
            raise ValueError(f"canal {config.name!r}: bot_token de Telegram con formato inválido")
        chat_id = str(config.chat_id).strip()
        if not _CHAT_ID_RE.fullmatch(chat_id):
            raise ValueError(f"canal {config.name!r}: chat_id de Telegram inválido (número o @canal)")
        self._token = token
        self._chat_id: int | str = int(chat_id) if chat_id.lstrip("-").isdigit() else chat_id
        thread_id = config.message_thread_id
        if thread_id is not None and not (0 < int(thread_id) < 2**31):
            raise ValueError(f"canal {config.name!r}: message_thread_id de Telegram inválido")
        self._thread_id: int | None = int(thread_id) if thread_id is not None else None
        register_secret(token)

    @property
    def _url(self) -> str:
        return f"{self.api_base}/bot{self._token}/sendMessage"

    async def send(self, result: AnalysisResult) -> None:
        alert = build_alert(result, self.settings)
        payload: dict[str, Any] = {
            "chat_id": self._chat_id,
            "text": alert.to_telegram_html(TELEGRAM_MAX_CHARS),
            "parse_mode": "HTML",
            "disable_web_page_preview": True,  # nombre histórico (sigue aceptado)
            "link_preview_options": {"is_disabled": True},  # nombre actual (Bot API 7.0+)
        }
        if self._thread_id is not None:
            payload["message_thread_id"] = self._thread_id
        resp, data = await self._post(payload)
        if resp.status_code == 400 and "parse entities" in str(data.get("description", "")).lower():
            log.warning("Telegram rechazó el formato HTML de la alerta; se reenvía como texto plano")
            payload = {k: v for k, v in payload.items() if k != "parse_mode"}
            payload["text"] = alert.to_text(TELEGRAM_MAX_CHARS - 96)
            resp, data = await self._post(payload)
        self._check(resp, data)

    async def _post(self, payload: dict[str, Any]) -> tuple[httpx.Response, dict[str, Any]]:
        try:
            resp = await self.http.post(self._url, json=payload, timeout=self.timeout)
        except httpx.HTTPError as exc:
            raise AlertDeliveryError(
                f"Telegram: error de red ({describe_exception(exc, [self._token])})", channel=self.name
            ) from None
        try:
            data = resp.json()
        except ValueError:
            data = {}
        return resp, data if isinstance(data, dict) else {}

    def _check(self, resp: httpx.Response, data: dict[str, Any]) -> None:
        if resp.status_code == 200 and data.get("ok") is True:
            return
        status = resp.status_code
        desc = redact(str(data.get("description") or resp.reason_phrase or "")[:300], [self._token])
        params = data.get("parameters") if isinstance(data.get("parameters"), dict) else {}
        if status == 429 or data.get("error_code") == 429:
            retry_after = parse_retry_after(params.get("retry_after"), resp.headers.get("Retry-After"))
            raise AlertRateLimitedError(
                f"Telegram: demasiados mensajes (429); reintentar en {retry_after:g} s",
                channel=self.name,
                status=429,
                retry_after=retry_after,
            )
        if self._thread_id is not None and "thread not found" in desc.lower():
            raise AlertDeliveryError(
                f"Telegram: el tema message_thread_id={self._thread_id} no existe en ese grupo",
                channel=self.name,
                status=status,
                retryable=False,
            )
        if params.get("migrate_to_chat_id"):
            raise AlertDeliveryError(
                f"Telegram: el grupo pasó a supergrupo; cambiá chat_id a {params['migrate_to_chat_id']}",
                channel=self.name,
                status=status,
                retryable=False,
            )
        raise AlertDeliveryError(
            f"Telegram respondió {status}: {desc}",
            channel=self.name,
            status=status,
            retryable=status >= 500,
        )
