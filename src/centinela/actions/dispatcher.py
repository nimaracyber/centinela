"""Acciones sobre un resultado: etiquetar el mail original y alertar (con deduplicación).

1. Etiquetado: `connectors[result.ref.connector].apply_verdict(...)` si el veredicto es sospechoso o
   malicioso y alcanza `actions.tag.min_level`. Nunca sobre limpio ni error. Respeta `tag: false`
   del conector (ese buzón nunca se modifica). Pasivo: el conector solo agrega label/categoría/keyword.
   `apply_verdict` LANZA ante una falla real (métrica TAGS_APPLIED status="error") y devuelve None cuando
   no corresponde etiquetar (status="skipped").
2. Alertas: a cada canal habilitado cuyo `min_level` se alcance. Deduplicación por canal y ventana
   (`actions.alerts.dedup_window_minutes`): la clave es el conjunto de SHA-256 de los adjuntos con
   hallazgos relevantes (o el Message-ID, o el id del resultado). Así una campaña con el mismo
   malware a 30 buzones genera UNA alerta por canal por ventana, pero cada mail se etiqueta y se
   guarda igual. Reintenta cada canal con backoff (ante un 429, `AlertRateLimitedError.retry_after`,
   con tope de 60 s); un `AlertDeliveryError` con `retryable=False` (credenciales, chat inexistente) no
   se reintenta. Si al final falla, libera la clave de dedup para que el próximo mail de la campaña
   vuelva a intentar alertar.

`dispatch()` nunca lanza excepciones: devuelve la lista de acciones ejecutadas, por ejemplo
`["tag:gmail:label:Centinela/Malicioso", "alert:telegram:ok", "alert:email:dedup"]`.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import math
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from centinela import metrics
from centinela.actions.alerts import AlertDeliveryError, AlertRateLimitedError
from centinela.core.models import Severity, VerdictLevel
from centinela.logging_setup import redact

if TYPE_CHECKING:
    from centinela.actions.alerts.base import AlertChannel
    from centinela.connectors.base import Connector
    from centinela.core.cache import Cache
    from centinela.core.config import Settings
    from centinela.core.models import AnalysisResult

log = logging.getLogger(__name__)

_ACTIONABLE = (VerdictLevel.SUSPICIOUS, VerdictLevel.MALICIOUS)
_LEVEL_BY_NAME = {lv.value: lv for lv in VerdictLevel}


def _describe(exc: BaseException) -> str:
    """Texto corto del error para el log. Los errores de canales/conectores no llevan secretos por
    contrato; igual pasa por `redact` (defensa en profundidad) y se recorta."""
    text = str(exc).strip().replace("\n", " ")
    if not text:
        return type(exc).__name__
    if isinstance(exc, AlertDeliveryError):
        return redact(text, limit=300)
    return redact(f"{type(exc).__name__}: {text}", limit=300)


def _reaches(level: VerdictLevel, min_level: str) -> bool:
    if level not in _ACTIONABLE:
        return False
    threshold = _LEVEL_BY_NAME.get(min_level, VerdictLevel.SUSPICIOUS)
    return level.rank >= threshold.rank


def dedup_key(result: AnalysisResult) -> str:
    """Clave de deduplicación de alertas para un resultado.

    - Si hay adjuntos con hallazgos de severidad MEDIUM o mayor: sus SHA-256 ordenados (identifica la
      campaña aunque cambien asunto, remitente o destinatario).
    - Si no: el Message-ID (el mismo mail entregado a varios buzones) o, en último caso, el id.
    """
    flagged_ids = {
        f.artifact_id
        for f in result.findings
        if f.artifact_id and f.severity >= Severity.MEDIUM and f.score > 0
    }
    hashes = sorted({a.sha256.lower() for a in result.artifacts if a.id in flagged_ids and a.sha256})
    if hashes:
        joined = ",".join(hashes)
        if len(hashes) == 1:
            return f"sha256:{joined}"
        return "sha256set:" + hashlib.sha256(joined.encode()).hexdigest()
    if result.message_id:
        mid = result.message_id.strip().lower()
        return "msgid:" + (mid if len(mid) <= 200 else hashlib.sha256(mid.encode()).hexdigest())
    return f"result:{result.id}"


class ActionDispatcher:
    def __init__(
        self,
        settings: Settings,
        cache: Cache,
        connectors: dict[str, Connector],
        channels: list[AlertChannel],
        *,
        retries: int = 3,
        backoff_s: Sequence[float] = (1.0, 4.0),
        send_timeout_s: float = 30.0,
        tag_timeout_s: float = 60.0,
        max_retry_after_s: float = 60.0,
    ) -> None:
        self.settings = settings
        self.cache = cache
        self.connectors = connectors
        self.channels = channels
        self.retries = max(1, int(retries))
        self.backoff_s = tuple(backoff_s) or (1.0,)
        self.send_timeout_s = send_timeout_s
        self.tag_timeout_s = tag_timeout_s
        self.max_retry_after_s = max(0.0, float(max_retry_after_s))

    async def dispatch(self, result: AnalysisResult) -> list[str]:
        try:
            tag_coro = self._tag(result)
            alert_coros = [self._alert(ch, result) for ch in self.channels]
            outcomes = await asyncio.gather(tag_coro, *alert_coros, return_exceptions=True)
        except Exception:  # noqa: BLE001 - nunca romper el procesamiento por una acción
            log.exception("error inesperado despachando acciones")
            return []
        actions: list[str] = []
        for outcome in outcomes:
            if isinstance(outcome, BaseException):
                if not isinstance(outcome, Exception):
                    raise outcome  # CancelledError, KeyboardInterrupt...
                log.error("acción falló inesperadamente: %s", _describe(outcome))
                continue
            if outcome:
                actions.append(outcome)
        return actions

    # ------------------------------------------------------------- etiquetado

    async def _tag(self, result: AnalysisResult) -> str | None:
        tag_cfg = self.settings.actions.tag
        level = result.verdict.level
        if not tag_cfg.enabled or not _reaches(level, tag_cfg.min_level):
            return None
        name = result.ref.connector
        connector = self.connectors.get(name)
        if connector is None:
            log.debug("no hay conector %r cargado para etiquetar", name)
            return None
        if not getattr(connector.config, "tag", True):
            return None  # conector en modo solo-alertas
        try:
            desc = await asyncio.wait_for(
                connector.apply_verdict(result.ref, result, tag_cfg), timeout=self.tag_timeout_s
            )
        except Exception as exc:  # noqa: BLE001 - falla real del conector (lanza por contrato)
            metrics.TAGS_APPLIED.labels(connector=name, status="error").inc()
            log.warning("no se pudo etiquetar el mensaje en %s: %s", name, _describe(exc))
            log.debug("detalle del error de etiquetado", exc_info=True)
            return f"tag:{name}:error"
        if not desc:  # el conector no tenía nada que hacer (no aplica): no es un error
            metrics.TAGS_APPLIED.labels(connector=name, status="skipped").inc()
            return None
        metrics.TAGS_APPLIED.labels(connector=name, status="ok").inc()
        return f"tag:{desc}"

    # ------------------------------------------------------------- alertas

    async def _alert(self, channel: AlertChannel, result: AnalysisResult) -> str | None:
        cfg: Any = channel.config
        if not getattr(cfg, "enabled", True):
            return None
        if not _reaches(result.verdict.level, getattr(cfg, "min_level", "suspicious")):
            return None
        name = channel.name
        window_s = int(self.settings.actions.alerts.dedup_window_minutes) * 60
        # el nivel va en la clave: si una campaña escala de sospechosa a maliciosa, se vuelve a alertar
        key = f"alert:{name}:{result.verdict.level.value}:{dedup_key(result)}"
        if window_s > 0:
            try:
                first = await self.cache.add(key, str(result.id), window_s)
            except Exception:  # noqa: BLE001 - sin caché preferimos alertar de más que de menos
                log.warning("caché de dedup no disponible; se alerta igual")
                first = True
            if not first:
                metrics.ALERTS_SENT.labels(channel=name, status="dedup").inc()
                return f"alert:{name}:dedup"

        last_error = ""
        attempts = 0
        for attempt in range(self.retries):
            attempts = attempt + 1
            try:
                await asyncio.wait_for(channel.send(result), timeout=self.send_timeout_s)
            except Exception as exc:  # noqa: BLE001
                last_error = _describe(exc)
                if isinstance(exc, AlertDeliveryError) and not exc.retryable:
                    log.warning("alerta por %s falló y no se reintenta: %s", name, last_error)
                    break
                log.warning(
                    "alerta por %s falló (intento %d/%d): %s", name, attempts, self.retries, last_error
                )
                if attempts < self.retries:
                    await asyncio.sleep(self._retry_delay(exc, attempt))
                continue
            metrics.ALERTS_SENT.labels(channel=name, status="ok").inc()
            return f"alert:{name}:ok"

        metrics.ALERTS_SENT.labels(channel=name, status="error").inc()
        log.error("alerta por %s descartada tras %d intento(s): %s", name, attempts, last_error)
        if window_s > 0:
            try:  # liberar la dedup: el próximo mail de la campaña vuelve a intentar
                await self.cache.set(key, "failed", 1)
            except Exception:  # noqa: BLE001
                log.debug("no se pudo liberar la clave de dedup", exc_info=True)
        return f"alert:{name}:error"

    def _retry_delay(self, exc: BaseException, attempt: int) -> float:
        """Espera antes del próximo intento: la que pide el servicio ante un 429 (con tope) o el backoff."""
        if isinstance(exc, AlertRateLimitedError) and exc.retry_after is not None:
            try:
                wait = float(exc.retry_after)
            except (TypeError, ValueError):
                wait = math.nan
            if not math.isnan(wait) and wait >= 0:
                return min(wait, self.max_retry_after_s)
        return self.backoff_s[min(attempt, len(self.backoff_s) - 1)]

    async def close(self) -> None:
        for ch in self.channels:
            try:
                await ch.close()
            except Exception:  # noqa: BLE001
                log.debug("error cerrando canal %s", ch.name, exc_info=True)


__all__ = ["ActionDispatcher", "dedup_key"]
