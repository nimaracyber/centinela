"""Cola de trabajo sobre Redis Streams con consumer groups (implementa `core.queue.WorkQueue`).

Semántica: entrega al-menos-una-vez.
- publish: XADD (MAXLEN ~ aproximado) con los campos `ref` (JSON), `received_at` (ISO) y `raw` (bytes).
- consume: XREADGROUP con BLOCK corto (reacciona rápido al evento de parada) y, cada
  `claim_interval_s`, XAUTOCLAIM de entradas colgadas más de `claim_idle_s` (workers que murieron).
  El número de intento sale del contador de entregas de XPENDING.
- ack: XACK + XDEL (la longitud del stream = trabajo pendiente, que es lo que muestra QUEUE_DEPTH).
- fail: si se agotaron los intentos -> XADD al stream de dead-letter + XACK + XDEL; si no, queda
  pendiente para que se reclame (se adelanta su reintento a `retry_delay_s` con XCLAIM IDLE).
- Un mensaje que voltea al worker (OOM, segfault de una librería) vuelve por XAUTOCLAIM con su
  contador de entregas incrementado; al superar `max_attempts` va directo a dead-letter sin procesarse.
- Entradas malformadas (no se pueden decodificar) van directo a dead-letter.

El cliente Redis debe crearse con `decode_responses=False` (el mail crudo son bytes).
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any

from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import ResponseError
from redis.exceptions import TimeoutError as RedisTimeoutError

from centinela import metrics
from centinela.core.models import MessageRef, RawMessage, utcnow
from centinela.core.queue import Job

log = logging.getLogger(__name__)


def _s(value: Any) -> str:
    return value.decode("utf-8", "replace") if isinstance(value, bytes | bytearray) else str(value)


def _field(fields: dict[Any, Any], name: str) -> Any:
    if name in fields:
        return fields[name]
    return fields.get(name.encode())


class RedisStreamQueue:
    def __init__(
        self,
        redis_url: str | None = None,
        stream: str = "centinela:inbox",
        group: str = "workers",
        max_attempts: int = 3,
        dead_stream: str = "centinela:dead",
        *,
        client: Any = None,
        maxlen: int = 100_000,
        dead_maxlen: int = 1_000,
        block_ms: int = 1_000,
        claim_idle_s: float = 300.0,
        claim_interval_s: float = 30.0,
        claim_count: int = 10,
        retry_delay_s: float = 60.0,
        depth_interval_s: float = 15.0,
    ) -> None:
        if client is None:
            if not redis_url:
                raise ValueError("RedisStreamQueue necesita redis_url o client")
            import redis.asyncio as aioredis

            client = aioredis.Redis.from_url(
                redis_url,
                decode_responses=False,
                socket_connect_timeout=5,
                socket_timeout=block_ms / 1000 + 10,
                health_check_interval=30,
            )
            self._owns_client = True
        else:
            self._owns_client = False
        self.redis = client
        self.stream = stream
        self.group = group
        self.dead_stream = dead_stream
        self.max_attempts = max(1, int(max_attempts))
        self.maxlen = maxlen
        self.dead_maxlen = dead_maxlen
        self.block_ms = max(1, int(block_ms))
        self.claim_idle_ms = max(1, int(claim_idle_s * 1000))
        self.claim_interval_s = claim_interval_s
        self.claim_count = max(1, int(claim_count))
        self.retry_delay_ms = max(0, int(retry_delay_s * 1000))
        self.depth_interval_s = depth_interval_s
        self._group_ready = False
        self._autoclaim = True  # se apaga si el servidor no soporta XAUTOCLAIM (Redis < 6.2)
        self._consumers: dict[str, str] = {}  # job.id -> consumer (para adelantar reintentos con XCLAIM)

    # ------------------------------------------------------------- infraestructura

    async def ensure_group(self) -> None:
        """XGROUP CREATE ... MKSTREAM, idempotente (BUSYGROUP = ya existía)."""
        if self._group_ready:
            return
        try:
            await self.redis.xgroup_create(self.stream, self.group, id="0", mkstream=True)
            log.info("cola: grupo %s creado en %s", self.group, self.stream)
        except ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise
        self._group_ready = True

    @staticmethod
    def _is_nogroup(exc: ResponseError) -> bool:
        text = str(exc)
        return "NOGROUP" in text or "requires the key to exist" in text

    async def depth(self) -> int:
        """Mensajes en el stream (pendientes de procesar + en proceso). Actualiza QUEUE_DEPTH."""
        n = int(await self.redis.xlen(self.stream))
        metrics.QUEUE_DEPTH.set(n)
        return n

    async def dead_count(self) -> int:
        return int(await self.redis.xlen(self.dead_stream))

    async def ping(self) -> bool:
        return bool(await self.redis.ping())

    async def close(self) -> None:
        if self._owns_client:
            try:
                await self.redis.aclose()
            except Exception:  # noqa: BLE001
                log.debug("error cerrando cliente redis", exc_info=True)

    # ------------------------------------------------------------- WorkQueue

    async def publish(self, message: RawMessage) -> str:
        await self.ensure_group()
        fields = {
            "ref": message.ref.model_dump_json(),
            "received_at": message.received_at.isoformat(),
            "raw": message.raw,
        }
        entry_id = await self.redis.xadd(self.stream, fields, maxlen=self.maxlen, approximate=True)
        return _s(entry_id)

    async def consume(self, consumer: str, stop: asyncio.Event) -> AsyncIterator[Job]:
        backoff = 1.0
        last_claim = float("-inf")
        last_depth = float("-inf")
        while not stop.is_set():
            try:
                await self.ensure_group()
                now = time.monotonic()
                if now - last_depth >= self.depth_interval_s:
                    last_depth = now
                    await self.depth()
                if self._autoclaim and now - last_claim >= self.claim_interval_s:
                    last_claim = now
                    for job in await self._reclaim_safe(consumer):
                        yield job
                        if stop.is_set():
                            return
                t_read = time.monotonic()
                resp = await self.redis.xreadgroup(
                    self.group, consumer, {self.stream: ">"}, count=1, block=self.block_ms
                )
                backoff = 1.0
                if not resp and time.monotonic() - t_read < self.block_ms / 2000:
                    # el servidor no respetó BLOCK (proxy, emulador): no girar en vacío
                    await asyncio.sleep(min(self.block_ms / 1000, 0.1))
            except ResponseError as exc:
                if self._is_nogroup(exc):  # alguien borró el stream/grupo: recrear y seguir
                    log.warning("cola: el grupo %s no existe; se recrea", self.group)
                    self._group_ready = False
                    continue
                raise
            except (RedisConnectionError, RedisTimeoutError, OSError) as exc:
                log.warning("cola: Redis no disponible (%s); reintento en %.0fs", type(exc).__name__, backoff)
                await self._sleep(stop, backoff)
                backoff = min(backoff * 2, 30.0)
                continue
            for _stream, entries in resp or []:
                for entry_id, fields in entries:
                    job = await self._to_job(consumer, entry_id, fields, attempts=1)
                    if job is not None:
                        yield job

    async def ack(self, job: Job) -> None:
        self._consumers.pop(job.id, None)
        async with self.redis.pipeline(transaction=True) as pipe:
            pipe.xack(self.stream, self.group, job.id)
            pipe.xdel(self.stream, job.id)
            await pipe.execute()

    async def fail(self, job: Job, error: str) -> None:
        consumer = self._consumers.pop(job.id, None)
        if job.attempts >= self.max_attempts:
            log.error("cola: mensaje %s agotó %d intentos; va a dead-letter", job.id, job.attempts)
            await self._dead_letter(job.id, self._fields_of(job.message), error, job.attempts)
            return
        log.warning(
            "cola: mensaje %s falló (intento %d/%d); se reintenta", job.id, job.attempts, self.max_attempts
        )
        if consumer is None or self.retry_delay_ms >= self.claim_idle_ms:
            return  # queda pendiente: XAUTOCLAIM lo levanta cuando supere claim_idle
        try:
            # adelantar el reintento: marcarlo como "inactivo hace (claim_idle - retry_delay)".
            # JUSTID: no incrementa el contador de entregas.
            await self.redis.xclaim(
                self.stream,
                self.group,
                consumer,
                min_idle_time=0,
                message_ids=[job.id],
                idle=self.claim_idle_ms - self.retry_delay_ms,
                justid=True,
            )
        except Exception:  # noqa: BLE001 - si falla, el reintento simplemente tarda claim_idle
            log.debug("cola: no se pudo adelantar el reintento de %s", job.id, exc_info=True)

    # ------------------------------------------------------------- internos

    @staticmethod
    async def _sleep(stop: asyncio.Event, seconds: float) -> None:
        try:
            await asyncio.wait_for(stop.wait(), timeout=seconds * (0.8 + random.random() * 0.4))  # noqa: S311
        except TimeoutError:
            pass

    @staticmethod
    def _fields_of(message: RawMessage) -> dict[str, Any]:
        return {
            "ref": message.ref.model_dump_json(),
            "received_at": message.received_at.isoformat(),
            "raw": message.raw,
        }

    async def _delivery_count(self, entry_id: Any) -> int:
        try:
            rows = await self.redis.xpending_range(
                self.stream, self.group, min=entry_id, max=entry_id, count=1
            )
        except ResponseError:
            return 1
        if not rows:
            return 1
        return int(rows[0].get("times_delivered") or 1)

    async def _reclaim_safe(self, consumer: str) -> list[Job]:
        try:
            return await self._reclaim(consumer)
        except ResponseError as exc:
            text = str(exc).lower()
            if not self._is_nogroup(exc) and ("unknown command" in text or "unknown subcommand" in text):
                self._autoclaim = False
                log.warning(
                    "cola: este Redis no soporta XAUTOCLAIM (hace falta Redis >= 6.2); los mensajes de "
                    "workers caídos no se van a reintentar solos"
                )
                return []
            raise

    async def _reclaim(self, consumer: str) -> list[Job]:
        """XAUTOCLAIM de entradas colgadas (worker caído). Devuelve los jobs a reprocesar."""
        jobs: list[Job] = []
        start: Any = "0-0"
        for _ in range(10):  # tope de vueltas por ronda
            res = await self.redis.xautoclaim(
                self.stream,
                self.group,
                consumer,
                min_idle_time=self.claim_idle_ms,
                start_id=start,
                count=self.claim_count,
            )
            next_id, entries = res[0], res[1]
            deleted = res[2] if len(res) > 2 else []
            if deleted:
                log.warning(
                    "cola: %d entradas pendientes ya no existen (recortadas por MAXLEN)", len(deleted)
                )
            for entry_id, fields in entries:
                if not fields:  # entrada borrada (Redis < 7)
                    await self.redis.xack(self.stream, self.group, entry_id)
                    continue
                attempts = await self._delivery_count(entry_id)
                if attempts > self.max_attempts:
                    log.error(
                        "cola: mensaje %s reclamado %d veces (el worker se cae procesándolo); va a dead-letter",
                        _s(entry_id),
                        attempts,
                    )
                    await self._dead_letter(
                        _s(entry_id),
                        fields,
                        "el worker se detuvo procesando este mensaje demasiadas veces",
                        attempts,
                    )
                    continue
                job = await self._to_job(consumer, entry_id, fields, attempts=attempts)
                if job is not None:
                    log.info("cola: mensaje %s reclamado (intento %d)", job.id, attempts)
                    jobs.append(job)
            if _s(next_id) == "0-0" or len(jobs) >= self.claim_count:
                break
            start = next_id
        return jobs

    async def _to_job(
        self, consumer: str, entry_id: Any, fields: dict[Any, Any], *, attempts: int
    ) -> Job | None:
        job_id = _s(entry_id)
        try:
            ref = MessageRef.model_validate_json(_field(fields, "ref"))
            received_raw = _field(fields, "received_at")
            received_at = datetime.fromisoformat(_s(received_raw)) if received_raw else utcnow()
            raw = _field(fields, "raw")
            if not isinstance(raw, bytes | bytearray):
                raise ValueError("campo raw ausente o inválido")
            message = RawMessage(ref=ref, raw=bytes(raw), received_at=received_at)
        except Exception as exc:  # noqa: BLE001 - entrada hostil o de otra versión
            log.error("cola: entrada %s malformada (%s); va a dead-letter", job_id, type(exc).__name__)
            await self._dead_letter(job_id, fields, f"entrada malformada: {type(exc).__name__}", attempts)
            return None
        self._consumers[job_id] = consumer
        if len(self._consumers) > 10_000:  # no debería pasar; evita crecer sin límite
            self._consumers.pop(next(iter(self._consumers)))
        return Job(id=job_id, message=message, attempts=attempts)

    async def _dead_letter(self, entry_id: str, fields: dict[Any, Any], error: str, attempts: int) -> None:
        dead_fields: dict[str, Any] = {}
        for name in ("ref", "received_at", "raw"):
            value = _field(fields, name)
            if value is not None:
                dead_fields[name] = value
        dead_fields.update(
            {
                "error": error[:2000],
                "attempts": str(attempts),
                "original_id": entry_id,
                "failed_at": utcnow().isoformat(),
            }
        )
        async with self.redis.pipeline(transaction=True) as pipe:
            pipe.xadd(self.dead_stream, dead_fields, maxlen=self.dead_maxlen, approximate=True)
            pipe.xack(self.stream, self.group, entry_id)
            pipe.xdel(self.stream, entry_id)
            await pipe.execute()


__all__ = ["RedisStreamQueue"]
