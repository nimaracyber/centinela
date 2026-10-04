"""Runtime: arma Centinela completo desde `Settings` y corre los roles de proceso.

    runtime = await Runtime.create(settings, role="all")   # all | ingest | worker | api
    await runtime.run_all(stop)                              # ingest + worker + retención
    await runtime.close()

- `process(raw)`: dedup por ref -> pipeline -> guardar -> etiquetar/alertar -> registrar acciones.
- `emit_for(connector)`: la función `emit` que recibe cada conector. Los conectores inline (milter)
  analizan en el momento; el resto publica en la cola y el worker procesa.
- `run_ingest`: corre todos los conectores supervisados (uno que se cae se reinicia con backoff y
  nunca tumba a los demás).
- `run_worker`: consume la cola con N análisis en paralelo, ack/fail por mensaje.
- `run_retention`: purga diaria según `general.retention_days`.
- `health()`: estado de base, Redis, ClamAV, conectores, cola y analizadores (para /healthz).
- La cola se consulta solo por su API pública (`depth()`, `dead_count()`, y en modo todo-en-uno
  `InMemoryQueue.drain_nowait()` al apagar: lo que no se llegue a analizar queda como ERROR, nunca se pierde
  en silencio).

La API (dashboard) la arranca la CLI aparte con `create_app(runtime)`; `runtime.storage` es el ResultStore.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import random
import socket
import time
from collections.abc import Awaitable, Callable
from datetime import timedelta
from typing import TYPE_CHECKING, Any

import httpx

from centinela import __version__, metrics
from centinela.actions.dispatcher import ActionDispatcher
from centinela.core.cache import MemoryCache, RedisCache
from centinela.core.models import AnalysisResult, Verdict, VerdictLevel, utcnow
from centinela.core.queue import InMemoryQueue
from centinela.logging_setup import redact, setup_logging
from centinela.storage.db import SqlResultStore
from centinela.storage.state import DbStateStore

if TYPE_CHECKING:
    from centinela.actions.alerts.base import AlertChannel
    from centinela.connectors.base import Connector, EmitFn
    from centinela.core.cache import Cache
    from centinela.core.config import Settings
    from centinela.core.models import RawMessage
    from centinela.core.queue import Job, WorkQueue

log = logging.getLogger(__name__)

ROLES = frozenset({"all", "ingest", "worker", "api"})


async def _sleep_or_stop(stop: asyncio.Event, seconds: float) -> None:
    """Espera `seconds` o hasta que se active `stop` (lo que pase primero)."""
    if seconds <= 0 or stop.is_set():
        return
    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(stop.wait(), timeout=seconds)


def _peek_headers(raw: bytes) -> tuple[str, str | None]:
    """Asunto y remitente (solo para identificar un mensaje que no se pudo analizar). Lee únicamente
    los headers de los primeros 64 KB, sin parseo estructurado; ante cualquier rareza devuelve vacío."""
    try:
        from email.header import decode_header, make_header
        from email.parser import BytesHeaderParser
        from email.policy import compat32

        msg = BytesHeaderParser(policy=compat32).parsebytes(raw[:65536])
        subject = str(make_header(decode_header(str(msg.get("Subject") or "")[:1000])))[:300]
        sender = str(msg.get("From") or "")[:320] or None
        return subject, sender
    except Exception:  # noqa: BLE001 - input hostil
        return "", None


def _short_error(exc: BaseException) -> str:
    return redact(f"{type(exc).__name__}: {exc}", limit=300)


class Runtime:
    # Parámetros operativos (atributos para poder ajustarlos en tests o subclases).
    restart_backoff_s: float = 1.0
    restart_backoff_max_s: float = 300.0
    shutdown_grace_s: float = 20.0
    retention_interval_s: float = 24 * 3600.0
    depth_interval_s: float = 15.0
    health_timeout_s: float = 3.0

    def __init__(
        self,
        settings: Settings,
        *,
        role: str,
        store: SqlResultStore,
        state: DbStateStore,
        cache: Cache,
        queue: WorkQueue,
        http: httpx.AsyncClient,
        pipeline: Any,
        connectors: list[Connector],
        channels: list[AlertChannel],
        dispatcher: ActionDispatcher,
        redis: Any = None,
    ) -> None:
        if role not in ROLES:
            raise ValueError(f"rol desconocido: {role!r} (usar all, ingest, worker o api)")
        self.settings = settings
        self.role = role
        self.store = store
        self.state = state
        self.cache = cache
        self.queue = queue
        self.http = http
        self.pipeline = pipeline
        self.connectors = connectors
        self.channels = channels
        self.dispatcher = dispatcher
        self.redis = redis
        self.version = __version__
        self.consumer_name = f"{socket.gethostname()}-{os.getpid()}"
        self.started_at = utcnow()
        self._closed = False

    # ------------------------------------------------------------- construcción

    @classmethod
    async def create(
        cls,
        settings: Settings,
        *,
        role: str = "all",
        pipeline: Any = None,
        connectors: list[Connector] | None = None,
        channels: list[AlertChannel] | None = None,
        configure_logging: bool = True,
    ) -> Runtime:
        """Arma todo desde la configuración. `pipeline`/`connectors`/`channels` permiten inyectar
        implementaciones (tests, embebido); si se omiten se construyen desde `settings`."""
        if role not in ROLES:
            raise ValueError(f"rol desconocido: {role!r} (usar all, ingest, worker o api)")
        if configure_logging:
            setup_logging(settings)

        store = SqlResultStore(settings)
        redis_client: Any = None
        http: httpx.AsyncClient | None = None
        try:
            await store.init()
            state = DbStateStore(store, settings)

            cache: Cache
            queue: WorkQueue
            if settings.redis_url:
                import redis.asyncio as aioredis

                from centinela.storage.redis_queue import RedisStreamQueue

                redis_client = aioredis.Redis.from_url(
                    settings.redis_url,
                    decode_responses=False,  # la cola transporta el mail crudo en bytes
                    socket_connect_timeout=5,
                    socket_timeout=15,
                    health_check_interval=30,
                )
                cache = RedisCache(redis_client)
                queue = RedisStreamQueue(settings.redis_url, client=redis_client)
            else:
                cache = MemoryCache()
                queue = InMemoryQueue()

            http = httpx.AsyncClient(
                timeout=httpx.Timeout(20.0, connect=10.0),
                follow_redirects=False,
                headers={"User-Agent": f"Centinela/{__version__}"},
                limits=httpx.Limits(max_connections=50, max_keepalive_connections=10),
            )

            if pipeline is None:
                from centinela.analyzers import build_analyzers
                from centinela.core.pipeline import Pipeline

                pipeline = Pipeline(settings, build_analyzers(settings), http, cache)
            if connectors is None:
                connectors = _build_connectors(settings, state)
            if channels is None:
                channels = _build_channels(settings, http)
            dispatcher = ActionDispatcher(settings, cache, {c.name: c for c in connectors}, channels)
        except BaseException:
            if http is not None:
                await http.aclose()
            if redis_client is not None:
                with contextlib.suppress(Exception):
                    await redis_client.aclose()
            await store.close()
            raise

        runtime = cls(
            settings,
            role=role,
            store=store,
            state=state,
            cache=cache,
            queue=queue,
            http=http,
            pipeline=pipeline,
            connectors=connectors,
            channels=channels,
            dispatcher=dispatcher,
            redis=redis_client,
        )
        if role in {"all", "worker"} or (role == "ingest" and any(c.inline for c in connectors)):
            await runtime._setup_pipeline()  # compilar YARA, etc. al arrancar y no en el primer mail
        log.info(
            "Centinela %s listo (rol=%s, base=%s, cola=%s, conectores=%d, analizadores=%d, alertas=%d)",
            __version__,
            role,
            store.dialect,
            "redis" if redis_client is not None else "memoria",
            len(connectors),
            len(runtime.analyzers),
            len(channels),
        )
        return runtime

    async def _setup_pipeline(self) -> None:
        setup = getattr(self.pipeline, "setup", None)
        if setup is None:
            return
        try:
            await setup()
        except Exception:
            log.exception("no se pudo inicializar el pipeline de análisis")

    @property
    def storage(self) -> SqlResultStore:
        """El `ResultStore` (alias de `store`): es el nombre que espera el dashboard (`create_app`)."""
        return self.store

    @property
    def analyzers(self) -> list[Any]:
        return list(getattr(self.pipeline, "analyzers", []) or [])

    def _analyzer(self, name: str) -> Any:
        for a in self.analyzers:
            if getattr(a, "name", None) == name:
                return a
        return None

    # ------------------------------------------------------------- procesamiento

    async def process(self, raw: RawMessage) -> AnalysisResult | None:
        """Analiza, guarda y ejecuta acciones. None si ese mensaje ya se había analizado."""
        if await self.store.has_ref(raw.ref):
            log.debug("mensaje ya analizado (%s/%s): se omite", raw.ref.connector, raw.ref.mailbox)
            return None
        result: AnalysisResult = await self.pipeline.analyze(raw)
        if not await self.store.save_result(result):
            return None  # otro worker lo guardó primero (reentrega concurrente)
        self._observe(result)
        actions = await self.dispatcher.dispatch(result)
        if actions:
            try:
                await self.store.record_actions(result.id, actions)
            except Exception:
                log.exception("no se pudieron registrar las acciones del resultado %s", result.id)
            result.actions = [*result.actions, *[a for a in actions if a not in result.actions]]
        log.info(
            "mensaje analizado: %s nivel=%s score=%d hallazgos=%d %dms acciones=%s",
            result.id,
            result.verdict.level.value,
            result.verdict.score,
            len(result.findings),
            result.duration_ms,
            ",".join(actions) or "-",
            extra={"connector": result.ref.connector, "mailbox": result.ref.mailbox},
        )
        return result

    def _observe(self, result: AnalysisResult) -> None:
        try:
            metrics.MESSAGES_ANALYZED.labels(
                connector=result.ref.connector, verdict=result.verdict.level.value
            ).inc()
            metrics.ANALYSIS_DURATION.observe(max(0, result.duration_ms) / 1000)
            for f in result.findings:
                metrics.FINDINGS.labels(category=f.category.value, severity=f.severity.name.lower()).inc()
            for err in result.errors:
                metrics.ANALYZER_ERRORS.labels(analyzer=self._error_source(err)).inc()
        except Exception:  # noqa: BLE001 - las métricas nunca rompen el análisis
            log.debug("error actualizando métricas", exc_info=True)

    def _error_source(self, error: str) -> str:
        """'office[att0]: timeout' -> 'office'. Etiqueta de baja cardinalidad (nombres conocidos)."""
        token = error.split(":", 1)[0].split("[", 1)[0].split(".", 1)[0].strip()
        known = {getattr(a, "name", "") for a in self.analyzers} | {"parse", "pipeline"}
        return token if token in known else "other"

    def emit_for(self, connector: Connector) -> EmitFn:
        name = connector.name
        inline = bool(getattr(connector, "inline", False))

        async def emit(raw: RawMessage) -> AnalysisResult | None:
            metrics.MESSAGES_INGESTED.labels(connector=name).inc()
            if inline:
                return await self.process(raw)
            try:
                if await self.store.has_ref(raw.ref):
                    return None  # ya analizado (reconexión, backfill repetido): no re-encolar
            except Exception:  # noqa: BLE001 - si la base no responde, el worker deduplica igual
                log.debug("no se pudo consultar dedup antes de encolar", exc_info=True)
            await self.queue.publish(raw)
            return None

        return emit

    # ------------------------------------------------------------- roles

    async def run_ingest(self, stop: asyncio.Event) -> None:
        if not self.connectors:
            log.warning("no hay conectores habilitados: no se va a recibir ningún mail (ver config.yaml)")
            await stop.wait()
            return
        tasks = [
            asyncio.create_task(self._supervise_connector(c, stop), name=f"connector:{c.name}")
            for c in self.connectors
        ]
        try:
            await stop.wait()
            _done, pending = await asyncio.wait(tasks, timeout=self.shutdown_grace_s)
            if pending:
                log.warning("%d conectores no terminaron a tiempo; se cancelan", len(pending))
        finally:
            for t in tasks:
                if not t.done():
                    t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _supervise_connector(self, connector: Connector, stop: asyncio.Event) -> None:
        name = connector.name
        backoff = self.restart_backoff_s
        emit = self.emit_for(connector)
        while not stop.is_set():
            started = time.monotonic()
            try:
                await connector.run(emit, stop)
                if stop.is_set():
                    break
                log.warning("el conector %s terminó sin que se lo pidieran; se reinicia", name)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("el conector %s falló; se reinicia en %.0fs", name, backoff)
            with contextlib.suppress(Exception):
                metrics.CONNECTOR_UP.labels(connector=name).set(0)
            if time.monotonic() - started > 300:
                backoff = self.restart_backoff_s  # anduvo un rato: no penalizar
            await _sleep_or_stop(stop, backoff * (0.8 + random.random() * 0.4))  # noqa: S311 - jitter
            backoff = min(backoff * 2, self.restart_backoff_max_s)

    async def run_worker(self, stop: asyncio.Event, concurrency: int = 4) -> None:
        concurrency = max(1, int(concurrency))
        sem = asyncio.Semaphore(concurrency)
        inflight: set[asyncio.Task[None]] = set()
        depth_task = asyncio.create_task(self._depth_loop(stop), name="queue-depth")
        agen = self.queue.consume(self.consumer_name, stop)
        log.info("worker %s consumiendo la cola (concurrencia=%d)", self.consumer_name, concurrency)

        def _done(task: asyncio.Task[None]) -> None:
            inflight.discard(task)
            sem.release()

        try:
            while not stop.is_set():
                if not await self._acquire(sem, stop):
                    break
                try:
                    job = await agen.__anext__()
                except StopAsyncIteration:
                    sem.release()
                    break
                except Exception:
                    sem.release()
                    log.exception("error leyendo la cola; se reintenta")
                    with contextlib.suppress(Exception):
                        await agen.aclose()
                    await _sleep_or_stop(stop, 2.0)
                    agen = self.queue.consume(self.consumer_name, stop)
                    continue
                task = asyncio.create_task(self._handle_job(job), name=f"job:{job.id}")
                inflight.add(task)
                task.add_done_callback(_done)
        finally:
            with contextlib.suppress(Exception):
                await agen.aclose()
            depth_task.cancel()
            if inflight:
                _done_set, pending = await asyncio.wait(set(inflight), timeout=self.shutdown_grace_s)
                for t in pending:
                    t.cancel()
                if pending:
                    log.warning("%d análisis en curso cancelados por el apagado", len(pending))
                    await asyncio.gather(*pending, return_exceptions=True)
            await self._drain_memory_queue()
            await asyncio.wait({depth_task})

    @staticmethod
    async def _acquire(sem: asyncio.Semaphore, stop: asyncio.Event) -> bool:
        """Toma un lugar de concurrencia, o devuelve False si se pidió parar mientras esperaba."""
        if stop.is_set():
            return False
        if not sem.locked():
            await sem.acquire()
            return True
        acquire = asyncio.ensure_future(sem.acquire())
        stopper = asyncio.ensure_future(stop.wait())
        try:
            await asyncio.wait({acquire, stopper}, return_when=asyncio.FIRST_COMPLETED)
        except BaseException:
            acquire.cancel()
            stopper.cancel()
            raise
        stopper.cancel()
        if acquire.done() and not acquire.cancelled():
            if stop.is_set():
                sem.release()
                return False
            return True
        acquire.cancel()
        await asyncio.wait({acquire})  # no propaga la cancelación del propio acquire
        if not acquire.cancelled() and acquire.exception() is None:
            sem.release()  # se adquirió justo al cancelar
        return False

    @property
    def _job_timeout_s(self) -> float:
        # análisis (con su propio timeout) + guardado + alertas con reintentos (cada canal: hasta 3 envíos
        # de 30 s + 2 esperas de hasta 60 s si el servicio pide "retry-after")
        return float(self.settings.limits.message_timeout_s) + 300.0

    @property
    def _max_attempts(self) -> int:
        q = self.queue
        return int(getattr(q, "max_attempts", None) or getattr(q, "MAX_ATTEMPTS", 3))

    async def _record_failure(self, raw: RawMessage, error: str) -> None:
        """El mensaje agotó sus reintentos: dejarlo visible en el dashboard como ERROR (nunca "limpio")."""
        subject, from_addr = _peek_headers(raw.raw)
        result = AnalysisResult(
            ref=raw.ref,
            subject=subject,
            from_addr=from_addr,
            received_at=raw.received_at,
            size=len(raw.raw),
            verdict=Verdict(
                level=VerdictLevel.ERROR,
                score=0,
                summary="No se pudo analizar este mensaje después de varios intentos. Tratalo con cuidado "
                "hasta revisarlo.",
            ),
            errors=[f"worker: {error}"],
        )
        try:
            if await self.store.save_result(result):
                self._observe(result)
        except Exception:
            log.exception("no se pudo registrar el mensaje fallido %s", raw.ref.remote_id)

    async def _handle_job(self, job: Job) -> None:
        try:
            await asyncio.wait_for(self.process(job.message), timeout=self._job_timeout_s)
        except asyncio.CancelledError:
            raise  # apagado: en Redis queda pendiente y otro worker lo reclama
        except Exception as exc:
            log.exception("falló el procesamiento del mensaje %s (intento %d)", job.id, job.attempts)
            error = _short_error(exc)
            if job.attempts >= self._max_attempts:
                await self._record_failure(job.message, error)
            try:
                await self.queue.fail(job, error)
            except Exception:
                log.exception("no se pudo registrar el fallo del mensaje %s en la cola", job.id)
            return
        try:
            await self.queue.ack(job)
        except Exception:
            log.exception("no se pudo confirmar (ack) el mensaje %s", job.id)

    async def _drain_memory_queue(self) -> None:
        """Modo todo-en-uno: al apagar, procesa lo que quedó en la cola en memoria (con tope de tiempo).

        La cola en memoria se pierde al terminar el proceso y los conectores ya avanzaron su cursor: lo que
        no se llegue a analizar (o falle en todos los intentos) queda registrado como ERROR en el dashboard
        para que nadie lo dé por limpio."""
        if not isinstance(self.queue, InMemoryQueue):
            return
        jobs = self.queue.drain_nowait()  # ya confirmados en la cola: no se les hace ack/fail
        if not jobs:
            return
        deadline = time.monotonic() + self.shutdown_grace_s
        processed = failed = 0
        pending = list(jobs)
        while pending and time.monotonic() < deadline:
            job = pending.pop(0)
            if await self._process_drained(job, deadline):
                processed += 1
            else:
                failed += 1
        for job in pending:  # sin tiempo: que quede visible como no analizado
            await self._record_failure(job.message, "Centinela se apagó antes de analizar este mensaje")
        if processed or failed or pending:
            log.warning(
                "apagado: %d mensajes pendientes procesados, %d con error, %d sin procesar",
                processed,
                failed,
                len(pending),
            )

    async def _process_drained(self, job: Job, deadline: float) -> bool:
        """Procesa un mensaje sacado de la cola al apagar, con los reintentos que le queden."""
        attempts = job.attempts
        while True:
            remaining = max(1.0, deadline - time.monotonic())
            try:
                await asyncio.wait_for(self.process(job.message), timeout=min(remaining, self._job_timeout_s))
                return True
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.exception(
                    "falló el procesamiento del mensaje pendiente %s (intento %d)", job.id, attempts
                )
                error = _short_error(exc)
                if attempts >= self._max_attempts or time.monotonic() >= deadline:
                    await self._record_failure(job.message, error)
                    return False
                attempts += 1

    async def queue_depth(self) -> int | None:
        n = int(await self.queue.depth())
        metrics.QUEUE_DEPTH.set(n)
        return n

    async def dead_letters(self) -> int | None:
        """Mensajes en dead-letter (None si la cola no lo informa)."""
        dead_count = getattr(self.queue, "dead_count", None)
        if not callable(dead_count):
            return None
        return int(await dead_count())

    async def _depth_loop(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            try:
                await self.queue_depth()
            except Exception:  # noqa: BLE001
                log.debug("no se pudo medir la cola", exc_info=True)
            await _sleep_or_stop(stop, self.depth_interval_s)

    async def run_retention(self, stop: asyncio.Event) -> None:
        days = int(self.settings.general.retention_days)
        if days <= 0:
            log.info("retención deshabilitada (general.retention_days <= 0)")
            await stop.wait()
            return
        lock_ttl = int(max(1.0, self.retention_interval_s - 300))
        while not stop.is_set():
            try:
                # con Redis, un solo worker purga por día aunque haya varios
                if await self.cache.add("retention:lock", self.consumer_name, lock_ttl):
                    cutoff = utcnow() - timedelta(days=days)
                    await self.store.purge_older_than(cutoff)
            except Exception:
                log.exception("falló la purga de retención; se reintenta en el próximo ciclo")
            await _sleep_or_stop(stop, self.retention_interval_s)

    async def run_all(self, stop: asyncio.Event, concurrency: int = 4) -> None:
        tasks = [
            asyncio.create_task(self.run_ingest(stop), name="ingest"),
            asyncio.create_task(
                self._supervised("worker", lambda: self.run_worker(stop, concurrency), stop), name="worker"
            ),
            asyncio.create_task(
                self._supervised("retention", lambda: self.run_retention(stop), stop), name="retention"
            ),
        ]
        try:
            await asyncio.gather(*tasks)
        finally:
            for t in tasks:
                if not t.done():
                    t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _supervised(
        self, name: str, factory: Callable[[], Awaitable[None]], stop: asyncio.Event
    ) -> None:
        backoff = self.restart_backoff_s
        while not stop.is_set():
            try:
                await factory()
                if stop.is_set():
                    return
                log.warning("%s terminó inesperadamente; se reinicia", name)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("%s falló; se reinicia en %.0fs", name, backoff)
            await _sleep_or_stop(stop, backoff)
            backoff = min(backoff * 2, self.restart_backoff_max_s)

    # ------------------------------------------------------------- salud y cierre

    async def _timed(self, coro: Awaitable[Any], limit_s: float | None = None) -> tuple[bool, Any]:
        try:
            return True, await asyncio.wait_for(coro, timeout=limit_s or self.health_timeout_s)
        except Exception as exc:  # noqa: BLE001
            return False, _short_error(exc)

    async def health(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "version": __version__,
            "role": self.role,
            "started_at": self.started_at.isoformat(),
        }
        degraded: list[str] = []

        ok, err = await self._timed(self.store.ping())
        out["db"] = {"ok": ok, "backend": self.store.dialect} | ({} if ok else {"error": err})

        if self.redis is None:
            out["redis"] = {"ok": True, "enabled": False}
        else:
            ok_r, val = await self._timed(self.redis.ping())
            out["redis"] = {"ok": bool(ok_r and val), "enabled": True} | ({} if ok_r else {"error": val})

        ok_q, depth = await self._timed(self.queue_depth())
        queue_info: dict[str, Any] = {
            "backend": "redis" if self.redis is not None else "memory",
            "depth": depth if ok_q else None,
        }
        ok_d, dead = await self._timed(self.dead_letters())
        queue_info["dead_letters"] = dead if ok_d else None
        out["queue"] = queue_info

        clam = self._analyzer("clamav")
        if clam is not None and callable(getattr(clam, "ping", None)):
            ok_c, val = await self._timed(clam.ping(), limit_s=1.0)
            out["clamav"] = {"ok": bool(ok_c and val is not False)} | ({} if ok_c else {"error": val})
            if not out["clamav"]["ok"]:
                degraded.append("clamav")

        async def _conn_health(c: Connector) -> tuple[str, dict[str, Any]]:
            ok_h, val = await self._timed(c.healthcheck())
            if not ok_h:
                return c.name, {"ok": False, "error": val}
            info = dict(val) if isinstance(val, dict) else {"ok": bool(val)}
            info.setdefault("ok", True)
            return c.name, info

        if self.role in {"all", "ingest"}:
            conn_results = await asyncio.gather(*(_conn_health(c) for c in self.connectors))
            out["connectors"] = dict(conn_results)
            degraded += [f"connector:{n}" for n, info in conn_results if not info.get("ok")]
        else:  # en despliegues separados los conectores corren en el proceso `ingest`
            out["connectors"] = {
                c.name: {"ok": None, "detail": "corre en el proceso ingest"} for c in self.connectors
            }

        out["analyzers"] = [getattr(a, "name", type(a).__name__) for a in self.analyzers]
        out["alert_channels"] = [c.name for c in self.channels]

        core_ok = out["db"]["ok"] and out["redis"]["ok"]
        out["ok"] = bool(core_ok)
        out["status"] = "error" if not core_ok else ("degraded" if degraded else "ok")
        out["degraded"] = degraded
        return out

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        steps: list[tuple[str, Callable[[], Awaitable[Any]]]] = []
        close_pipeline = getattr(self.pipeline, "close", None)
        if close_pipeline is not None:
            steps.append(("pipeline", close_pipeline))
        steps.append(("alertas", self.dispatcher.close))
        steps += [(f"conector {c.name}", c.close) for c in self.connectors]
        steps.append(("cola", self.queue.close))
        steps.append(("http", self.http.aclose))
        if self.redis is not None:
            steps.append(("redis", self.redis.aclose))
        steps.append(("base", self.store.close))
        for label, fn in steps:
            try:
                await asyncio.wait_for(fn(), timeout=10)
            except Exception:  # noqa: BLE001
                log.debug("error cerrando %s", label, exc_info=True)


def _build_connectors(settings: Settings, state: DbStateStore) -> list[Connector]:
    """Construye los conectores habilitados; uno roto (dependencia faltante, config mala) no tumba al resto."""
    from centinela import connectors as registry

    try:
        return list(registry.build_connectors(settings, state))
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "no se pudieron construir todos los conectores juntos (%s); se cargan de a uno", _short_error(exc)
        )
    out: list[Connector] = []
    for cfg in settings.connectors:
        if not cfg.enabled:
            continue
        try:
            out.append(registry.connector_class(cfg.type)(cfg, settings, state))
        except Exception as exc:  # noqa: BLE001
            log.error("conector %s (%s) no disponible: %s", cfg.name, cfg.type, _short_error(exc))
    return out


def _build_channels(settings: Settings, http: httpx.AsyncClient) -> list[AlertChannel]:
    if not settings.actions.alerts.channels:
        return []
    try:
        from centinela.actions.alerts import build_channels
    except Exception as exc:  # noqa: BLE001
        log.error("canales de alerta no disponibles: %s", _short_error(exc))
        return []
    try:
        return list(build_channels(settings, http))
    except Exception as exc:  # noqa: BLE001
        log.error("no se pudieron construir los canales de alerta: %s", _short_error(exc))
        return []


__all__ = ["ROLES", "Runtime"]
