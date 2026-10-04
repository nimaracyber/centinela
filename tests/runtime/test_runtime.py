from __future__ import annotations

import asyncio
import importlib
import logging
import sys
import time
import types
from datetime import timedelta

import fakeredis
import pytest
from fakeredis import aioredis as fake_aioredis

from centinela import metrics
from centinela.core.cache import MemoryCache, RedisCache
from centinela.core.models import (
    AnalysisResult,
    ArtifactSummary,
    Finding,
    FindingCategory,
    MessageRef,
    RawMessage,
    Severity,
    Verdict,
    VerdictLevel,
    utcnow,
)
from centinela.core.queue import InMemoryQueue
from centinela.runtime import Runtime
from centinela.storage.protocol import ResultFilter
from tests.helpers import build_eml, eicar, make_raw
from tests.runtime.fakes import FakeAnalyzer, FakeChannel, FakeConnector, StubPipeline
from tests.storage.factories import make_result, sha


def canned(raw: RawMessage) -> AnalysisResult:
    """Resultado fijo "malicioso" (como si el pipeline hubiera detectado EICAR en un adjunto)."""
    return AnalysisResult(
        ref=raw.ref,
        message_id="<test-1@proveedor.com>",
        subject="Factura",
        from_addr="juan@proveedor.com",
        received_at=raw.received_at,
        duration_ms=250,
        size=len(raw.raw),
        artifacts=[
            ArtifactSummary(
                id="att0", filename="factura.exe", detected_type="pe", size=68, sha256=sha("eicar")
            )
        ],
        findings=[
            Finding(
                analyzer="clamav",
                rule="clamav.Eicar-Signature",
                title="Archivo de prueba antivirus (EICAR)",
                category=FindingCategory.MALWARE,
                severity=Severity.CRITICAL,
                score=95,
                artifact_id="att0",
                malware_family="EICAR",
            )
        ],
        verdict=Verdict(
            level=VerdictLevel.MALICIOUS, score=95, summary="Adjunto malicioso.", malware_families=["EICAR"]
        ),
        errors=["yara[att0]: timeout", "rarisimo: algo"],
    )


def eml_raw(remote_id: str = "1", connector: str = "test") -> RawMessage:
    raw = make_raw(
        build_eml(attachments=[("factura.exe", eicar(), "application/octet-stream")]), remote_id=remote_id
    )
    return raw.model_copy(update={"ref": raw.ref.model_copy(update={"connector": connector})})


@pytest.fixture
async def make_runtime(settings):
    created: list[Runtime] = []
    settings.general.timezone = "UTC"

    async def _make(**kw) -> Runtime:
        kw.setdefault(
            "pipeline", StubPipeline(canned, analyzers=[FakeAnalyzer("clamav"), FakeAnalyzer("yara")])
        )
        kw.setdefault("connectors", [FakeConnector()])
        kw.setdefault("channels", [FakeChannel()])
        kw.setdefault("configure_logging", False)
        role = kw.pop("role", "all")
        rt = await Runtime.create(settings, role=role, **kw)
        rt.restart_backoff_s = 0.01
        rt.shutdown_grace_s = 2.0
        created.append(rt)
        return rt

    yield _make
    for rt in created:
        await rt.close()


async def wait_until(predicate, limit_s: float = 5.0) -> None:
    deadline = time.monotonic() + limit_s
    while time.monotonic() < deadline:
        if await predicate():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("condición no alcanzada a tiempo")


# --------------------------------------------------------------------------- process


async def test_process_stores_tags_alerts_and_dedups(make_runtime):
    rt = await make_runtime()
    assert isinstance(rt.queue, InMemoryQueue) and isinstance(rt.cache, MemoryCache)
    assert rt.pipeline.setup_called  # rol all: el pipeline se inicializa al arrancar
    before = metrics.MESSAGES_ANALYZED.labels(connector="test", verdict="malicious")._value.get()
    err_before = metrics.ANALYZER_ERRORS.labels(analyzer="yara")._value.get()
    other_before = metrics.ANALYZER_ERRORS.labels(analyzer="other")._value.get()

    result = await rt.process(eml_raw("1"))
    assert result is not None
    assert result.actions == ["tag:test:keyword:Centinela/Malicioso", "alert:telegram:ok"]
    stored = await rt.store.get_result(result.id)
    assert stored is not None and stored.verdict.level == VerdictLevel.MALICIOUS
    assert stored.actions == result.actions
    assert metrics.MESSAGES_ANALYZED.labels(connector="test", verdict="malicious")._value.get() == before + 1
    assert metrics.ANALYZER_ERRORS.labels(analyzer="yara")._value.get() == err_before + 1
    assert metrics.ANALYZER_ERRORS.labels(analyzer="other")._value.get() == other_before + 1

    # mismo mensaje otra vez (reentrega): no se reanaliza
    assert await rt.process(eml_raw("1")) is None
    assert len(rt.pipeline.calls) == 1
    # otro buzón con el mismo malware: se etiqueta y guarda, la alerta se deduplica
    second = await rt.process(eml_raw("2"))
    assert second.actions == ["tag:test:keyword:Centinela/Malicioso", "alert:telegram:dedup"]
    assert len(rt.channels[0].sent) == 1
    _, total = await rt.store.list_results(ResultFilter())
    assert total == 2


async def test_process_clean_result_has_no_actions(make_runtime):
    rt = await make_runtime(pipeline=StubPipeline(lambda raw: make_result(raw.ref.remote_id)))
    r = await rt.process(make_raw(build_eml(), remote_id="limpio"))
    assert r is not None and r.actions == [] and r.verdict.level == VerdictLevel.CLEAN
    assert rt.connectors[0].tag_calls == [] and rt.channels[0].attempts == 0


async def test_process_with_real_pipeline_class(make_runtime, monkeypatch):
    """Con el Pipeline real (si sus dependencias ya existen), parcheando analyze()."""
    try:
        pipeline_mod = importlib.import_module("centinela.core.pipeline")
    except Exception as exc:  # noqa: BLE001 - parser/scoring los escriben otros módulos
        pytest.skip(f"pipeline todavía no disponible: {exc}")
    import centinela.analyzers as analyzers_mod

    async def fake_analyze(self, raw):
        return canned(raw)

    monkeypatch.setattr(pipeline_mod.Pipeline, "analyze", fake_analyze)
    monkeypatch.setattr(analyzers_mod, "build_analyzers", lambda settings: [])
    rt = await make_runtime(pipeline=None, connectors=[], channels=[])
    assert isinstance(rt.pipeline, pipeline_mod.Pipeline)
    result = await rt.process(eml_raw("real"))
    assert result is not None and await rt.store.has_ref(result.ref)


async def test_emit_inline_vs_queued(make_runtime):
    inline = FakeConnector("milter", inline=True)
    queued = FakeConnector("test")
    rt = await make_runtime(connectors=[inline, queued])
    ing_before = metrics.MESSAGES_INGESTED.labels(connector="test")._value.get()
    res = await rt.emit_for(inline)(eml_raw("i1", connector="milter"))
    assert isinstance(res, AnalysisResult)  # inline: analiza en el momento
    assert await rt.emit_for(queued)(eml_raw("q1")) is None
    assert await rt.queue_depth() == 1
    assert metrics.QUEUE_DEPTH._value.get() == 1
    assert metrics.MESSAGES_INGESTED.labels(connector="test")._value.get() == ing_before + 1
    # ya analizado: no se vuelve a encolar
    await rt.process(eml_raw("q2"))
    assert await rt.emit_for(queued)(eml_raw("q2")) is None
    assert await rt.queue_depth() == 1


# --------------------------------------------------------------------------- roles


async def test_run_all_end_to_end(make_runtime):
    msgs = [eml_raw("a"), eml_raw("b"), eml_raw("a")]  # "a" repetido (reconexión del conector)
    conn = FakeConnector(to_emit=msgs)
    rt = await make_runtime(connectors=[conn])
    stop = asyncio.Event()
    task = asyncio.create_task(rt.run_all(stop, concurrency=2))

    async def two_stored() -> bool:
        return (await rt.store.list_results(ResultFilter()))[1] == 2

    await wait_until(two_stored)
    stop.set()
    await asyncio.wait_for(task, 5)
    assert len(conn.tag_calls) == 2  # el duplicado nunca se guarda ni se etiqueta dos veces
    assert len(rt.channels[0].sent) == 1  # misma campaña: una sola alerta
    assert len(rt.pipeline.calls) in (2, 3)  # el duplicado puede llegar a analizarse si corre en paralelo


async def test_crashing_connector_is_restarted_without_killing_others(make_runtime, caplog):
    flaky = FakeConnector("flaky", crash_first_runs=2, to_emit=[eml_raw("f1", connector="flaky")])
    steady = FakeConnector("steady", to_emit=[eml_raw("s1", connector="steady")])
    rt = await make_runtime(connectors=[flaky, steady])
    stop = asyncio.Event()
    task = asyncio.create_task(rt.run_all(stop))

    async def both_stored() -> bool:
        return (await rt.store.list_results(ResultFilter()))[1] == 2

    await wait_until(both_stored)
    stop.set()
    await asyncio.wait_for(task, 5)
    assert flaky.runs == 3 and steady.runs == 1
    assert metrics.CONNECTOR_UP.labels(connector="flaky")._value.get() == 0


async def test_worker_retries_and_dead_letters_failing_messages(make_runtime):
    rt = await make_runtime(pipeline=StubPipeline(canned, fail=RuntimeError("base caída token=abc")))
    await rt.queue.publish(eml_raw("x"))
    stop = asyncio.Event()
    task = asyncio.create_task(rt.run_worker(stop, concurrency=2))

    async def dead() -> bool:
        return await rt.queue.dead_count() == 1

    await wait_until(dead)
    stop.set()
    await asyncio.wait_for(task, 5)
    assert (await rt.health())["queue"]["dead_letters"] == 1
    ref_json, error = rt.queue.dead[0]  # la dead-letter en memoria guarda solo metadatos, no el mail crudo
    assert len(rt.pipeline.calls) == 3
    assert "RuntimeError" in error and "abc" not in error  # el error guardado pasa por redacción
    job_ref = MessageRef.model_validate_json(ref_json)
    # queda visible en el dashboard como ERROR (nunca como limpio), con asunto/remitente para ubicarlo
    items, total = await rt.store.list_results(ResultFilter(level=VerdictLevel.ERROR))
    assert total == 1
    failed = await rt.store.get_result(items[0].id)
    assert failed.ref == job_ref and failed.subject == "Hola"
    assert failed.from_addr == "Juan <juan@proveedor.com>"
    assert failed.errors and "abc" not in failed.errors[0]
    assert rt.connectors[0].tag_calls == [] and rt.channels[0].attempts == 0


def test_peek_headers_is_defensive():
    from centinela.runtime import _peek_headers

    raw = b"Subject: =?utf-8?q?Factura_=C3=B1?=\r\nFrom: Juan <juan@proveedor.com>\r\n\r\ncuerpo"
    assert _peek_headers(raw) == ("Factura ñ", "Juan <juan@proveedor.com>")
    assert _peek_headers(b"") == ("", None)
    assert _peek_headers(b"\xff\xfe\x00garbage" * 10000)[0] == ""
    subject, _ = _peek_headers(b"Subject: " + b"A" * 100_000 + b"\r\n\r\n")
    assert len(subject) <= 300


async def test_worker_concurrency_limit(make_runtime):
    active, peak = 0, 0

    class SlowPipeline(StubPipeline):
        async def analyze(self, raw):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.05)
            active -= 1
            return make_result(raw.ref.remote_id)

    rt = await make_runtime(pipeline=SlowPipeline(canned))
    for i in range(8):
        await rt.queue.publish(make_raw(b"x", remote_id=f"c{i}"))
    stop = asyncio.Event()
    task = asyncio.create_task(rt.run_worker(stop, concurrency=3))

    async def all_done() -> bool:
        return (await rt.store.list_results(ResultFilter()))[1] == 8

    await wait_until(all_done)
    stop.set()
    await asyncio.wait_for(task, 5)
    assert peak == 3


async def test_shutdown_drains_memory_queue(make_runtime, caplog):
    rt = await make_runtime()
    for i in range(3):
        await rt.queue.publish(eml_raw(f"d{i}"))
    stop = asyncio.Event()
    stop.set()  # se pide apagar con mensajes todavía en la cola en memoria
    with caplog.at_level(logging.WARNING, logger="centinela.runtime"):
        await asyncio.wait_for(rt.run_worker(stop), 5)
    assert (await rt.store.list_results(ResultFilter()))[1] == 3
    assert await rt.queue.depth() == 0
    # drain_nowait ya confirmó cada job: nada de ack doble (task_done() de más) al procesarlos
    assert "no se pudo confirmar" not in caplog.text
    assert "3 mensajes pendientes procesados, 0 con error, 0 sin procesar" in caplog.text


async def test_shutdown_drain_retries_then_records_failures_as_error(make_runtime):
    rt = await make_runtime(pipeline=StubPipeline(canned, fail=RuntimeError("análisis roto token=xyz")))
    await rt.queue.publish(eml_raw("f1"))
    stop = asyncio.Event()
    stop.set()
    await asyncio.wait_for(rt.run_worker(stop), 5)
    assert len(rt.pipeline.calls) == 3  # reintentos también durante el apagado
    items, total = await rt.store.list_results(ResultFilter(level=VerdictLevel.ERROR))
    assert total == 1
    failed = await rt.store.get_result(items[0].id)
    assert "xyz" not in failed.errors[0] and "RuntimeError" in failed.errors[0]


async def test_shutdown_without_time_left_records_pending_as_error(make_runtime):
    rt = await make_runtime()
    rt.shutdown_grace_s = 0.0  # sin tiempo para analizar: no se pierde en silencio
    for i in range(2):
        await rt.queue.publish(eml_raw(f"p{i}"))
    stop = asyncio.Event()
    stop.set()
    await asyncio.wait_for(rt.run_worker(stop), 5)
    assert rt.pipeline.calls == []
    items, total = await rt.store.list_results(ResultFilter(level=VerdictLevel.ERROR))
    assert total == 2
    failed = await rt.store.get_result(items[0].id)
    assert "se apagó antes de analizar" in failed.errors[0]
    assert failed.verdict.level == VerdictLevel.ERROR


async def test_storage_alias_and_queue_metrics_use_public_api(make_runtime):
    rt = await make_runtime()
    assert rt.storage is rt.store  # el nombre que espera create_app

    class CountingQueue(InMemoryQueue):
        depth_calls = 0

        async def depth(self) -> int:
            self.depth_calls += 1
            return 7

        async def dead_count(self) -> int:
            return 3

    rt.queue = CountingQueue()
    assert await rt.queue_depth() == 7 and rt.queue.depth_calls == 1
    assert metrics.QUEUE_DEPTH._value.get() == 7
    h = await rt.health()
    assert h["queue"] == {"backend": "memory", "depth": 7, "dead_letters": 3}


async def test_create_app_accepts_real_runtime(make_runtime, settings):
    from centinela.api.app import create_app

    settings.dashboard.enabled = False  # sin secretos: solo /healthz, /readyz y /metrics
    rt = await make_runtime()
    app = create_app(rt)
    assert app.state.centinela.store is rt.store


async def test_run_retention_purges_old_results(make_runtime, settings):
    settings.general.retention_days = 180
    rt = await make_runtime()
    old = make_result("old", received_at=utcnow() - timedelta(days=200))
    new = make_result("new")
    await rt.store.save_result(old)
    await rt.store.save_result(new)
    stop = asyncio.Event()
    task = asyncio.create_task(rt.run_retention(stop))

    async def purged() -> bool:
        return await rt.store.get_result(old.id) is None

    await wait_until(purged)
    stop.set()
    await asyncio.wait_for(task, 2)
    assert await rt.store.get_result(new.id) is not None


async def test_retention_disabled(make_runtime, settings):
    settings.general.retention_days = 0
    rt = await make_runtime()
    old = make_result("old", received_at=utcnow() - timedelta(days=2000))
    await rt.store.save_result(old)
    stop = asyncio.Event()
    task = asyncio.create_task(rt.run_retention(stop))
    await asyncio.sleep(0.05)
    stop.set()
    await asyncio.wait_for(task, 2)
    assert await rt.store.get_result(old.id) is not None


async def test_no_connectors_ingest_waits_for_stop(make_runtime):
    rt = await make_runtime(connectors=[])
    stop = asyncio.Event()
    task = asyncio.create_task(rt.run_ingest(stop))
    await asyncio.sleep(0.05)
    assert not task.done()
    stop.set()
    await asyncio.wait_for(task, 2)


# --------------------------------------------------------------------------- health / close / create


async def test_health_reports_components(make_runtime):
    ok_conn = FakeConnector("gmail1")
    bad_conn = FakeConnector("imap1", health=ConnectionError("login falló password=hunter2"))
    rt = await make_runtime(connectors=[ok_conn, bad_conn])
    h = await rt.health()
    assert h["ok"] is True and h["status"] == "degraded"
    assert h["db"] == {"ok": True, "backend": "sqlite"}
    assert h["redis"] == {"ok": True, "enabled": False}
    assert h["queue"] == {"backend": "memory", "depth": 0, "dead_letters": 0}
    assert h["clamav"] == {"ok": True}
    assert h["connectors"]["gmail1"] == {"ok": True, "detail": "conectado"}
    assert h["connectors"]["imap1"]["ok"] is False
    assert "hunter2" not in h["connectors"]["imap1"]["error"]
    assert h["degraded"] == ["connector:imap1"]
    assert h["analyzers"] == ["clamav", "yara"] and h["alert_channels"] == ["telegram"]
    assert h["version"] and h["role"] == "all"


async def test_health_clamav_down_or_hanging(make_runtime):
    rt = await make_runtime(pipeline=StubPipeline(canned, analyzers=[FakeAnalyzer("clamav", ping_delay=5)]))
    t0 = time.monotonic()
    h = await rt.health()
    assert time.monotonic() - t0 < 3
    assert h["clamav"]["ok"] is False and "clamav" in h["degraded"] and h["status"] == "degraded"
    rt2 = await make_runtime(
        pipeline=StubPipeline(canned, analyzers=[FakeAnalyzer("clamav", ping_result=False)])
    )
    assert (await rt2.health())["clamav"]["ok"] is False
    rt3 = await make_runtime(pipeline=StubPipeline(canned, analyzers=[]))
    assert "clamav" not in await rt3.health()


async def test_health_db_down(make_runtime):
    rt = await make_runtime()

    async def broken_ping():
        raise OSError("db inalcanzable postgresql://centinela:supersecreta@db/c")

    rt.store.ping = broken_ping
    h = await rt.health()
    assert h["ok"] is False and h["status"] == "error"
    assert h["db"]["ok"] is False and "supersecreta" not in h["db"]["error"]


async def test_close_is_idempotent_and_closes_everything(make_runtime):
    rt = await make_runtime()
    await rt.close()
    await rt.close()
    assert rt.pipeline.closed and rt.connectors[0].closed and rt.channels[0].closed
    assert rt.http.is_closed


async def test_invalid_role(settings):
    with pytest.raises(ValueError):
        await Runtime.create(settings, role="todo", configure_logging=False)


async def test_api_role_does_not_setup_pipeline(make_runtime):
    bad_conn = FakeConnector("imap1", health=ConnectionError("no conectado"))
    rt = await make_runtime(role="api", connectors=[bad_conn])
    assert rt.pipeline.setup_called is False
    h = await rt.health()  # el proceso api no corre conectores: no los reporta como caídos
    assert h["connectors"]["imap1"]["ok"] is None and h["status"] == "ok"


async def test_alert_channels_import_failure_is_tolerated(make_runtime, settings, monkeypatch):
    from centinela.core.config import TelegramAlertConfig

    settings.actions.alerts.channels = [
        TelegramAlertConfig(type="telegram", name="tg", bot_token="123:abc", chat_id="1")
    ]
    broken = types.ModuleType("centinela.actions.alerts")  # sin build_channels
    monkeypatch.setitem(sys.modules, "centinela.actions.alerts", broken)
    rt = await make_runtime(channels=None)
    assert rt.channels == []

    def explode(settings, http):
        raise RuntimeError("config inválida")

    broken.build_channels = explode
    rt2 = await make_runtime(channels=None)
    assert rt2.channels == []

    sentinel = FakeChannel("desde-build")
    broken.build_channels = lambda settings, http: [sentinel]
    rt3 = await make_runtime(channels=None)
    assert rt3.channels == [sentinel]


async def test_connector_build_failure_is_isolated(make_runtime, settings, monkeypatch):
    from centinela import connectors as registry
    from centinela.core.config import DirectoryConnectorConfig

    settings.connectors = [
        DirectoryConnectorConfig(type="directory", name="dir-ok", path="/tmp/x"),  # noqa: S108
        DirectoryConnectorConfig(type="directory", name="dir-roto", path="/tmp/y"),  # noqa: S108
        DirectoryConnectorConfig(type="directory", name="dir-off", path="/tmp/z", enabled=False),  # noqa: S108
    ]

    class DirConn(FakeConnector):
        def __init__(self, cfg, settings, state):
            if cfg.name == "dir-roto":
                raise ValueError("ruta inválida")
            super().__init__(cfg.name)

    monkeypatch.setattr(registry, "connector_class", lambda type_: DirConn)
    rt = await make_runtime(connectors=None)
    assert [c.name for c in rt.connectors] == ["dir-ok"]


async def test_create_with_redis_uses_streams_and_worker(make_runtime, settings, monkeypatch):
    import redis.asyncio as real_aioredis

    server = fakeredis.FakeServer()
    clients = []

    def fake_from_url(url, **kw):
        c = fake_aioredis.FakeRedis(server=server, decode_responses=kw.get("decode_responses", False))
        clients.append(c)
        return c

    monkeypatch.setattr(real_aioredis.Redis, "from_url", staticmethod(fake_from_url))
    settings.redis_url = "redis://redis:6379/0"
    rt = await make_runtime()
    from centinela.storage.redis_queue import RedisStreamQueue

    assert isinstance(rt.queue, RedisStreamQueue) and isinstance(rt.cache, RedisCache)
    rt.queue.block_ms = 20
    assert await rt.emit_for(rt.connectors[0])(eml_raw("r1")) is None
    assert await rt.queue_depth() == 1
    stop = asyncio.Event()
    task = asyncio.create_task(rt.run_worker(stop))

    async def stored() -> bool:
        return (await rt.store.list_results(ResultFilter()))[1] == 1

    await wait_until(stored)
    stop.set()
    await asyncio.wait_for(task, 5)
    assert await rt.queue_depth() == 0  # ack + XDEL
    h = await rt.health()
    assert h["redis"] == {"ok": True, "enabled": True}
    assert h["queue"]["backend"] == "redis" and h["queue"]["dead_letters"] == 0
    # dedup de alertas compartido vía Redis
    assert await rt.cache.get(f"alert:telegram:malicious:sha256:{sha('eicar')}") is not None
