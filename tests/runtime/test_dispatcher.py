from __future__ import annotations

import logging

import pytest

from centinela import metrics
from centinela.actions.alerts import AlertDeliveryError, AlertRateLimitedError
from centinela.actions.dispatcher import ActionDispatcher, dedup_key
from centinela.core.cache import MemoryCache
from centinela.core.models import Severity, VerdictLevel
from tests.runtime.fakes import FakeChannel, FakeConnector
from tests.storage.factories import artifact, finding, make_result, malicious_result


def suspicious(remote_id: str = "s1", **kw):
    return make_result(
        remote_id,
        level=VerdictLevel.SUSPICIOUS,
        score=45,
        artifacts=[artifact("factura.docm", "docm-1", detected_type="ooxml")],
        findings=[finding("office.vba.macro", severity=Severity.MEDIUM, score=40)],
        **kw,
    )


def make_dispatcher(settings, connectors=None, channels=None, cache=None, **kw) -> ActionDispatcher:
    kw.setdefault("backoff_s", (0.0, 0.0))
    return ActionDispatcher(
        settings,
        cache or MemoryCache(),
        {c.name: c for c in (connectors or [])},
        channels or [],
        **kw,
    )


def counter(metric, **labels) -> float:
    return metric.labels(**labels)._value.get()


async def test_clean_and_error_results_do_nothing(settings):
    conn, ch = FakeConnector(), FakeChannel()
    d = make_dispatcher(settings, [conn], [ch])
    assert await d.dispatch(make_result("c", level=VerdictLevel.CLEAN)) == []
    assert await d.dispatch(make_result("e", level=VerdictLevel.ERROR)) == []
    assert conn.tag_calls == [] and ch.attempts == 0


async def test_suspicious_is_tagged_and_alerted(settings):
    conn, ch = FakeConnector(), FakeChannel("telegram")
    d = make_dispatcher(settings, [conn], [ch])
    before = counter(metrics.TAGS_APPLIED, connector="test", status="ok")
    actions = await d.dispatch(suspicious())
    assert actions == ["tag:test:keyword:Centinela/Sospechoso", "alert:telegram:ok"]
    assert len(conn.tag_calls) == 1 and conn.tag_calls[0][1] == VerdictLevel.SUSPICIOUS
    assert conn.tag_calls[0][2] is settings.actions.tag
    assert len(ch.sent) == 1
    assert counter(metrics.TAGS_APPLIED, connector="test", status="ok") == before + 1


async def test_malicious_uses_malicious_label(settings):
    conn = FakeConnector()
    d = make_dispatcher(settings, [conn])
    assert await d.dispatch(malicious_result("m")) == ["tag:test:keyword:Centinela/Malicioso"]


async def test_thresholds(settings):
    settings.actions.tag.min_level = "malicious"
    conn = FakeConnector()
    low, high = FakeChannel("todo", min_level="suspicious"), FakeChannel("graves", min_level="malicious")
    d = make_dispatcher(settings, [conn], [low, high])
    actions = await d.dispatch(suspicious())
    assert actions == ["alert:todo:ok"]  # sin tag (umbral malicious) ni alerta al canal de graves
    assert conn.tag_calls == [] and high.attempts == 0
    actions = await d.dispatch(malicious_result("m"))
    assert actions == ["tag:test:keyword:Centinela/Malicioso", "alert:todo:ok", "alert:graves:ok"]


async def test_tagging_disabled_globally_or_per_connector(settings):
    readonly = FakeConnector("journal", tag=False)
    d = make_dispatcher(settings, [readonly], [FakeChannel()])
    assert await d.dispatch(suspicious(connector="journal")) == ["alert:telegram:ok"]
    assert readonly.tag_calls == []
    settings.actions.tag.enabled = False
    conn = FakeConnector()
    d2 = make_dispatcher(settings, [conn])
    assert await d2.dispatch(malicious_result("m")) == []
    assert conn.tag_calls == []


async def test_unknown_connector_and_disabled_channel(settings):
    ch_off = FakeChannel("apagado", enabled=False)
    d = make_dispatcher(settings, [FakeConnector("otro")], [ch_off])
    assert await d.dispatch(suspicious()) == []  # ref.connector="test" no está cargado
    assert ch_off.attempts == 0


async def test_connector_exception_does_not_block_alerts(settings, caplog):
    conn, ch = FakeConnector(fail_tag=True), FakeChannel()
    d = make_dispatcher(settings, [conn], [ch])
    before = counter(metrics.TAGS_APPLIED, connector="test", status="error")
    skipped = counter(metrics.TAGS_APPLIED, connector="test", status="skipped")
    with caplog.at_level(logging.WARNING, logger="centinela.actions.dispatcher"):
        actions = await d.dispatch(malicious_result("m"))
    assert actions == ["tag:test:error", "alert:telegram:ok"]
    assert counter(metrics.TAGS_APPLIED, connector="test", status="error") == before + 1
    assert counter(metrics.TAGS_APPLIED, connector="test", status="skipped") == skipped
    # el log dice QUÉ pasó (el mensaje de la excepción), no solo el tipo
    assert "no se pudo conectar al servidor" in caplog.text


async def test_connector_returning_none_counts_as_skipped_not_error(settings):
    conn, ch = FakeConnector(skip_tag=True), FakeChannel()
    d = make_dispatcher(settings, [conn], [ch])
    err = counter(metrics.TAGS_APPLIED, connector="test", status="error")
    skipped = counter(metrics.TAGS_APPLIED, connector="test", status="skipped")
    assert await d.dispatch(malicious_result("m")) == ["alert:telegram:ok"]
    assert len(conn.tag_calls) == 1
    assert counter(metrics.TAGS_APPLIED, connector="test", status="skipped") == skipped + 1
    assert counter(metrics.TAGS_APPLIED, connector="test", status="error") == err


async def test_same_campaign_alerts_once_per_channel_but_tags_every_message(settings):
    conn = FakeConnector()
    tg, mail = FakeChannel("telegram"), FakeChannel("email")
    d = make_dispatcher(settings, [conn], [tg, mail])
    before = counter(metrics.ALERTS_SENT, channel="telegram", status="dedup")
    outs = []
    for i, mb in enumerate(["ventas@empresa.com", "compras@empresa.com", "rrhh@empresa.com"]):
        r = malicious_result(f"m{i}", mailbox=mb, message_id=f"<distinto-{i}@spam>", subject=f"Asunto {i}")
        outs.append(await d.dispatch(r))
    assert len(conn.tag_calls) == 3
    assert len(tg.sent) == 1 and len(mail.sent) == 1
    assert outs[0][1:] == ["alert:telegram:ok", "alert:email:ok"]
    assert outs[1][1:] == ["alert:telegram:dedup", "alert:email:dedup"]
    assert outs[2][1:] == ["alert:telegram:dedup", "alert:email:dedup"]
    assert counter(metrics.ALERTS_SENT, channel="telegram", status="dedup") == before + 2
    # otro malware distinto: alerta nueva
    other = await d.dispatch(malicious_result("m9", seed="otro-sample"))
    assert "alert:telegram:ok" in other


async def test_escalation_from_suspicious_to_malicious_alerts_again(settings):
    ch = FakeChannel()
    d = make_dispatcher(settings, [], [ch])
    r1 = make_result(
        "e1",
        level=VerdictLevel.SUSPICIOUS,
        score=40,
        artifacts=[artifact("a.exe", "same")],
        findings=[finding(severity=Severity.MEDIUM, score=40)],
    )
    r2 = make_result(
        "e2",
        level=VerdictLevel.MALICIOUS,
        score=99,
        artifacts=[artifact("a.exe", "same")],
        findings=[finding(severity=Severity.CRITICAL, score=99)],
    )
    assert await d.dispatch(r1) == ["alert:telegram:ok"]
    assert await d.dispatch(r2) == ["alert:telegram:ok"]
    assert len(ch.sent) == 2


async def test_dedup_by_message_id_without_flagged_artifacts(settings):
    ch = FakeChannel()
    d = make_dispatcher(settings, [], [ch])
    phish = dict(
        level=VerdictLevel.SUSPICIOUS, score=50, findings=[finding("url.ip_literal", artifact_id=None)]
    )
    assert await d.dispatch(make_result("p1", message_id="<camp@x>", mailbox="a@empresa.com", **phish)) == [
        "alert:telegram:ok"
    ]
    assert await d.dispatch(make_result("p2", message_id="<CAMP@x>", mailbox="b@empresa.com", **phish)) == [
        "alert:telegram:dedup"
    ]
    assert await d.dispatch(make_result("p3", message_id="<otro@x>", **phish)) == ["alert:telegram:ok"]
    # sin Message-ID: cada resultado es único
    assert await d.dispatch(make_result("p4", **phish)) == ["alert:telegram:ok"]
    assert await d.dispatch(make_result("p5", **phish)) == ["alert:telegram:ok"]


async def test_dedup_window_zero_disables_dedup(settings):
    settings.actions.alerts.dedup_window_minutes = 0
    ch = FakeChannel()
    d = make_dispatcher(settings, [], [ch])
    for i in range(3):
        assert await d.dispatch(malicious_result(f"m{i}")) == ["alert:telegram:ok"]
    assert len(ch.sent) == 3


def test_dedup_key_uses_only_flagged_artifacts():
    logo = artifact("logo.png", "logo", id="att1", detected_type="image/png")
    exe = artifact("f.exe", "exe", id="att0")
    r = make_result(
        "k",
        artifacts=[exe, logo],
        findings=[
            finding(artifact_id="att0"),
            finding("x.info", artifact_id="att1", severity=Severity.LOW, score=5),
        ],
    )
    r_other_logo = make_result(
        "k2",
        artifacts=[exe, artifact("logo2.png", "logo2", id="att1")],
        findings=[finding(artifact_id="att0")],
    )
    assert dedup_key(r) == dedup_key(r_other_logo) == f"sha256:{exe.sha256}"
    two = make_result(
        "k3",
        artifacts=[exe, artifact("g.js", "js", id="att2")],
        findings=[finding(artifact_id="att2"), finding(artifact_id="att0")],
    )
    two_rev = make_result(
        "k4",
        artifacts=[artifact("g.js", "js", id="att9"), exe],
        findings=[finding(artifact_id="att0"), finding(artifact_id="att9")],
    )
    assert dedup_key(two) == dedup_key(two_rev) and dedup_key(two).startswith("sha256set:")
    assert dedup_key(make_result("k5", message_id="<A@B>")) == "msgid:<a@b>"
    res = make_result("k6")
    assert dedup_key(res) == f"result:{res.id}"
    long_mid = make_result("k7", message_id="<" + "x" * 5000 + ">")
    assert len(dedup_key(long_mid)) < 100


async def test_retries_then_success(settings):
    ch = FakeChannel(fail_times=2)
    d = make_dispatcher(settings, [], [ch])
    assert await d.dispatch(malicious_result("m")) == ["alert:telegram:ok"]
    assert ch.attempts == 3 and len(ch.sent) == 1


async def test_retries_exhausted_reports_error_and_releases_dedup(settings):
    cache = MemoryCache()
    ch = FakeChannel(fail_times=100)
    ok_ch = FakeChannel("email")
    d = make_dispatcher(settings, [], [ch, ok_ch], cache=cache)
    before = counter(metrics.ALERTS_SENT, channel="telegram", status="error")
    r = malicious_result("m")
    assert await d.dispatch(r) == ["alert:telegram:error", "alert:email:ok"]
    assert ch.attempts == 3
    assert counter(metrics.ALERTS_SENT, channel="telegram", status="error") == before + 1
    key = f"alert:telegram:malicious:{dedup_key(r)}"
    assert await cache.get(key) == "failed"  # liberada (TTL corto) para que el próximo mail reintente
    assert await cache.get(f"alert:email:malicious:{dedup_key(r)}") == str(r.id)


async def test_rate_limited_channel_waits_retry_after_with_cap(settings):
    err = AlertRateLimitedError("Telegram: demasiados mensajes (429)", status=429, retry_after=30.0)
    ch = FakeChannel(fail_times=1, error=err)
    # backoff enorme: si se usara el backoff en lugar de retry_after (con tope) el test tardaría 5 s
    d = make_dispatcher(settings, [], [ch], backoff_s=(5.0,), max_retry_after_s=0.05)
    assert await d.dispatch(malicious_result("m")) == ["alert:telegram:ok"]
    assert ch.attempts == 2
    gap = ch.attempt_times[1] - ch.attempt_times[0]
    assert 0.04 <= gap < 2.0


def test_retry_delay_rules(settings):
    d = make_dispatcher(settings, backoff_s=(1.0, 4.0))
    assert d._retry_delay(AlertRateLimitedError("x", retry_after=3.0), 0) == 3.0
    assert d._retry_delay(AlertRateLimitedError("x", retry_after=120.0), 0) == 60.0  # tope 60 s
    assert d._retry_delay(AlertRateLimitedError("x", retry_after=float("inf")), 0) == 60.0
    assert d._retry_delay(AlertRateLimitedError("x", retry_after=float("nan")), 1) == 4.0
    assert d._retry_delay(AlertRateLimitedError("x", retry_after=None), 0) == 1.0
    assert d._retry_delay(AlertRateLimitedError("x", retry_after=-5), 0) == 1.0
    assert d._retry_delay(ConnectionError("x"), 0) == 1.0
    assert d._retry_delay(ConnectionError("x"), 7) == 4.0


async def test_non_retryable_error_is_not_retried(settings, caplog):
    cache = MemoryCache()
    err = AlertDeliveryError("Telegram respondió 401: Unauthorized", status=401, retryable=False)
    ch = FakeChannel(fail_times=100, error=err)
    d = make_dispatcher(settings, [], [ch], cache=cache)
    r = malicious_result("m")
    with caplog.at_level(logging.WARNING, logger="centinela.actions.dispatcher"):
        assert await d.dispatch(r) == ["alert:telegram:error"]
    assert ch.attempts == 1
    assert "Telegram respondió 401: Unauthorized" in caplog.text
    assert "no se reintenta" in caplog.text
    # igual se libera la dedup (cuando se arregle la config, el próximo mail vuelve a intentar)
    assert await cache.get(f"alert:telegram:malicious:{dedup_key(r)}") == "failed"


async def test_alert_failure_log_has_message_but_no_secrets(settings, caplog):
    ch = FakeChannel(fail_times=100, error=RuntimeError("fallo al enviar password=hunter2"))
    d = make_dispatcher(settings, [], [ch], retries=2)
    with caplog.at_level(logging.WARNING, logger="centinela.actions.dispatcher"):
        assert await d.dispatch(malicious_result("m")) == ["alert:telegram:error"]
    assert ch.attempts == 2
    assert "RuntimeError: fallo al enviar" in caplog.text
    assert "hunter2" not in caplog.text


async def test_hanging_channel_times_out(settings):
    ch = FakeChannel(hang=True)
    d = make_dispatcher(settings, [], [ch], send_timeout_s=0.05, retries=2)
    assert await d.dispatch(malicious_result("m")) == ["alert:telegram:error"]
    assert ch.attempts == 2


async def test_broken_cache_still_alerts(settings):
    class BrokenCache(MemoryCache):
        async def add(self, key, value, ttl_s):
            raise ConnectionError("redis caído")

    ch = FakeChannel()
    d = make_dispatcher(settings, [], [ch], cache=BrokenCache())
    assert await d.dispatch(malicious_result("m")) == ["alert:telegram:ok"]


async def test_close_closes_channels(settings):
    ch = FakeChannel()
    await make_dispatcher(settings, [], [ch]).close()
    assert ch.closed


@pytest.mark.parametrize("level", [VerdictLevel.CLEAN, VerdictLevel.ERROR])
async def test_never_tags_clean_or_error_even_with_findings(settings, level):
    conn = FakeConnector()
    r = make_result("x", level=level, artifacts=[artifact("a.exe", "a")], findings=[finding()])
    assert await make_dispatcher(settings, [conn], [FakeChannel()]).dispatch(r) == []
    assert conn.tag_calls == []
