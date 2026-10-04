from __future__ import annotations

import asyncio
import base64
import json
import logging
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from centinela.connectors import connector_class
from centinela.connectors.gmail import (
    GMAIL_API,
    PUBSUB_API,
    SCOPE_MODIFY,
    SCOPE_PUBSUB,
    SCOPE_READONLY,
    GmailAuthError,
    GmailConnector,
    oauth_mailboxes_key,
    refresh_token_key,
)
from centinela.core.config import GmailConnectorConfig, TagConfig
from centinela.core.models import MessageRef, VerdictLevel
from centinela.core.state import MemoryStateStore
from tests.connectors_cloud.conftest import Collector, make_result
from tests.helpers import build_eml, eicar

MB = "ventas@empresa.com"
GB = f"{GMAIL_API}/users/{MB}"
SUB = "projects/mi-proyecto/subscriptions/centinela-sub"
TOPIC = "projects/mi-proyecto/topics/centinela"


def make_conn(settings, *, state=None, **cfg_over) -> GmailConnector:
    data = {
        "type": "gmail",
        "name": "gw",
        "service_account_file": Path("sa.json"),
        "mailboxes": [MB],
        "poll_interval_s": 1,
    }
    data.update(cfg_over)
    conn = GmailConnector(GmailConnectorConfig(**data), settings, state or MemoryStateStore())
    conn.token_calls = []

    async def fake_token(key: str, force: bool = False) -> str:
        conn.token_calls.append((key, force))
        return f"tok-{len(conn.token_calls)}"

    conn._access_token = fake_token  # sin google-auth ni red
    conn.start_jitter_s = 0
    conn.min_poll_s = 0.01
    conn.stop_grace_s = 1.0
    return conn


def raw_msg(eml: bytes, internal_ms: int = 1_759_500_000_000) -> dict:
    return {"raw": base64.urlsafe_b64encode(eml).decode().rstrip("="), "internalDate": str(internal_ms)}


def mock_message(
    router, mid: str, eml: bytes, *, labels=("INBOX", "UNREAD"), size=None, internal_ms=1_759_500_000_000
):
    meta = router.get(f"{GB}/messages/{mid}", params__contains={"format": "minimal"}).respond(
        200,
        json={
            "id": mid,
            "labelIds": list(labels),
            "sizeEstimate": size if size is not None else len(eml),
            "internalDate": str(internal_ms),
        },
    )
    raw = router.get(f"{GB}/messages/{mid}", params__contains={"format": "raw"}).respond(
        200, json=raw_msg(eml, internal_ms)
    )
    return meta, raw


def history_page(entries, *, next_token=None, history_id="1050"):
    body = {"historyId": history_id, "history": entries}
    if next_token:
        body["nextPageToken"] = next_token
    return body


def added(record_id: int, mid: str, labels):
    return {
        "id": str(record_id),
        "messagesAdded": [{"message": {"id": mid, "threadId": "t", "labelIds": list(labels)}}],
    }


async def test_registered_in_connector_registry():
    assert connector_class("gmail") is GmailConnector


async def test_first_run_initializes_cursor_without_emitting(settings, router, collector):
    conn = make_conn(settings)
    router.get(f"{GB}/profile").respond(
        200, json={"emailAddress": MB, "historyId": "1000", "messagesTotal": 12}
    )
    listing = router.get(f"{GB}/messages")
    await conn.sync_mailbox(MB, collector, asyncio.Event())
    assert collector.items == []
    assert not listing.called  # sin backfill no se lista nada
    assert await conn.get_cursor(f"gmail:{MB}:history_id") == "1000"
    assert await conn.get_cursor(f"gmail:{MB}:last_sync") is not None


async def test_first_run_backfill_emits_recent_mail(settings, router, collector):
    conn = make_conn(settings, backfill_hours=6)
    router.get(f"{GB}/profile").respond(200, json={"emailAddress": MB, "historyId": "1000"})
    listing = router.get(f"{GB}/messages").respond(200, json={"messages": [{"id": "m2"}, {"id": "m1"}]})
    eml1 = build_eml(subject="Factura 1", attachments=[("f.txt", eicar(), "text/plain")])
    eml2 = build_eml(subject="Factura 2")
    mock_message(router, "m1", eml1, labels=["INBOX"])
    mock_message(router, "m2", eml2, labels=["SPAM"])
    before = int((datetime.now(UTC) - timedelta(hours=6)).timestamp())
    await conn.sync_mailbox(MB, collector, asyncio.Event())

    q = listing.calls.last.request.url.params["q"]
    assert q.startswith("(in:inbox OR in:spam) after:")
    assert abs(int(q.rsplit(":", 1)[1]) - before) < 60
    assert listing.calls.last.request.url.params["includeSpamTrash"] == "true"
    assert collector.ids == ["m1", "m2"]  # más viejo primero
    first = collector.items[0]
    assert first.raw == eml1
    assert first.ref == MessageRef(connector="gw", mailbox=MB, remote_id="m1", folder="INBOX")
    assert collector.items[1].ref.folder == "SPAM"
    assert first.received_at == datetime.fromtimestamp(1_759_500_000, tz=UTC)
    assert await conn.get_cursor(f"gmail:{MB}:history_id") == "1000"


async def test_history_new_messages_paginated_with_label_filtering(settings, router, collector):
    conn = make_conn(settings)
    await conn.set_cursor(f"gmail:{MB}:history_id", "1000")
    history = router.get(f"{GB}/history").mock(
        side_effect=[
            httpx.Response(
                200,
                json=history_page(
                    [
                        added(1001, "m1", ["INBOX", "UNREAD"]),
                        added(1002, "s1", ["SENT"]),  # saliente: nunca
                        added(1003, "d1", ["DRAFT"]),
                        added(
                            1004, "p1", ["CATEGORY_PROMOTIONS"]
                        ),  # archivado por filtro: fuera de INBOX/SPAM
                        {"id": "1005", "labelsAdded": [{"message": {"id": "x"}}]},
                        "basura",
                        {
                            "id": "1006",
                            "messagesAdded": [{"message": {"id": "../../etc"}}, {"message": None}],
                        },
                    ],
                    next_token="pg2",
                ),
            ),
            httpx.Response(
                200,
                json=history_page(
                    [added(1010, "m4", ["SPAM"]), added(1011, "m1", ["INBOX"])], history_id="1050"
                ),
            ),
        ]
    )
    mock_message(router, "m1", build_eml(subject="uno"), labels=["INBOX", "UNREAD"])
    mock_message(router, "m4", build_eml(subject="spam"), labels=["SPAM"])
    await conn.sync_mailbox(MB, collector, asyncio.Event())

    assert collector.ids == ["m1", "m4"]
    assert [r.ref.folder for r in collector.items] == ["INBOX", "SPAM"]
    p1, p2 = (c.request.url.params for c in history.calls)
    assert p1["startHistoryId"] == "1000" and p1["historyTypes"] == "messageAdded"
    assert p2["pageToken"] == "pg2" and p2["startHistoryId"] == "1000"  # mismo start que el pageToken
    assert await conn.get_cursor(f"gmail:{MB}:history_id") == "1050"


async def test_history_404_resyncs_with_bounded_catchup(settings, router, collector, caplog):
    conn = make_conn(settings)
    await conn.set_cursor(f"gmail:{MB}:history_id", "10")
    router.get(f"{GB}/history").respond(
        404, json={"error": {"code": 404, "message": "Requested entity was not found."}}
    )
    router.get(f"{GB}/profile").respond(200, json={"emailAddress": MB, "historyId": "2000"})
    listing = router.get(f"{GB}/messages").respond(200, json={"messages": [{"id": "m9"}]})
    mock_message(router, "m9", build_eml(subject="perdido"))
    with caplog.at_level(logging.WARNING):
        await conn.sync_mailbox(MB, collector, asyncio.Event())
    assert "expiró" in caplog.text
    assert collector.ids == ["m9"]
    after = int(listing.calls.last.request.url.params["q"].rsplit(":", 1)[1])
    two_days_ago = int((datetime.now(UTC) - timedelta(days=2)).timestamp())
    assert abs(after - two_days_ago) < 60  # sin last_sync: ventana máxima de 2 días
    assert await conn.get_cursor(f"gmail:{MB}:history_id") == "2000"


async def test_resync_uses_last_sync_when_recent(settings, router, collector):
    conn = make_conn(settings)
    await conn.set_cursor(f"gmail:{MB}:history_id", "10")
    last = int(time.time()) - 3 * 3600
    await conn.set_cursor(f"gmail:{MB}:last_sync", str(last))
    router.get(f"{GB}/history").respond(404)
    router.get(f"{GB}/profile").respond(200, json={"historyId": "2000"})
    listing = router.get(f"{GB}/messages").respond(200, json={})
    await conn.sync_mailbox(MB, collector, asyncio.Event())
    after = int(listing.calls.last.request.url.params["q"].rsplit(":", 1)[1])
    assert abs(after - (last - 3600)) < 5


async def test_catchup_is_bounded(settings, router, collector):
    conn = make_conn(settings, backfill_hours=1)
    conn.max_catchup_messages = 3
    router.get(f"{GB}/profile").respond(200, json={"historyId": "5"})
    router.get(f"{GB}/messages").respond(
        200, json={"messages": [{"id": f"m{i}"} for i in range(10)], "nextPageToken": "otra"}
    )
    for i in range(10):
        mock_message(router, f"m{i}", build_eml(subject=str(i)))
    await conn.sync_mailbox(MB, collector, asyncio.Event())
    assert len(collector.items) == 3


BIG_HEADERS = [
    {
        "name": "Received",
        "value": "from mx.proveedor.com (mx.proveedor.com [203.0.113.7])\r\n\tby mx.google.com",
    },
    {"name": "Authentication-Results", "value": "mx.google.com; spf=fail smtp.mailfrom=proveedor.com"},
    {"name": "From", "value": "Juan Pérez <juan@proveedor.com>"},
    {"name": "To", "value": MB},
    {"name": "Subject", "value": "Factura adjunta\r\nBcc: inyectado@evil.example"},  # intento de inyección
    {"name": "Message-ID", "value": "<grande-1@proveedor.com>"},
    {"name": "Bad Name:", "value": "x"},
    {"name": 5, "value": "no es texto"},
    "basura",
]


def mock_metadata(router, mid: str, *, headers=BIG_HEADERS, size=5_000_123, internal_ms=1_759_500_000_000):
    return router.get(f"{GB}/messages/{mid}", params__contains={"format": "metadata"}).respond(
        200,
        json={"sizeEstimate": size, "internalDate": str(internal_ms), "payload": {"headers": headers}},
    )


async def test_oversized_message_emits_headers_only_from_metadata(settings, router, collector):
    settings.limits.max_message_bytes = 1000
    conn = make_conn(settings)
    await conn.set_cursor(f"gmail:{MB}:history_id", "1000")
    router.get(f"{GB}/history").respond(
        200, json=history_page([added(1001, "big", ["INBOX"])], history_id="1001")
    )
    _meta, raw = mock_message(router, "big", b"x", size=5_000_000)
    metadata = mock_metadata(router, "big")
    await conn.sync_mailbox(MB, collector, asyncio.Event())

    assert not raw.called  # format=raw solo si entra en el límite
    params = metadata.calls.last.request.url.params
    assert params["format"] == "metadata" and "payload/headers" in params["fields"]
    (item,) = collector.items  # NO se omite: mandar un mail enorme sería una evasión trivial
    assert item.truncated is True and item.original_size == 5_000_123
    assert item.ref == MessageRef(connector="gw", mailbox=MB, remote_id="big", folder="INBOX")
    assert item.received_at == datetime.fromtimestamp(1_759_500_000, tz=UTC)
    assert item.raw.startswith(b"Received: from mx.proveedor.com") and item.raw.endswith(b"\r\n\r\n")
    assert "From: Juan Pérez <juan@proveedor.com>\r\n".encode() in item.raw
    assert b"Subject: Factura adjunta Bcc: inyectado@evil.example\r\n" in item.raw
    assert b"\r\nBcc:" not in item.raw  # el salto de línea del valor no crea un header nuevo
    assert b"BadName: x\r\n" in item.raw and b"no es texto" not in item.raw
    assert conn.truncated_too_large == 1
    assert (await conn.healthcheck())["truncated_too_large"] == 1
    assert await conn.get_cursor(f"gmail:{MB}:history_id") == "1001"

    # el parser ve remitente, asunto y autenticación: el análisis de headers sigue funcionando
    from centinela.parsing.mime import parse_message

    pm = parse_message(item, settings.limits)
    assert pm.from_addr == "juan@proveedor.com" and pm.subject.startswith("Factura adjunta")
    assert pm.header("Authentication-Results").endswith("spf=fail smtp.mailfrom=proveedor.com")
    assert pm.artifacts == []


async def test_lying_size_estimate_is_truncated_after_download(settings, router, collector):
    settings.limits.max_message_bytes = 2000
    conn = make_conn(settings)
    await conn.set_cursor(f"gmail:{MB}:history_id", "1000")
    router.get(f"{GB}/history").respond(
        200, json=history_page([added(1001, "liar", ["INBOX"])], history_id="1001")
    )
    eml = build_eml(subject="Mentiroso", text="A" * 30_000)  # > límite, pero dentro del tope de descarga
    mock_message(router, "liar", eml, size=10)  # sizeEstimate miente
    metadata = mock_metadata(router, "liar")
    await conn.sync_mailbox(MB, collector, asyncio.Event())
    (item,) = collector.items
    assert item.truncated is True and item.original_size == len(eml)
    assert b"Subject: Mentiroso" in item.raw and b"AAAA" not in item.raw  # headers del raw ya bajado
    assert not metadata.called  # sin request extra
    assert conn.truncated_too_large == 1


async def test_raw_download_over_hard_cap_falls_back_to_metadata(settings, router, collector):
    settings.limits.max_message_bytes = 1000
    conn = make_conn(settings)
    await conn.set_cursor(f"gmail:{MB}:history_id", "1000")
    router.get(f"{GB}/history").respond(
        200, json=history_page([added(1001, "huge", ["SPAM"])], history_id="1001")
    )
    mock_message(router, "huge", b"A" * 200_000, labels=["SPAM"], size=10)  # base64 > tope de descarga
    metadata = mock_metadata(router, "huge", size=200_000)
    await conn.sync_mailbox(MB, collector, asyncio.Event())
    assert metadata.called
    (item,) = collector.items
    assert item.truncated is True and item.original_size == 200_000 and item.ref.folder == "SPAM"
    assert b"Message-ID: <grande-1@proveedor.com>\r\n" in item.raw


async def test_oversized_message_without_headers_uses_lower_bound(settings, router, collector):
    settings.limits.max_message_bytes = 1000
    conn = make_conn(settings)
    await conn.set_cursor(f"gmail:{MB}:history_id", "1000")
    router.get(f"{GB}/history").respond(
        200, json=history_page([added(1001, "big", ["INBOX"])], history_id="1001")
    )
    mock_message(router, "big", b"x", size=5000)
    router.get(f"{GB}/messages/big", params__contains={"format": "metadata"}).respond(200, json={})
    await conn.sync_mailbox(MB, collector, asyncio.Event())
    (item,) = collector.items
    assert item.raw == b"\r\n" and item.truncated is True and item.original_size == 5000


async def test_oversized_message_deleted_before_metadata(settings, router, collector):
    settings.limits.max_message_bytes = 1000
    conn = make_conn(settings)
    await conn.set_cursor(f"gmail:{MB}:history_id", "1000")
    router.get(f"{GB}/history").respond(
        200, json=history_page([added(1001, "big", ["INBOX"])], history_id="1001")
    )
    mock_message(router, "big", b"x", size=5_000_000)
    router.get(f"{GB}/messages/big", params__contains={"format": "metadata"}).respond(404)
    await conn.sync_mailbox(MB, collector, asyncio.Event())
    assert collector.items == [] and conn.truncated_too_large == 0
    assert await conn.get_cursor(f"gmail:{MB}:history_id") == "1001"


async def test_oversized_metadata_error_does_not_advance_cursor(settings, router, collector, sleeps):
    settings.limits.max_message_bytes = 1000
    conn = make_conn(settings)
    await conn.set_cursor(f"gmail:{MB}:history_id", "1000")
    router.get(f"{GB}/history").respond(
        200, json=history_page([added(1001, "big", ["INBOX"])], history_id="1001")
    )
    mock_message(router, "big", b"x", size=5_000_000)
    router.get(f"{GB}/messages/big", params__contains={"format": "metadata"}).respond(500)
    with pytest.raises(Exception):  # noqa: B017 - HttpError: el loop hace backoff y reintenta
        await conn.sync_mailbox(MB, collector, asyncio.Event())
    assert collector.items == []
    assert await conn.get_cursor(f"gmail:{MB}:history_id") == "1000"  # al-menos-una-vez


async def test_rate_limits_and_retry_after(settings, router, collector, sleeps):
    conn = make_conn(settings)
    await conn.set_cursor(f"gmail:{MB}:history_id", "1000")
    router.get(f"{GB}/history").mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "7"}),
            httpx.Response(
                403, json={"error": {"code": 403, "errors": [{"reason": "userRateLimitExceeded"}]}}
            ),
            httpx.Response(200, json=history_page([], history_id="1001")),
        ]
    )
    await conn.sync_mailbox(MB, collector, asyncio.Event())
    assert sleeps[0] == 7.0 and len(sleeps) == 2
    assert await conn.get_cursor(f"gmail:{MB}:history_id") == "1001"


async def test_401_triggers_forced_token_refresh(settings, router, collector):
    conn = make_conn(settings)
    router.get(f"{GB}/profile").mock(
        side_effect=[httpx.Response(401), httpx.Response(200, json={"historyId": "7"})]
    )
    await conn.sync_mailbox(MB, collector, asyncio.Event())
    assert (MB, True) in conn.token_calls
    assert await conn.get_cursor(f"gmail:{MB}:history_id") == "7"


async def test_emit_failure_does_not_advance_cursor(settings, router):
    conn = make_conn(settings)
    await conn.set_cursor(f"gmail:{MB}:history_id", "1000")
    router.get(f"{GB}/history").respond(
        200, json=history_page([added(1001, "m1", ["INBOX"])], history_id="1001")
    )
    mock_message(router, "m1", build_eml())
    with pytest.raises(RuntimeError):
        await conn.sync_mailbox(MB, Collector(fail_on={"m1"}), asyncio.Event())
    assert await conn.get_cursor(f"gmail:{MB}:history_id") == "1000"  # al-menos-una-vez


async def test_deleted_message_and_hostile_payloads_are_skipped(settings, router, collector):
    conn = make_conn(settings)
    await conn.set_cursor(f"gmail:{MB}:history_id", "1000")
    router.get(f"{GB}/history").respond(
        200,
        json=history_page(
            [
                added(1001, "gone", ["INBOX"]),
                added(1002, "badb64", ["INBOX"]),
                added(1003, "noraw", ["INBOX"]),
            ],
            history_id="1003",
        ),
    )
    router.get(f"{GB}/messages/gone").respond(404)
    router.get(f"{GB}/messages/badb64", params__contains={"format": "minimal"}).respond(
        200, json={"labelIds": ["INBOX"], "sizeEstimate": 10}
    )
    router.get(f"{GB}/messages/badb64", params__contains={"format": "raw"}).respond(
        200, json={"raw": "abcde"}
    )  # padding imposible
    router.get(f"{GB}/messages/noraw", params__contains={"format": "minimal"}).respond(
        200, json={"labelIds": ["INBOX"]}
    )
    router.get(f"{GB}/messages/noraw", params__contains={"format": "raw"}).respond(200, json={"raw": 123})
    await conn.sync_mailbox(MB, collector, asyncio.Event())
    assert collector.items == []
    assert await conn.get_cursor(f"gmail:{MB}:history_id") == "1003"


async def test_history_non_json_raises(settings, router, collector):
    conn = make_conn(settings)
    await conn.set_cursor(f"gmail:{MB}:history_id", "1000")
    router.get(f"{GB}/history").respond(200, content=b"<html>proxy</html>")
    with pytest.raises(Exception):  # noqa: B017 - HttpError: el loop hace backoff
        await conn.sync_mailbox(MB, collector, asyncio.Event())
    assert await conn.get_cursor(f"gmail:{MB}:history_id") == "1000"


async def test_message_labels_now_spam_overrides_folder(settings, router, collector):
    conn = make_conn(settings)
    await conn.set_cursor(f"gmail:{MB}:history_id", "1000")
    router.get(f"{GB}/history").respond(
        200, json=history_page([added(1001, "m1", ["INBOX"])], history_id="1001")
    )
    mock_message(router, "m1", build_eml(), labels=["SPAM"])  # Gmail lo movió a spam después
    await conn.sync_mailbox(MB, collector, asyncio.Event())
    assert collector.items[0].ref.folder == "SPAM"


def test_watched_labels_from_label_query(settings):
    assert make_conn(settings).watched_labels() == {"INBOX", "SPAM"}
    assert make_conn(settings, label_query="in:inbox").watched_labels() == {"INBOX"}
    assert make_conn(settings, label_query="label:facturas").watched_labels() == {"INBOX", "SPAM"}


# ----------------------------------------------------------------------------- etiquetado


async def test_apply_verdict_creates_label_and_parent_then_caches(settings, router):
    conn = make_conn(settings)
    labels = router.get(f"{GB}/labels").respond(
        200, json={"labels": [{"id": "INBOX", "name": "INBOX", "type": "system"}]}
    )
    created: list[dict] = []

    def create(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        created.append(body)
        return httpx.Response(200, json={"id": f"Label_{len(created)}", "name": body["name"]})

    router.post(f"{GB}/labels").mock(side_effect=create)
    modify = router.post(f"{GB}/messages/m1/modify").respond(200, json={"id": "m1"})
    ref = MessageRef(connector="gw", mailbox=MB, remote_id="m1", folder="INBOX")
    out = await conn.apply_verdict(ref, make_result(ref, VerdictLevel.MALICIOUS), TagConfig())
    assert out == "gmail:label:Centinela/Malicioso"
    assert [c["name"] for c in created] == ["Centinela", "Centinela/Malicioso"]
    assert created[1]["color"]["backgroundColor"] == "#cc3a21"
    body = json.loads(modify.calls.last.request.content)
    assert body == {"addLabelIds": ["Label_2"]}  # nunca removeLabelIds

    ref2 = MessageRef(connector="gw", mailbox=MB, remote_id="m2")
    router.post(f"{GB}/messages/m2/modify").respond(200, json={})
    assert (
        await conn.apply_verdict(ref2, make_result(ref2, VerdictLevel.MALICIOUS), TagConfig())
        == "gmail:label:Centinela/Malicioso"
    )
    assert labels.call_count == 1  # cacheado


async def test_apply_verdict_reuses_existing_label_case_insensitive(settings, router):
    conn = make_conn(settings)
    router.get(f"{GB}/labels").respond(
        200, json={"labels": [{"id": "Label_9", "name": "centinela/sospechoso"}]}
    )
    create = router.post(f"{GB}/labels")
    modify = router.post(f"{GB}/messages/m1/modify").respond(200, json={})
    ref = MessageRef(connector="gw", mailbox=MB, remote_id="m1")
    out = await conn.apply_verdict(ref, make_result(ref, VerdictLevel.SUSPICIOUS), TagConfig())
    assert out == "gmail:label:Centinela/Sospechoso"
    assert not create.called
    assert json.loads(modify.calls.last.request.content) == {"addLabelIds": ["Label_9"]}


async def test_apply_verdict_create_conflict_relists(settings, router):
    conn = make_conn(settings)
    router.get(f"{GB}/labels").mock(
        side_effect=[
            httpx.Response(200, json={"labels": [{"id": "Label_P", "name": "Centinela"}]}),
            httpx.Response(200, json={"labels": [{"id": "Label_R", "name": "Centinela/Malicioso"}]}),
        ]
    )
    router.post(f"{GB}/labels").respond(
        409, json={"error": {"code": 409, "message": "Label name exists or conflicts"}}
    )
    modify = router.post(f"{GB}/messages/m1/modify").respond(200, json={})
    ref = MessageRef(connector="gw", mailbox=MB, remote_id="m1")
    assert await conn.apply_verdict(ref, make_result(ref, VerdictLevel.MALICIOUS), TagConfig())
    assert json.loads(modify.calls.last.request.content) == {"addLabelIds": ["Label_R"]}


async def test_apply_verdict_noop_cases(settings, router):
    ref = MessageRef(connector="gw", mailbox=MB, remote_id="m1")
    conn = make_conn(settings)
    assert await conn.apply_verdict(ref, make_result(ref, VerdictLevel.CLEAN), TagConfig()) is None
    assert await conn.apply_verdict(ref, make_result(ref, VerdictLevel.ERROR), TagConfig()) is None
    assert (
        await conn.apply_verdict(
            ref, make_result(ref, VerdictLevel.SUSPICIOUS), TagConfig(min_level="malicious")
        )
        is None
    )
    assert (
        await conn.apply_verdict(ref, make_result(ref, VerdictLevel.MALICIOUS), TagConfig(enabled=False))
        is None
    )
    other = MessageRef(connector="otro", mailbox=MB, remote_id="m1")
    assert await conn.apply_verdict(other, make_result(other, VerdictLevel.MALICIOUS), TagConfig()) is None
    readonly = make_conn(settings, tag=False)
    assert await readonly.apply_verdict(ref, make_result(ref, VerdictLevel.MALICIOUS), TagConfig()) is None
    hostile = MessageRef(connector="gw", mailbox=MB, remote_id="../labels")
    assert (
        await conn.apply_verdict(hostile, make_result(hostile, VerdictLevel.MALICIOUS), TagConfig()) is None
    )
    assert not router.calls  # ningún request


async def test_apply_verdict_message_gone_returns_none(settings, router):
    conn = make_conn(settings)
    router.get(f"{GB}/labels").respond(200, json={"labels": [{"id": "L", "name": "Centinela/Malicioso"}]})
    router.post(f"{GB}/messages/m1/modify").respond(404)
    ref = MessageRef(connector="gw", mailbox=MB, remote_id="m1")
    assert await conn.apply_verdict(ref, make_result(ref, VerdictLevel.MALICIOUS), TagConfig()) is None


# ----------------------------------------------------------------------------- Pub/Sub


def notification(email: str, history_id: int) -> str:
    return base64.b64encode(json.dumps({"emailAddress": email, "historyId": history_id}).encode()).decode()


async def test_watch_request_and_renewal(settings, router):
    conn = make_conn(settings, pubsub_topic=TOPIC, pubsub_subscription=SUB)
    exp = int((time.time() + 7 * 86400) * 1000)
    watch = router.post(f"{GB}/watch").respond(200, json={"historyId": "1", "expiration": str(exp)})
    await conn.ensure_watch(MB)
    await conn.ensure_watch(MB)  # dentro de las 24 h: no se repite
    assert watch.call_count == 1
    assert json.loads(watch.calls.last.request.content) == {
        "topicName": TOPIC,
        "labelIds": ["INBOX", "SPAM"],
        "labelFilterBehavior": "include",
    }
    conn._status[MB].watch_next_at = 1.0  # vencido
    await conn.ensure_watch(MB)
    assert watch.call_count == 2


async def test_watch_failure_falls_back_to_polling(settings, router):
    conn = make_conn(settings, pubsub_topic=TOPIC, pubsub_subscription=SUB, poll_interval_s=20)
    router.post(f"{GB}/watch").respond(
        403, json={"error": {"code": 403, "message": "User not authorized to perform this action."}}
    )
    await conn.ensure_watch(MB)
    assert conn._status[MB].watching is False
    conn._pubsub_ok = True
    assert conn._idle_timeout(MB) == 20


async def test_pubsub_pull_wakes_mailbox_and_acks(settings, router):
    conn = make_conn(settings, pubsub_topic=TOPIC, pubsub_subscription=SUB)
    conn._wake = {MB: asyncio.Event(), "otro@empresa.com": asyncio.Event()}
    router.post(f"{PUBSUB_API}/{SUB}:pull").respond(
        200,
        json={
            "receivedMessages": [
                {
                    "ackId": "a1",
                    "message": {"data": notification("VENTAS@empresa.com", 99), "messageId": "1"},
                },
                {"ackId": "a2", "message": {"data": "@@@no-base64@@@"}},
                "basura",
            ]
        },
    )
    ack = router.post(f"{PUBSUB_API}/{SUB}:acknowledge").respond(200, json={})
    n = await conn.pubsub_pull_once()
    assert n == 3
    assert json.loads(ack.calls.last.request.content) == {"ackIds": ["a1", "a2"]}
    assert conn._wake[MB].is_set()
    assert conn._wake["otro@empresa.com"].is_set()  # la notificación ilegible despierta a todos (barato)
    assert ("__pubsub__", False) in conn.token_calls


async def test_pubsub_empty_pull(settings, router):
    conn = make_conn(settings, pubsub_topic=TOPIC, pubsub_subscription=SUB)
    router.post(f"{PUBSUB_API}/{SUB}:pull").respond(200, json={})
    ack = router.post(f"{PUBSUB_API}/{SUB}:acknowledge")
    assert await conn.pubsub_pull_once() == 0 and not ack.called


def test_handle_notification_targets_one_mailbox(settings):
    conn = make_conn(settings)
    conn._wake = {MB: asyncio.Event(), "otro@empresa.com": asyncio.Event()}
    assert conn.handle_notification(notification(MB, 5)) == MB
    assert conn._wake[MB].is_set() and not conn._wake["otro@empresa.com"].is_set()
    # url-safe base64 sin padding también se acepta
    conn._wake[MB].clear()
    data = base64.urlsafe_b64encode(json.dumps({"emailAddress": MB}).encode()).decode().rstrip("=")
    assert conn.handle_notification(data) == MB
    assert conn.handle_notification("x" * 100_000) is None  # demasiado grande: ignorado


# ----------------------------------------------------------------------------- run() / stop


async def test_run_end_to_end_and_stop_is_responsive(settings, router):
    conn = make_conn(settings, backfill_hours=1, poll_interval_s=3600)
    router.get(f"{GB}/profile").respond(200, json={"historyId": "1000"})
    router.get(f"{GB}/messages").respond(200, json={"messages": [{"id": "m1"}]})
    mock_message(router, "m1", build_eml(subject="hola"))
    stop = asyncio.Event()
    got = asyncio.Event()
    items = []

    async def emit(raw):
        items.append(raw)
        got.set()

    task = asyncio.create_task(conn.run(emit, stop))
    await asyncio.wait_for(got.wait(), 5)
    await asyncio.sleep(0.05)
    assert (await conn.healthcheck())["mailboxes"][MB]["ok"] is True
    t0 = time.monotonic()
    stop.set()
    await asyncio.wait_for(task, 3)
    assert time.monotonic() - t0 < 2  # no espera los 3600 s del polling
    assert [r.ref.remote_id for r in items] == ["m1"]
    assert await conn.get_cursor(f"gmail:{MB}:history_id") == "1000"
    await conn.close()


async def test_run_errors_back_off_and_stop_still_responsive(settings, router, sleeps):
    conn = make_conn(settings)
    router.get(f"{GB}/profile").respond(500)
    stop = asyncio.Event()
    task = asyncio.create_task(conn.run(Collector(), stop))
    for _ in range(100):
        await asyncio.sleep(0.02)
        if conn._status.get(MB) and conn._status[MB].error:
            break
    health = await conn.healthcheck()
    assert health["ok"] is False and "500" in health["mailboxes"][MB]["error"]
    stop.set()
    await asyncio.wait_for(task, 3)


async def test_run_cancellation_cancels_children(settings, router):
    conn = make_conn(settings, poll_interval_s=3600)
    router.get(f"{GB}/profile").respond(200, json={"historyId": "1"})
    task = asyncio.create_task(conn.run(Collector(), asyncio.Event()))
    await asyncio.sleep(0.1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 2)


async def test_run_requires_mailboxes(settings):
    conn = make_conn(
        settings, auth="oauth_user", oauth_client_file=Path("c.json"), mailboxes=[], service_account_file=None
    )
    with pytest.raises(ValueError, match="no hay buzones"):
        await conn.run(Collector(), asyncio.Event())


@pytest.mark.parametrize(
    "over, msg",
    [
        ({"mailboxes": []}, "mailboxes"),
        ({"service_account_file": None}, "service_account_file"),
        ({"pubsub_topic": TOPIC}, "van juntos"),
        ({"pubsub_topic": "mal", "pubsub_subscription": SUB}, "pubsub_topic"),
        ({"pubsub_topic": TOPIC, "pubsub_subscription": "projects/x/subs/y"}, "pubsub_subscription"),
    ],
)
def test_validate_config_errors(settings, over, msg):
    with pytest.raises(ValueError, match=msg):
        make_conn(settings, **over).validate()


# ----------------------------------------------------------------------------- credenciales


class FakeSACreds:
    def __init__(self, file, scopes):
        self.file, self.scopes, self.subject = file, scopes, None

    def with_subject(self, subject):
        self.subject = subject
        return self


async def test_service_account_credentials_scopes(settings, monkeypatch):
    from google.oauth2 import service_account

    monkeypatch.setattr(
        service_account.Credentials,
        "from_service_account_file",
        classmethod(lambda cls, f, scopes: FakeSACreds(f, scopes)),
    )
    conn = GmailConnector(
        GmailConnectorConfig(type="gmail", name="gw", service_account_file=Path("sa.json"), mailboxes=[MB]),
        settings,
        MemoryStateStore(),
    )
    creds = conn.build_credentials(MB)
    assert creds.subject == MB and creds.scopes == [SCOPE_MODIFY]
    ro = GmailConnector(
        GmailConnectorConfig(
            type="gmail", name="gw", service_account_file=Path("sa.json"), mailboxes=[MB], tag=False
        ),
        settings,
        MemoryStateStore(),
    )
    assert ro.build_credentials(MB).scopes == [SCOPE_READONLY]
    settings.actions.tag.enabled = False  # etiquetado global apagado => solo lectura
    assert conn.build_credentials(MB).scopes == [SCOPE_READONLY]
    ps = conn.build_credentials("__pubsub__")
    assert ps.scopes == [SCOPE_PUBSUB] and ps.subject is None


async def test_oauth_user_credentials_from_state(settings, tmp_path):
    client_file = tmp_path / "client.json"
    client_file.write_text(
        json.dumps({"installed": {"client_id": "cid", "client_secret": "csec"}}), encoding="utf-8"
    )
    state = MemoryStateStore()
    cfg = GmailConnectorConfig(
        type="gmail", name="personal", auth="oauth_user", oauth_client_file=client_file
    )
    conn = GmailConnector(cfg, settings, state)
    with pytest.raises(GmailAuthError, match="centinela auth gmail personal"):
        await conn._make_credentials("yo@gmail.com")
    await state.set_secret(refresh_token_key("personal", "yo@gmail.com"), "1//refresh")
    await state.set(oauth_mailboxes_key("personal"), json.dumps(["yo@gmail.com", "YO@gmail.com", 5]))
    assert await conn.resolve_mailboxes() == ["yo@gmail.com"]
    creds = await conn._make_credentials("yo@gmail.com")
    assert creds.refresh_token == "1//refresh" and creds.client_id == "cid" and creds.client_secret == "csec"


async def test_refresh_error_becomes_spanish_hint(settings, monkeypatch):
    conn = GmailConnector(
        GmailConnectorConfig(type="gmail", name="gw", service_account_file=Path("sa.json"), mailboxes=[MB]),
        settings,
        MemoryStateStore(),
    )

    class Creds:
        valid = False
        token = None

        def refresh(self, request):
            raise RuntimeError(
                "('unauthorized_client: Client is unauthorized to retrieve access tokens', {})"
            )

    async def fake_make(key):
        return Creds()

    monkeypatch.setattr(conn, "_make_credentials", fake_make)
    monkeypatch.setattr("centinela.connectors.gmail._refresh_sync", lambda creds: creds.refresh(None))
    with pytest.raises(GmailAuthError, match="Delegación de todo el dominio"):
        await conn._access_token(MB)
    assert MB not in conn._creds  # se re-crean en el próximo intento (ej. tras re-autorizar)


def test_real_google_auth_service_account_object(settings, tmp_path):
    """Con google-auth real (clave generada en el test, sin red): sujeto delegado y scopes correctos."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    sa = tmp_path / "sa.json"
    sa.write_text(
        json.dumps(
            {
                "type": "service_account",
                "project_id": "p-123",
                "private_key_id": "k1",
                "private_key": pem,
                "client_email": "centinela@p-123.iam.gserviceaccount.com",
                "client_id": "1",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        ),
        encoding="utf-8",
    )
    conn = GmailConnector(
        GmailConnectorConfig(type="gmail", name="gw", service_account_file=sa, mailboxes=[MB], tag=False),
        settings,
        MemoryStateStore(),
    )
    creds = conn.build_credentials(MB)
    assert creds._subject == MB and list(creds.scopes) == [SCOPE_READONLY]
    assert not creds.valid  # todavía sin token: se refresca en thread al primer uso
    ps = conn.build_credentials("__pubsub__")
    assert ps._subject is None and list(ps.scopes) == [SCOPE_PUBSUB]


async def test_valid_cached_credentials_not_refreshed(settings, monkeypatch):
    conn = GmailConnector(
        GmailConnectorConfig(type="gmail", name="gw", service_account_file=Path("sa.json"), mailboxes=[MB]),
        settings,
        MemoryStateStore(),
    )

    class Creds:
        valid = True
        token = "vigente"
        refreshed = 0

        def refresh(self, request):
            Creds.refreshed += 1
            self.token = "renovado"

    async def fake_make(key):
        return Creds()

    monkeypatch.setattr(conn, "_make_credentials", fake_make)
    monkeypatch.setattr("centinela.connectors.gmail._refresh_sync", lambda creds: creds.refresh(None))
    assert await conn._access_token(MB) == "vigente"
    assert await conn._access_token(MB) == "vigente" and Creds.refreshed == 0
    assert await conn._access_token(MB, force=True) == "renovado" and Creds.refreshed == 1
