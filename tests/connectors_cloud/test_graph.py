from __future__ import annotations

import asyncio
import json
import time
from datetime import UTC, datetime, timedelta
from urllib.parse import unquote

import httpx
import pytest
from pydantic import SecretStr

from centinela.connectors import _http as http
from centinela.connectors import connector_class
from centinela.connectors.graph import (
    GRAPH_BASE,
    GraphAuthError,
    GraphConnector,
    GraphTokenProvider,
    load_certificate_credential,
)
from centinela.core.config import GraphConnectorConfig, TagConfig
from centinela.core.models import MessageRef, VerdictLevel
from centinela.core.state import MemoryStateStore
from tests.connectors_cloud.conftest import Collector, make_result
from tests.helpers import build_eml

MB = "compras@empresa.com"
UB = f"{GRAPH_BASE}/v1.0/users/{MB}"
DELTA = f"{UB}/mailFolders/inbox/messages/delta"


def make_conn(settings, **over) -> GraphConnector:
    data = {
        "type": "graph",
        "name": "m365",
        "tenant_id": "contoso.onmicrosoft.com",
        "client_id": "00000000-0000-0000-0000-000000000001",
        "client_secret": "s3cr3t",
        "mailboxes": [MB],
        "folders": ["inbox"],
        "poll_interval_s": 1,
    }
    data.update(over)
    conn = GraphConnector(GraphConnectorConfig(**data), settings, MemoryStateStore())
    conn.token_calls = []

    async def fake_token(force: bool = False) -> str:
        conn.token_calls.append(force)
        return f"tok-{len(conn.token_calls)}"

    conn.tokens = fake_token
    conn.start_jitter_s = 0
    conn.min_poll_s = 0.01
    conn.stop_grace_s = 1.0
    return conn


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def item(mid: str, received: datetime) -> dict:
    return {
        "@odata.type": "#microsoft.graph.message",
        "id": mid,
        "receivedDateTime": iso(received),
        "internetMessageId": f"<{mid}@x>",
    }


def mime_route(router, mid: str, eml: bytes):
    return router.get(f"{UB}/messages/{mid}/$value").respond(
        200, content=eml, headers={"Content-Type": "text/plain"}
    )


def filter_value(request: httpx.Request) -> str:
    raw = request.url.query.decode()
    for part in raw.split("&"):
        if part.startswith("$filter="):
            return unquote(part[len("$filter=") :])
    raise AssertionError(f"sin $filter en {raw}")


async def test_registered_in_connector_registry():
    assert connector_class("graph") is GraphConnector


async def test_first_run_gets_delta_link_without_emitting_old_mail(settings, router, collector):
    conn = make_conn(settings)
    now = datetime.now(UTC)
    route = router.get(DELTA).respond(
        200,
        json={
            "value": [item("viejo", now - timedelta(days=3))],  # (si el filtro no se aplicara) no se emite
            "@odata.deltaLink": f"{DELTA}?$deltatoken=D1",
        },
    )
    await conn.sync_folder(MB, "inbox", collector, asyncio.Event())
    assert collector.items == []
    req = route.calls.last.request
    assert "$select=id,receivedDateTime,internetMessageId" in req.url.query.decode()
    flt = filter_value(req)
    assert flt.startswith("receivedDateTime ge ")
    assert (
        abs((datetime.fromisoformat(flt.rsplit(" ", 1)[1].replace("Z", "+00:00")) - now).total_seconds()) < 60
    )
    prefer = req.headers["Prefer"]
    assert "odata.maxpagesize=50" in prefer and 'IdType="ImmutableId"' in prefer
    assert req.headers["Authorization"].startswith("Bearer tok-")
    assert await conn.get_cursor(f"graph:{MB}:inbox:delta") == f"{DELTA}?$deltatoken=D1"


async def test_first_run_backfill_emits_recent_and_skips_removed(settings, router, collector):
    conn = make_conn(settings, backfill_hours=24)
    now = datetime.now(UTC)
    route = router.get(DELTA).mock(
        side_effect=[
            httpx.Response(
                200,
                json={
                    "value": [
                        item("n1", now - timedelta(hours=2)),
                        {"id": "r1", "@removed": {"reason": "deleted"}},
                    ],
                    "@odata.nextLink": f"{DELTA}?$skiptoken=S1",
                },
            ),
            httpx.Response(
                200,
                json={
                    "value": [
                        item("n2", now - timedelta(hours=1)),
                        item("old", now - timedelta(hours=30)),
                        "basura",
                        {"id": 5},
                    ],
                    "@odata.deltaLink": f"{DELTA}?$deltatoken=D1",
                },
            ),
        ]
    )
    eml1, eml2 = build_eml(subject="uno"), build_eml(subject="dos")
    mime_route(router, "n1", eml1)
    mime_route(router, "n2", eml2)
    await conn.sync_folder(MB, "inbox", collector, asyncio.Event())
    assert collector.ids == ["n1", "n2"]
    assert collector.items[0].raw == eml1
    assert collector.items[0].ref == MessageRef(connector="m365", mailbox=MB, remote_id="n1", folder="inbox")
    assert abs((collector.items[0].received_at - (now - timedelta(hours=2))).total_seconds()) < 2
    flt = filter_value(route.calls[0].request)
    since = datetime.fromisoformat(flt.rsplit(" ", 1)[1].replace("Z", "+00:00"))
    assert abs((since - (now - timedelta(hours=24))).total_seconds()) < 60
    assert route.calls[1].request.url.query.decode() == "$skiptoken=S1"  # nextLink tal cual
    assert await conn.get_cursor(f"graph:{MB}:inbox:delta") == f"{DELTA}?$deltatoken=D1"


async def test_incremental_round_with_paging(settings, router, collector):
    conn = make_conn(settings)
    since = datetime.now(UTC) - timedelta(hours=1)
    await conn.set_cursor(f"graph:{MB}:inbox:delta", f"{DELTA}?$deltatoken=D1")
    await conn.set_cursor(f"graph:{MB}:inbox:since", iso(since))
    now = datetime.now(UTC)
    route = router.get(DELTA).mock(
        side_effect=[
            httpx.Response(
                200, json={"value": [item("a", now)], "@odata.nextLink": f"{DELTA}?$skiptoken=S2"}
            ),
            httpx.Response(
                200,
                json={
                    "value": [
                        item("b", now),
                        item("leido-viejo", since - timedelta(days=10)),
                    ],  # marcar leído un mail viejo
                    "@odata.deltaLink": f"{DELTA}?$deltatoken=D2",
                },
            ),
        ]
    )
    mime_route(router, "a", build_eml(subject="a"))
    mime_route(router, "b", build_eml(subject="b"))
    await conn.sync_folder(MB, "inbox", collector, asyncio.Event())
    assert collector.ids == ["a", "b"]
    assert route.calls[0].request.url.query.decode() == "$deltatoken=D1"
    assert await conn.get_cursor(f"graph:{MB}:inbox:delta") == f"{DELTA}?$deltatoken=D2"
    assert await conn.get_cursor(f"graph:{MB}:inbox:since") == iso(since)

    # el mismo mail reaparece (ej. lo marcaron leído): no se vuelve a descargar
    router.get(DELTA).mock(
        return_value=httpx.Response(
            200, json={"value": [item("a", now)], "@odata.deltaLink": f"{DELTA}?$deltatoken=D3"}
        )
    )
    calls_before = len(router.calls)
    await conn.sync_folder(MB, "inbox", collector, asyncio.Event())
    assert collector.ids == ["a", "b"]
    assert len(router.calls) == calls_before + 1  # solo el delta, sin $value


async def test_initial_round_requests_created_only_with_fallback(settings, router, collector):
    conn = make_conn(settings)
    route = router.get(DELTA).mock(
        side_effect=[
            httpx.Response(
                400, json={"error": {"code": "ErrorInvalidRequest", "message": "changeType not supported"}}
            ),
            httpx.Response(200, json={"value": [], "@odata.deltaLink": f"{DELTA}?$deltatoken=D"}),
        ]
    )
    await conn.sync_folder(MB, "inbox", collector, asyncio.Event())
    first, second = (c.request.url.query.decode() for c in route.calls)
    assert first.startswith("changeType=created&$select=")
    assert "changeType" not in second and "$filter=" in second
    assert await conn.get_cursor(f"graph:{MB}:inbox:no_changetype") == "1"
    assert await conn.get_cursor(f"graph:{MB}:inbox:delta") == f"{DELTA}?$deltatoken=D"

    # la siguiente ronda inicial (ej. otra carpeta re-creada) ya no lo intenta
    await conn.state.delete(f"connector:m365:graph:{MB}:inbox:delta")
    route.mock(
        return_value=httpx.Response(200, json={"value": [], "@odata.deltaLink": f"{DELTA}?$deltatoken=E"})
    )
    await conn.sync_folder(MB, "inbox", collector, asyncio.Event())
    assert "changeType" not in route.calls.last.request.url.query.decode()


async def test_sliding_watermark_skips_changes_on_old_mail(settings, router, collector):
    conn = make_conn(settings)
    now = datetime.now(UTC)
    await conn.set_cursor(f"graph:{MB}:inbox:delta", f"{DELTA}?$deltatoken=D1")
    await conn.set_cursor(f"graph:{MB}:inbox:since", iso(now - timedelta(days=90)))
    await conn.set_cursor(f"graph:{MB}:inbox:checkpoint", iso(now - timedelta(minutes=1)))
    router.get(DELTA).respond(
        200,
        json={
            "value": [
                item("hace-20-dias", now - timedelta(days=20)),
                item("hace-3-dias", now - timedelta(days=3)),
            ],
            "@odata.deltaLink": f"{DELTA}?$deltatoken=D2",
        },
    )
    old = router.get(f"{UB}/messages/hace-20-dias/$value")
    mime_route(router, "hace-3-dias", build_eml())
    await conn.sync_folder(MB, "inbox", collector, asyncio.Event())
    assert collector.ids == ["hace-3-dias"] and not old.called
    assert await conn.get_cursor(f"graph:{MB}:inbox:since") == iso(
        now - timedelta(days=90)
    )  # ventana del token intacta


async def test_410_resyncs_from_checkpoint(settings, router, collector, caplog):
    conn = make_conn(settings)
    checkpoint = datetime.now(UTC) - timedelta(hours=5)
    await conn.set_cursor(f"graph:{MB}:inbox:delta", f"{DELTA}?$deltatoken=VENCIDO")
    await conn.set_cursor(f"graph:{MB}:inbox:since", iso(checkpoint - timedelta(days=1)))
    await conn.set_cursor(f"graph:{MB}:inbox:checkpoint", iso(checkpoint))
    now = datetime.now(UTC)
    route = router.get(DELTA).mock(
        side_effect=[
            httpx.Response(
                410,
                json={"error": {"code": "SyncStateNotFound", "message": "gone"}},
                headers={"Location": DELTA},
            ),
            httpx.Response(
                200,
                json={
                    "value": [item("perdido", now - timedelta(hours=2))],
                    "@odata.deltaLink": f"{DELTA}?$deltatoken=NUEVO",
                },
            ),
        ]
    )
    mime_route(router, "perdido", build_eml())
    await conn.sync_folder(MB, "inbox", collector, asyncio.Event())
    assert "venció" in caplog.text
    assert collector.ids == ["perdido"]
    flt = filter_value(route.calls[1].request)
    since = datetime.fromisoformat(flt.rsplit(" ", 1)[1].replace("Z", "+00:00"))
    expected = checkpoint - timedelta(seconds=conn.resync_slack_s)
    assert abs((since - expected).total_seconds()) < 5
    assert await conn.get_cursor(f"graph:{MB}:inbox:delta") == f"{DELTA}?$deltatoken=NUEVO"


async def test_sync_state_not_found_400_also_resyncs_bounded(settings, router, collector):
    conn = make_conn(settings)
    await conn.set_cursor(f"graph:{MB}:inbox:delta", f"{DELTA}?$deltatoken=X")
    await conn.set_cursor(f"graph:{MB}:inbox:since", iso(datetime.now(UTC) - timedelta(days=30)))
    route = router.get(DELTA).mock(
        side_effect=[
            httpx.Response(400, json={"error": {"code": "syncStateNotFound"}}),
            httpx.Response(200, json={"value": [], "@odata.deltaLink": f"{DELTA}?$deltatoken=Y"}),
        ]
    )
    await conn.sync_folder(MB, "inbox", collector, asyncio.Event())
    since = datetime.fromisoformat(
        filter_value(route.calls[1].request).rsplit(" ", 1)[1].replace("Z", "+00:00")
    )
    assert abs((since - (datetime.now(UTC) - timedelta(days=2))).total_seconds()) < 60  # tope de 2 días


async def test_429_and_503_retry_after(settings, router, collector, sleeps):
    conn = make_conn(settings)
    router.get(DELTA).mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "13"}, json={"error": {"code": "TooManyRequests"}}),
            httpx.Response(503, headers={"Retry-After": "2"}),
            httpx.Response(200, json={"value": [], "@odata.deltaLink": f"{DELTA}?$deltatoken=D"}),
        ]
    )
    await conn.sync_folder(MB, "inbox", collector, asyncio.Event())
    assert sleeps == [13.0, 2.0]
    assert await conn.get_cursor(f"graph:{MB}:inbox:delta") == f"{DELTA}?$deltatoken=D"


async def test_401_refreshes_token(settings, router, collector):
    conn = make_conn(settings)
    router.get(DELTA).mock(
        side_effect=[
            httpx.Response(401),
            httpx.Response(200, json={"value": [], "@odata.deltaLink": f"{DELTA}?$deltatoken=D"}),
        ]
    )
    await conn.sync_folder(MB, "inbox", collector, asyncio.Event())
    assert True in conn.token_calls


BIG_HEADERS = [
    {"name": "Received", "value": "from mx.proveedor.com (203.0.113.7) by AM0PR01.outlook.com"},
    {
        "name": "Authentication-Results",
        "value": "spf=fail (sender IP is 203.0.113.7) smtp.mailfrom=proveedor.com",
    },
    {"name": "From", "value": "Proveedor <facturas@proveedor.com>"},
    {"name": "Subject", "value": "Factura vencida\r\nX-Inyectado: si"},
    {"name": "", "value": "sin nombre"},
    {"value": "sin nombre"},
]


def oversize_delta(router, *mids: str) -> None:
    now = datetime.now(UTC)
    router.get(DELTA).respond(
        200, json={"value": [item(m, now) for m in mids], "@odata.deltaLink": f"{DELTA}?$deltatoken=D"}
    )


async def test_oversized_mime_emits_headers_only(settings, router, collector):
    settings.limits.max_message_bytes = 1000
    conn = make_conn(settings, backfill_hours=1)
    oversize_delta(router, "grande", "chico")
    router.get(f"{UB}/messages/grande/$value").respond(200, content=b"A" * 5000)
    hdrs = router.get(f"{UB}/messages/grande").respond(
        200,
        json={
            "receivedDateTime": "2026-10-04T12:00:00Z",
            "internetMessageHeaders": BIG_HEADERS,
            "singleValueExtendedProperties": [{"id": "Integer 0xe08", "value": "73400320"}],
        },
    )
    mime_route(router, "chico", b"Subject: x\r\n\r\nhola")
    await conn.sync_folder(MB, "inbox", collector, asyncio.Event())

    # NO se omite: mandar un mail enorme sería una evasión trivial
    assert collector.ids == ["grande", "chico"]
    big, small = collector.items
    assert big.truncated is True and big.original_size == 73_400_320  # PR_MESSAGE_SIZE
    assert big.ref == MessageRef(connector="m365", mailbox=MB, remote_id="grande", folder="inbox")
    assert big.raw == (
        b"Received: from mx.proveedor.com (203.0.113.7) by AM0PR01.outlook.com\r\n"
        b"Authentication-Results: spf=fail (sender IP is 203.0.113.7) smtp.mailfrom=proveedor.com\r\n"
        b"From: Proveedor <facturas@proveedor.com>\r\n"
        b"Subject: Factura vencida X-Inyectado: si\r\n"
        b"\r\n"
    )
    assert small.truncated is False and small.raw == b"Subject: x\r\n\r\nhola"
    req = hdrs.calls.last.request
    query = unquote(req.url.query.decode())
    assert "$select=internetMessageHeaders," in query
    assert "$expand=singleValueExtendedProperties($filter=id eq 'Integer 0x0E08')" in query
    assert 'IdType="ImmutableId"' in req.headers["Prefer"]
    assert conn.truncated_too_large == 1
    assert (await conn.healthcheck())["truncated_too_large"] == 1
    assert await conn.get_cursor(f"graph:{MB}:inbox:delta") == f"{DELTA}?$deltatoken=D"


async def test_oversized_mime_without_extended_property_support(settings, router, collector):
    settings.limits.max_message_bytes = 1000
    conn = make_conn(settings, backfill_hours=1)
    oversize_delta(router, "grande")
    router.get(f"{UB}/messages/grande/$value").respond(200, content=b"A" * 5000)
    hdrs = router.get(f"{UB}/messages/grande").mock(
        side_effect=[
            httpx.Response(400, json={"error": {"code": "ErrorInvalidProperty"}}),
            httpx.Response(200, json={"internetMessageHeaders": BIG_HEADERS[:3]}),
        ]
    )
    await conn.sync_folder(MB, "inbox", collector, asyncio.Event())
    first, second = (unquote(c.request.url.query.decode()) for c in hdrs.calls)
    assert "$expand=" in first and "$expand=" not in second and "$select=internetMessageHeaders" in second
    (big,) = collector.items
    assert big.truncated is True and big.original_size == 5000  # Content-Length declarado del $value
    assert b"From: Proveedor <facturas@proveedor.com>\r\n" in big.raw


async def test_oversized_internal_mail_gets_synthetic_headers(settings, router, collector):
    """Mails internos de Exchange no tienen headers de Internet: se arman From/To/Subject/Message-ID."""
    settings.limits.max_message_bytes = 1000
    conn = make_conn(settings, backfill_hours=1)
    oversize_delta(router, "interno")
    router.get(f"{UB}/messages/interno/$value").respond(200, content=b"A" * 5000)
    router.get(f"{UB}/messages/interno").respond(
        200,
        json={
            "subject": "Reunión\r\nBcc: x@evil.example",
            "from": {"emailAddress": {"name": "Jefe Pérez", "address": "jefe@empresa.com"}},
            "toRecipients": [{"emailAddress": {"name": "", "address": MB}}, "basura", {"emailAddress": {}}],
            "internetMessageId": "<abc-1@empresa.com>",
            "internetMessageHeaders": None,
        },
    )
    await conn.sync_folder(MB, "inbox", collector, asyncio.Event())
    (big,) = collector.items
    assert big.truncated is True
    from centinela.parsing.mime import parse_message

    pm = parse_message(big, settings.limits)
    assert pm.from_addr == "jefe@empresa.com" and pm.from_display == "Jefe Pérez"
    assert pm.to == [MB] and pm.subject.startswith("Reunión")
    assert pm.header("Bcc") is None


async def test_oversized_mime_deleted_before_headers(settings, router, collector):
    settings.limits.max_message_bytes = 1000
    conn = make_conn(settings, backfill_hours=1)
    oversize_delta(router, "grande")
    router.get(f"{UB}/messages/grande/$value").respond(200, content=b"A" * 5000)
    router.get(f"{UB}/messages/grande").respond(404, json={"error": {"code": "ErrorItemNotFound"}})
    await conn.sync_folder(MB, "inbox", collector, asyncio.Event())
    assert collector.items == [] and conn.truncated_too_large == 0
    assert await conn.get_cursor(f"graph:{MB}:inbox:delta") == f"{DELTA}?$deltatoken=D"


async def test_oversized_headers_error_keeps_old_delta_link(settings, router, collector, sleeps):
    settings.limits.max_message_bytes = 1000
    conn = make_conn(settings, backfill_hours=1)
    oversize_delta(router, "grande")
    router.get(f"{UB}/messages/grande/$value").respond(200, content=b"A" * 5000)
    router.get(f"{UB}/messages/grande").respond(500)
    with pytest.raises(http.HttpError):
        await conn.sync_folder(MB, "inbox", collector, asyncio.Event())
    assert collector.items == []
    assert await conn.get_cursor(f"graph:{MB}:inbox:delta") is None  # se reintenta (al-menos-una-vez)


async def test_deleted_message_mime_404_skipped(settings, router, collector):
    conn = make_conn(settings, backfill_hours=1)
    router.get(DELTA).respond(
        200,
        json={"value": [item("borrado", datetime.now(UTC))], "@odata.deltaLink": f"{DELTA}?$deltatoken=D"},
    )
    router.get(f"{UB}/messages/borrado/$value").respond(404, json={"error": {"code": "ErrorItemNotFound"}})
    await conn.sync_folder(MB, "inbox", collector, asyncio.Event())
    assert collector.items == []
    assert await conn.get_cursor(f"graph:{MB}:inbox:delta") == f"{DELTA}?$deltatoken=D"


async def test_foreign_next_link_is_never_followed(settings, router, collector):
    conn = make_conn(settings)
    evil = router.get(url__startswith="https://evil.example").respond(200, json={})
    router.get(DELTA).respond(200, json={"value": [], "@odata.nextLink": "https://evil.example/steal?x=1"})
    with pytest.raises(http.HttpError, match="nextLink"):
        await conn.sync_folder(MB, "inbox", collector, asyncio.Event())
    assert not evil.called  # el token nunca viaja a otro host
    assert await conn.get_cursor(f"graph:{MB}:inbox:delta") is None


async def test_tampered_stored_delta_link_triggers_fresh_round(settings, router, collector):
    conn = make_conn(settings)
    await conn.set_cursor(f"graph:{MB}:inbox:delta", "http://evil.example/delta")
    await conn.set_cursor(f"graph:{MB}:inbox:since", iso(datetime.now(UTC)))
    evil = router.get(url__startswith="http://evil.example").respond(200, json={})
    router.get(DELTA).respond(200, json={"value": [], "@odata.deltaLink": f"{DELTA}?$deltatoken=OK"})
    await conn.sync_folder(MB, "inbox", collector, asyncio.Event())
    assert not evil.called
    assert await conn.get_cursor(f"graph:{MB}:inbox:delta") == f"{DELTA}?$deltatoken=OK"


async def test_emit_failure_keeps_old_delta_link(settings, router):
    conn = make_conn(settings, backfill_hours=1)
    router.get(DELTA).respond(
        200, json={"value": [item("m1", datetime.now(UTC))], "@odata.deltaLink": f"{DELTA}?$deltatoken=D"}
    )
    mime_route(router, "m1", build_eml())
    with pytest.raises(RuntimeError):
        await conn.sync_folder(MB, "inbox", Collector(fail_on={"m1"}), asyncio.Event())
    assert await conn.get_cursor(f"graph:{MB}:inbox:delta") is None


async def test_stop_mid_round_does_not_store_delta_link(settings, router):
    conn = make_conn(settings, backfill_hours=1)
    now = datetime.now(UTC)
    router.get(DELTA).respond(
        200, json={"value": [item("m1", now), item("m2", now)], "@odata.deltaLink": f"{DELTA}?$deltatoken=D"}
    )
    mime_route(router, "m1", build_eml())
    mime_route(router, "m2", build_eml())
    stop = asyncio.Event()
    got = []

    async def emit(raw):
        got.append(raw)
        stop.set()

    await conn.sync_folder(MB, "inbox", emit, stop)
    assert len(got) == 1
    assert await conn.get_cursor(f"graph:{MB}:inbox:delta") is None


# ----------------------------------------------------------------------------- etiquetado


async def test_apply_verdict_merges_categories_and_creates_master(settings, router):
    conn = make_conn(settings)
    msg_url = f"{UB}/messages/AAMkAD%2Bx="
    get = router.get(msg_url).respond(200, json={"id": "AAMkAD+x=", "categories": ["Cliente VIP", 7]})
    patch = router.patch(msg_url).respond(200, json={})
    master_get = router.get(f"{UB}/outlook/masterCategories").respond(
        200, json={"value": [{"displayName": "Cliente VIP", "color": "preset4"}]}
    )
    master_post = router.post(f"{UB}/outlook/masterCategories").respond(201, json={"id": "c1"})
    ref = MessageRef(connector="m365", mailbox=MB, remote_id="AAMkAD+x=", folder="inbox")
    out = await conn.apply_verdict(ref, make_result(ref, VerdictLevel.MALICIOUS), TagConfig())
    assert out == "graph:category:Centinela/Malicioso"
    assert "$select=categories" in get.calls.last.request.url.query.decode()
    assert json.loads(patch.calls.last.request.content) == {
        "categories": ["Cliente VIP", "Centinela/Malicioso"]
    }
    assert 'IdType="ImmutableId"' in patch.calls.last.request.headers["Prefer"]
    assert json.loads(master_post.calls.last.request.content) == {
        "displayName": "Centinela/Malicioso",
        "color": "preset0",
    }
    # segunda vez: la categoría maestra ya está asegurada (cache)
    await conn.apply_verdict(ref, make_result(ref, VerdictLevel.MALICIOUS), TagConfig())
    assert master_get.call_count == 1


async def test_apply_verdict_suspicious_orange_and_already_tagged(settings, router):
    conn = make_conn(settings)
    msg_url = f"{UB}/messages/m1"
    router.get(msg_url).respond(200, json={"categories": ["centinela/sospechoso"]})
    patch = router.patch(msg_url)
    router.get(f"{UB}/outlook/masterCategories").respond(200, json={"value": []})
    master_post = router.post(f"{UB}/outlook/masterCategories").respond(201, json={})
    ref = MessageRef(connector="m365", mailbox=MB, remote_id="m1")
    assert (
        await conn.apply_verdict(ref, make_result(ref, VerdictLevel.SUSPICIOUS), TagConfig())
        == "graph:category:Centinela/Sospechoso"
    )
    assert not patch.called  # ya la tenía: no se toca
    assert json.loads(master_post.calls.last.request.content)["color"] == "preset1"


async def test_apply_verdict_master_forbidden_is_ignored(settings, router):
    conn = make_conn(settings)
    router.get(f"{UB}/outlook/masterCategories").respond(403, json={"error": {"code": "ErrorAccessDenied"}})
    router.get(f"{UB}/messages/m1").respond(200, json={"categories": []})
    patch = router.patch(f"{UB}/messages/m1").respond(200, json={})
    ref = MessageRef(connector="m365", mailbox=MB, remote_id="m1")
    assert await conn.apply_verdict(ref, make_result(ref, VerdictLevel.MALICIOUS), TagConfig())
    assert json.loads(patch.calls.last.request.content) == {"categories": ["Centinela/Malicioso"]}
    assert MB in conn._master_forbidden


async def test_apply_verdict_patch_forbidden_raises_spanish(settings, router):
    conn = make_conn(settings)
    router.get(f"{UB}/outlook/masterCategories").respond(403)
    router.get(f"{UB}/messages/m1").respond(200, json={"categories": []})
    router.patch(f"{UB}/messages/m1").respond(403, json={"error": {"code": "ErrorAccessDenied"}})
    ref = MessageRef(connector="m365", mailbox=MB, remote_id="m1")
    with pytest.raises(http.HttpError, match="Mail.ReadWrite"):
        await conn.apply_verdict(ref, make_result(ref, VerdictLevel.MALICIOUS), TagConfig())


async def test_apply_verdict_noop_cases(settings, router):
    conn = make_conn(settings)
    ref = MessageRef(connector="m365", mailbox=MB, remote_id="m1")
    assert await conn.apply_verdict(ref, make_result(ref, VerdictLevel.CLEAN), TagConfig()) is None
    assert (
        await conn.apply_verdict(
            ref, make_result(ref, VerdictLevel.SUSPICIOUS), TagConfig(min_level="malicious")
        )
        is None
    )
    assert (
        await make_conn(settings, tag=False).apply_verdict(
            ref, make_result(ref, VerdictLevel.MALICIOUS), TagConfig()
        )
        is None
    )
    other = MessageRef(connector="otro", mailbox=MB, remote_id="m1")
    assert await conn.apply_verdict(other, make_result(other, VerdictLevel.MALICIOUS), TagConfig()) is None
    assert not router.calls


async def test_apply_verdict_message_gone(settings, router):
    conn = make_conn(settings)
    router.get(f"{UB}/outlook/masterCategories").respond(
        200, json={"value": [{"displayName": "Centinela/Malicioso"}]}
    )
    router.get(f"{UB}/messages/m1").respond(404)
    ref = MessageRef(connector="m365", mailbox=MB, remote_id="m1")
    assert await conn.apply_verdict(ref, make_result(ref, VerdictLevel.MALICIOUS), TagConfig()) is None


# ----------------------------------------------------------------------------- run() / stop


async def test_run_two_folders_and_stop_is_responsive(settings, router):
    conn = make_conn(settings, folders=["inbox", "junkemail"], poll_interval_s=3600)
    router.get(DELTA).respond(200, json={"value": [], "@odata.deltaLink": f"{DELTA}?$deltatoken=I"})
    junk = f"{UB}/mailFolders/junkemail/messages/delta"
    router.get(junk).respond(200, json={"value": [], "@odata.deltaLink": f"{junk}?$deltatoken=J"})
    stop = asyncio.Event()
    task = asyncio.create_task(conn.run(Collector(), stop))
    for _ in range(100):
        await asyncio.sleep(0.02)
        if all(st.ok for st in conn._status.values()) and len(conn._status) == 2:
            break
    health = await conn.healthcheck()
    assert health["ok"] is True and set(health["folders"]) == {f"{MB}/inbox", f"{MB}/junkemail"}
    t0 = time.monotonic()
    stop.set()
    await asyncio.wait_for(task, 3)
    assert time.monotonic() - t0 < 2
    assert await conn.get_cursor(f"graph:{MB}:junkemail:delta") == f"{junk}?$deltatoken=J"
    await conn.close()


async def test_run_auth_error_reported_in_health(settings, router):
    conn = make_conn(settings)

    async def failing(force: bool = False) -> str:
        raise GraphAuthError("invalid_client: AADSTS7000215")

    conn.tokens = failing
    stop = asyncio.Event()
    task = asyncio.create_task(conn.run(Collector(), stop))
    for _ in range(100):
        await asyncio.sleep(0.02)
        if conn._status[(MB, "inbox")].error:
            break
    assert "AADSTS7000215" in (await conn.healthcheck())["folders"][f"{MB}/inbox"]["error"]
    stop.set()
    await asyncio.wait_for(task, 3)


def test_validate_requires_credentials_and_mailboxes(settings):
    with pytest.raises(ValueError, match="mailboxes"):
        make_conn(settings, mailboxes=[]).validate()
    with pytest.raises(ValueError, match="client_secret"):
        make_conn(settings, client_secret=None).validate()


# ----------------------------------------------------------------------------- credenciales


def _self_signed_pem() -> tuple[bytes, str]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "centinela-test")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM) + key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return pem, cert.fingerprint(hashes.SHA1()).hex().upper()


def test_certificate_thumbprint_from_pem(tmp_path):
    pem, thumb = _self_signed_pem()
    f = tmp_path / "graph.pem"
    f.write_bytes(pem)
    cred = load_certificate_credential(f)
    assert cred["thumbprint"] == thumb and len(thumb) == 40
    assert cred["private_key"].startswith("-----BEGIN PRIVATE KEY-----")


def test_certificate_errors(tmp_path):
    only_cert = tmp_path / "solo.pem"
    pem, _ = _self_signed_pem()
    only_cert.write_bytes(pem.split(b"-----BEGIN RSA PRIVATE KEY-----")[0])
    with pytest.raises(GraphAuthError, match="clave privada"):
        load_certificate_credential(only_cert)
    garbage = tmp_path / "basura.pem"
    garbage.write_text(
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nBBBB\n-----END PRIVATE KEY-----\n"
    )
    with pytest.raises(GraphAuthError, match="inválidos"):
        load_certificate_credential(garbage)
    with pytest.raises(GraphAuthError):
        load_certificate_credential(tmp_path / "no-existe.pem")
    assert load_certificate_credential_pfx(tmp_path) == {"private_key_pfx_path": str(tmp_path / "c.pfx")}


def load_certificate_credential_pfx(tmp_path):
    p = tmp_path / "c.pfx"
    p.write_bytes(b"\x30\x82")
    return load_certificate_credential(p)


class FakeMsalApp:
    instances: list[FakeMsalApp] = []
    result: dict = {"access_token": "eyJ.fake.tok", "expires_in": 3599}

    def __init__(self, client_id, client_credential=None, authority=None, token_cache=None, timeout=None):
        self.client_id, self.credential, self.authority, self.timeout = (
            client_id,
            client_credential,
            authority,
            timeout,
        )
        self.calls = 0
        FakeMsalApp.instances.append(self)

    def acquire_token_for_client(self, scopes):
        self.calls += 1
        assert scopes == ["https://graph.microsoft.com/.default"]
        return dict(FakeMsalApp.result)


async def test_token_provider_caches_and_forces(settings, monkeypatch):
    import msal

    FakeMsalApp.instances = []
    FakeMsalApp.result = {"access_token": "eyJ.fake.tok", "expires_in": 3599}
    monkeypatch.setattr(msal, "ConfidentialClientApplication", FakeMsalApp)
    cfg = GraphConnectorConfig(
        type="graph",
        name="m",
        tenant_id="tid",
        client_id="cid",
        client_secret=SecretStr("sec"),
        mailboxes=[MB],
    )
    p = GraphTokenProvider(cfg)
    assert await p() == "eyJ.fake.tok"
    assert await p() == "eyJ.fake.tok"
    assert len(FakeMsalApp.instances) == 1 and FakeMsalApp.instances[0].calls == 1  # cacheado
    assert FakeMsalApp.instances[0].credential == "sec"
    assert FakeMsalApp.instances[0].authority == "https://login.microsoftonline.com/tid"
    await p(True)
    assert len(FakeMsalApp.instances) == 2  # forzado: app/cache nuevos


async def test_token_provider_error_is_spanish_and_secret_free(settings, monkeypatch):
    import msal

    FakeMsalApp.result = {
        "error": "invalid_client",
        "error_description": "AADSTS7000215: Invalid client secret provided.\r\nTrace ID: x",
        "error_codes": [7000215],
    }
    monkeypatch.setattr(msal, "ConfidentialClientApplication", FakeMsalApp)
    cfg = GraphConnectorConfig(
        type="graph",
        name="m",
        tenant_id="tid",
        client_id="cid",
        client_secret=SecretStr("SUPERSECRETO"),
        mailboxes=[MB],
    )
    with pytest.raises(GraphAuthError) as ei:
        await GraphTokenProvider(cfg)()
    msg = str(ei.value)
    assert "client_secret es inválido" in msg and "SUPERSECRETO" not in msg and "Trace ID" not in msg
