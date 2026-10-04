from __future__ import annotations

import asyncio
import logging
import ssl
import time
from datetime import UTC, datetime, timedelta

import pytest
from imapclient import SocketTimeout
from imapclient.exceptions import IMAPClientAbortError, IMAPClientError, LoginError

import centinela.connectors.imap as imap_mod
from centinela.connectors import connector_class
from centinela.connectors.imap import (
    KEYWORD_MALICIOUS,
    KEYWORD_SUSPICIOUS,
    ImapConnector,
    make_remote_id,
    parse_remote_id,
)
from centinela.core.config import ImapConnectorConfig, TagConfig
from centinela.core.models import AnalysisResult, MessageRef, Verdict, VerdictLevel
from centinela.core.state import MemoryStateStore
from centinela.metrics import REGISTRY
from tests.connectors_imap.fakes import FakeServer, eml, header_of

NAME = "buzon"
USER = "ventas@empresa.com"


# --------------------------------------------------------------------------- utilidades


@pytest.fixture
def server(monkeypatch) -> FakeServer:
    srv = FakeServer()
    monkeypatch.setattr(imap_mod, "IMAPClient", srv.client_class)
    return srv


@pytest.fixture
def state() -> MemoryStateStore:
    return MemoryStateStore()


def make_conn(settings, state, **overrides) -> ImapConnector:
    data = {
        "type": "imap",
        "name": NAME,
        "host": "imap.example.com",
        "username": USER,
        "password": "app-pass",
    }
    data.update(overrides)
    cfg = ImapConnectorConfig.model_validate(data)
    conn = ImapConnector(cfg, settings, state)
    # tiempos cortos para tests
    conn.IDLE_CHECK_S = 0.02
    conn.BACKOFF_BASE_S = 0.01
    conn.BACKOFF_CAP_S = 0.05
    conn.AUTH_RETRY_MIN_S = 0.05
    conn.VERDICT_RETRY_DELAY_S = 0.01
    conn.CLOSE_TIMEOUT_S = 1.0
    return conn


class Collector:
    def __init__(self, on_emit=None) -> None:
        self.items = []
        self.fail_next = 0
        self.on_emit = on_emit

    async def __call__(self, raw):
        if self.fail_next:
            self.fail_next -= 1
            raise RuntimeError("cola caída")
        self.items.append(raw)
        if self.on_emit:
            self.on_emit(raw)
        return None

    @property
    def uids(self) -> list[int]:
        return [parse_remote_id(r.ref.remote_id)[2] for r in self.items]


class Running:
    def __init__(self, conn: ImapConnector, emit) -> None:
        self.conn, self.emit = conn, emit
        self.stop = asyncio.Event()

    async def __aenter__(self):
        self.task = asyncio.create_task(self.conn.run(self.emit, self.stop))
        return self

    async def __aexit__(self, *exc):
        self.stop.set()
        await asyncio.wait_for(self.task, timeout=5)


async def eventually(cond, within: float = 5.0, what: str = "condición") -> None:
    deadline = time.monotonic() + within
    while not cond():
        if time.monotonic() > deadline:
            raise AssertionError(f"timeout esperando {what}")
        await asyncio.sleep(0.01)


def idling(server: FakeServer, folder: str = "INBOX") -> bool:
    return any(c.idling and not c.closed and c.selected == folder for c in server.clients)


def gauge() -> float | None:
    return REGISTRY.get_sample_value("centinela_connector_up", {"connector": NAME})


async def set_cursor(state, folder="INBOX", validity=1000, last=0) -> None:
    await state.set(f"connector:{NAME}:{folder}:uidvalidity", str(validity))
    await state.set(f"connector:{NAME}:{folder}:last_uid", str(last))


async def get_cursor(state, folder="INBOX") -> tuple[str | None, str | None]:
    return (
        await state.get(f"connector:{NAME}:{folder}:uidvalidity"),
        await state.get(f"connector:{NAME}:{folder}:last_uid"),
    )


def result_for(ref: MessageRef, level: VerdictLevel) -> AnalysisResult:
    return AnalysisResult(
        ref=ref, received_at=datetime.now(UTC), verdict=Verdict(level=level, score=80, summary="test")
    )


# --------------------------------------------------------------------------- helpers puros


def test_registry_resolves_imap_connector():
    assert connector_class("imap") is ImapConnector


def test_remote_id_roundtrip_with_colons_in_folder():
    rid = make_remote_id("Archivo:2026:Q3", 77, 1234)
    assert rid == "Archivo:2026:Q3:77:1234"
    assert parse_remote_id(rid) == ("Archivo:2026:Q3", 77, 1234)


@pytest.mark.parametrize("bad", ["", "INBOX", "INBOX:1", "INBOX:x:1", ":1:2", "INBOX:1:0", "INBOX:-1:5"])
def test_parse_remote_id_rejects_garbage(bad):
    with pytest.raises(ValueError):
        parse_remote_id(bad)


def test_idle_response_classification():
    assert imap_mod._has_new_mail([(3, b"EXISTS")])
    assert imap_mod._has_new_mail([(b"OK", b"Still here"), (1, b"RECENT")])
    assert not imap_mod._has_new_mail(
        [(b"OK", b"Still here"), (2, b"EXPUNGE"), (1, b"FETCH", (b"FLAGS", ()))]
    )
    assert not imap_mod._has_new_mail([])
    assert imap_mod._has_bye([(b"BYE", b"Autologout; idle for too long")])
    assert not imap_mod._has_bye([(b"OK", b"BYE in text")])
    assert not imap_mod._has_new_mail(["basura", None, (), (b"",)])


def test_permanentflags_and_body_helpers():
    assert imap_mod._allows_keyword((b"\\Seen", b"\\*"), KEYWORD_MALICIOUS)
    assert imap_mod._allows_keyword(None, KEYWORD_MALICIOUS)
    assert imap_mod._allows_keyword((b"$centinela_malicious",), KEYWORD_MALICIOUS)
    assert not imap_mod._allows_keyword((b"\\Seen", b"\\Flagged"), KEYWORD_MALICIOUS)
    assert not imap_mod._allows_keyword((), KEYWORD_MALICIOUS)
    assert imap_mod._body_from({b"SEQ": 1, b"BODY[]<0>": b"abc"}) == b"abc"
    assert imap_mod._body_from({b"BODY[]": b"abc"}) == b"abc"
    assert imap_mod._body_from({b"BODY[]": None}) is None
    assert imap_mod._body_from({b"RFC822.SIZE": 3}) is None


# --------------------------------------------------------------------------- cursor e ingesta


async def test_first_run_starts_at_uidnext_and_emits_only_new_mail(settings, state, server, caplog):
    caplog.set_level(logging.DEBUG)
    for _ in range(3):
        server.deliver()  # histórico: NO debe analizarse
    conn = make_conn(settings, state)
    emit = Collector()
    async with Running(conn, emit):
        await eventually(lambda: idling(server), what="IDLE")
        assert await get_cursor(state) == ("1000", "3")
        assert emit.items == []
        when = datetime(2026, 10, 2, 13, 0, tzinfo=UTC)
        uid = server.deliver(raw=eml("Factura"), internaldate=when)
        await eventually(lambda: len(emit.items) == 1, what="mail nuevo")
        await eventually(lambda: conn._status["INBOX"].last_uid == uid)

    raw = emit.items[0]
    assert raw.ref == MessageRef(connector=NAME, mailbox=USER, remote_id=f"INBOX:1000:{uid}", folder="INBOX")
    assert raw.raw == server.folders["INBOX"].messages[uid].raw
    assert raw.received_at == when and raw.received_at.tzinfo is not None
    assert await get_cursor(state) == ("1000", str(uid))

    # pasividad: toda carpeta vigilada se abrió en solo lectura y el cuerpo se bajó con PEEK
    assert server.calls_of("select") and all(c[2][1] is True for c in server.calls_of("select"))
    body_fetches = [c for c in server.calls_of("fetch") if any("BODY" in i or "RFC822" == i for i in c[2][1])]
    assert body_fetches
    for _, _, (_uids, items) in body_fetches:
        assert all(i.startswith("BODY.PEEK[]") for i in items if "BODY" in i)
        assert "RFC822" not in items
    assert all(b"\\Seen" not in m.flags for m in server.folders["INBOX"].messages.values())
    # secretos fuera de los logs
    assert "app-pass" not in caplog.text


async def test_resume_from_stored_cursor_in_ascending_order(settings, state, server):
    for _ in range(5):
        server.deliver()
    await set_cursor(state, last=2)
    conn = make_conn(settings, state)
    emit = Collector()
    async with Running(conn, emit):
        await eventually(lambda: len(emit.items) == 3, what="3 mails")
    assert emit.uids == [3, 4, 5]
    assert (await get_cursor(state))[1] == "5"


async def test_cursor_does_not_reemit_when_star_range_returns_last_message(settings, state, server):
    # RFC 3501: "UID 6:*" con UID máximo 5 devuelve el 5; no debe re-analizarse
    for _ in range(5):
        server.deliver()
    await set_cursor(state, last=5)
    conn = make_conn(settings, state)
    emit = Collector()
    async with Running(conn, emit):
        await eventually(lambda: idling(server), what="IDLE")
        await asyncio.sleep(0.1)
    assert emit.items == []


async def test_uidvalidity_change_resets_cursor_without_reprocessing(settings, state, server, caplog):
    caplog.set_level(logging.WARNING)
    for _ in range(3):
        server.deliver()
    await set_cursor(state, validity=999, last=1)
    conn = make_conn(settings, state)
    emit = Collector()
    async with Running(conn, emit):
        await eventually(lambda: idling(server), what="IDLE")
        assert emit.items == []
        assert await get_cursor(state) == ("1000", "3")
        uid = server.deliver()
        await eventually(lambda: emit.uids == [uid], what="mail tras reset")
    assert "UIDVALIDITY" in caplog.text


async def test_uidvalidity_change_while_running(settings, state, server):
    conn = make_conn(settings, state)
    emit = Collector()
    async with Running(conn, emit):
        await eventually(lambda: idling(server), what="IDLE")
        server.deliver()
        server.deliver()
        await eventually(lambda: len(emit.items) == 2)
        server.renumber(new_validity=2000)  # el server regeneró la carpeta
        server.fail("idle_check", IMAPClientAbortError("socket error: EOF"))
        await eventually(lambda: conn._status["INBOX"].uidvalidity == 2000, what="nuevo UIDVALIDITY")
        await eventually(lambda: idling(server))
        uid = server.deliver()
        await eventually(lambda: len(emit.items) == 3)
    assert emit.items[-1].ref.remote_id == f"INBOX:2000:{uid}"
    assert await get_cursor(state) == ("2000", str(uid))


async def test_cursor_ahead_of_server_is_reset(settings, state, server):
    for _ in range(2):
        server.deliver()
    await set_cursor(state, last=50)  # imposible: UIDNEXT=3
    conn = make_conn(settings, state)
    emit = Collector()
    async with Running(conn, emit):
        await eventually(lambda: idling(server))
        assert (await get_cursor(state))[1] == "2"
        uid = server.deliver()
        await eventually(lambda: emit.uids == [uid])


async def test_missing_uidnext_uses_status_fallback(settings, state, server):
    server.send_uidnext = False
    for _ in range(4):
        server.deliver()
    conn = make_conn(settings, state)
    emit = Collector()
    async with Running(conn, emit):
        await eventually(lambda: idling(server))
        assert (await get_cursor(state))[1] == "4"
    assert server.calls_of("status")
    assert emit.items == []


async def test_backfill_hours_analyzes_only_recent_history(settings, state, server):
    now = datetime.now(UTC)
    server.deliver(internaldate=now - timedelta(days=3))
    server.deliver(internaldate=now - timedelta(hours=30))
    u3 = server.deliver(internaldate=now - timedelta(hours=2))
    u4 = server.deliver(internaldate=now - timedelta(minutes=10))
    conn = make_conn(settings, state, backfill_hours=24)
    emit = Collector()
    async with Running(conn, emit):
        await eventually(lambda: len(emit.items) == 2, what="backfill")
        await eventually(lambda: idling(server))
    assert emit.uids == [u3, u4]
    since = [c for c in server.calls_of("search") if c[2][0][0] == "SINCE"]
    assert since, "debe usar SEARCH SINCE"


async def test_oversize_messages_are_emitted_headers_only(settings, state, server, caplog):
    caplog.set_level(logging.WARNING)
    settings.limits.max_message_bytes = 2000
    big, liar = eml("grande", size=5000), eml("mentiroso", size=5000)
    u1 = server.deliver(raw=eml("chico 1"))
    u2 = server.deliver(raw=big)
    u3 = server.deliver(raw=eml("chico 2"))
    u4 = server.deliver(raw=liar, size_override=100)  # el server miente el tamaño
    await set_cursor(state, last=0)
    conn = make_conn(settings, state)
    emit = Collector()
    async with Running(conn, emit):
        await eventually(lambda: len(emit.items) == 4, what="4 mails")
        await eventually(lambda: idling(server))
    # nada se omite: mandar un mail enorme sería una evasión trivial
    assert emit.uids == [u1, u2, u3, u4]
    by_uid = dict(zip(emit.uids, emit.items, strict=True))
    for uid in (u1, u3):
        assert by_uid[uid].truncated is False and by_uid[uid].original_size is None
    grande, mentiroso = by_uid[u2], by_uid[u4]
    assert grande.truncated is True and grande.original_size == 5000
    assert grande.raw == header_of(big) and b"Subject: grande" in grande.raw and b"xxx" not in grande.raw
    assert grande.ref.remote_id == f"INBOX:1000:{u2}" and grande.received_at.tzinfo is not None
    # el mentiroso se bajó acotado a límite+1 y se recortó a los headers; tamaño real = cota inferior
    assert mentiroso.truncated is True and mentiroso.original_size == 2001
    assert mentiroso.raw == header_of(liar)
    assert (await get_cursor(state))[1] == str(u4)
    st = conn._status["INBOX"]
    assert (st.emitted, st.truncated, st.skipped) == (4, 2, 0)
    assert (await conn.healthcheck())["folders"]["INBOX"]["truncated_too_large"] == 2
    # el grande nunca se bajó completo: solo BODY.PEEK[HEADER] acotado (sin marcar \Seen)
    fetched = {c[2][0]: c[2][1] for c in server.calls_of("fetch") if any("BODY" in i for i in c[2][1])}
    assert fetched[(u2,)] == ("BODY.PEEK[HEADER]<0.2000>", "INTERNALDATE")
    assert "BODY.PEEK[]<0.2001>" in fetched[(u4,)]
    assert all(b"\\Seen" not in m.flags for m in server.folders["INBOX"].messages.values())
    assert "solo los encabezados" in caplog.text


async def test_oversize_header_fetch_failure_is_retried(settings, state, server, monkeypatch):
    settings.limits.max_message_bytes = 2000
    u1 = server.deliver(raw=eml("grande", size=5000))
    await set_cursor(state, last=0)
    cls = server.client_class
    original_fetch = cls.fetch
    failed = {"n": 0}

    def fetch(self, messages, data, modifiers=None):
        if any("HEADER" in str(d) for d in data) and failed["n"] == 0:
            failed["n"] += 1
            raise IMAPClientAbortError("socket error: EOF")  # se corta justo al pedir los headers
        return original_fetch(self, messages, data, modifiers)

    monkeypatch.setattr(cls, "fetch", fetch)
    conn = make_conn(settings, state)
    emit = Collector()
    async with Running(conn, emit):
        await eventually(lambda: emit.uids == [u1], what="reintento tras reconectar")
    assert emit.items[0].truncated is True and failed["n"] == 1
    assert len(server.clients) >= 2  # reconectó; el cursor no había avanzado
    assert (await get_cursor(state))[1] == str(u1)


async def test_oversize_poison_message_is_skipped_after_max_attempts(settings, state, server):
    settings.limits.max_message_bytes = 2000
    u1, u2 = server.deliver(raw=eml("grande", size=5000)), server.deliver()
    server.fail_body_uids = {u1}  # también falla BODY.PEEK[HEADER]
    await set_cursor(state, last=0)
    conn = make_conn(settings, state)
    conn.MAX_UID_ATTEMPTS = 2
    emit = Collector()
    async with Running(conn, emit):
        await eventually(lambda: emit.uids == [u2], what="saltear el mensaje veneno")
    assert conn._status["INBOX"].skipped == 1


async def test_emit_failure_does_not_advance_cursor_and_retries(settings, state, server):
    server.deliver()
    await set_cursor(state, last=0)
    conn = make_conn(settings, state)
    emit = Collector()
    emit.fail_next = 1
    async with Running(conn, emit):
        await eventually(lambda: emit.uids == [1], what="reintento de emit")
        await eventually(lambda: idling(server))
    assert (await get_cursor(state))[1] == "1"
    assert len(server.clients) >= 2  # reconectó tras el error


async def test_poison_message_is_skipped_after_max_attempts(settings, state, server, caplog):
    caplog.set_level(logging.ERROR)
    u1, u2, u3 = server.deliver(), server.deliver(), server.deliver()
    server.fail_body_uids = {u2}
    await set_cursor(state, last=0)
    conn = make_conn(settings, state)
    conn.MAX_UID_ATTEMPTS = 3
    emit = Collector()
    async with Running(conn, emit):
        await eventually(lambda: emit.uids == [u1, u3], what="saltear el mensaje veneno")
    assert (await get_cursor(state))[1] == str(u3)
    assert f"UID {u2}" in caplog.text


async def test_message_expunged_between_size_and_body_is_skipped(settings, state, server, monkeypatch):
    u1, u2 = server.deliver(), server.deliver()
    await set_cursor(state, last=0)
    cls = server.client_class
    original_fetch = cls.fetch

    def fetch(self, messages, data, modifiers=None):
        if any("BODY" in str(d) for d in data) and list(messages) == [u1]:
            server.folders["INBOX"].messages.pop(u1, None)  # lo borraron justo antes
        return original_fetch(self, messages, data, modifiers)

    monkeypatch.setattr(cls, "fetch", fetch)
    conn = make_conn(settings, state)
    emit = Collector()
    async with Running(conn, emit):
        await eventually(lambda: emit.uids == [u2])
    assert (await get_cursor(state))[1] == str(u2)


# --------------------------------------------------------------------------- tiempo real


async def test_idle_new_mail_arrives_in_real_time(settings, state, server):
    conn = make_conn(settings, state)
    conn.IDLE_RENEW_S = 60
    emit = Collector()
    async with Running(conn, emit):
        await eventually(lambda: idling(server))
        for _ in range(3):
            server.deliver()
            await eventually(lambda n=len(emit.items): len(emit.items) == n + 1, within=2)
    assert emit.uids == [1, 2, 3]
    assert not server.calls_of("noop")
    assert conn._status["INBOX"].mode == "idle"


async def test_mail_arriving_during_fetch_is_not_left_waiting_for_idle_renewal(settings, state, server):
    """Un EXISTS que llega mientras se baja otro mail (fuera de IDLE) no debe esperar 10 minutos."""
    conn = make_conn(settings, state)
    conn.IDLE_RENEW_S = 600

    def on_emit(raw):
        if len(emit.items) == 1:
            server.deliver()  # llega otro justo ahora

    emit = Collector(on_emit=on_emit)
    async with Running(conn, emit):
        await eventually(lambda: idling(server))
        server.deliver()
        await eventually(lambda: len(emit.items) == 2, within=2, what="segundo mail sin esperar renovación")


async def test_idle_is_renewed_periodically(settings, state, server):
    conn = make_conn(settings, state)
    conn.IDLE_RENEW_S = 0.1
    emit = Collector()
    async with Running(conn, emit):
        await eventually(lambda: len(server.calls_of("idle")) >= 3, what="renovación de IDLE")
    assert len(server.calls_of("idle_done")) >= 2
    assert len(server.clients) == 1  # renovar no implica reconectar


async def test_polling_when_server_has_no_idle(settings, state, monkeypatch):
    srv = FakeServer(capabilities=(b"IMAP4REV1",))
    monkeypatch.setattr(imap_mod, "IMAPClient", srv.client_class)
    conn = make_conn(settings, state, poll_interval_s=1)
    emit = Collector()
    async with Running(conn, emit):
        await eventually(lambda: conn._status["INBOX"].connected)
        srv.deliver()
        await eventually(lambda: len(emit.items) == 1, within=4, what="polling")
    assert srv.calls_of("noop")
    assert not srv.calls_of("idle")
    assert conn._status["INBOX"].mode == "poll"


async def test_idle_disabled_in_config_uses_polling(settings, state, server):
    conn = make_conn(settings, state, idle=False, poll_interval_s=1)
    emit = Collector()
    async with Running(conn, emit):
        await eventually(lambda: conn._status["INBOX"].connected)
        server.deliver()
        await eventually(lambda: len(emit.items) == 1, within=4)
    assert not server.calls_of("idle")


async def test_stop_is_noticed_quickly_during_idle_with_default_timing(settings, state, server):
    conn = make_conn(settings, state)
    conn.IDLE_CHECK_S = ImapConnector.IDLE_CHECK_S  # valor real (1 s)
    emit = Collector()
    stop = asyncio.Event()
    task = asyncio.create_task(conn.run(emit, stop))
    await eventually(lambda: idling(server))
    t0 = time.monotonic()
    stop.set()
    await asyncio.wait_for(task, timeout=5)
    assert time.monotonic() - t0 < 2.5
    assert server.calls_of("idle_done") and server.calls_of("logout")
    assert gauge() == 0


# --------------------------------------------------------------------------- reconexión


async def test_connection_drop_reconnects_and_catches_up(settings, state, server, caplog):
    caplog.set_level(logging.WARNING)
    conn = make_conn(settings, state)
    emit = Collector()
    async with Running(conn, emit):
        await eventually(lambda: idling(server))
        assert gauge() == 1
        server.fail("connect", ConnectionRefusedError("connection refused"), times=2)
        server.fail("idle_check", ConnectionResetError("connection reset by peer"))
        uid = server.deliver()  # llega mientras estamos desconectados
        await eventually(lambda: emit.uids == [uid], what="mail recuperado tras reconectar")
        await eventually(lambda: idling(server))
        assert gauge() == 1
        health = await conn.healthcheck()
        assert health["ok"] is True
    assert len(server.clients) >= 2
    assert "connection reset" in (health["folders"]["INBOX"]["last_error"] or "").lower() or "refused" in (
        health["folders"]["INBOX"]["last_error"] or ""
    )
    assert "reintento" in caplog.text


async def test_server_bye_triggers_reconnect(settings, state, server, monkeypatch):
    conn = make_conn(settings, state)
    emit = Collector()
    cls = server.client_class
    original = cls.idle_check
    fired = {"n": 0}

    def idle_check(self, timeout=None):
        if fired["n"] == 0:
            fired["n"] += 1
            return [(b"BYE", b"Server shutting down")]
        return original(self, timeout)

    monkeypatch.setattr(cls, "idle_check", idle_check)
    async with Running(conn, emit):
        await eventually(lambda: len(server.clients) >= 2, what="reconexión tras BYE")
        await eventually(lambda: idling(server))
        uid = server.deliver()
        await eventually(lambda: emit.uids == [uid])
    assert "BYE" in conn._status["INBOX"].last_error


async def test_wrong_password_keeps_retrying_without_crashing(settings, state, server, caplog):
    caplog.set_level(logging.ERROR)
    conn = make_conn(settings, state, password="incorrecta")
    emit = Collector()
    async with Running(conn, emit):
        await eventually(lambda: len(server.calls_of("login")) >= 3, what="reintentos de login")
        health = await conn.healthcheck()
        assert health["ok"] is False
        assert gauge() == 0
    assert "contraseña" in health["folders"]["INBOX"]["last_error"]
    assert "incorrecta" not in caplog.text  # el password nunca va a los logs
    assert not server.calls_of("select")


async def test_non_ascii_password_does_not_leak_into_logs(settings, state, server, caplog):
    caplog.set_level(logging.DEBUG)
    conn = make_conn(settings, state, password="ClaveñSecreta2026")
    async with Running(conn, Collector()):
        await eventually(lambda: conn._status["INBOX"].last_error is not None)
    err = conn._status["INBOX"].last_error
    assert "no ASCII" in err
    for leak in ("Clave", "Secreta", "\\xf1", "position"):
        assert leak not in err and leak not in caplog.text


async def test_auth_failures_wait_at_least_the_auth_floor(settings, state, server):
    conn = make_conn(settings, state, password="incorrecta")
    conn.AUTH_RETRY_MIN_S = 0.5
    emit = Collector()
    async with Running(conn, emit):
        await asyncio.sleep(0.8)
    assert len(server.calls_of("login")) <= 2  # sin el piso serían decenas


async def test_missing_folder_retries_and_other_folders_keep_working(settings, state, server):
    conn = make_conn(settings, state, folders=["INBOX", "NoExiste"])
    emit = Collector()
    async with Running(conn, emit):
        await eventually(lambda: idling(server, "INBOX"))
        uid = server.deliver()
        await eventually(lambda: emit.uids == [uid])
        await eventually(lambda: conn._status["NoExiste"].last_error is not None)
        health = await conn.healthcheck()
    assert health["ok"] is False
    assert health["folders"]["INBOX"]["connected"] is True
    assert "NONEXISTENT" in health["folders"]["NoExiste"]["last_error"]
    assert gauge() == 0  # no todas las carpetas están arriba


async def test_multiple_folders_have_independent_cursors(settings, state, monkeypatch):
    srv = FakeServer(folders=("INBOX", "Spam"))
    monkeypatch.setattr(imap_mod, "IMAPClient", srv.client_class)
    conn = make_conn(settings, state, folders=["INBOX", "Spam", "INBOX"])
    assert conn.folders == ["INBOX", "Spam"]
    emit = Collector()
    async with Running(conn, emit):
        await eventually(lambda: idling(srv, "INBOX") and idling(srv, "Spam"))
        srv.deliver("Spam")
        srv.deliver("Spam")
        srv.deliver("INBOX")
        await eventually(lambda: len(emit.items) == 3)
        assert gauge() == 1
    by_folder = sorted((r.ref.folder, r.ref.remote_id) for r in emit.items)
    assert by_folder == [("INBOX", "INBOX:1000:1"), ("Spam", "Spam:1000:1"), ("Spam", "Spam:1000:2")]
    assert await get_cursor(state, "Spam") == ("1000", "2")
    assert await get_cursor(state, "INBOX") == ("1000", "1")


async def test_no_folders_waits_for_stop(settings, state, server):
    conn = make_conn(settings, state, folders=[])
    stop = asyncio.Event()
    task = asyncio.create_task(conn.run(Collector(), stop))
    await asyncio.sleep(0.05)
    assert not task.done()
    stop.set()
    await asyncio.wait_for(task, 1)
    assert not server.clients


# --------------------------------------------------------------------------- TLS


async def test_ssl_connection_verifies_certificates(settings, state, server):
    conn = make_conn(settings, state)
    async with Running(conn, Collector()):
        await eventually(lambda: idling(server))
    c = server.clients[0]
    assert c.ssl is True and c.port == 993
    assert isinstance(c.ssl_context, ssl.SSLContext)
    assert c.ssl_context.verify_mode == ssl.CERT_REQUIRED and c.ssl_context.check_hostname
    assert isinstance(c.timeout, SocketTimeout) and c.timeout.connect and c.timeout.read
    assert c.normalise_times is False


async def test_starttls_negotiated_with_verification_before_login(settings, state, server):
    server.capabilities.add(b"STARTTLS")
    conn = make_conn(settings, state, security="starttls", port=143)
    async with Running(conn, Collector()):
        await eventually(lambda: idling(server))
    c = server.clients[0]
    assert c.ssl is False and c.port == 143
    assert c.starttls_context.verify_mode == ssl.CERT_REQUIRED and c.starttls_context.check_hostname
    order = [m for cid, m, _ in server.calls if cid == 0]
    assert order.index("starttls") < order.index("login")


async def test_starttls_missing_never_sends_credentials(settings, state, server):
    conn = make_conn(settings, state, security="starttls", port=143)
    async with Running(conn, Collector()):
        await eventually(lambda: len(server.calls_of("starttls")) >= 2)
        health = await conn.healthcheck()
    assert not server.calls_of("login")
    assert "STARTTLS" in health["folders"]["INBOX"]["last_error"]


# --------------------------------------------------------------------------- apply_verdict


async def _ref_for(server, folder="INBOX") -> MessageRef:
    uid = server.deliver(folder)
    v = server.folders[folder].uidvalidity
    return MessageRef(connector=NAME, mailbox=USER, remote_id=make_remote_id(folder, v, uid), folder=folder)


async def test_apply_verdict_keyword_with_wildcard_permanentflags(settings, state, server):
    ref = await _ref_for(server)
    conn = make_conn(settings, state)
    out = await conn.apply_verdict(ref, result_for(ref, VerdictLevel.MALICIOUS), TagConfig())
    assert out == f"imap:keyword:{KEYWORD_MALICIOUS}"
    msg = server.folders["INBOX"].messages[1]
    assert KEYWORD_MALICIOUS.encode() in msg.flags
    assert b"\\Seen" not in msg.flags
    # conexión aparte, en lectura-escritura, cerrada al terminar
    assert server.calls_of("select")[-1][2] == ("INBOX", False)
    assert server.clients[-1].closed
    assert not server.calls_of("add_gmail_labels")


async def test_apply_verdict_suspicious_keyword(settings, state, server):
    ref = await _ref_for(server)
    conn = make_conn(settings, state)
    out = await conn.apply_verdict(ref, result_for(ref, VerdictLevel.SUSPICIOUS), TagConfig())
    assert out == f"imap:keyword:{KEYWORD_SUSPICIOUS}"


async def test_apply_verdict_uses_gmail_labels_when_available(settings, state, server):
    server.capabilities.add(b"X-GM-EXT-1")
    ref = await _ref_for(server)
    conn = make_conn(settings, state)
    tag = TagConfig()
    out = await conn.apply_verdict(ref, result_for(ref, VerdictLevel.MALICIOUS), tag)
    assert out == f"imap:gmlabel:{tag.label_malicious}"
    assert server.folders["INBOX"].messages[1].labels == {tag.label_malicious}
    assert not server.calls_of("add_flags")


async def test_apply_verdict_gmail_label_created_when_missing(settings, state, server):
    server.capabilities.add(b"X-GM-EXT-1")
    server.gmail_label_must_exist = True
    ref = await _ref_for(server)
    conn = make_conn(settings, state)
    out = await conn.apply_verdict(ref, result_for(ref, VerdictLevel.SUSPICIOUS), TagConfig())
    assert out == "imap:gmlabel:Centinela/Sospechoso"
    assert server.created_folders == ["Centinela/Sospechoso"]


async def test_apply_verdict_without_wildcard_does_nothing(settings, state, server):
    server.folders["INBOX"].permanentflags = (b"\\Seen", b"\\Flagged", b"\\Deleted")
    ref = await _ref_for(server)
    conn = make_conn(settings, state)
    out = await conn.apply_verdict(ref, result_for(ref, VerdictLevel.MALICIOUS), TagConfig())
    assert out is None
    assert not server.calls_of("add_flags")
    assert server.folders["INBOX"].messages[1].flags == set()


async def test_apply_verdict_keyword_already_permitted_without_wildcard(settings, state, server):
    server.folders["INBOX"].permanentflags = (b"\\Seen", KEYWORD_MALICIOUS.encode())
    ref = await _ref_for(server)
    conn = make_conn(settings, state)
    out = await conn.apply_verdict(ref, result_for(ref, VerdictLevel.MALICIOUS), TagConfig())
    assert out == f"imap:keyword:{KEYWORD_MALICIOUS}"


async def test_apply_verdict_without_permanentflags_assumes_allowed(settings, state, server):
    server.folders["INBOX"].permanentflags = None
    ref = await _ref_for(server)
    conn = make_conn(settings, state)
    out = await conn.apply_verdict(ref, result_for(ref, VerdictLevel.SUSPICIOUS), TagConfig())
    assert out == f"imap:keyword:{KEYWORD_SUSPICIOUS}"


@pytest.mark.parametrize(
    ("level", "tag_kwargs", "conn_kwargs"),
    [
        (VerdictLevel.CLEAN, {}, {}),
        (VerdictLevel.ERROR, {}, {}),
        (VerdictLevel.SUSPICIOUS, {"min_level": "malicious"}, {}),
        (VerdictLevel.MALICIOUS, {"enabled": False}, {}),
        (VerdictLevel.MALICIOUS, {}, {"tag": False}),
        (VerdictLevel.MALICIOUS, {}, {"tag_mode": "none"}),
    ],
)
async def test_apply_verdict_skips_without_connecting(
    settings, state, server, level, tag_kwargs, conn_kwargs
):
    ref = await _ref_for(server)
    conn = make_conn(settings, state, **conn_kwargs)
    out = await conn.apply_verdict(ref, result_for(ref, level), TagConfig(**tag_kwargs))
    assert out is None
    assert server.clients == []


async def test_apply_verdict_min_level_malicious_tags_malicious(settings, state, server):
    ref = await _ref_for(server)
    conn = make_conn(settings, state)
    out = await conn.apply_verdict(
        ref, result_for(ref, VerdictLevel.MALICIOUS), TagConfig(min_level="malicious")
    )
    assert out == f"imap:keyword:{KEYWORD_MALICIOUS}"


async def test_apply_verdict_uidvalidity_mismatch_does_not_tag(settings, state, server):
    ref = await _ref_for(server)
    server.renumber(new_validity=5555)
    conn = make_conn(settings, state)
    out = await conn.apply_verdict(ref, result_for(ref, VerdictLevel.MALICIOUS), TagConfig())
    assert out is None
    assert not server.calls_of("add_flags")


async def test_apply_verdict_message_gone_or_bad_ref(settings, state, server):
    ref = await _ref_for(server)
    server.folders["INBOX"].messages.clear()
    conn = make_conn(settings, state)
    assert await conn.apply_verdict(ref, result_for(ref, VerdictLevel.MALICIOUS), TagConfig()) is None
    bad = MessageRef(connector=NAME, mailbox=USER, remote_id="basura")
    assert await conn.apply_verdict(bad, result_for(bad, VerdictLevel.MALICIOUS), TagConfig()) is None
    other = MessageRef(connector="otro", mailbox=USER, remote_id="INBOX:1000:1")
    assert await conn.apply_verdict(other, result_for(other, VerdictLevel.MALICIOUS), TagConfig()) is None
    assert not server.calls_of("add_flags")


async def test_apply_verdict_retries_transient_error_once(settings, state, server):
    ref = await _ref_for(server)
    server.fail("connect", TimeoutError("timed out"))
    conn = make_conn(settings, state)
    out = await conn.apply_verdict(ref, result_for(ref, VerdictLevel.MALICIOUS), TagConfig())
    assert out == f"imap:keyword:{KEYWORD_MALICIOUS}"


async def test_apply_verdict_transient_failure_retries_once_then_raises(settings, state, server):
    """Contrato: string si etiquetó, None si no corresponde, y EXCEPCIÓN ante una falla real."""
    ref = await _ref_for(server)
    server.fail("connect", OSError("network unreachable"), times=2)
    conn = make_conn(settings, state)
    with pytest.raises(OSError, match="unreachable"):
        await conn.apply_verdict(ref, result_for(ref, VerdictLevel.MALICIOUS), TagConfig())
    assert not server.failures["connect"]  # se intentó 2 veces
    health = await conn.healthcheck()
    assert "unreachable" in health["last_tag_error"] and health["last_tag_error_at"]
    assert health["last_tag"] is None
    assert not server.folders["INBOX"].messages[1].flags


async def test_apply_verdict_store_error_raises_without_retry(settings, state, server, monkeypatch):
    ref = await _ref_for(server)

    def add_flags(self, messages, flags, silent=False):
        raise IMAPClientError("STORE failed: [READ-ONLY]")

    monkeypatch.setattr(server.client_class, "add_flags", add_flags)
    conn = make_conn(settings, state)
    with pytest.raises(IMAPClientError, match="READ-ONLY"):
        await conn.apply_verdict(ref, result_for(ref, VerdictLevel.MALICIOUS), TagConfig())
    assert len(server.clients) == 1  # error del servidor, no transitorio: no se reintenta
    assert server.clients[0].closed  # la conexión de etiquetado se cerró igual
    assert "READ-ONLY" in (await conn.healthcheck())["last_tag_error"]


async def test_apply_verdict_wrong_password_raises_without_retry(settings, state, server, caplog):
    caplog.set_level(logging.DEBUG)
    ref = await _ref_for(server)
    conn = make_conn(settings, state, password="incorrecta")
    with pytest.raises(LoginError):
        await conn.apply_verdict(ref, result_for(ref, VerdictLevel.MALICIOUS), TagConfig())
    assert len(server.calls_of("login")) == 1  # reintentar un password rechazado puede bloquear la cuenta
    assert "incorrecta" not in caplog.text
    assert "incorrecta" not in (await conn.healthcheck())["last_tag_error"]


async def test_dispatcher_records_tag_error_and_success(settings, state, server):
    """Integración con el dispatcher: una falla real se cuenta como `tag:<conector>:error`."""
    from centinela.actions.dispatcher import ActionDispatcher
    from centinela.core.cache import MemoryCache

    ref = await _ref_for(server)
    conn = make_conn(settings, state)
    dispatcher = ActionDispatcher(settings, MemoryCache(), {NAME: conn}, [])
    server.fail("connect", OSError("network unreachable"), times=2)
    assert await dispatcher.dispatch(result_for(ref, VerdictLevel.MALICIOUS)) == [f"tag:{NAME}:error"]
    assert await dispatcher.dispatch(result_for(ref, VerdictLevel.MALICIOUS)) == [
        f"tag:imap:keyword:{KEYWORD_MALICIOUS}"
    ]


def test_tag_retry_budget_fits_dispatcher_timeout():
    """2 intentos + la pausa deben entrar en el timeout de etiquetado del dispatcher (si no, la cancela)."""
    import inspect

    from centinela.actions.dispatcher import ActionDispatcher

    default = inspect.signature(ActionDispatcher.__init__).parameters["tag_timeout_s"].default
    budget = 2 * ImapConnector.VERDICT_TIMEOUT_S + ImapConnector.VERDICT_RETRY_DELAY_S
    assert budget < default


async def test_tagging_does_not_disturb_running_readonly_session(settings, state, server):
    conn = make_conn(settings, state)
    emit = Collector()
    async with Running(conn, emit):
        await eventually(lambda: idling(server))
        uid = server.deliver()
        await eventually(lambda: len(emit.items) == 1)
        ref = emit.items[0].ref
        out = await conn.apply_verdict(ref, result_for(ref, VerdictLevel.SUSPICIOUS), TagConfig())
        assert out == f"imap:keyword:{KEYWORD_SUSPICIOUS}"
        await eventually(lambda: idling(server))
    readonly_selects = [c for c in server.calls_of("select") if c[2][1] is True]
    rw_selects = [c for c in server.calls_of("select") if c[2][1] is False]
    assert len(rw_selects) == 1 and readonly_selects
    assert server.folders["INBOX"].messages[uid].flags == {KEYWORD_SUSPICIOUS.encode()}


# --------------------------------------------------------------------------- salud / diagnóstico


async def test_healthcheck_reports_connection_state(settings, state, server):
    conn = make_conn(settings, state)
    before = await conn.healthcheck()
    assert before["ok"] is False and before["last_connect"] is None
    async with Running(conn, Collector()):
        await eventually(lambda: idling(server))
        h = await conn.healthcheck()
    assert h["ok"] is True
    assert h["type"] == "imap" and h["host"] == "imap.example.com" and h["auth"] == "password"
    assert h["last_connect"] is not None
    assert h["folders"]["INBOX"]["mode"] == "idle"
    assert h["folders"]["INBOX"]["uidvalidity"] == 1000
    assert "app-pass" not in repr(h)
    after = await conn.healthcheck()
    assert after["ok"] is False


async def test_check_connection(settings, state, server):
    for _ in range(2):
        server.deliver()
    conn = make_conn(settings, state)
    out = await conn.check_connection()
    assert out["ok"] is True and out["idle"] is True
    assert out["folders"]["INBOX"]["UIDNEXT"] == 3
    bad = make_conn(settings, state, password="mala")
    out = await bad.check_connection()
    assert out["ok"] is False and "LoginError" in out["error"]


# --------------------------------------------------------------------------- XOAUTH2 (msal / google mockeados)


class FakeMsalApp:
    instances: list[FakeMsalApp] = []
    responses: list[dict] = []

    def __init__(self, client_id, authority=None, timeout=None, **kwargs):
        self.client_id, self.authority, self.timeout = client_id, authority, timeout
        self.calls: list[tuple[str, list[str]]] = []
        FakeMsalApp.instances.append(self)

    def acquire_token_by_refresh_token(self, refresh_token, scopes, **kwargs):
        self.calls.append((refresh_token, list(scopes)))
        return FakeMsalApp.responses.pop(0)


@pytest.fixture
def fake_msal(monkeypatch):
    import msal

    FakeMsalApp.instances = []
    FakeMsalApp.responses = []
    monkeypatch.setattr(msal, "PublicClientApplication", FakeMsalApp)
    return FakeMsalApp


MS_OAUTH = {"provider": "microsoft", "client_id": "cid-123", "tenant": "organizations"}


async def test_xoauth2_microsoft_refresh_login_and_rotation(settings, state, server, fake_msal, caplog):
    caplog.set_level(logging.DEBUG)
    server.tokens = {"AT-SECRET-1"}
    await state.set_secret(f"connector:{NAME}:imap_refresh_token", "RT-SECRET-1")
    fake_msal.responses = [
        {"access_token": "AT-SECRET-1", "refresh_token": "RT-SECRET-2", "expires_in": 3600}
    ]
    conn = make_conn(settings, state, password=None, oauth2=MS_OAUTH)
    emit = Collector()
    async with Running(conn, emit):
        await eventually(lambda: idling(server))
        uid = server.deliver()
        await eventually(lambda: emit.uids == [uid])
    app = fake_msal.instances[0]
    assert app.authority == "https://login.microsoftonline.com/organizations"
    assert app.calls == [("RT-SECRET-1", ["https://outlook.office.com/IMAP.AccessAsUser.All"])]
    assert server.calls_of("oauth2_login")[0][2] == (USER, "AT-SECRET-1")
    assert not server.calls_of("login")
    assert await state.get_secret(f"connector:{NAME}:imap_refresh_token") == "RT-SECRET-2"
    for secret in ("AT-SECRET-1", "RT-SECRET-1", "RT-SECRET-2"):
        assert secret not in caplog.text
    assert (await conn.healthcheck())["auth"] == "oauth2:microsoft"


async def test_xoauth2_rejected_token_is_refreshed_on_next_attempt(settings, state, server, fake_msal):
    server.tokens = {"AT-2"}
    await state.set_secret(f"connector:{NAME}:imap_refresh_token", "RT-1")
    fake_msal.responses = [
        {"access_token": "AT-1", "expires_in": 3600},  # revocado del lado del server
        {"access_token": "AT-2", "expires_in": 3600},
    ]
    conn = make_conn(settings, state, password=None, oauth2=MS_OAUTH)
    async with Running(conn, Collector()):
        await eventually(lambda: idling(server), what="login con token renovado")
    tokens = [c[2][1] for c in server.calls_of("oauth2_login")]
    assert tokens == ["AT-1", "AT-2"]
    # sin rotación informada, el refresh token original sigue guardado
    assert await state.get_secret(f"connector:{NAME}:imap_refresh_token") == "RT-1"


async def test_xoauth2_without_refresh_token_asks_for_auth(settings, state, server, fake_msal):
    conn = make_conn(settings, state, password=None, oauth2=MS_OAUTH)
    async with Running(conn, Collector()):
        await eventually(lambda: conn._status["INBOX"].last_error is not None)
    assert "centinela auth buzon" in conn._status["INBOX"].last_error
    assert server.clients == []  # ni siquiera se conecta
    assert fake_msal.instances == []


async def test_xoauth2_invalid_grant_asks_for_reauth(settings, state, server, fake_msal):
    await state.set_secret(f"connector:{NAME}:imap_refresh_token", "RT-1")
    fake_msal.responses = [
        {"error": "invalid_grant", "error_description": "AADSTS70008: The refresh token has expired."}
    ] * 20
    conn = make_conn(settings, state, password=None, oauth2=MS_OAUTH)
    async with Running(conn, Collector()):
        await eventually(lambda: conn._status["INBOX"].last_error is not None)
    err = conn._status["INBOX"].last_error
    assert "centinela auth buzon" in err and "invalid_grant" in err
    assert server.clients == []


async def test_xoauth2_google_refresh(settings, state, server, monkeypatch):
    from google.oauth2 import credentials as gcreds

    created = []

    class FakeCreds:
        def __init__(
            self,
            token=None,
            refresh_token=None,
            token_uri=None,
            client_id=None,
            client_secret=None,
            scopes=None,
        ):
            self.token, self.refresh_token = token, refresh_token
            self.kwargs = {
                "token_uri": token_uri,
                "client_id": client_id,
                "client_secret": client_secret,
                "scopes": scopes,
            }
            self.expiry = None
            created.append(self)

        def refresh(self, request):
            self.token = "G-AT-1"
            self.expiry = datetime.now(UTC).replace(tzinfo=None) + timedelta(hours=1)

    monkeypatch.setattr(gcreds, "Credentials", FakeCreds)
    server.tokens = {"G-AT-1"}
    await state.set_secret(f"connector:{NAME}:imap_refresh_token", "G-RT-1")
    oauth = {"provider": "google", "client_id": "gid.apps.googleusercontent.com", "client_secret": "gsecret"}
    conn = make_conn(settings, state, password=None, oauth2=oauth, username="ventas@gmail.com")
    async with Running(conn, Collector()):
        await eventually(lambda: idling(server))
    assert created[0].kwargs["scopes"] == ["https://mail.google.com/"]
    assert created[0].kwargs["token_uri"] == "https://oauth2.googleapis.com/token"
    assert created[0].kwargs["client_secret"] == "gsecret"
    assert server.calls_of("oauth2_login")[0][2] == ("ventas@gmail.com", "G-AT-1")
    assert await state.get_secret(f"connector:{NAME}:imap_refresh_token") == "G-RT-1"


async def test_oauth_tagging_uses_token(settings, state, server, fake_msal):
    server.tokens = {"AT-1"}
    await state.set_secret(f"connector:{NAME}:imap_refresh_token", "RT-1")
    fake_msal.responses = [{"access_token": "AT-1", "expires_in": 3600}]
    ref = await _ref_for(server)
    conn = make_conn(settings, state, password=None, oauth2=MS_OAUTH)
    out = await conn.apply_verdict(ref, result_for(ref, VerdictLevel.MALICIOUS), TagConfig())
    assert out == f"imap:keyword:{KEYWORD_MALICIOUS}"
    assert server.calls_of("oauth2_login")[0][2] == (USER, "AT-1")
