from __future__ import annotations

import asyncio
import email
import hashlib
import logging
import random
import socket
import struct
import time
from email.header import decode_header, make_header

import pytest

from centinela.connectors import connector_class
from centinela.connectors import milter as m
from centinela.connectors.milter import MilterConnector, prefixed_subject
from centinela.core.config import MilterConnectorConfig
from centinela.core.models import AnalysisResult, RawMessage, Verdict, VerdictLevel
from centinela.core.state import MemoryStateStore
from tests.connectors_smtp.milter_client import (
    ALL_ACTIONS,
    V2_ACTIONS,
    V2_PROTOCOL,
    MilterClient,
    decode_reply,
)

HEADERS = [
    ("Received", "from mx.proveedor.com (mx.proveedor.com [203.0.113.7])\n\tby mx.empresa.com"),
    ("From", "Juan <juan@proveedor.com>"),
    ("To", "ventas@empresa.com"),
    ("Subject", "Factura pendiente"),
    ("Message-ID", "<abc-1@proveedor.com>"),
]
BODY = [b"Hola,\r\n", b"adjunto la factura SECRETO-DEL-CUERPO.\r\n"]


class FakeEmit:
    """emit inline falso: devuelve un AnalysisResult con el veredicto pedido."""

    def __init__(
        self,
        level: VerdictLevel = VerdictLevel.MALICIOUS,
        *,
        score: int = 95,
        families: list[str] | None = None,
        delay: float = 0.0,
        exc: Exception | None = None,
        return_none: bool = False,
    ) -> None:
        self.level, self.score, self.families = level, score, families or []
        self.delay, self.exc, self.return_none = delay, exc, return_none
        self.received: list[RawMessage] = []
        self.results: list[AnalysisResult] = []
        self.finished = asyncio.Event()

    async def __call__(self, raw: RawMessage) -> AnalysisResult | None:
        self.received.append(raw)
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.exc:
            raise self.exc
        result = AnalysisResult(
            ref=raw.ref,
            received_at=raw.received_at,
            verdict=Verdict(
                level=self.level, score=self.score, summary="prueba", malware_families=self.families
            ),
        )
        self.results.append(result)
        self.finished.set()
        return None if self.return_none else result


@pytest.fixture
async def start_milter(settings):
    running: list[tuple[MilterConnector, asyncio.Event, asyncio.Task]] = []

    async def _start(emit, **overrides) -> MilterConnector:
        cfg = MilterConnectorConfig(
            type="milter",
            name="mta",
            listen_host="127.0.0.1",
            listen_port=overrides.pop("listen_port", 0),
            **overrides,
        )
        conn = MilterConnector(cfg, settings, MemoryStateStore())
        stop = asyncio.Event()
        task = asyncio.create_task(conn.run(emit, stop))
        await asyncio.wait_for(conn.ready.wait(), 5)
        running.append((conn, stop, task))
        return conn

    yield _start
    for _, stop, task in running:
        stop.set()
        await asyncio.wait_for(task, 20)


def decoded(replies):
    return [decode_reply(c, d) for c, d in replies]


# --------------------------------------------------------------------------- flujo completo


async def test_registry_resolves_milter_type():
    assert connector_class("milter") is MilterConnector
    assert MilterConnector.inline is True
    assert MilterConnector.type == "milter"


async def test_full_flow_postfix_v6(start_milter, caplog):
    caplog.set_level(logging.DEBUG)
    emit = FakeEmit(VerdictLevel.MALICIOUS, score=97, families=["AgentTesla", "Formbook"])
    conn = await start_milter(emit, subject_prefix="[PELIGRO] ", inline_timeout_s=5)
    client = await MilterClient.connect(conn.port)

    version, actions, pflags = await client.negotiate()
    assert version == 6
    assert actions == m.SMFIF_ADDHDRS | m.SMFIF_CHGHDRS  # nada de reject/discard/cambiar cuerpo
    assert pflags == m.WANTED_PROTOCOL
    assert pflags & m.SMFIP_NR_HDR and pflags & m.SMFIP_NR_BODY and not pflags & m.SMFIP_NORCPT

    headers = [
        *HEADERS,
        ("X-Centinela-Verdict", "clean"),  # falsificado por el atacante
        ("x-centinela-score", "0"),  # falsificado (otra capitalización)
        ("X-Centinela-Verdict", "clean"),  # segundo falsificado con el mismo nombre
    ]
    await client.macro(b"C", j="mx.empresa.com", _="mx.proveedor.com [203.0.113.7]")
    replies = await client.message(
        rcpts=["Ventas@Empresa.com", "compras@empresa.com"],
        headers=headers,
        body_chunks=BODY,
        queue_id="4F2A1B3C",
    )
    got = decoded(replies)

    assert len(emit.results) == 1
    result_id = str(emit.results[0].id)
    assert got == [
        ("chg", 2, "X-Centinela-Verdict", ""),
        ("chg", 1, "X-Centinela-Verdict", ""),
        ("chg", 1, "x-centinela-score", ""),
        ("add", "X-Centinela-Verdict", "malicious"),
        ("add", "X-Centinela-Score", "97"),
        ("add", "X-Centinela-Families", "AgentTesla, Formbook"),
        ("add", "X-Centinela-Id", result_id),
        ("chg", 1, "Subject", "[PELIGRO] Factura pendiente"),
        ("a",),
    ]

    raw = emit.received[0]
    assert raw.ref.connector == "mta"
    assert raw.ref.mailbox == "ventas@empresa.com"
    # queue id + hash corto (los queue id cortos de Postfix se repiten con el tiempo)
    assert raw.ref.remote_id == "4F2A1B3C#" + hashlib.sha256(raw.raw).hexdigest()[:12]
    # headers en el orden recibido, plegado con CRLF + whitespace, línea en blanco y cuerpo intacto
    assert raw.raw.startswith(
        b"Received: from mx.proveedor.com (mx.proveedor.com [203.0.113.7])\r\n\tby mx.empresa.com\r\nFrom: "
    )
    assert raw.raw.endswith(b"\r\n\r\nHola,\r\nadjunto la factura SECRETO-DEL-CUERPO.\r\n")
    parsed = email.message_from_bytes(raw.raw)
    assert [k for k, _ in parsed.items()] == [h for h, _ in headers]
    assert parsed["Subject"] == "Factura pendiente"

    await client.quit()
    # nunca loguear el cuerpo del mail
    assert "SECRETO-DEL-CUERPO" not in caplog.text


async def test_mta_v2_without_noreply_flags_gets_continue_for_every_command(start_milter):
    emit = FakeEmit(VerdictLevel.CLEAN, score=0)
    conn = await start_milter(emit, subject_prefix="[PELIGRO] ")
    client = await MilterClient.connect(conn.port)

    version, actions, pflags = await client.negotiate(version=2, actions=V2_ACTIONS, pflags=V2_PROTOCOL)
    assert version == 2
    assert actions == m.SMFIF_ADDHDRS | m.SMFIF_CHGHDRS
    assert pflags == m.SMFIP_NOCONNECT | m.SMFIP_NOHELO | m.SMFIP_NOMAIL | m.SMFIP_NOEOH
    assert not pflags & m.SMFIP_NR_HDR

    # sin NR_*: el cliente exige SMFIR_CONTINUE a rcpt, data, cada header y cada chunk (lo verifica command())
    replies = await client.message(
        rcpts=["ventas@empresa.com"], headers=HEADERS, body_chunks=BODY, queue_id="Q2"
    )
    got = decoded(replies)
    assert got[:2] == [("add", "X-Centinela-Verdict", "clean"), ("add", "X-Centinela-Score", "0")]
    assert got[2][1] == "X-Centinela-Id"
    assert got[-1] == ("a",)
    # limpio: nada de asunto modificado ni familias
    assert not any(r[0] == "chg" for r in got)
    assert not any(len(r) > 1 and r[1] == "X-Centinela-Families" for r in got)
    # comandos no pedidos pero enviados igual por un MTA viejo: se responden y no rompen nada
    await client.send(m.SMFIC_UNKNOWN, b"XFOO bar\0")
    assert await client.recv() == (m.SMFIR_CONTINUE, b"")
    await client.send(m.SMFIC_CONNECT, b"mx.proveedor.com\x004\x00\x19203.0.113.7\0")
    assert await client.recv() == (m.SMFIR_CONTINUE, b"")
    await client.quit()


async def test_multiple_messages_on_one_connection_do_not_leak_state(start_milter):
    emit = FakeEmit(VerdictLevel.CLEAN, score=0)
    conn = await start_milter(emit)
    client = await MilterClient.connect(conn.port)
    await client.negotiate()

    r1 = await client.message(
        rcpts=["a@empresa.com"],
        headers=[("Subject", "uno"), ("X-Centinela-Score", "1")],
        body_chunks=[b"primero\r\n"],
        queue_id="QID-1",
    )
    r2 = await client.message(
        rcpts=["b@empresa.com"], headers=[("Subject", "dos")], body_chunks=[b"segundo\r\n"]
    )

    assert decoded(r1)[0] == ("chg", 1, "X-Centinela-Score", "")
    assert not any(r[0] == "chg" for r in decoded(r2))  # el header falsificado era del mensaje 1
    first, second = emit.received
    assert first.ref.remote_id.startswith("QID-1#") and first.ref.mailbox == "a@empresa.com"
    assert second.ref.mailbox == "b@empresa.com"
    # el queue id del mensaje 1 no se filtra al 2 (que no trajo macro "i"): uuid4 hex
    assert "QID-1" not in second.ref.remote_id and len(second.ref.remote_id) == 32
    assert b"primero" not in second.raw and b"uno" not in second.raw
    await client.quit()


async def test_reused_queue_id_does_not_collide(start_milter):
    """Postfix reutiliza queue ids cortos: dos mails distintos con el mismo id no deben compartir ref."""
    emit = FakeEmit(VerdictLevel.CLEAN, score=0)
    conn = await start_milter(emit)
    client = await MilterClient.connect(conn.port)
    await client.negotiate()
    for body in (b"benigno\r\n", b"malicioso\r\n"):
        await client.message(
            rcpts=["ventas@empresa.com"], headers=HEADERS, body_chunks=[body], queue_id="ABC12"
        )
    a, b = (r.ref.remote_id for r in emit.received)
    assert a.startswith("ABC12#") and b.startswith("ABC12#") and a != b
    await client.quit()


# --------------------------------------------------------------------------- timeout / errores


async def test_timeout_accepts_without_verdict_and_analysis_continues(start_milter):
    emit = FakeEmit(VerdictLevel.MALICIOUS, delay=1.0)
    conn = await start_milter(emit, inline_timeout_s=0.2, subject_prefix="[PELIGRO] ")
    client = await MilterClient.connect(conn.port)
    await client.negotiate()

    t0 = time.perf_counter()
    replies = await client.message(
        rcpts=["ventas@empresa.com"],
        headers=[*HEADERS, ("X-Centinela-Verdict", "clean")],
        body_chunks=BODY,
        queue_id="SLOW1",
    )
    elapsed = time.perf_counter() - t0
    # solo se borra el falsificado y se acepta; sin headers de veredicto ni prefijo
    assert decoded(replies) == [("chg", 1, "X-Centinela-Verdict", ""), ("a",)]
    assert elapsed < 0.9
    assert not emit.finished.is_set()
    # el análisis NO se cancela: termina en segundo plano (y las alertas salen después)
    await asyncio.wait_for(emit.finished.wait(), 5)
    assert len(emit.results) == 1
    await asyncio.sleep(0)
    assert (await conn.healthcheck())["pending_analyses"] == 0
    await client.quit()


async def test_emit_exception_still_accepts(start_milter):
    emit = FakeEmit(exc=RuntimeError("pipeline caído"))
    conn = await start_milter(emit, subject_prefix="[PELIGRO] ")
    client = await MilterClient.connect(conn.port)
    await client.negotiate()
    replies = await client.message(
        rcpts=["ventas@empresa.com"], headers=HEADERS, body_chunks=BODY, queue_id="E1"
    )
    assert decoded(replies) == [("a",)]
    # la conexión sigue sana para el próximo mensaje
    replies = await client.message(rcpts=["ventas@empresa.com"], headers=HEADERS, body_chunks=BODY)
    assert decoded(replies) == [("a",)]
    await client.quit()


async def test_emit_returning_none_accepts_without_headers(start_milter):
    emit = FakeEmit(VerdictLevel.MALICIOUS, return_none=True)
    conn = await start_milter(emit, subject_prefix="[PELIGRO] ")
    client = await MilterClient.connect(conn.port)
    await client.negotiate()
    replies = await client.message(rcpts=["ventas@empresa.com"], headers=HEADERS, body_chunks=BODY)
    assert decoded(replies) == [("a",)]
    await client.quit()


async def test_abort_resets_message_state(start_milter):
    emit = FakeEmit(VerdictLevel.CLEAN, score=3)
    conn = await start_milter(emit)
    client = await MilterClient.connect(conn.port)
    await client.negotiate()

    await client.message(
        rcpts=["primero@empresa.com"],
        headers=[("Subject", "abortado"), ("X-Centinela-Verdict", "clean")],
        body_chunks=[b"cuerpo-abortado\r\n"],
        queue_id="ABORTED",
        eob=False,
    )
    await client.send(m.SMFIC_ABORT)  # sin respuesta
    replies = await client.message(
        rcpts=["segundo@empresa.com"], headers=[("Subject", "bueno")], body_chunks=[b"cuerpo-bueno\r\n"]
    )
    got = decoded(replies)
    assert got[-1] == ("a",)
    assert not any(r[0] == "chg" for r in got)  # el falsificado era del mensaje abortado
    assert len(emit.received) == 1
    raw = emit.received[0]
    assert raw.ref.mailbox == "segundo@empresa.com"
    assert "ABORTED" not in raw.ref.remote_id
    assert b"abortado" not in raw.raw
    assert raw.raw == b"Subject: bueno\r\n\r\ncuerpo-bueno\r\n"
    await client.quit()


# --------------------------------------------------------------------------- modificaciones


async def test_tag_false_never_modifies_message(start_milter):
    emit = FakeEmit(VerdictLevel.MALICIOUS, families=["Lumma Stealer"])
    conn = await start_milter(emit, tag=False, subject_prefix="[PELIGRO] ")
    client = await MilterClient.connect(conn.port)
    await client.negotiate()
    replies = await client.message(
        rcpts=["ventas@empresa.com"], headers=[*HEADERS, ("X-Centinela-Verdict", "clean")], body_chunks=BODY
    )
    assert decoded(replies) == [("a",)]
    assert len(emit.results) == 1  # igual se analizó (alertas)
    await client.quit()


async def test_add_headers_false_only_prefixes_subject(start_milter):
    emit = FakeEmit(VerdictLevel.SUSPICIOUS, score=45)
    conn = await start_milter(emit, add_headers=False, subject_prefix="[SOSPECHOSO] ")
    client = await MilterClient.connect(conn.port)
    await client.negotiate()
    replies = await client.message(rcpts=["ventas@empresa.com"], headers=HEADERS, body_chunks=BODY)
    assert decoded(replies) == [("chg", 1, "Subject", "[SOSPECHOSO] Factura pendiente"), ("a",)]
    await client.quit()


async def test_suspicious_without_subject_adds_one(start_milter):
    emit = FakeEmit(VerdictLevel.SUSPICIOUS, score=40)
    conn = await start_milter(emit, add_headers=False, subject_prefix="[SOSPECHOSO] ")
    client = await MilterClient.connect(conn.port)
    await client.negotiate()
    replies = await client.message(
        rcpts=["ventas@empresa.com"], headers=[("From", "x@proveedor.com")], body_chunks=[b"hola\r\n"]
    )
    assert decoded(replies) == [("add", "Subject", "[SOSPECHOSO]"), ("a",)]
    await client.quit()


@pytest.mark.parametrize("level", [VerdictLevel.CLEAN, VerdictLevel.ERROR])
async def test_clean_or_error_never_prefixes_subject(start_milter, level):
    emit = FakeEmit(level, score=0)
    conn = await start_milter(emit, subject_prefix="[PELIGRO] ")
    client = await MilterClient.connect(conn.port)
    await client.negotiate()
    replies = await client.message(rcpts=["ventas@empresa.com"], headers=HEADERS, body_chunks=BODY)
    got = decoded(replies)
    assert ("add", "X-Centinela-Verdict", level.value) in got
    assert not any(r[0] == "chg" for r in got)
    await client.quit()


async def test_subject_already_prefixed_is_not_prefixed_twice(start_milter):
    emit = FakeEmit(VerdictLevel.MALICIOUS)
    conn = await start_milter(emit, add_headers=False, subject_prefix="[PELIGRO] ")
    client = await MilterClient.connect(conn.port)
    await client.negotiate()
    replies = await client.message(
        rcpts=["ventas@empresa.com"], headers=[("Subject", "[PELIGRO] Factura")], body_chunks=[b"x\r\n"]
    )
    assert decoded(replies) == [("a",)]
    await client.quit()


async def test_mta_without_chghdrs_only_adds_headers(start_milter):
    emit = FakeEmit(VerdictLevel.MALICIOUS)
    conn = await start_milter(emit, subject_prefix="[PELIGRO] ")
    client = await MilterClient.connect(conn.port)
    _, actions, _ = await client.negotiate(actions=m.SMFIF_ADDHDRS)
    assert actions == m.SMFIF_ADDHDRS
    replies = await client.message(
        rcpts=["ventas@empresa.com"], headers=[*HEADERS, ("X-Centinela-Verdict", "clean")], body_chunks=BODY
    )
    got = decoded(replies)
    assert all(r[0] in ("add", "a") for r in got)  # sin permiso de cambio: ni borrar ni tocar el asunto
    assert got[-1] == ("a",)
    await client.quit()


async def test_body_over_limit_is_truncated_but_accepted(start_milter, settings):
    settings.limits.max_message_bytes = 2048
    emit = FakeEmit(VerdictLevel.CLEAN, score=0)
    conn = await start_milter(emit)
    client = await MilterClient.connect(conn.port)
    await client.negotiate()
    big = [b"A" * 1000 + b"\r\n"] * 10
    replies = await client.message(rcpts=["ventas@empresa.com"], headers=HEADERS, body_chunks=big)
    got = decoded(replies)
    assert got[-1] == ("a",)
    assert ("add", "X-Centinela-Truncated", "yes") in got
    msg = emit.received[0]
    assert len(msg.raw) <= 2048
    assert msg.raw.startswith(b"Received: ")
    # el pipeline necesita saberlo para el hallazgo policy.message_too_large (con el tamaño real)
    header_bytes = sum(len(f"{n}: {v}".replace("\n", "\r\n").encode()) + 2 for n, v in HEADERS)
    assert msg.truncated is True
    assert msg.original_size == header_bytes + 2 + sum(len(c) for c in big)
    assert (await conn.healthcheck())["truncated_too_large"] == 1
    await client.quit()


async def test_message_within_limit_is_not_marked_truncated(start_milter):
    emit = FakeEmit(VerdictLevel.CLEAN, score=0)
    conn = await start_milter(emit)
    client = await MilterClient.connect(conn.port)
    await client.negotiate()
    replies = await client.message(rcpts=["ventas@empresa.com"], headers=HEADERS, body_chunks=BODY)
    assert not any(len(r) > 1 and r[1] == "X-Centinela-Truncated" for r in decoded(replies))
    msg = emit.received[0]
    assert msg.truncated is False and msg.original_size is None
    assert (await conn.healthcheck())["truncated_too_large"] == 0
    await client.quit()


async def test_header_flood_is_bounded(start_milter):
    emit = FakeEmit(VerdictLevel.CLEAN, score=0)
    conn = await start_milter(emit)
    conn.max_headers = 50
    client = await MilterClient.connect(conn.port)
    await client.negotiate()
    headers = [("X-Spam", str(i)) for i in range(200)] + [("X-Centinela-Id", "forjado")]
    replies = await client.message(rcpts=["ventas@empresa.com"], headers=headers, body_chunks=[b"x\r\n"])
    got = decoded(replies)
    # el falsificado se borra aunque haya llegado después del límite de headers guardados
    assert got[0] == ("chg", 1, "X-Centinela-Id", "")
    assert got[-1] == ("a",)
    assert ("add", "X-Centinela-Truncated", "yes") in got
    assert emit.received[0].raw.count(b"X-Spam:") == 50
    # recortado por cantidad de headers, no por tamaño: no es "mail demasiado grande"
    assert emit.received[0].truncated is False and emit.received[0].original_size is None
    await client.quit()


async def test_oversized_header_block_is_marked_truncated(start_milter, settings):
    settings.limits.max_message_bytes = 1024
    emit = FakeEmit(VerdictLevel.CLEAN, score=0)
    conn = await start_milter(emit)
    client = await MilterClient.connect(conn.port)
    await client.negotiate()
    headers = [("Subject", "grande"), *[("X-Relleno", "x" * 200) for _ in range(20)]]
    await client.message(rcpts=["ventas@empresa.com"], headers=headers, body_chunks=[b"cuerpo\r\n"])
    msg = emit.received[0]
    assert msg.truncated is True and msg.original_size > 1024 and len(msg.raw) <= 1024
    assert msg.raw.startswith(b"Subject: grande\r\n")
    await client.quit()


# --------------------------------------------------------------------------- input hostil


async def _assert_server_alive(conn: MilterConnector) -> None:
    client = await MilterClient.connect(conn.port)
    version, _, _ = await client.negotiate()
    assert version == 6
    await client.quit()


@pytest.mark.parametrize(
    "payload",
    [
        struct.pack("!I", 0x7FFFFFFF) + b"O",  # longitud gigante
        struct.pack("!I", 0),  # longitud cero
        struct.pack("!I", 2 * 1024 * 1024) + b"B" + b"x" * 100,  # chunk mayor al máximo
        struct.pack("!I", 1) + b"Z",  # comando inexistente
        struct.pack("!I", 5) + b"O" + b"\0\0\0\6",  # OPTNEG truncado
        struct.pack("!I", 13) + b"O" + struct.pack("!III", 1, 0x1FF, 0x1FFFFF),  # versión 1
    ],
    ids=["huge-len", "zero-len", "over-max", "unknown-cmd", "short-optneg", "old-version"],
)
async def test_malformed_packets_close_connection_without_crash(start_milter, payload):
    emit = FakeEmit()
    conn = await start_milter(emit)
    client = await MilterClient.connect(conn.port)
    await client.send_raw(payload)
    assert await client.closed_by_server()
    client.close()
    await _assert_server_alive(conn)
    assert emit.received == []


async def test_truncated_packet_and_disconnect(start_milter):
    conn = await start_milter(FakeEmit())
    client = await MilterClient.connect(conn.port)
    await client.negotiate()
    await client.send_raw(struct.pack("!I", 100) + b"L" + b"Subject\0x")  # paquete a medias
    client.writer.close()
    await asyncio.sleep(0.1)
    await _assert_server_alive(conn)


async def test_random_garbage_does_not_crash(start_milter):
    conn = await start_milter(FakeEmit())
    rnd = random.Random(1234)
    for _ in range(5):
        client = await MilterClient.connect(conn.port)
        await client.send_raw(rnd.randbytes(4096))
        client.writer.write_eof()
        await client.wait_eof()  # el servidor termina la sesión (paquete inválido o EOF a mitad)
        client.close()
    await _assert_server_alive(conn)


async def test_garbage_inside_valid_packets_is_tolerated(start_milter):
    emit = FakeEmit(VerdictLevel.CLEAN, score=0)
    conn = await start_milter(emit)
    client = await MilterClient.connect(conn.port)
    await client.negotiate()
    await client.send(m.SMFIC_MACRO, b"")  # macro vacía
    await client.send(m.SMFIC_MACRO, b"R{rcpt_addr}")  # macro sin valor
    await client.send(m.SMFIC_RCPT, b"")  # rcpt vacío
    await client.send(m.SMFIC_HEADER, b"")  # header vacío
    await client.send(m.SMFIC_HEADER, b"Bad Name:\r\n\0v\0")  # nombre inválido
    await client.send(m.SMFIC_HEADER, b"Subject\0hola\nX-Inyectado: si\0")  # intento de inyección
    replies = await client.eob()
    assert decoded(replies)[-1] == ("a",)
    raw = emit.received[0].raw
    assert emit.received[0].ref.mailbox == "desconocido"
    # la línea "inyectada" queda como continuación del Subject, no como header nuevo
    parsed = email.message_from_bytes(raw)
    assert parsed["X-Inyectado"] is None
    assert b"BadName: v\r\n" in raw
    await client.quit()


async def test_max_connections(start_milter):
    conn = await start_milter(FakeEmit())
    conn.max_connections = 1
    first = await MilterClient.connect(conn.port)
    await first.negotiate()
    second = await MilterClient.connect(conn.port)
    assert await second.closed_by_server()
    second.close()
    await first.quit()


async def test_idle_connection_is_closed(start_milter):
    conn = await start_milter(FakeEmit())
    conn.idle_timeout_s = 0.2
    client = await MilterClient.connect(conn.port)
    await client.negotiate()
    assert await client.closed_by_server(wait_s=3)
    client.close()


# --------------------------------------------------------------------------- ciclo de vida


async def test_run_stop_and_healthcheck(settings):
    cfg = MilterConnectorConfig(type="milter", name="mta", listen_host="127.0.0.1", listen_port=0)
    conn = MilterConnector(cfg, settings, MemoryStateStore())
    stop = asyncio.Event()
    task = asyncio.create_task(conn.run(FakeEmit(), stop))
    await asyncio.wait_for(conn.ready.wait(), 5)
    health = await conn.healthcheck()
    assert health["ok"] is True and health["listen"].endswith(f":{conn.port}")
    client = await MilterClient.connect(conn.port)
    await client.negotiate()  # conexión abierta al apagar: no debe colgar el shutdown
    stop.set()
    await asyncio.wait_for(task, 10)
    assert (await conn.healthcheck())["ok"] is False
    client.close()


async def test_shutdown_waits_for_background_analysis(settings):
    cfg = MilterConnectorConfig(
        type="milter", name="mta", listen_host="127.0.0.1", listen_port=0, inline_timeout_s=0.05
    )
    conn = MilterConnector(cfg, settings, MemoryStateStore())
    emit = FakeEmit(VerdictLevel.MALICIOUS, delay=0.5)
    stop = asyncio.Event()
    task = asyncio.create_task(conn.run(emit, stop))
    await asyncio.wait_for(conn.ready.wait(), 5)
    client = await MilterClient.connect(conn.port)
    await client.negotiate()
    replies = await client.message(rcpts=["ventas@empresa.com"], headers=HEADERS, body_chunks=BODY)
    assert decoded(replies) == [("a",)]
    await client.quit()
    stop.set()
    await asyncio.wait_for(task, 10)
    assert emit.finished.is_set()  # el análisis en curso terminó antes de apagar


async def test_bind_failure_retries_until_stop(settings):
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)
    port = blocker.getsockname()[1]
    try:
        cfg = MilterConnectorConfig(type="milter", name="mta", listen_host="127.0.0.1", listen_port=port)
        conn = MilterConnector(cfg, settings, MemoryStateStore())
        stop = asyncio.Event()
        task = asyncio.create_task(conn.run(FakeEmit(), stop))
        await asyncio.sleep(0.3)
        assert not conn.ready.is_set()
        stop.set()
        await asyncio.wait_for(task, 5)
    finally:
        blocker.close()


# --------------------------------------------------------------------------- helpers puros


def _display(subject: bytes) -> str:
    text = subject.decode("ascii").replace("\n", "")
    return str(make_header(decode_header(text)))


def test_prefixed_subject_ascii():
    assert prefixed_subject("[PELIGRO] ", b"Factura") == b"[PELIGRO] Factura"
    assert prefixed_subject("[PELIGRO] ", b"[PELIGRO] Factura") is None
    assert prefixed_subject("   ", b"Factura") is None


def test_prefixed_subject_keeps_folding_as_lf():
    out = prefixed_subject("[X] ", b"linea uno\r\n\tlinea dos")
    assert out == b"[X] linea uno\n\tlinea dos"


def test_prefixed_subject_non_ascii_prefix_plain_subject():
    out = prefixed_subject("[¡PELIGRO!] ", b"Factura")
    assert out is not None and out.isascii()
    assert _display(out) == "[¡PELIGRO!] Factura"


def test_prefixed_subject_non_ascii_prefix_encoded_subject():
    original = b"=?utf-8?q?Factura_ma=C3=B1ana?="
    out = prefixed_subject("[¡PELIGRO!] ", original)
    assert out is not None and out.isascii()
    assert _display(out) == "[¡PELIGRO!] Factura mañana"
    # ya prefijado (comparando el asunto decodificado)
    assert prefixed_subject("[¡PELIGRO!] ", out) is None


def test_prefixed_subject_hostile_huge_subject_is_fast():
    hostile = b"=?utf-8?q?a?= " * 20000  # ~280 KB de encoded-words
    t0 = time.perf_counter()
    out = prefixed_subject("[PELIGRO] ", hostile)
    assert time.perf_counter() - t0 < 0.5
    assert out is not None and out.startswith(b"[PELIGRO] =?utf-8?q?a?=")


def test_fold_crlf_never_creates_new_header_lines():
    assert m._fold_crlf(b"a\nb\r\n\tc\rd") == b"a\r\n b\r\n\tc\r\n d"


def test_clean_header_name():
    assert m._clean_header_name(b"X-Ok") == b"X-Ok"
    assert m._clean_header_name(b"Bad Name:\r\n") == b"BadName"
    assert m._clean_header_name(b"\x00\xff:") == b""


def test_wanted_flags_are_passive():
    assert m.WANTED_ACTIONS == m.SMFIF_ADDHDRS | m.SMFIF_CHGHDRS
    assert not m.WANTED_ACTIONS & (m.SMFIF_CHGBODY | m.SMFIF_ADDRCPT | m.SMFIF_DELRCPT | m.SMFIF_QUARANTINE)
    assert ALL_ACTIONS & m.WANTED_ACTIONS == m.WANTED_ACTIONS
