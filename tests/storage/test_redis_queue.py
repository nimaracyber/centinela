from __future__ import annotations

import asyncio
import contextlib
import time
from datetime import UTC, datetime

import fakeredis
import pytest
from fakeredis import aioredis
from redis.exceptions import ConnectionError as RedisConnectionError

from centinela import metrics
from centinela.core.models import MessageRef, RawMessage
from centinela.core.queue import WorkQueue
from centinela.storage.redis_queue import RedisStreamQueue
from tests.helpers import build_eml, make_raw

STREAM, DEAD = "centinela:inbox", "centinela:dead"


@pytest.fixture
async def client():
    c = aioredis.FakeRedis(server=fakeredis.FakeServer())
    yield c
    await c.aclose()


def make_queue(client, **kw) -> RedisStreamQueue:
    defaults = {"block_ms": 20, "claim_interval_s": 0.0, "depth_interval_s": 0.0}
    defaults.update(kw)
    return RedisStreamQueue(client=client, **defaults)


async def take(q: RedisStreamQueue, n: int, consumer: str = "c1", wait_s: float = 3.0) -> list:
    """Consume hasta `n` jobs (o hasta el timeout) y para el generador."""
    stop = asyncio.Event()
    jobs = []
    timer = asyncio.get_running_loop().call_later(wait_s, stop.set)  # parada por evento, como en producción

    async def run():
        async for job in q.consume(consumer, stop):
            jobs.append(job)
            if len(jobs) >= n:
                stop.set()

    try:
        await asyncio.wait_for(run(), timeout=wait_s + 5)
    finally:
        timer.cancel()
    return jobs


async def test_publish_consume_ack_roundtrip(client):
    q = make_queue(client)
    assert isinstance(q, WorkQueue)
    binary = build_eml(attachments=[("x.bin", bytes(range(256)) * 4, "application/octet-stream")])
    received = datetime(2026, 10, 3, 12, 30, tzinfo=UTC)
    m1 = RawMessage(
        ref=MessageRef(
            connector="imap1", mailbox="ventas@empresa.com", remote_id="INBOX:1:7", folder="INBOX"
        ),
        raw=binary,
        received_at=received,
    )
    m2 = make_raw(b"Subject: hola\r\n\r\ntexto", remote_id="2")
    id1 = await q.publish(m1)
    id2 = await q.publish(m2)
    assert isinstance(id1, str) and id1 != id2
    assert await q.depth() == 2
    assert metrics.QUEUE_DEPTH._value.get() == 2

    jobs = await take(q, 2)
    assert [j.id for j in jobs] == [id1, id2]
    assert jobs[0].message == m1 and jobs[0].attempts == 1
    assert jobs[0].message.raw == binary
    assert jobs[1].message.ref == m2.ref
    for j in jobs:
        await q.ack(j)
    assert await client.xlen(STREAM) == 0
    assert (await client.xpending(STREAM, "workers"))["pending"] == 0
    assert await q.depth() == 0


async def test_group_creation_is_idempotent(client):
    q1, q2 = make_queue(client), make_queue(client)
    await q1.ensure_group()
    await q2.ensure_group()
    await q2.publish(make_raw(b"x"))
    groups = await client.xinfo_groups(STREAM)
    assert len(groups) == 1


async def test_messages_published_before_group_are_delivered(client):
    await client.xadd(
        STREAM,
        {
            "ref": make_raw(b"a").ref.model_dump_json(),
            "received_at": "2026-01-01T00:00:00+00:00",
            "raw": b"a",
        },
    )
    q = make_queue(client)
    jobs = await take(q, 1)
    assert len(jobs) == 1 and jobs[0].message.raw == b"a"


async def test_fail_retries_then_dead_letters(client):
    q = make_queue(client, max_attempts=3, claim_idle_s=0.05, retry_delay_s=0.0)
    await q.publish(make_raw(b"mail que rompe", remote_id="boom"))
    seen_attempts = []
    stop = asyncio.Event()

    async def worker():
        async for job in q.consume("c1", stop):
            seen_attempts.append(job.attempts)
            await q.fail(job, "RuntimeError: falla de prueba")
            if job.attempts >= 3:
                stop.set()

    task = asyncio.create_task(worker())
    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(stop.wait(), 5)
    stop.set()
    await asyncio.wait_for(task, 3)
    assert seen_attempts == [1, 2, 3]
    assert await client.xlen(STREAM) == 0
    assert (await client.xpending(STREAM, "workers"))["pending"] == 0
    dead = await client.xrange(DEAD)
    assert len(dead) == 1
    fields = dead[0][1]
    assert fields[b"raw"] == b"mail que rompe"
    assert fields[b"attempts"] == b"3"
    assert b"falla de prueba" in fields[b"error"]
    assert MessageRef.model_validate_json(fields[b"ref"]).remote_id == "boom"
    assert await q.dead_count() == 1


async def test_failed_job_is_not_redelivered_before_claim_idle(client):
    q = make_queue(client, max_attempts=3, claim_idle_s=60, retry_delay_s=60)
    await q.publish(make_raw(b"x"))
    jobs = await take(q, 1)
    await q.fail(jobs[0], "error transitorio")
    assert await take(q, 1, wait_s=0.3) == []  # sigue pendiente, sin reentrega inmediata
    assert (await client.xpending(STREAM, "workers"))["pending"] == 1


async def test_crashed_worker_entries_are_reclaimed_with_attempts(client):
    q_a = make_queue(client, claim_idle_s=0.05)
    await q_a.publish(make_raw(b"huerfano", remote_id="o1"))
    jobs = await take(q_a, 1, consumer="worker-a")
    assert jobs[0].attempts == 1  # worker-a "muere" sin ack
    await asyncio.sleep(0.1)
    q_b = make_queue(client, claim_idle_s=0.05)
    reclaimed = await take(q_b, 1, consumer="worker-b")
    assert len(reclaimed) == 1
    assert reclaimed[0].id == jobs[0].id and reclaimed[0].attempts == 2
    assert reclaimed[0].message.raw == b"huerfano"
    await q_b.ack(reclaimed[0])
    assert await client.xlen(STREAM) == 0


async def test_poison_message_that_kills_workers_goes_to_dead_letter(client):
    q = make_queue(client, max_attempts=1, claim_idle_s=0.05)
    await q.publish(make_raw(b"zip bomb hipotetico", remote_id="poison"))
    first = await take(q, 1, consumer="worker-a")
    assert len(first) == 1  # se entrega una vez y el worker "se cae"
    await asyncio.sleep(0.1)
    again = await take(
        make_queue(client, max_attempts=1, claim_idle_s=0.05), 1, consumer="worker-b", wait_s=0.5
    )
    assert again == []  # no se vuelve a procesar
    dead = await client.xrange(DEAD)
    assert len(dead) == 1 and b"demasiadas veces" in dead[0][1][b"error"]
    assert await client.xlen(STREAM) == 0


async def test_malformed_entries_go_to_dead_letter(client):
    q = make_queue(client)
    await q.ensure_group()
    await client.xadd(STREAM, {"ref": b"{no es json", "raw": b"x"})
    await client.xadd(STREAM, {"ref": make_raw(b"a").ref.model_dump_json()})  # sin raw
    await client.xadd(STREAM, {"basura": b"\xff\xfe"})
    good_id = await q.publish(make_raw(b"bueno"))
    jobs = await take(q, 1)
    assert [j.id for j in jobs] == [good_id]
    dead = await client.xrange(DEAD)
    assert len(dead) == 3
    assert all(b"malformada" in f[b"error"] for _, f in dead)


async def test_consume_is_stop_aware(client):
    q = make_queue(client, block_ms=200)
    stop = asyncio.Event()

    async def run():
        return [j async for j in q.consume("c1", stop)]

    task = asyncio.create_task(run())
    await asyncio.sleep(0.1)
    t0 = time.monotonic()
    stop.set()
    assert await asyncio.wait_for(task, 2) == []
    assert time.monotonic() - t0 < 1.0


async def test_recovers_when_stream_is_deleted(client):
    q = make_queue(client)
    await q.publish(make_raw(b"uno", remote_id="1"))
    first = await take(q, 1)
    await q.ack(first[0])
    await client.delete(STREAM)  # alguien borró el stream (FLUSHDB, etc.)
    await q.publish(make_raw(b"dos", remote_id="2"))  # XADD recrea el stream pero sin grupo
    jobs = await take(q, 1)
    assert len(jobs) == 1 and jobs[0].message.raw == b"dos"


async def test_survives_redis_connection_errors(client, monkeypatch):
    q = make_queue(client)
    await q.publish(make_raw(b"x"))
    real = client.xreadgroup
    calls = {"n": 0}

    async def flaky(*a, **kw):
        calls["n"] += 1
        if calls["n"] <= 2:
            raise RedisConnectionError("Redis caído")
        return await real(*a, **kw)

    monkeypatch.setattr(client, "xreadgroup", flaky)

    async def no_sleep(stop, seconds):
        await asyncio.sleep(0)

    monkeypatch.setattr(RedisStreamQueue, "_sleep", staticmethod(no_sleep))
    jobs = await take(q, 1)
    assert len(jobs) == 1 and calls["n"] >= 3


async def test_close_only_closes_owned_client(client):
    q = make_queue(client)
    await q.close()
    assert await client.ping()  # el cliente inyectado sigue vivo
    with pytest.raises(ValueError):
        RedisStreamQueue()


async def test_old_redis_without_xautoclaim_degrades_gracefully(client, monkeypatch):
    from redis.exceptions import ResponseError

    async def unsupported(*a, **kw):
        raise ResponseError("ERR unknown command 'XAUTOCLAIM', with args beginning with:")

    monkeypatch.setattr(client, "xautoclaim", unsupported)
    q = make_queue(client)
    await q.publish(make_raw(b"nuevo"))
    jobs = await take(q, 1)
    assert len(jobs) == 1 and jobs[0].message.raw == b"nuevo"
    assert q._autoclaim is False
