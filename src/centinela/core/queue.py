"""Cola de trabajo entre `ingest` (conectores) y `worker` (análisis).

- InMemoryQueue: modo todo-en-uno (un proceso, sin Redis). Ideal para una oficina chica.
- RedisStreamQueue (centinela.storage.redis_queue): Redis Streams con consumer groups, reintentos
  (XAUTOCLAIM de mensajes colgados) y dead-letter tras N intentos. Permite escalar workers.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from centinela.core.models import RawMessage


@dataclass
class Job:
    id: str
    message: RawMessage
    attempts: int = 1


@runtime_checkable
class WorkQueue(Protocol):
    async def publish(self, message: RawMessage) -> str: ...
    def consume(self, consumer: str, stop: asyncio.Event) -> AsyncIterator[Job]: ...
    async def ack(self, job: Job) -> None: ...
    async def fail(self, job: Job, error: str) -> None:
        """Reintento o dead-letter según `job.attempts`."""
        ...

    async def depth(self) -> int:
        """Mensajes pendientes (para métricas y health)."""
        ...

    async def close(self) -> None: ...


class InMemoryQueue:
    MAX_ATTEMPTS = 3
    MAX_DEAD = 100  # solo metadatos; el mail crudo no se retiene

    def __init__(self, maxsize: int = 1000) -> None:
        self._q: asyncio.Queue[Job] = asyncio.Queue(maxsize=maxsize)
        self._seq = 0
        self.dead: list[tuple[str, str]] = []  # (ref json, error)

    async def depth(self) -> int:
        return self._q.qsize()

    async def dead_count(self) -> int:
        return len(self.dead)

    def drain_nowait(self) -> list[Job]:
        """Saca todo lo pendiente (para procesar antes de apagar en modo todo-en-uno)."""
        jobs: list[Job] = []
        while True:
            try:
                jobs.append(self._q.get_nowait())
                self._q.task_done()
            except asyncio.QueueEmpty:
                return jobs

    async def publish(self, message: RawMessage) -> str:
        self._seq += 1
        job = Job(id=str(self._seq), message=message)
        await self._q.put(job)
        return job.id

    async def consume(self, consumer: str, stop: asyncio.Event) -> AsyncIterator[Job]:
        while not stop.is_set():
            try:
                job = await asyncio.wait_for(self._q.get(), timeout=0.5)
            except TimeoutError:
                continue
            yield job

    async def ack(self, job: Job) -> None:
        self._q.task_done()

    async def fail(self, job: Job, error: str) -> None:
        self._q.task_done()
        if job.attempts >= self.MAX_ATTEMPTS:
            self.dead.append((job.message.ref.model_dump_json(), error[:500]))
            del self.dead[: -self.MAX_DEAD]
            return
        await self._q.put(Job(id=job.id, message=job.message, attempts=job.attempts + 1))

    async def close(self) -> None:
        pass
