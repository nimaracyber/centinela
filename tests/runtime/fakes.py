"""Conectores, canales y pipeline falsos para tests de dispatcher/runtime (sin red)."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

from centinela.actions.alerts.base import AlertChannel
from centinela.connectors.base import Connector
from centinela.core.config import Settings
from centinela.core.models import RawMessage
from centinela.core.state import MemoryStateStore


class FakeConnector(Connector):
    type = "imap"

    def __init__(
        self,
        name: str = "test",
        *,
        tag: bool = True,
        fail_tag: bool = False,
        skip_tag: bool = False,
        inline: bool = False,
        to_emit: list[RawMessage] | None = None,
        crash_first_runs: int = 0,
        health: Any = None,
    ) -> None:
        super().__init__(SimpleNamespace(name=name, tag=tag, type="imap"), Settings(), MemoryStateStore())
        self.inline = inline  # type: ignore[misc]  # sombrea el ClassVar a propósito
        self.fail_tag = fail_tag
        self.skip_tag = skip_tag
        self.tag_calls: list[tuple[Any, Any, Any]] = []
        self.to_emit = list(to_emit or [])
        self.crash_first_runs = crash_first_runs
        self.runs = 0
        self.emitted: list[Any] = []
        self.closed = False
        self._health = health

    async def run(self, emit, stop: asyncio.Event) -> None:
        self.runs += 1
        if self.runs <= self.crash_first_runs:
            raise ConnectionError("IMAP caído password=hunter2")
        while self.to_emit and not stop.is_set():
            self.emitted.append(await emit(self.to_emit.pop(0)))
        await stop.wait()

    async def apply_verdict(self, ref, result, tag) -> str | None:
        self.tag_calls.append((ref, result.verdict.level, tag))
        if self.fail_tag:  # contrato: una falla real LANZA
            raise RuntimeError("no se pudo conectar al servidor")
        if self.skip_tag:  # contrato: "no aplica" devuelve None
            return None
        label = tag.label_malicious if result.verdict.level.value == "malicious" else tag.label_suspicious
        return f"{self.name}:keyword:{label}"

    async def healthcheck(self) -> dict[str, Any]:
        if isinstance(self._health, Exception):
            raise self._health
        return self._health if self._health is not None else {"ok": True, "detail": "conectado"}

    async def close(self) -> None:
        self.closed = True


class FakeChannel(AlertChannel):
    type = "fake"

    def __init__(
        self,
        name: str = "telegram",
        *,
        min_level: str = "suspicious",
        enabled: bool = True,
        fail_times: int = 0,
        hang: bool = False,
        error: Exception | None = None,
    ) -> None:
        super().__init__(SimpleNamespace(name=name, min_level=min_level, enabled=enabled), Settings(), None)  # type: ignore[arg-type]
        self.fail_times = fail_times
        self.hang = hang
        self.error = error  # excepción a lanzar en los intentos fallidos (default: ConnectionError)
        self.attempts = 0
        self.attempt_times: list[float] = []
        self.sent: list[Any] = []
        self.closed = False

    async def send(self, result) -> None:
        self.attempts += 1
        self.attempt_times.append(asyncio.get_running_loop().time())
        if self.hang:
            await asyncio.sleep(3600)
        if self.attempts <= self.fail_times:
            raise self.error if self.error is not None else ConnectionError("canal caído")
        self.sent.append(result)

    async def close(self) -> None:
        self.closed = True


class FakeAnalyzer:
    def __init__(self, name: str, ping_result: Any = True, ping_delay: float = 0.0) -> None:
        self.name = name
        self._ping_result = ping_result
        self._ping_delay = ping_delay

    async def ping(self) -> Any:
        if self._ping_delay:
            await asyncio.sleep(self._ping_delay)
        if isinstance(self._ping_result, Exception):
            raise self._ping_result
        return self._ping_result


class StubPipeline:
    """Imita `core.pipeline.Pipeline` sin parser ni analizadores reales."""

    def __init__(self, factory, analyzers: list[Any] | None = None, fail: Exception | None = None) -> None:
        self.factory = factory
        self.analyzers = analyzers or []
        self.fail = fail
        self.calls: list[RawMessage] = []
        self.setup_called = False
        self.closed = False

    async def setup(self) -> None:
        self.setup_called = True

    async def analyze(self, raw: RawMessage):
        self.calls.append(raw)
        if self.fail is not None:
            raise self.fail
        return self.factory(raw)

    async def close(self) -> None:
        self.closed = True
