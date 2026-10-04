"""Fixtures de los tests de conectores cloud: HTTP mockeado con respx, sin red ni credenciales reales."""

from __future__ import annotations

import pytest
import respx

from centinela.connectors import _http as http
from centinela.core.models import AnalysisResult, MessageRef, RawMessage, Verdict, VerdictLevel, utcnow


@pytest.fixture
def router():
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as r:
        yield r


@pytest.fixture
def sleeps(monkeypatch):
    """Reemplaza las esperas de reintento del helper HTTP: registra los segundos sin dormir."""
    delays: list[float] = []

    async def fake_sleep(seconds: float, stop=None) -> bool:
        delays.append(seconds)
        return bool(stop is not None and stop.is_set())

    monkeypatch.setattr(http, "_sleep", fake_sleep)
    return delays


class Collector:
    """`emit` falso: junta los RawMessage entregados."""

    def __init__(self, fail_on: set[str] | None = None) -> None:
        self.items: list[RawMessage] = []
        self.fail_on = fail_on or set()

    async def __call__(self, raw: RawMessage) -> None:
        if raw.ref.remote_id in self.fail_on:
            raise RuntimeError("cola caída")
        self.items.append(raw)

    @property
    def ids(self) -> list[str]:
        return [r.ref.remote_id for r in self.items]


@pytest.fixture
def collector() -> Collector:
    return Collector()


def make_result(ref: MessageRef, level: VerdictLevel) -> AnalysisResult:
    return AnalysisResult(
        ref=ref,
        received_at=utcnow(),
        verdict=Verdict(level=level, score=90 if level == VerdictLevel.MALICIOUS else 40, summary="x"),
    )
