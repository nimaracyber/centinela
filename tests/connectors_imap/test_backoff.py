from __future__ import annotations

import asyncio
import time

import pytest

from centinela.connectors._backoff import Backoff, backoff_delay, sleep_or_stop


class FixedRng:
    def __init__(self, value: float) -> None:
        self.value = value

    def random(self) -> float:
        return self.value


def test_delay_grows_exponentially_and_caps():
    b = Backoff(1, 300, jitter=0.0)
    delays = [b.next() for _ in range(12)]
    assert delays[:5] == [1, 2, 4, 8, 16]
    assert max(delays) == 300 and delays[-1] == 300
    b.reset()
    assert b.next() == 1


@pytest.mark.parametrize("r", [0.0, 0.5, 0.999])
def test_jitter_stays_within_bounds(r):
    b = Backoff(1, 300, jitter=0.2, rng=FixedRng(r))
    for attempt in range(20):
        d = b.next()
        nominal = min(300, 2**attempt)
        assert nominal * 0.8 - 1e-9 <= d <= nominal
        assert d <= 300


def test_real_rng_never_exceeds_cap_or_goes_negative():
    b = Backoff(1, 300)
    for _ in range(200):
        d = b.next()
        assert 0 <= d <= 300


def test_huge_attempt_counts_do_not_overflow():
    assert backoff_delay(10**9, base=1, cap=300, jitter=0) == 300
    assert backoff_delay(-5, base=1, cap=300, jitter=0) == 1
    b = Backoff(1, 300)
    b.attempts = 10**6
    assert b.next() <= 300


def test_degenerate_parameters():
    assert backoff_delay(3, base=0, cap=300) == 0
    assert backoff_delay(3, base=1, cap=0) == 0
    with pytest.raises(ValueError):
        Backoff(1, 10, factor=0.5)


async def test_sleep_or_stop_returns_false_on_timeout():
    stop = asyncio.Event()
    t0 = time.monotonic()
    assert await sleep_or_stop(stop, 0.05) is False
    assert time.monotonic() - t0 >= 0.04


async def test_sleep_or_stop_wakes_up_when_stopped():
    stop = asyncio.Event()
    asyncio.get_running_loop().call_later(0.05, stop.set)
    t0 = time.monotonic()
    assert await sleep_or_stop(stop, 30) is True
    assert time.monotonic() - t0 < 1


async def test_sleep_or_stop_already_set_and_zero_delay():
    stop = asyncio.Event()
    assert await sleep_or_stop(stop, 0) is False
    stop.set()
    assert await sleep_or_stop(stop, 10) is True
    assert await sleep_or_stop(stop, 0) is True
