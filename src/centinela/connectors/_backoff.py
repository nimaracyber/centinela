"""Backoff exponencial con jitter y tope, compartido por los conectores.

Uso típico en un loop de reconexión::

    backoff = Backoff(base=1, cap=300)
    while not stop.is_set():
        try:
            ...  # conectar y trabajar
            backoff.reset()
        except Exception:
            if await sleep_or_stop(stop, backoff.next()):
                break

El jitter evita que muchos conectores reconecten todos juntos ("thundering herd") después de una
caída del servidor: el delay de cada intento cae al azar en ``[d * (1 - jitter), d]`` con
``d = min(cap, base * factor ** intento)``. Nunca supera ``cap``.
"""

from __future__ import annotations

import asyncio
import random
from typing import Protocol

__all__ = ["Backoff", "backoff_delay", "sleep_or_stop"]

_MAX_EXPONENT = 64  # evita OverflowError con muchísimos intentos seguidos


class _Rng(Protocol):
    def random(self) -> float: ...


_SYSTEM_RNG: _Rng = random.SystemRandom()


def backoff_delay(
    attempt: int,
    *,
    base: float = 1.0,
    cap: float = 300.0,
    factor: float = 2.0,
    jitter: float = 0.2,
    rng: _Rng | None = None,
) -> float:
    """Delay (segundos) para el intento número ``attempt`` (0 = primer reintento)."""
    if base <= 0 or cap <= 0:
        return 0.0
    attempt = max(0, min(int(attempt), _MAX_EXPONENT))
    jitter = min(max(jitter, 0.0), 1.0)
    try:
        d = base * (factor**attempt)
    except OverflowError:
        d = cap
    d = min(cap, d)
    r = (rng or _SYSTEM_RNG).random()
    return max(0.0, d * (1.0 - jitter * r))


class Backoff:
    """Contador de intentos con delay exponencial, jitter y tope."""

    def __init__(
        self,
        base: float = 1.0,
        cap: float = 300.0,
        *,
        factor: float = 2.0,
        jitter: float = 0.2,
        rng: _Rng | None = None,
    ) -> None:
        if factor < 1.0:
            raise ValueError("factor debe ser >= 1")
        self.base = float(base)
        self.cap = float(cap)
        self.factor = float(factor)
        self.jitter = float(jitter)
        self._rng = rng
        self.attempts = 0

    def next(self) -> float:
        """Devuelve el delay a esperar e incrementa el contador de intentos."""
        delay = backoff_delay(
            self.attempts, base=self.base, cap=self.cap, factor=self.factor, jitter=self.jitter, rng=self._rng
        )
        self.attempts = min(self.attempts + 1, _MAX_EXPONENT)
        return delay

    def reset(self) -> None:
        self.attempts = 0


async def sleep_or_stop(stop: asyncio.Event, delay: float) -> bool:
    """Espera ``delay`` segundos o hasta que ``stop`` se active. Devuelve True si hay que parar."""
    if stop.is_set():
        return True
    if delay <= 0:
        await asyncio.sleep(0)
        return stop.is_set()
    try:
        await asyncio.wait_for(stop.wait(), timeout=delay)
    except TimeoutError:
        return False
    return True
