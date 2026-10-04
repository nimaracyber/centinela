"""Caché con TTL (resultados de reputación, dedup de alertas). Memoria o Redis."""

from __future__ import annotations

import time
from typing import Protocol, runtime_checkable


@runtime_checkable
class Cache(Protocol):
    async def get(self, key: str) -> str | None: ...
    async def set(self, key: str, value: str, ttl_s: int) -> None: ...
    async def add(self, key: str, value: str, ttl_s: int) -> bool:
        """SET NX: True si la clave no existía (para dedup atómico)."""
        ...


class MemoryCache:
    def __init__(self, max_items: int = 50_000) -> None:
        self._d: dict[str, tuple[float, str]] = {}
        self._max = max_items

    def _expired(self, key: str) -> bool:
        item = self._d.get(key)
        if item is None:
            return True
        if item[0] < time.monotonic():
            del self._d[key]
            return True
        return False

    async def get(self, key: str) -> str | None:
        return None if self._expired(key) else self._d[key][1]

    async def set(self, key: str, value: str, ttl_s: int) -> None:
        if len(self._d) >= self._max:
            # desalojo simple: tirar el 10% más viejo por vencimiento
            for k, _ in sorted(self._d.items(), key=lambda kv: kv[1][0])[: self._max // 10]:
                del self._d[k]
        self._d[key] = (time.monotonic() + ttl_s, value)

    async def add(self, key: str, value: str, ttl_s: int) -> bool:
        if not self._expired(key):
            return False
        await self.set(key, value, ttl_s)
        return True


class RedisCache:
    def __init__(self, redis_client, prefix: str = "centinela:cache:") -> None:  # redis.asyncio.Redis
        self._r = redis_client
        self._p = prefix

    async def get(self, key: str) -> str | None:
        v = await self._r.get(self._p + key)
        return v.decode() if isinstance(v, bytes) else v

    async def set(self, key: str, value: str, ttl_s: int) -> None:
        await self._r.set(self._p + key, value, ex=max(1, ttl_s))

    async def add(self, key: str, value: str, ttl_s: int) -> bool:
        return bool(await self._r.set(self._p + key, value, ex=max(1, ttl_s), nx=True))
