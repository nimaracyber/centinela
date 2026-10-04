"""Almacén clave-valor persistente para cursores de conectores y secretos (tokens OAuth).

La implementación real (tabla `kv_state` en la base, secretos cifrados con Fernet usando
Settings.encryption_key) vive en centinela.storage.state.DbStateStore.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class StateStore(Protocol):
    async def get(self, key: str) -> str | None: ...
    async def set(self, key: str, value: str) -> None: ...
    async def delete(self, key: str) -> None: ...
    async def get_secret(self, key: str) -> str | None: ...
    async def set_secret(self, key: str, value: str) -> None: ...


class MemoryStateStore:
    """Para tests y `centinela scan`. No persiste."""

    def __init__(self) -> None:
        self._d: dict[str, str] = {}
        self._s: dict[str, str] = {}

    async def get(self, key: str) -> str | None:
        return self._d.get(key)

    async def set(self, key: str, value: str) -> None:
        self._d[key] = value

    async def delete(self, key: str) -> None:
        self._d.pop(key, None)
        self._s.pop(key, None)

    async def get_secret(self, key: str) -> str | None:
        return self._s.get(key)

    async def set_secret(self, key: str, value: str) -> None:
        self._s[key] = value
