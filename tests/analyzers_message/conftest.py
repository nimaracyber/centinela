"""Fixtures locales: estos analizadores NUNCA usan la red.

Se reemplaza el fixture `http` de tests/conftest.py por un objeto que falla ante cualquier uso. Así se
garantiza que headers/urls/content/filetype no hacen pedidos (ni siquiera por error) y se evita crear un
httpx.AsyncClient por test (que en Windows tarda ~0,4 s por el contexto SSL).
"""

from __future__ import annotations

import pytest


class NoNetwork:
    def __getattr__(self, name: str):
        raise AssertionError(f"los analizadores de mensaje no deben usar la red (se accedió a http.{name})")


@pytest.fixture
def http() -> NoNetwork:
    return NoNetwork()
