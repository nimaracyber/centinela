from __future__ import annotations

import ssl
from functools import cache

import httpx
import pytest

from centinela.analyzers.base import AnalysisContext
from centinela.core.cache import MemoryCache
from centinela.core.config import Settings
from centinela.core.models import ParsedMessage
from tests.helpers import make_ref


@pytest.fixture
def settings(tmp_path) -> Settings:
    s = Settings()
    s.general.data_dir = tmp_path
    s.general.company_domains = ["empresa.com"]
    s.database_url = f"sqlite+aiosqlite:///{(tmp_path / 'test.db').as_posix()}"
    return s


@cache
def _ssl_context() -> ssl.SSLContext:
    # crear el contexto SSL cuesta ~0,4 s en Windows: uno solo para toda la sesión de tests
    return ssl.create_default_context()


@pytest.fixture
async def http():
    async with httpx.AsyncClient(verify=_ssl_context()) as client:
        yield client


@pytest.fixture
def make_ctx(settings, http):
    def _make(message: ParsedMessage | None = None) -> AnalysisContext:
        return AnalysisContext(
            settings=settings,
            message=message or ParsedMessage(ref=make_ref()),
            http=http,
            cache=MemoryCache(),
        )

    return _make
