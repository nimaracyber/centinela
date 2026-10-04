"""Fixtures de los tests de la CLI: config.yaml temporales y aislamiento del logging global."""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml

from centinela import logging_setup


@pytest.fixture(autouse=True)
def restore_logging() -> Iterator[None]:
    """Los comandos configuran el logger raíz (setup_logging): se restaura después de cada test para no
    afectar a otros tests (nivel, handlers apuntando a streams del CliRunner ya cerrados)."""
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    names = [*logging_setup._QUIET_LOGGERS, "uvicorn", "uvicorn.error", "uvicorn.access"]
    saved = {n: (logging.getLogger(n).level, logging.getLogger(n).propagate) for n in names}
    yield
    for h in list(root.handlers):
        if h not in handlers:
            root.removeHandler(h)
            h.close()
    for h in handlers:
        if h not in root.handlers:
            root.addHandler(h)
    root.setLevel(level)
    for n, (lvl, prop) in saved.items():
        logging.getLogger(n).setLevel(lvl)
        logging.getLogger(n).propagate = prop


@pytest.fixture
def write_config(tmp_path: Path) -> Callable[..., Path]:
    """Escribe un config.yaml mínimo (base SQLite en tmp, dashboard apagado) con `overrides` mezclados."""

    def _write(overrides: dict[str, Any] | None = None, name: str = "config.yaml") -> Path:
        data: dict[str, Any] = {
            "general": {
                "company_name": "Ferretería El Tornillo",
                "company_domains": ["empresa.com"],
                "data_dir": tmp_path.as_posix(),
                "timezone": "UTC",
                "log_json": False,
            },
            "database_url": f"sqlite+aiosqlite:///{(tmp_path / 'centinela.db').as_posix()}",
            "dashboard": {"enabled": False},
        }
        for key, value in (overrides or {}).items():
            if isinstance(value, dict) and isinstance(data.get(key), dict):
                data[key] = {**data[key], **value}
            else:
                data[key] = value
        path = tmp_path / name
        path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
        return path

    return _write
