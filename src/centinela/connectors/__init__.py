"""Registro de conectores por `type`."""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING

from centinela.connectors.base import Connector, EmitFn

if TYPE_CHECKING:
    from centinela.core.config import Settings
    from centinela.core.state import StateStore

CONNECTORS: dict[str, tuple[str, str]] = {
    "imap": ("centinela.connectors.imap", "ImapConnector"),
    "gmail": ("centinela.connectors.gmail", "GmailConnector"),
    "graph": ("centinela.connectors.graph", "GraphConnector"),
    "milter": ("centinela.connectors.milter", "MilterConnector"),
    "smtp_journal": ("centinela.connectors.smtp_journal", "SmtpJournalConnector"),
    "directory": ("centinela.connectors.directory", "DirectoryConnector"),
}


def connector_class(type_: str) -> type[Connector]:
    module_name, class_name = CONNECTORS[type_]
    return getattr(importlib.import_module(module_name), class_name)


def build_connectors(
    settings: Settings, state: StateStore, *, only: list[str] | None = None
) -> list[Connector]:
    out: list[Connector] = []
    for cfg in settings.connectors:
        if not cfg.enabled or (only and cfg.name not in only):
            continue
        out.append(connector_class(cfg.type)(cfg, settings, state))
    return out


__all__ = ["CONNECTORS", "Connector", "EmitFn", "build_connectors", "connector_class"]
