"""Contrato de los canales de alerta (email, Telegram, webhook/Slack/Teams/Discord, syslog CEF).

Cada canal recibe el AnalysisResult y lo formatea con centinela.actions.alerts.format (texto en
español para un no-técnico + link al dashboard). Nunca incluye el contenido de los adjuntos;
solo nombre, tipo, SHA-256, familia y hallazgos.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:
    import httpx

    from centinela.core.config import Settings
    from centinela.core.models import AnalysisResult


class AlertChannel(ABC):
    type: ClassVar[str]

    def __init__(self, config: Any, settings: Settings, http: httpx.AsyncClient) -> None:
        self.config = config
        self.name: str = config.name
        self.settings = settings
        self.http = http

    @abstractmethod
    async def send(self, result: AnalysisResult) -> None:
        """Envía la alerta. Debe lanzar excepción si falla (el dispatcher reintenta y registra)."""

    async def close(self) -> None:  # noqa: B027
        pass
