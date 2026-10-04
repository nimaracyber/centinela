"""Contrato de los conectores (de dónde vienen los mails).

Un conector:
- `run(emit, stop)`: loop infinito hasta que `stop` se active. Por cada mail NUEVO llama `await emit(raw)`.
  Debe reconectar solo con backoff exponencial (con tope) ante errores de red/auth, sin perder su
  posición: guarda el cursor (UID IMAP, historyId de Gmail, deltaLink de Graph) en `self.state`
  DESPUÉS de que `emit` retorna (entrega al-menos-una-vez; el storage deduplica por ref).
- `apply_verdict(ref, result)`: etiqueta el mail original (label Gmail, categoría Outlook, keyword IMAP).
  NO borra, NO mueve, NO modifica el contenido. Devuelve una descripción corta de lo hecho
  ("gmail:label:Centinela/Malicioso") o None si no hizo nada.
- Conectores "inline" (milter): `emit` devuelve el AnalysisResult (análisis síncrono con timeout)
  para poder agregar headers antes de aceptar el mail.

Pasividad: Centinela pide los permisos mínimos. Para etiquetar hacen falta permisos de modificación
(gmail.modify, Mail.ReadWrite); con `tag: false` en el conector se usan permisos de solo lectura.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:
    import asyncio

    from centinela.core.config import Settings, TagConfig
    from centinela.core.models import AnalysisResult, MessageRef, RawMessage
    from centinela.core.state import StateStore

EmitFn = Callable[["RawMessage"], Awaitable["AnalysisResult | None"]]


class Connector(ABC):
    type: ClassVar[str]  # igual al `type` de su ConnectorConfig
    inline: ClassVar[bool] = False

    def __init__(self, config: Any, settings: Settings, state: StateStore) -> None:
        self.config = config
        self.name: str = config.name
        self.settings = settings
        self.state = state

    @abstractmethod
    async def run(self, emit: EmitFn, stop: asyncio.Event) -> None: ...

    async def apply_verdict(self, ref: MessageRef, result: AnalysisResult, tag: TagConfig) -> str | None:
        return None

    async def healthcheck(self) -> dict[str, Any]:
        return {"ok": True}

    async def close(self) -> None:  # noqa: B027
        pass

    # helpers de estado con namespace por conector
    async def get_cursor(self, key: str) -> str | None:
        return await self.state.get(f"connector:{self.name}:{key}")

    async def set_cursor(self, key: str, value: str) -> None:
        await self.state.set(f"connector:{self.name}:{key}", value)
