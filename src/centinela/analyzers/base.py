"""Contrato de los analizadores.

Hay dos tipos:
- MessageAnalyzer: mira el mail completo (headers, remitente, links, texto).
- ArtifactAnalyzer: mira UN archivo (adjunto o extraído de un contenedor). El pipeline lo llama una vez
  por cada artifact para el que `accepts()` devuelva True.

Reglas para implementar un analizador:
1. NUNCA ejecutar, abrir con aplicaciones, ni escribir a disco el contenido de un artifact
   (si una librería exige archivo, usar tempfile en un directorio privado y borrarlo en finally).
2. Trabajo CPU-bound (oletools, yara, pefile...) va dentro de `await asyncio.to_thread(...)`.
3. Toda excepción esperable se convierte en Finding de categoría POLICY o se loguea; las inesperadas
   el pipeline las captura y las registra en AnalysisResult.errors (no tumban el análisis).
4. `rule` es un id estable con prefijo del analizador ("office.vba.autoexec"). `title`/`description`
   en español claro: el lector es el dueño de una PyME, no un analista.
5. Si una dependencia opcional no está instalada, `available()` devuelve False y el analizador se omite.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    import httpx

    from centinela.core.cache import Cache
    from centinela.core.config import Settings
    from centinela.core.models import Artifact, Finding, ParsedMessage


@dataclass
class AnalysisContext:
    settings: Settings
    message: ParsedMessage
    http: httpx.AsyncClient
    cache: Cache
    # espacio de trabajo por mensaje (un AnalysisContext por mensaje); claves con prefijo del analizador
    extra: dict[str, object] = field(default_factory=dict)

    def children(self, artifact_id: str) -> list[Artifact]:
        """Artifacts extraídos directamente de `artifact_id` (por parent_id)."""
        return [a for a in self.message.artifacts if a.parent_id == artifact_id]


class Analyzer(ABC):
    name: ClassVar[str]  # id corto y estable: "office", "yara", "headers"...

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    @classmethod
    def available(cls) -> bool:
        """False si falta una dependencia opcional (ej: yara-python)."""
        return True

    @classmethod
    def enabled(cls, settings: Settings) -> bool:
        return cls.name not in settings.analyzers.disabled

    async def setup(self) -> None:  # noqa: B027 - hook opcional
        """Inicialización costosa (compilar reglas YARA, conectar a clamd...). Se llama una vez."""

    async def close(self) -> None:  # noqa: B027 - hook opcional
        pass


class MessageAnalyzer(Analyzer):
    @abstractmethod
    async def analyze(self, ctx: AnalysisContext) -> list[Finding]: ...


class ArtifactAnalyzer(Analyzer):
    def accepts(self, artifact: Artifact) -> bool:
        return True

    @abstractmethod
    async def analyze(self, ctx: AnalysisContext, artifact: Artifact) -> list[Finding]: ...
