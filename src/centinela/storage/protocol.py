"""Contrato del almacenamiento de resultados (lo implementa storage/db.py, lo consume api/ y runtime).

Privacidad: se guardan METADATOS (asunto, remitente, destinatarios, hashes, hallazgos, veredicto),
nunca los adjuntos. El cuerpo solo si `privacy.store_bodies` (no se modela aquí: off por defecto).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, Field

from centinela.core.models import AnalysisResult, MessageRef, VerdictLevel


class ResultListItem(BaseModel):
    """Fila liviana para listados (sin findings/artifacts completos)."""

    id: uuid.UUID
    connector: str
    mailbox: str
    subject: str
    from_addr: str | None
    from_display: str | None
    received_at: datetime
    analyzed_at: datetime
    level: VerdictLevel
    score: int
    summary: str
    malware_families: list[str] = Field(default_factory=list)
    artifact_count: int = 0
    finding_count: int = 0
    false_positive: bool = False


class ResultFilter(BaseModel):
    ids: list[uuid.UUID] | None = None
    level: VerdictLevel | None = None
    min_level: VerdictLevel | None = None  # ej: SUSPICIOUS => sospechosos + maliciosos
    connector: str | None = None
    mailbox: str | None = None
    q: str | None = None  # busca en asunto, remitente, nombre de adjunto, sha256
    sha256: str | None = None
    family: str | None = None
    since: datetime | None = None
    until: datetime | None = None
    include_false_positives: bool = True


class Stats(BaseModel):
    since: datetime
    total: int = 0
    by_level: dict[str, int] = Field(default_factory=dict)  # "clean"/"suspicious"/"malicious"/"error"
    top_families: list[tuple[str, int]] = Field(default_factory=list)
    top_senders: list[tuple[str, int]] = Field(
        default_factory=list
    )  # remitentes de mails sospechosos/maliciosos
    top_rules: list[tuple[str, int]] = Field(default_factory=list)
    by_connector: dict[str, int] = Field(default_factory=dict)
    timeline: list[dict[str, Any]] = Field(
        default_factory=list
    )  # [{"bucket": iso, "clean": n, "suspicious": n, "malicious": n}]
    avg_duration_ms: float = 0.0


class Campaign(BaseModel):
    """Mismo adjunto (sha256) recibido en varios mails/buzones."""

    sha256: str
    filename: str | None
    detected_type: str
    first_seen: datetime
    last_seen: datetime
    message_count: int
    mailboxes: list[str]
    max_level: VerdictLevel
    malware_families: list[str] = Field(default_factory=list)


@runtime_checkable
class ResultStore(Protocol):
    async def init(self) -> None:
        """Crea tablas / corre migraciones idempotentes."""
        ...

    async def close(self) -> None: ...

    async def has_ref(self, ref: MessageRef) -> bool:
        """True si ese mensaje (connector+mailbox+remote_id) ya fue analizado (dedup al-menos-una-vez)."""
        ...

    async def save_result(self, result: AnalysisResult) -> bool:
        """Guarda el resultado completo. False si ya existía uno para el mismo ref (no duplica)."""
        ...

    async def get_result(self, result_id: uuid.UUID) -> AnalysisResult | None:
        """Resultado completo, con los campos false_positive* completados desde el feedback guardado."""
        ...

    async def list_results(
        self, flt: ResultFilter, *, limit: int = 50, offset: int = 0
    ) -> tuple[list[ResultListItem], int]:
        """(filas ordenadas por received_at desc, total que matchea el filtro)."""
        ...

    async def stats(self, since: datetime, *, bucket: str = "hour") -> Stats:
        """bucket: "hour" | "day"."""
        ...

    async def campaigns(
        self, since: datetime, *, min_messages: int = 2, limit: int = 50, include_clean: bool = False
    ) -> list[Campaign]:
        """Por defecto solo cuenta mensajes sospechosos/maliciosos no marcados como falso positivo."""
        ...

    async def record_actions(self, result_id: uuid.UUID, actions: list[str]) -> None:
        """Agrega acciones ejecutadas (tag/alertas) al resultado."""
        ...

    async def set_false_positive(
        self, result_id: uuid.UUID, value: bool, *, user: str, note: str = ""
    ) -> bool:
        """Feedback del usuario desde el dashboard. False si el id no existe."""
        ...

    async def purge_older_than(self, cutoff: datetime) -> int:
        """Retención: borra resultados viejos. Devuelve cuántos borró."""
        ...
