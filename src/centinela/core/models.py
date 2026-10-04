"""Modelos de datos compartidos por todo Centinela.

Este módulo es el CONTRATO entre conectores, parser, analizadores, scoring, storage,
acciones y dashboard. Cambiarlo implica revisar todos esos módulos.
"""

from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from centinela.core.defang import neutralize


def utcnow() -> datetime:
    return datetime.now(UTC)


class Severity(enum.IntEnum):
    """Severidad de un hallazgo individual. Ordenable (INFO < ... < CRITICAL)."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class VerdictLevel(enum.StrEnum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    ERROR = "error"  # el análisis falló; nunca se trata como "limpio"

    @property
    def rank(self) -> int:
        return {"clean": 0, "error": 1, "suspicious": 2, "malicious": 3}[self.value]


class FindingCategory(enum.StrEnum):
    MALWARE = "malware"  # firma/regla de familia concreta (RAT, stealer, loader...)
    SUSPICIOUS_FILE = "suspicious_file"  # heurística sobre archivo (macro autoexec, doble extensión...)
    PHISHING = "phishing"  # links / contenido de credential-harvesting
    SPOOFING = "spoofing"  # suplantación de remitente, SPF/DKIM/DMARC fallidos
    REPUTATION = "reputation"  # hash conocido en MalwareBazaar / VirusTotal
    POLICY = "policy"  # archivo cifrado, demasiado grande, no analizable...


class MessageRef(BaseModel):
    """Identifica un mensaje en su origen para poder etiquetarlo después."""

    model_config = ConfigDict(frozen=True)

    connector: str  # nombre de la instancia de conector (ConnectorConfig.name)
    mailbox: str  # dirección / buzón (ej: ventas@empresa.com)
    remote_id: (
        str  # id en el proveedor: Gmail id, Graph id, "INBOX:<uidvalidity>:<uid>", queue-id del milter...
    )
    folder: str | None = None


class RawMessage(BaseModel):
    """Lo que produce un conector: el mail crudo RFC 5322 + de dónde vino.

    Si el mail supera `limits.max_message_bytes`, el conector NO lo descarta en silencio (sería una
    evasión trivial): emite solo los headers con `truncated=True` y `original_size`, y el pipeline
    genera un hallazgo POLICY "no se pudo analizar completo".
    """

    ref: MessageRef
    raw: bytes
    received_at: datetime = Field(default_factory=utcnow)
    truncated: bool = False
    original_size: int | None = None


class Artifact(BaseModel):
    """Un archivo a analizar: adjunto, archivo dentro de un ZIP/ISO, objeto embebido en un doc, etc.

    `data` NUNCA se serializa ni se persiste: Centinela no guarda ni sube los archivos, solo sus hashes.
    """

    id: str  # ruta estable y legible: "att0", "att0/factura.zip/factura.pdf.exe"
    filename: str | None = None
    declared_content_type: str | None = None  # el Content-Type del MIME (lo que dice el atacante)
    detected_type: str = "unknown"  # tipo real por magic bytes: "pe", "zip", "ole", "ooxml", "pdf", "lnk", "html", "script/js"...
    size: int = 0
    sha256: str = ""
    sha1: str = ""
    md5: str = ""
    depth: int = 0  # 0 = adjunto directo; 1+ = extraído de un contenedor
    parent_id: str | None = None
    encrypted: bool = False  # contenedor con contraseña que NO se pudo abrir
    password_protected: bool = False  # tenía contraseña (se haya podido abrir o no) — técnica de evasión
    listing_only: bool = (
        False  # entrada listada pero no extraída (cifrada, muy grande...): data vacío y SIN hashes
    )
    extraction_note: str | None = None  # ej: "límite de profundidad alcanzado"
    data: bytes = Field(default=b"", exclude=True, repr=False)

    @property
    def extension(self) -> str:
        if not self.filename or "." not in self.filename:
            return ""
        return self.filename.rsplit(".", 1)[-1].lower()


class ExtractedUrl(BaseModel):
    url: str
    source: str  # "body_html" | "body_text" | "artifact:<artifact_id>"
    display_text: str | None = None  # texto visible del <a>, para detectar links engañosos


class ParsedMessage(BaseModel):
    ref: MessageRef
    message_id: str | None = None
    subject: str = ""
    from_addr: str | None = None  # dirección (lowercase) del header From
    from_display: str | None = None  # nombre visible del From
    reply_to: list[str] = Field(default_factory=list)
    return_path: str | None = None
    to: list[str] = Field(default_factory=list)
    cc: list[str] = Field(default_factory=list)
    date: datetime | None = None
    received_at: datetime = Field(default_factory=utcnow)
    headers: list[tuple[str, str]] = Field(default_factory=list)  # en orden, decodificados
    body_text: str = ""
    body_html: str = ""
    artifacts: list[Artifact] = Field(default_factory=list)
    urls: list[ExtractedUrl] = Field(default_factory=list)
    parse_errors: list[str] = Field(default_factory=list)
    size: int = 0

    def header(self, name: str) -> str | None:
        name = name.lower()
        for k, v in self.headers:
            if k.lower() == name:
                return v
        return None

    def header_all(self, name: str) -> list[str]:
        name = name.lower()
        return [v for k, v in self.headers if k.lower() == name]


class Finding(BaseModel):
    analyzer: str  # nombre del analizador que lo produjo
    rule: str  # id máquina estable, ej: "office.vba.autoexec", "yara.AsyncRAT", "headers.dmarc_fail"
    title: str  # título corto para humanos (español)
    description: str = ""  # explicación para un no-técnico: qué es y por qué importa
    category: FindingCategory
    severity: Severity
    score: int = Field(ge=0, le=100)  # aporte al score total del mail
    artifact_id: str | None = None
    malware_family: str | None = None  # ej: "AsyncRAT", "Lumma Stealer", "AgentTesla"
    # datos concretos (strings, offsets, urls...), sin secretos. Se neutralizan al construir el Finding
    # (ver core/defang.py) para que nada de lo que Centinela guarda o muestra sea un comando literal.
    evidence: dict[str, Any] = Field(default_factory=dict)
    # el pipeline deduplica por (rule, artifact_id, dedupe_key): usarlo para varios hallazgos de la misma
    # regla a nivel mensaje (ej: un dominio distinto por hallazgo)
    dedupe_key: str | None = None

    @field_validator("evidence", mode="after")
    @classmethod
    def _neutralize_evidence(cls, v: dict[str, Any]) -> dict[str, Any]:
        return neutralize(v)


class Verdict(BaseModel):
    level: VerdictLevel
    score: int = Field(ge=0, le=100)
    summary: str  # una o dos oraciones en español para el alerta
    malware_families: list[str] = Field(default_factory=list)


class ArtifactSummary(BaseModel):
    """Artifact sin `data`, para persistir y mostrar."""

    id: str
    filename: str | None = None
    declared_content_type: str | None = None
    detected_type: str = "unknown"
    size: int = 0
    sha256: str = ""
    sha1: str = ""
    md5: str = ""
    depth: int = 0
    parent_id: str | None = None
    encrypted: bool = False
    password_protected: bool = False
    listing_only: bool = False
    extraction_note: str | None = None

    @classmethod
    def from_artifact(cls, a: Artifact) -> ArtifactSummary:
        return cls(**a.model_dump(exclude={"data"}))


class AnalysisResult(BaseModel):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    ref: MessageRef
    message_id: str | None = None
    subject: str = ""
    from_addr: str | None = None
    from_display: str | None = None
    to: list[str] = Field(default_factory=list)
    received_at: datetime
    analyzed_at: datetime = Field(default_factory=utcnow)
    duration_ms: int = 0
    size: int = 0
    artifacts: list[ArtifactSummary] = Field(default_factory=list)
    urls: list[ExtractedUrl] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    verdict: Verdict
    errors: list[str] = Field(default_factory=list)  # errores de analizadores (no fatales)
    actions: list[str] = Field(default_factory=list)  # ej: "tagged:gmail-label", "alert:telegram"
    truncated: bool = False  # el mail superaba el límite de tamaño: se analizaron solo los headers
    # feedback del usuario desde el dashboard (lo completa el storage al leer)
    false_positive: bool = False
    false_positive_by: str | None = None
    false_positive_note: str | None = None
    false_positive_at: datetime | None = None
