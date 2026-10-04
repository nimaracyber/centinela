"""Almacenamiento de resultados en SQL: PostgreSQL (asyncpg) o SQLite (aiosqlite), con SQLAlchemy 2 async.

Implementa `centinela.storage.protocol.ResultStore`. Guarda METADATOS (asunto, remitente, hashes,
hallazgos, veredicto); nunca el contenido de los adjuntos.

Decisiones de portabilidad (el mismo código corre sobre SQLite y PostgreSQL):
- Fechas siempre en UTC (`UTCDateTime`): en SQLite se guardan "naive" en UTC y se devuelven con tz=UTC.
- Listas/dicts como JSON en columnas TEXT (`*_json`), sin tipos JSON específicos del motor.
- Duplicados: se detectan por la restricción UNIQUE(connector, mailbox, remote_id) capturando
  IntegrityError (funciona igual en ambos motores, sin `ON CONFLICT`).
- La línea de tiempo de `stats()` se arma en Python sobre una consulta acotada (sin `date_trunc`
  ni `strftime`), en la zona horaria configurada en `general.timezone`.
- SQLite: WAL + foreign_keys + busy_timeout, y reintento corto ante "database is locked".

Versiones de esquema (tabla `centinela_schema`); las migraciones son ADITIVAS e idempotentes (solo agregan
columnas con default, verificando antes si ya existen), así una base de una versión anterior se actualiza
sola al arrancar sin perder datos:
- v1: esquema inicial.
- v2: `analyses.truncated` (mail que superaba el límite de tamaño: solo se analizaron los headers) y
  `artifacts.password_protected` / `artifacts.listing_only`.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import random
import uuid
from collections import Counter
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta, tzinfo
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypeVar

import sqlalchemy as sa
from pydantic import ValidationError
from sqlalchemy import event
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError, OperationalError, ProgrammingError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.pool import StaticPool

from centinela.core.models import (
    AnalysisResult,
    ArtifactSummary,
    ExtractedUrl,
    Finding,
    MessageRef,
    Verdict,
    VerdictLevel,
    utcnow,
)
from centinela.storage.protocol import Campaign, ResultFilter, ResultListItem, Stats

if TYPE_CHECKING:
    from sqlalchemy.engine import Connection

    from centinela.core.config import Settings

log = logging.getLogger(__name__)

T = TypeVar("T")

SCHEMA_VERSION = 2

# Límites defensivos de lo que se persiste por resultado.
MAX_ARTIFACTS = 2000
MAX_FINDINGS = 2000
MAX_URLS = 1000
MAX_ERRORS = 200
MAX_ACTIONS = 200
MAX_EVIDENCE_CHARS = 64_000
MAX_QUERY_CHARS = 200
MAX_PAGE = 500
TIMELINE_MAX_ROWS = 500_000
TIMELINE_MAX_BUCKETS = {"hour": 24 * 93, "day": 3660}
FAMILY_SCAN_MAX_ROWS = 200_000
CAMPAIGN_DETAIL_MAX_ROWS = 50_000
PURGE_BATCH = 500
MAX_FILTER_IDS = 1000  # ResultFilter.ids: tope de ids por consulta (límite de parámetros del motor)
MAX_KEY_MAILBOX = 320
MAX_KEY_REMOTE_ID = 1024

_THREAT_LEVELS = (VerdictLevel.SUSPICIOUS.value, VerdictLevel.MALICIOUS.value)


# --------------------------------------------------------------------------- tipos y tablas


class UTCDateTime(sa.types.TypeDecorator):
    """DateTime que siempre entra y sale en UTC con tzinfo (SQLite no guarda zona horaria)."""

    impl = sa.DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: sa.Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        value = value.astimezone(UTC)
        if dialect.name == "sqlite":
            return value.replace(tzinfo=None)
        return value

    def process_result_value(self, value: Any, dialect: sa.Dialect) -> datetime | None:
        if value is None:
            return None
        if isinstance(value, str):
            value = datetime.fromisoformat(value)
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


_BigIntPK = sa.BigInteger().with_variant(sa.Integer(), "sqlite")

metadata = sa.MetaData()

analyses = sa.Table(
    "analyses",
    metadata,
    sa.Column("id", sa.Uuid(), primary_key=True),
    sa.Column("connector", sa.String(64), nullable=False),
    sa.Column("mailbox", sa.String(MAX_KEY_MAILBOX + 70), nullable=False),
    sa.Column("remote_id", sa.String(MAX_KEY_REMOTE_ID + 70), nullable=False),
    sa.Column("folder", sa.Text),
    sa.Column("message_id", sa.Text),
    sa.Column("subject", sa.Text, nullable=False, default=""),
    sa.Column("from_addr", sa.Text),
    sa.Column("from_display", sa.Text),
    sa.Column("to_json", sa.Text, nullable=False, default="[]"),
    sa.Column("received_at", UTCDateTime(), nullable=False),
    sa.Column("analyzed_at", UTCDateTime(), nullable=False),
    sa.Column("duration_ms", sa.Integer, nullable=False, default=0),
    sa.Column("size", sa.BigInteger, nullable=False, default=0),
    sa.Column("level", sa.String(16), nullable=False),
    sa.Column("score", sa.Integer, nullable=False, default=0),
    sa.Column("summary", sa.Text, nullable=False, default=""),
    sa.Column("families_json", sa.Text, nullable=False, default="[]"),
    sa.Column("urls_json", sa.Text, nullable=False, default="[]"),
    sa.Column("errors_json", sa.Text, nullable=False, default="[]"),
    sa.Column("actions_json", sa.Text, nullable=False, default="[]"),
    sa.Column("false_positive", sa.Boolean, nullable=False, default=False),
    sa.Column("fp_user", sa.Text),
    sa.Column("fp_note", sa.Text),
    sa.Column("fp_at", UTCDateTime()),
    # v2: el mail superaba limits.max_message_bytes y solo se analizaron los headers
    sa.Column("truncated", sa.Boolean, nullable=False, default=False, server_default=sa.false()),
    sa.UniqueConstraint("connector", "mailbox", "remote_id", name="uq_analyses_ref"),
    sa.Index("ix_analyses_received_at", "received_at"),
    sa.Index("ix_analyses_level", "level"),
    sa.Index("ix_analyses_mailbox", "mailbox"),
)

artifacts = sa.Table(
    "artifacts",
    metadata,
    sa.Column("pk", _BigIntPK, primary_key=True, autoincrement=True),
    sa.Column("analysis_id", sa.Uuid(), sa.ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False),
    sa.Column("position", sa.Integer, nullable=False, default=0),
    sa.Column("artifact_id", sa.Text, nullable=False),
    sa.Column("filename", sa.Text),
    sa.Column("declared_content_type", sa.Text),
    sa.Column("detected_type", sa.String(64), nullable=False, default="unknown"),
    sa.Column("size", sa.BigInteger, nullable=False, default=0),
    sa.Column("sha256", sa.String(64), nullable=False, default=""),
    sa.Column("sha1", sa.String(40), nullable=False, default=""),
    sa.Column("md5", sa.String(32), nullable=False, default=""),
    sa.Column("depth", sa.Integer, nullable=False, default=0),
    sa.Column("parent_id", sa.Text),
    sa.Column("encrypted", sa.Boolean, nullable=False, default=False),
    sa.Column("extraction_note", sa.Text),
    # v2: contenedor con contraseña (abierto o no) / entrada listada pero no extraída (sin hashes)
    sa.Column("password_protected", sa.Boolean, nullable=False, default=False, server_default=sa.false()),
    sa.Column("listing_only", sa.Boolean, nullable=False, default=False, server_default=sa.false()),
    sa.Index("ix_artifacts_analysis_id", "analysis_id"),
    sa.Index("ix_artifacts_sha256", "sha256"),
)

findings = sa.Table(
    "findings",
    metadata,
    sa.Column("pk", _BigIntPK, primary_key=True, autoincrement=True),
    sa.Column("analysis_id", sa.Uuid(), sa.ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False),
    sa.Column("position", sa.Integer, nullable=False, default=0),
    sa.Column("analyzer", sa.String(64), nullable=False),
    sa.Column("rule", sa.String(200), nullable=False),
    sa.Column("title", sa.Text, nullable=False, default=""),
    sa.Column("description", sa.Text, nullable=False, default=""),
    sa.Column("category", sa.String(32), nullable=False),
    sa.Column("severity", sa.Integer, nullable=False),
    sa.Column("score", sa.Integer, nullable=False),
    sa.Column("artifact_id", sa.Text),
    sa.Column("malware_family", sa.String(200)),
    sa.Column("evidence_json", sa.Text, nullable=False, default="{}"),
    sa.Index("ix_findings_analysis_id", "analysis_id"),
    sa.Index("ix_findings_rule", "rule"),
    sa.Index("ix_findings_family", "malware_family"),
)

kv_state = sa.Table(
    "kv_state",
    metadata,
    sa.Column("key", sa.String(512), primary_key=True),
    sa.Column("value", sa.Text, nullable=False),
    sa.Column("is_secret", sa.Boolean, nullable=False, default=False),
    sa.Column("updated_at", UTCDateTime(), nullable=False),
)

schema_info = sa.Table(
    "centinela_schema",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, autoincrement=False),
    sa.Column("version", sa.Integer, nullable=False),
    sa.Column("updated_at", UTCDateTime(), nullable=False),
)


def _add_missing_columns(conn: Connection, wanted: tuple[tuple[str, str], ...]) -> None:
    """Agrega (si faltan) columnas definidas en `metadata`. Idempotente: revisa antes qué columnas existen
    y, en PostgreSQL, usa además `ADD COLUMN IF NOT EXISTS` (dos procesos migrando a la vez)."""
    inspector = sa.inspect(conn)
    preparer = conn.dialect.identifier_preparer
    for table_name, column_name in wanted:
        table = metadata.tables[table_name]
        existing = {col["name"] for col in inspector.get_columns(table_name)}
        if column_name in existing:
            continue
        column_ddl = sa.schema.CreateColumn(table.c[column_name]).compile(dialect=conn.dialect)
        if_not_exists = "IF NOT EXISTS " if conn.dialect.name == "postgresql" else ""
        try:
            conn.exec_driver_sql(
                f"ALTER TABLE {preparer.format_table(table)} ADD COLUMN {if_not_exists}{column_ddl}"
            )
        except OperationalError as exc:
            if "duplicate column" not in str(exc).lower():  # SQLite: otro proceso la agregó recién
                raise
        log.info("esquema: columna %s.%s agregada", table_name, column_name)


_V2_COLUMNS = (
    ("analyses", "truncated"),
    ("artifacts", "password_protected"),
    ("artifacts", "listing_only"),
)


def _migrate_v1_to_v2(conn: Connection) -> None:
    _add_missing_columns(conn, _V2_COLUMNS)


# MIGRATIONS[n] lleva el esquema de la versión n a la n+1 (sync, dentro de run_sync). Deben ser aditivas
# e idempotentes: se pueden correr de nuevo sobre una base ya migrada sin efecto.
MIGRATIONS: dict[int, Callable[[Connection], None]] = {1: _migrate_v1_to_v2}


# --------------------------------------------------------------------------- helpers


def _clean_text(value: str) -> str:
    """Texto apto para cualquier motor: sin NUL (PostgreSQL los rechaza) ni surrogates sueltos
    (asyncpg/sqlite3 fallan al codificar). Los headers de un mail hostil pueden traer ambos."""
    if "\x00" in value:
        value = value.replace("\x00", "")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        value = value.encode("utf-8", "replace").decode("utf-8")
    return value


def _clip(value: str | None, n: int) -> str | None:
    if value is None:
        return None
    value = _clean_text(str(value))
    return value if len(value) <= n else value[: n - 1] + "…"


def _key_part(value: str, n: int) -> str:
    """Partes de la clave única: si son absurdamente largas o traen caracteres que la base no acepta,
    se reemplazan por su hash (determinístico, así `has_ref` sigue encontrándolas)."""
    if len(value) <= n and _clean_text(value) == value:
        return value
    return "sha256:" + hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()


def _dumps(obj: Any) -> str:
    # json escapa NUL como \u0000 (texto válido); _clean_text cubre surrogates sueltos
    return _clean_text(json.dumps(obj, ensure_ascii=False, separators=(",", ":"), default=str))


def _loads_list(text: str | None) -> list[Any]:
    try:
        value = json.loads(text or "[]")
    except (TypeError, ValueError):
        return []
    return value if isinstance(value, list) else []


def _bound(obj: Any, depth: int = 0) -> Any:
    """Acota recursivamente un objeto de evidencia (strings largos, listas enormes, anidamiento)."""
    if depth > 6:
        return "…"
    if obj is None or isinstance(obj, bool | int | float):
        return obj
    if isinstance(obj, str):
        return obj if len(obj) <= 2000 else obj[:2000] + "…"
    if isinstance(obj, bytes | bytearray):
        return bytes(obj[:256]).hex() + ("…" if len(obj) > 256 else "")
    if isinstance(obj, dict):
        return {str(k)[:200]: _bound(v, depth + 1) for k, v in list(obj.items())[:100]}
    if isinstance(obj, list | tuple | set | frozenset):
        return [_bound(v, depth + 1) for v in list(obj)[:200]]
    return _bound(str(obj), depth + 1)


def _evidence_json(evidence: dict[str, Any]) -> str:
    text = _dumps(_bound(evidence))
    if len(text) > MAX_EVIDENCE_CHARS:
        text = _dumps({"_truncado": True, "claves": [str(k)[:100] for k in list(evidence)[:50]]})
    return text


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _merge_unique(current: list[Any], new: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in [*current, *new]:
        s = str(item)
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _level(value: str | None) -> VerdictLevel:
    try:
        return VerdictLevel(value)
    except ValueError:
        return VerdictLevel.ERROR


def _aware(dt: datetime) -> datetime:
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt


def load_timezone(name: str | None) -> tzinfo:
    """ZoneInfo de `general.timezone`; si no hay base de zonas (tzdata) cae a UTC con un aviso."""
    if not name or name.upper() == "UTC":
        return UTC
    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo(name)
    except Exception:  # noqa: BLE001 - ZoneInfoNotFoundError, ValueError, falta tzdata...
        log.warning("zona horaria %r no disponible (¿falta tzdata?); se usa UTC para las estadísticas", name)
        return UTC


def _floor(dt_local: datetime, bucket: str) -> datetime:
    if bucket == "day":
        return dt_local.replace(hour=0, minute=0, second=0, microsecond=0)
    return dt_local.replace(minute=0, second=0, microsecond=0)


def bucket_key(dt: datetime, bucket: str, tz: tzinfo) -> str:
    return _floor(_aware(dt).astimezone(tz), bucket).isoformat()


def bucket_keys(start: datetime, end: datetime, bucket: str, tz: tzinfo) -> list[str]:
    """Claves de bucket continuas (sin huecos) entre start y end, en la zona `tz`."""
    keys: list[str] = []
    seen: set[str] = set()
    cursor = _aware(start).astimezone(UTC).replace(minute=0, second=0, microsecond=0)
    end = _aware(end).astimezone(UTC)
    while cursor <= end:
        k = bucket_key(cursor, bucket, tz)
        if k not in seen:
            seen.add(k)
            keys.append(k)
        cursor += timedelta(hours=1)
    return keys


def _normalize_url(url: str) -> str:
    """Acepta URLs de base "cortas" y fuerza drivers async (postgres:// -> postgresql+asyncpg://)."""
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://") :]
    u = make_url(url)
    explicit = u.drivername.split("+", 1)[1] if "+" in u.drivername else None
    if u.get_backend_name() == "postgresql" and explicit not in {"asyncpg", "psycopg"}:
        u = u.set(drivername="postgresql+asyncpg")
    elif u.get_backend_name() == "sqlite" and explicit != "aiosqlite":
        u = u.set(drivername="sqlite+aiosqlite")
    return u.render_as_string(hide_password=False)


def _is_memory_sqlite(url: str) -> bool:
    u = make_url(url)
    db = u.database or ""
    return u.get_backend_name() == "sqlite" and (db in {"", ":memory:"} or "mode=memory" in url)


# --------------------------------------------------------------------------- store


class SqlResultStore:
    """`ResultStore` sobre SQLAlchemy async. `SqlResultStore(settings)` usa `settings.database_url`."""

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        url: str | None = None,
        engine: AsyncEngine | None = None,
    ) -> None:
        self.settings = settings
        self._tz = load_timezone(settings.general.timezone if settings else "UTC")
        self._initialized = False
        self._write_lock = asyncio.Lock()
        self._owns_engine = engine is None
        if engine is None:
            raw_url = url or (settings.database_url if settings else "sqlite+aiosqlite://")
            self._url = _normalize_url(raw_url)
            engine = self._make_engine(self._url)
        else:
            self._url = engine.url.render_as_string(hide_password=False)
        self.engine: AsyncEngine = engine

    # ------------------------------------------------------------- infraestructura

    @property
    def dialect(self) -> str:
        return self.engine.dialect.name

    @property
    def is_sqlite(self) -> bool:
        return self.dialect == "sqlite"

    @staticmethod
    def _make_engine(url: str) -> AsyncEngine:
        u = make_url(url)
        if u.get_backend_name() == "sqlite":
            memory = _is_memory_sqlite(url)
            if memory:
                engine = create_async_engine(
                    url, poolclass=StaticPool, connect_args={"check_same_thread": False}
                )
            else:
                engine = create_async_engine(url, connect_args={"timeout": 30})

            @event.listens_for(engine.sync_engine, "connect")
            def _sqlite_pragmas(dbapi_connection: Any, _record: Any) -> None:
                cursor = dbapi_connection.cursor()
                try:
                    cursor.execute("PRAGMA foreign_keys=ON")
                    cursor.execute("PRAGMA busy_timeout=10000")
                    if not memory:
                        cursor.execute("PRAGMA journal_mode=WAL")
                        cursor.execute("PRAGMA synchronous=NORMAL")
                finally:
                    cursor.close()
                # el driver sqlite3 no abre transacción antes de un SELECT (lectura-modificación-escritura
                # perdería actualizaciones): SQLAlchemy emite su propio BEGIN (receta oficial para aiosqlite)
                dbapi_connection.isolation_level = None

            @event.listens_for(engine.sync_engine, "begin")
            def _sqlite_begin(conn: Any) -> None:
                conn.exec_driver_sql("BEGIN")

            return engine
        return create_async_engine(url, pool_pre_ping=True, pool_size=5, max_overflow=10, pool_recycle=1800)

    def _prepare_sqlite_path(self) -> None:
        u = make_url(self._url)
        if u.get_backend_name() != "sqlite" or _is_memory_sqlite(self._url):
            return
        db = u.database or ""
        if db.startswith("file:"):
            return
        parent = Path(db).expanduser().parent
        if str(parent) not in {"", "."}:
            parent.mkdir(parents=True, exist_ok=True)

    async def _retry(self, fn: Callable[[], Awaitable[T]]) -> T:
        """Ejecuta una transacción de escritura. En SQLite (un solo escritor a la vez) las serializa
        dentro del proceso y reintenta ante "database is locked" causado por otros procesos."""
        attempts = 6
        for attempt in range(attempts):
            try:
                if self.is_sqlite:
                    async with self._write_lock:
                        return await fn()
                return await fn()
            except OperationalError as exc:
                text = str(exc).lower()
                if (
                    not self.is_sqlite
                    or ("locked" not in text and "busy" not in text)
                    or attempt == attempts - 1
                ):
                    raise
                await asyncio.sleep(0.05 * (2**attempt) + random.random() * 0.05)  # noqa: S311 - jitter
        raise AssertionError("inalcanzable")

    async def init(self) -> None:
        """Crea tablas/índices (idempotente) y registra/verifica la versión de esquema."""
        if self._initialized:
            return
        await asyncio.to_thread(self._prepare_sqlite_path)
        for attempt in range(3):
            try:
                async with self.engine.begin() as conn:
                    await conn.run_sync(metadata.create_all)
                break
            except (OperationalError, ProgrammingError, IntegrityError):
                # otro proceso creando las mismas tablas a la vez (ingest + worker arrancando juntos)
                if attempt == 2:
                    raise
                await asyncio.sleep(0.5 * (attempt + 1))
        await self._ensure_schema_version()
        self._initialized = True

    async def _ensure_schema_version(self) -> None:
        for attempt in range(5):
            try:
                async with self.engine.begin() as conn:
                    current = (
                        await conn.execute(sa.select(schema_info.c.version).where(schema_info.c.id == 1))
                    ).scalar_one_or_none()
                    if current is None:
                        await conn.execute(
                            schema_info.insert().values(id=1, version=SCHEMA_VERSION, updated_at=utcnow())
                        )
                        return
                    if current > SCHEMA_VERSION:
                        raise RuntimeError(
                            f"La base de datos tiene el esquema v{current}, más nuevo que el que entiende esta "
                            f"versión de Centinela (v{SCHEMA_VERSION}). Actualizá Centinela antes de usar esta base."
                        )
                    for version in range(current, SCHEMA_VERSION):
                        migration = MIGRATIONS.get(version)
                        if migration is None:
                            raise RuntimeError(f"falta la migración de esquema v{version} -> v{version + 1}")
                        log.info("migrando esquema de base v%d -> v%d", version, version + 1)
                        await conn.run_sync(migration)
                    if current < SCHEMA_VERSION:
                        await conn.execute(
                            schema_info.update()
                            .where(schema_info.c.id == 1)
                            .values(version=SCHEMA_VERSION, updated_at=utcnow())
                        )
                    return
            except IntegrityError:
                continue  # otro proceso insertó la fila de versión al mismo tiempo: releer
            except OperationalError as exc:
                # SQLite: otro proceso (ingest + worker arrancando juntos) está migrando: esperar y releer
                text = str(exc).lower()
                if not self.is_sqlite or ("locked" not in text and "busy" not in text) or attempt == 4:
                    raise
                await asyncio.sleep(0.2 * (attempt + 1))
        raise RuntimeError("no se pudo registrar la versión de esquema")

    async def close(self) -> None:
        if self._owns_engine:
            await self.engine.dispose()

    async def ping(self) -> bool:
        async with self.engine.connect() as conn:
            await conn.execute(sa.text("SELECT 1"))
        return True

    # ------------------------------------------------------------- escritura

    @staticmethod
    def _ref_values(ref: MessageRef) -> tuple[str, str, str]:
        return (
            _clean_text(ref.connector)[:64],
            _key_part(ref.mailbox, MAX_KEY_MAILBOX),
            _key_part(ref.remote_id, MAX_KEY_REMOTE_ID),
        )

    def _rows(
        self, result: AnalysisResult
    ) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
        connector, mailbox, remote_id = self._ref_values(result.ref)
        v = result.verdict
        analysis = {
            "id": result.id,
            "connector": connector,
            "mailbox": mailbox,
            "remote_id": remote_id,
            "folder": _clip(result.ref.folder, 1000),
            "message_id": _clip(result.message_id, 998),
            "subject": _clip(result.subject, 2000) or "",
            "from_addr": _clip(result.from_addr, 320),
            "from_display": _clip(result.from_display, 500),
            "to_json": _dumps([_clip(t, 320) for t in result.to[:200]]),
            "received_at": result.received_at,
            "analyzed_at": result.analyzed_at,
            "duration_ms": max(0, min(int(result.duration_ms), 2_000_000_000)),
            "size": max(0, int(result.size)),
            "level": v.level.value,
            "score": int(v.score),
            "summary": _clip(v.summary, 4000) or "",
            "families_json": _dumps([_clip(f, 200) for f in v.malware_families[:50]]),
            "urls_json": _dumps(
                [
                    {
                        "url": _clip(u.url, 4096),
                        "source": _clip(u.source, 300),
                        "display_text": _clip(u.display_text, 500),
                    }
                    for u in result.urls[:MAX_URLS]
                ]
            ),
            "errors_json": _dumps([_clip(e, 1000) for e in result.errors[:MAX_ERRORS]]),
            "actions_json": _dumps(
                _merge_unique([], [_clip(a, 300) or "" for a in result.actions])[:MAX_ACTIONS]
            ),
            "false_positive": False,
            "truncated": bool(result.truncated),
        }
        arts = [
            {
                "analysis_id": result.id,
                "position": i,
                "artifact_id": _clip(a.id, 2000) or "",
                "filename": _clip(a.filename, 1000),
                "declared_content_type": _clip(a.declared_content_type, 255),
                "detected_type": (_clip(a.detected_type, 64) or "unknown"),
                "size": max(0, int(a.size)),
                "sha256": (a.sha256 or "").lower()[:64],
                "sha1": (a.sha1 or "").lower()[:40],
                "md5": (a.md5 or "").lower()[:32],
                "depth": int(a.depth),
                "parent_id": _clip(a.parent_id, 2000),
                "encrypted": bool(a.encrypted),
                "password_protected": bool(a.password_protected),
                "listing_only": bool(a.listing_only),
                "extraction_note": _clip(a.extraction_note, 1000),
            }
            for i, a in enumerate(result.artifacts[:MAX_ARTIFACTS])
        ]
        fnds = [
            {
                "analysis_id": result.id,
                "position": i,
                "analyzer": _clip(f.analyzer, 64) or "",
                "rule": _clip(f.rule, 200) or "",
                "title": _clip(f.title, 500) or "",
                "description": _clip(f.description, 4000) or "",
                "category": f.category.value,
                "severity": int(f.severity),
                "score": int(f.score),
                "artifact_id": _clip(f.artifact_id, 2000),
                "malware_family": _clip(f.malware_family, 200),
                "evidence_json": _evidence_json(f.evidence),
            }
            for i, f in enumerate(result.findings[:MAX_FINDINGS])
        ]
        return analysis, arts, fnds

    async def save_result(self, result: AnalysisResult) -> bool:
        analysis, arts, fnds = self._rows(result)

        async def _tx() -> None:
            async with self.engine.begin() as conn:
                await conn.execute(analyses.insert().values(**analysis))
                if arts:
                    await conn.execute(artifacts.insert(), arts)
                if fnds:
                    await conn.execute(findings.insert(), fnds)

        try:
            await self._retry(_tx)
        except IntegrityError:
            if await self.has_ref(result.ref) or await self._id_exists(result.id):
                log.debug(
                    "resultado duplicado para %s/%s: no se guarda", result.ref.connector, result.ref.mailbox
                )
                return False
            raise
        return True

    async def _id_exists(self, result_id: uuid.UUID) -> bool:
        async with self.engine.connect() as conn:
            row = await conn.execute(sa.select(analyses.c.id).where(analyses.c.id == result_id).limit(1))
            return row.first() is not None

    async def has_ref(self, ref: MessageRef) -> bool:
        connector, mailbox, remote_id = self._ref_values(ref)
        async with self.engine.connect() as conn:
            row = await conn.execute(
                sa.select(analyses.c.id)
                .where(
                    analyses.c.connector == connector,
                    analyses.c.mailbox == mailbox,
                    analyses.c.remote_id == remote_id,
                )
                .limit(1)
            )
            return row.first() is not None

    async def record_actions(self, result_id: uuid.UUID, actions: list[str]) -> None:
        if not actions:
            return
        new = [_clip(a, 300) or "" for a in actions]

        async def _tx() -> None:
            async with self.engine.begin() as conn:
                current = (
                    await conn.execute(
                        sa.select(analyses.c.actions_json).where(analyses.c.id == result_id).with_for_update()
                    )
                ).scalar_one_or_none()
                if current is None:
                    return
                merged = _merge_unique(_loads_list(current), new)[:MAX_ACTIONS]
                await conn.execute(
                    analyses.update().where(analyses.c.id == result_id).values(actions_json=_dumps(merged))
                )

        await self._retry(_tx)

    async def set_false_positive(
        self, result_id: uuid.UUID, value: bool, *, user: str, note: str = ""
    ) -> bool:
        async def _tx() -> int:
            async with self.engine.begin() as conn:
                res = await conn.execute(
                    analyses.update()
                    .where(analyses.c.id == result_id)
                    .values(
                        false_positive=bool(value),
                        fp_user=_clip(user, 200),
                        fp_note=_clip(note, 2000) or None,
                        fp_at=utcnow(),
                    )
                )
                return res.rowcount or 0

        return (await self._retry(_tx)) > 0

    async def purge_older_than(self, cutoff: datetime) -> int:
        """Borra en lotes chicos (transacciones cortas: no bloquea a los workers en SQLite)."""

        async def _batch() -> int:
            async with self.engine.begin() as conn:
                ids = (
                    (
                        await conn.execute(
                            sa.select(analyses.c.id).where(analyses.c.received_at < cutoff).limit(PURGE_BATCH)
                        )
                    )
                    .scalars()
                    .all()
                )
                if not ids:
                    return 0
                # borrado explícito de hijos: no depende de que el motor tenga FKs en cascada activas
                await conn.execute(findings.delete().where(findings.c.analysis_id.in_(ids)))
                await conn.execute(artifacts.delete().where(artifacts.c.analysis_id.in_(ids)))
                res = await conn.execute(analyses.delete().where(analyses.c.id.in_(ids)))
                return res.rowcount or len(ids)

        total = 0
        for _ in range(100_000):  # tope de seguridad: 50M filas por corrida
            n = await self._retry(_batch)
            if not n:
                break
            total += n
            await asyncio.sleep(0)
        if total:
            log.info("retención: %d resultados anteriores a %s borrados", total, cutoff.isoformat())
        return total

    # ------------------------------------------------------------- lectura

    async def get_result(self, result_id: uuid.UUID) -> AnalysisResult | None:
        """Resultado completo. `false_positive*` refleja el último feedback guardado: si la marca se quitó,
        `false_positive` es False y `false_positive_by/at` dicen quién la quitó y cuándo."""
        async with self.engine.connect() as conn:
            row = (
                (await conn.execute(sa.select(analyses).where(analyses.c.id == result_id))).mappings().first()
            )
            if row is None:
                return None
            arts = (
                (
                    await conn.execute(
                        sa.select(artifacts)
                        .where(artifacts.c.analysis_id == result_id)
                        .order_by(artifacts.c.position)
                    )
                )
                .mappings()
                .all()
            )
            fnds = (
                (
                    await conn.execute(
                        sa.select(findings)
                        .where(findings.c.analysis_id == result_id)
                        .order_by(findings.c.position)
                    )
                )
                .mappings()
                .all()
            )
        return self._to_result(row, arts, fnds)

    @staticmethod
    def _to_result(row: Any, arts: list[Any], fnds: list[Any]) -> AnalysisResult:
        artifact_models = [
            ArtifactSummary(
                id=a["artifact_id"],
                filename=a["filename"],
                declared_content_type=a["declared_content_type"],
                detected_type=a["detected_type"],
                size=a["size"],
                sha256=a["sha256"],
                sha1=a["sha1"],
                md5=a["md5"],
                depth=a["depth"],
                parent_id=a["parent_id"],
                encrypted=bool(a["encrypted"]),
                password_protected=bool(a["password_protected"]),
                listing_only=bool(a["listing_only"]),
                extraction_note=a["extraction_note"],
            )
            for a in arts
        ]
        finding_models: list[Finding] = []
        for f in fnds:
            try:
                evidence = json.loads(f["evidence_json"] or "{}")
                finding_models.append(
                    Finding(
                        analyzer=f["analyzer"],
                        rule=f["rule"],
                        title=f["title"],
                        description=f["description"],
                        category=f["category"],
                        severity=f["severity"],
                        score=f["score"],
                        artifact_id=f["artifact_id"],
                        malware_family=f["malware_family"],
                        evidence=evidence if isinstance(evidence, dict) else {"valor": evidence},
                    )
                )
            except (ValidationError, ValueError, TypeError):
                log.warning("hallazgo ilegible en la base (regla %s); se omite", f["rule"])
        urls: list[ExtractedUrl] = []
        for u in _loads_list(row["urls_json"]):
            try:
                urls.append(ExtractedUrl.model_validate(u))
            except ValidationError:
                continue
        return AnalysisResult(
            id=row["id"],
            ref=MessageRef(
                connector=row["connector"],
                mailbox=row["mailbox"],
                remote_id=row["remote_id"],
                folder=row["folder"],
            ),
            message_id=row["message_id"],
            subject=row["subject"] or "",
            from_addr=row["from_addr"],
            from_display=row["from_display"],
            to=[str(t) for t in _loads_list(row["to_json"])],
            received_at=row["received_at"],
            analyzed_at=row["analyzed_at"],
            duration_ms=row["duration_ms"],
            size=row["size"],
            artifacts=artifact_models,
            urls=urls,
            findings=finding_models,
            verdict=Verdict(
                level=_level(row["level"]),
                score=max(0, min(100, row["score"])),
                summary=row["summary"] or "",
                malware_families=[str(x) for x in _loads_list(row["families_json"])],
            ),
            errors=[str(e) for e in _loads_list(row["errors_json"])],
            actions=[str(a) for a in _loads_list(row["actions_json"])],
            truncated=bool(row["truncated"]),
            false_positive=bool(row["false_positive"]),
            false_positive_by=row["fp_user"] or None,
            false_positive_note=row["fp_note"] or None,
            false_positive_at=row["fp_at"],
        )

    def _conditions(self, flt: ResultFilter) -> list[Any]:
        c: list[Any] = []
        if flt.ids is not None:
            ids = list(dict.fromkeys(flt.ids))
            if len(ids) > MAX_FILTER_IDS:
                raise ValueError(f"demasiados ids en el filtro ({len(ids)} > {MAX_FILTER_IDS})")
            c.append(analyses.c.id.in_(ids) if ids else sa.false())
        if flt.level is not None:
            c.append(analyses.c.level == flt.level.value)
        if flt.min_level is not None:
            c.append(analyses.c.level.in_([lv.value for lv in VerdictLevel if lv.rank >= flt.min_level.rank]))
        if flt.connector:
            c.append(analyses.c.connector == _clean_text(flt.connector)[:64])
        if flt.mailbox:
            c.append(sa.func.lower(analyses.c.mailbox) == _clean_text(flt.mailbox).strip().lower())
        q = _clean_text(flt.q or "").strip()[:MAX_QUERY_CHARS]
        if q:
            pat = f"%{_escape_like(q)}%"
            art_conds: list[Any] = [artifacts.c.filename.ilike(pat, escape="\\")]
            ql = q.lower()
            if len(ql) >= 8 and all(ch in "0123456789abcdef" for ch in ql):
                art_conds.append(artifacts.c.sha256.like(f"{ql}%"))  # hash completo o prefijo
            c.append(
                sa.or_(
                    analyses.c.subject.ilike(pat, escape="\\"),
                    analyses.c.from_addr.ilike(pat, escape="\\"),
                    analyses.c.from_display.ilike(pat, escape="\\"),
                    analyses.c.message_id == q,
                    sa.exists().where(artifacts.c.analysis_id == analyses.c.id, sa.or_(*art_conds)),
                )
            )
        if flt.sha256:
            sha = _clean_text(flt.sha256).strip().lower()[:64]
            c.append(sa.exists().where(artifacts.c.analysis_id == analyses.c.id, artifacts.c.sha256 == sha))
        fam = _clean_text(flt.family or "").strip()[:200]
        if fam:
            fam_json = _escape_like(_dumps(fam))  # '"AgentTesla"' tal como queda dentro de families_json
            c.append(
                sa.or_(
                    analyses.c.families_json.ilike(f"%{fam_json}%", escape="\\"),
                    sa.exists().where(
                        findings.c.analysis_id == analyses.c.id,
                        sa.func.lower(findings.c.malware_family) == fam.lower(),
                    ),
                )
            )
        if flt.since is not None:
            c.append(analyses.c.received_at >= flt.since)
        if flt.until is not None:
            c.append(analyses.c.received_at <= flt.until)
        if not flt.include_false_positives:
            c.append(analyses.c.false_positive == sa.false())
        return c

    async def list_results(
        self, flt: ResultFilter, *, limit: int = 50, offset: int = 0
    ) -> tuple[list[ResultListItem], int]:
        limit = max(1, min(int(limit), MAX_PAGE))
        offset = max(0, int(offset))
        conds = self._conditions(flt)
        art_count = (
            sa.select(sa.func.count())
            .select_from(artifacts)
            .where(artifacts.c.analysis_id == analyses.c.id)
            .correlate(analyses)
            .scalar_subquery()
        )
        find_count = (
            sa.select(sa.func.count())
            .select_from(findings)
            .where(findings.c.analysis_id == analyses.c.id)
            .correlate(analyses)
            .scalar_subquery()
        )
        rows_q = (
            sa.select(
                analyses.c.id,
                analyses.c.connector,
                analyses.c.mailbox,
                analyses.c.subject,
                analyses.c.from_addr,
                analyses.c.from_display,
                analyses.c.received_at,
                analyses.c.analyzed_at,
                analyses.c.level,
                analyses.c.score,
                analyses.c.summary,
                analyses.c.families_json,
                analyses.c.false_positive,
                art_count.label("artifact_count"),
                find_count.label("finding_count"),
            )
            .where(*conds)
            .order_by(analyses.c.received_at.desc(), analyses.c.id.desc())
            .limit(limit)
            .offset(offset)
        )
        count_q = sa.select(sa.func.count()).select_from(analyses).where(*conds)
        async with self.engine.connect() as conn:
            total = int((await conn.execute(count_q)).scalar_one())
            rows = (await conn.execute(rows_q)).mappings().all()
        items = [
            ResultListItem(
                id=r["id"],
                connector=r["connector"],
                mailbox=r["mailbox"],
                subject=r["subject"] or "",
                from_addr=r["from_addr"],
                from_display=r["from_display"],
                received_at=r["received_at"],
                analyzed_at=r["analyzed_at"],
                level=_level(r["level"]),
                score=max(0, min(100, r["score"])),
                summary=r["summary"] or "",
                malware_families=[str(x) for x in _loads_list(r["families_json"])],
                artifact_count=int(r["artifact_count"] or 0),
                finding_count=int(r["finding_count"] or 0),
                false_positive=bool(r["false_positive"]),
            )
            for r in rows
        ]
        return items, total

    async def stats(self, since: datetime, *, bucket: str = "hour") -> Stats:
        if bucket not in TIMELINE_MAX_BUCKETS:
            raise ValueError("bucket debe ser 'hour' o 'day'")
        since = _aware(since)
        now = utcnow()
        in_range = analyses.c.received_at >= since
        n = sa.func.count().label("n")
        stats = Stats(since=since)
        async with self.engine.connect() as conn:
            for level, count in (
                await conn.execute(sa.select(analyses.c.level, n).where(in_range).group_by(analyses.c.level))
            ).all():
                stats.by_level[str(level)] = int(count)
            stats.total = sum(stats.by_level.values())
            for connector, count in (
                await conn.execute(
                    sa.select(analyses.c.connector, n).where(in_range).group_by(analyses.c.connector)
                )
            ).all():
                stats.by_connector[str(connector)] = int(count)
            avg = (
                await conn.execute(sa.select(sa.func.avg(analyses.c.duration_ms)).where(in_range))
            ).scalar()
            stats.avg_duration_ms = round(float(avg or 0.0), 1)
            senders = await conn.execute(
                sa.select(analyses.c.from_addr, n)
                .where(
                    in_range,
                    analyses.c.level.in_(_THREAT_LEVELS),
                    analyses.c.from_addr.is_not(None),
                    analyses.c.from_addr != "",
                )
                .group_by(analyses.c.from_addr)
                .order_by(sa.desc("n"), analyses.c.from_addr)
                .limit(10)
            )
            stats.top_senders = [(str(s), int(c)) for s, c in senders.all()]
            n_msgs = sa.func.count(sa.distinct(findings.c.analysis_id)).label("n")
            rules = await conn.execute(
                sa.select(findings.c.rule, n_msgs)
                .select_from(findings.join(analyses, findings.c.analysis_id == analyses.c.id))
                .where(in_range, findings.c.severity > 0)
                .group_by(findings.c.rule)
                .order_by(sa.desc("n"), findings.c.rule)
                .limit(10)
            )
            stats.top_rules = [(str(r), int(c)) for r, c in rules.all()]

            families: Counter[str] = Counter()
            fam_rows = await conn.stream(
                sa.select(analyses.c.families_json)
                .where(in_range, analyses.c.families_json != "[]")
                .limit(FAMILY_SCAN_MAX_ROWS)
            )
            async for (fam_json,) in fam_rows:
                families.update({str(f) for f in _loads_list(fam_json) if f})
            stats.top_families = sorted(families.items(), key=lambda kv: (-kv[1], kv[0]))[:10]

            stats.timeline = await self._timeline(conn, since, now, bucket)
        return stats

    async def _timeline(self, conn: Any, since: datetime, now: datetime, bucket: str) -> list[dict[str, Any]]:
        if since > now:
            return []
        step = timedelta(days=1) if bucket == "day" else timedelta(hours=1)
        start = max(since, now - step * TIMELINE_MAX_BUCKETS[bucket])
        keys = bucket_keys(start, now, bucket, self._tz)
        levels = [lv.value for lv in (VerdictLevel.CLEAN, VerdictLevel.SUSPICIOUS, VerdictLevel.MALICIOUS)]
        table: dict[str, dict[str, Any]] = {
            k: {"bucket": k, **{lv: 0 for lv in levels}, VerdictLevel.ERROR.value: 0} for k in keys
        }
        rows = await conn.stream(
            sa.select(analyses.c.received_at, analyses.c.level)
            .where(analyses.c.received_at >= start)
            .limit(TIMELINE_MAX_ROWS)
        )
        seen = 0
        async for received_at, level in rows:
            seen += 1
            slot = table.get(bucket_key(received_at, bucket, self._tz))
            if slot is not None and level in slot:
                slot[level] += 1
        if seen >= TIMELINE_MAX_ROWS:
            log.warning("línea de tiempo truncada a %d mensajes", TIMELINE_MAX_ROWS)
        return [table[k] for k in keys]

    async def campaigns(
        self, since: datetime, *, min_messages: int = 2, limit: int = 50, include_clean: bool = False
    ) -> list[Campaign]:
        """Mismo adjunto (sha256) en varios mails. Por defecto solo cuenta mails sospechosos/maliciosos
        no marcados como falso positivo (así los logos de firma y PDFs legítimos repetidos no tapan
        las campañas reales); `include_clean=True` incluye todo."""
        limit = max(1, min(int(limit), 200))
        min_messages = max(1, int(min_messages))
        conds: list[Any] = [analyses.c.received_at >= _aware(since), artifacts.c.sha256 != ""]
        if not include_clean:
            conds += [analyses.c.level.in_(_THREAT_LEVELS), analyses.c.false_positive == sa.false()]
        joined = artifacts.join(analyses, artifacts.c.analysis_id == analyses.c.id)
        n = sa.func.count(sa.distinct(artifacts.c.analysis_id)).label("n")
        last = sa.func.max(analyses.c.received_at).label("last_seen")
        group_q = (
            sa.select(artifacts.c.sha256, n, sa.func.min(analyses.c.received_at).label("first_seen"), last)
            .select_from(joined)
            .where(*conds)
            .group_by(artifacts.c.sha256)
            .having(sa.func.count(sa.distinct(artifacts.c.analysis_id)) >= min_messages)
            .order_by(sa.desc("n"), sa.desc("last_seen"))
            .limit(limit)
        )
        async with self.engine.connect() as conn:
            groups = (await conn.execute(group_q)).all()
            if not groups:
                return []
            hashes = [g[0] for g in groups]
            detail = await conn.execute(
                sa.select(
                    artifacts.c.sha256,
                    artifacts.c.filename,
                    artifacts.c.detected_type,
                    analyses.c.mailbox,
                    analyses.c.level,
                    analyses.c.families_json,
                )
                .select_from(joined)
                .where(*conds, artifacts.c.sha256.in_(hashes))
                .limit(CAMPAIGN_DETAIL_MAX_ROWS)
            )
            detail_rows = detail.all()
        info: dict[str, dict[str, Any]] = {
            h: {
                "names": Counter(),
                "types": Counter(),
                "mailboxes": set(),
                "levels": set(),
                "families": Counter(),
            }
            for h in hashes
        }
        for sha, filename, dtype, mailbox, level, fam_json in detail_rows:
            d = info[sha]
            if filename:
                d["names"][filename] += 1
            d["types"][dtype or "unknown"] += 1
            d["mailboxes"].add(mailbox)
            d["levels"].add(_level(level))
            d["families"].update({str(f) for f in _loads_list(fam_json) if f})
        out: list[Campaign] = []
        for sha, count, first_seen, last_seen in groups:
            d = info[sha]
            levels = d["levels"] or {VerdictLevel.CLEAN}
            out.append(
                Campaign(
                    sha256=sha,
                    filename=d["names"].most_common(1)[0][0] if d["names"] else None,
                    detected_type=d["types"].most_common(1)[0][0] if d["types"] else "unknown",
                    first_seen=first_seen,
                    last_seen=last_seen,
                    message_count=int(count),
                    mailboxes=sorted(d["mailboxes"])[:200],
                    max_level=max(levels, key=lambda lv: lv.rank),
                    malware_families=[f for f, _ in d["families"].most_common(10)],
                )
            )
        return out


__all__ = ["SCHEMA_VERSION", "SqlResultStore", "UTCDateTime", "kv_state", "load_timezone", "metadata"]
