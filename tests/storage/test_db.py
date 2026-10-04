from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta, timezone

import pytest
import sqlalchemy as sa

from centinela.core.models import (
    ArtifactSummary,
    ExtractedUrl,
    FindingCategory,
    MessageRef,
    Severity,
    VerdictLevel,
    utcnow,
)
from centinela.storage.db import (
    MAX_FILTER_IDS,
    MIGRATIONS,
    SCHEMA_VERSION,
    SqlResultStore,
    _normalize_url,
    analyses,
    artifacts,
    bucket_key,
    bucket_keys,
    findings,
    schema_info,
)
from centinela.storage.protocol import ResultFilter, ResultStore
from tests.storage.factories import artifact, finding, make_result, malicious_result, sha


@pytest.fixture
async def store(settings):
    settings.general.timezone = "UTC"
    s = SqlResultStore(settings)
    await s.init()
    yield s
    await s.close()


async def _count(store: SqlResultStore, table: sa.Table) -> int:
    async with store.engine.connect() as conn:
        return int((await conn.execute(sa.select(sa.func.count()).select_from(table))).scalar_one())


# --------------------------------------------------------------------------- init / esquema


async def test_implements_protocol_and_init_is_idempotent(settings, store):
    assert isinstance(store, ResultStore)
    await store.init()  # segunda vez: no hace nada
    other = SqlResultStore(settings)  # otro proceso sobre la misma base
    await other.init()
    async with other.engine.connect() as conn:
        version = (await conn.execute(sa.select(schema_info.c.version))).scalars().all()
        journal = (await conn.exec_driver_sql("PRAGMA journal_mode")).scalar_one()
        fks = (await conn.exec_driver_sql("PRAGMA foreign_keys")).scalar_one()
    await other.close()
    assert version == [SCHEMA_VERSION]
    assert journal.lower() == "wal"
    assert fks == 1


async def test_newer_schema_is_rejected(settings, store):
    async with store.engine.begin() as conn:
        await conn.execute(schema_info.update().values(version=SCHEMA_VERSION + 5))
    other = SqlResultStore(settings)
    with pytest.raises(RuntimeError, match="más nuevo"):
        await other.init()
    await other.close()


async def test_creates_parent_directory_for_sqlite(tmp_path):
    db = tmp_path / "sub" / "dir" / "c.db"
    s = SqlResultStore(url=f"sqlite+aiosqlite:///{db.as_posix()}")
    await s.init()
    assert await s.save_result(make_result("x"))
    await s.close()
    assert db.exists()


async def test_in_memory_sqlite_works():
    s = SqlResultStore(url="sqlite+aiosqlite://")
    await s.init()
    r = make_result("m1")
    assert await s.save_result(r)
    assert (await s.get_result(r.id)) is not None
    assert await s.ping()
    await s.close()


async def _make_v1_database(settings) -> uuid.UUID:
    """Base con el esquema v1 (sin las columnas nuevas) y un resultado guardado "a la vieja"."""
    s = SqlResultStore(settings)
    await s.init()
    r = malicious_result("v1-mail")
    assert await s.save_result(r)
    await s.set_false_positive(r.id, True, user="ana", note="era de un proveedor")
    async with s.engine.begin() as conn:
        await conn.exec_driver_sql("ALTER TABLE analyses DROP COLUMN truncated")
        await conn.exec_driver_sql("ALTER TABLE artifacts DROP COLUMN password_protected")
        await conn.exec_driver_sql("ALTER TABLE artifacts DROP COLUMN listing_only")
        await conn.execute(schema_info.update().values(version=1))
    await s.close()
    return r.id


async def test_migration_v1_to_v2_is_additive_and_idempotent(settings):
    settings.general.timezone = "UTC"
    old_id = await _make_v1_database(settings)
    migrated = SqlResultStore(settings)
    await migrated.init()  # migra sola al arrancar
    try:
        async with migrated.engine.connect() as conn:
            version = (await conn.execute(sa.select(schema_info.c.version))).scalar_one()
            cols_a = {c["name"] for c in await conn.run_sync(lambda c: sa.inspect(c).get_columns("analyses"))}
            cols_b = {
                c["name"] for c in await conn.run_sync(lambda c: sa.inspect(c).get_columns("artifacts"))
            }
        assert version == SCHEMA_VERSION == 2
        assert "truncated" in cols_a and {"password_protected", "listing_only"} <= cols_b
        # los datos viejos siguen ahí, con los defaults de las columnas nuevas
        old = await migrated.get_result(old_id)
        assert old is not None and old.truncated is False
        assert old.artifacts[0].password_protected is False and old.artifacts[0].listing_only is False
        assert old.false_positive is True and old.false_positive_by == "ana"
        # se pueden guardar resultados nuevos con los campos nuevos
        new = make_result("v2-mail", artifacts=[artifact("x.zip", "z", detected_type="zip")])
        new.truncated = True
        new.artifacts[0].password_protected = True
        assert await migrated.save_result(new)
        got = await migrated.get_result(new.id)
        assert got.truncated is True and got.artifacts[0].password_protected is True
        # la migración se puede volver a correr sin efecto (idempotente)
        async with migrated.engine.begin() as conn:
            await conn.run_sync(MIGRATIONS[1])
    finally:
        await migrated.close()
    # y un segundo proceso que arranca después no intenta migrar de nuevo
    again = SqlResultStore(settings)
    await again.init()
    assert (await again.get_result(old_id)) is not None
    await again.close()


def test_normalize_url():
    assert _normalize_url("postgres://u:p@db:5432/c") == "postgresql+asyncpg://u:p@db:5432/c"
    assert _normalize_url("postgresql://u:p@db/c") == "postgresql+asyncpg://u:p@db/c"
    assert _normalize_url("postgresql+asyncpg://u:p@db/c") == "postgresql+asyncpg://u:p@db/c"
    assert _normalize_url("sqlite:///data/c.db") == "sqlite+aiosqlite:///data/c.db"


# --------------------------------------------------------------------------- guardar / leer


async def test_save_and_get_roundtrip(store):
    r = make_result(
        "42",
        level=VerdictLevel.MALICIOUS,
        score=97,
        subject="Factura pendiente ñandú 🧾",
        message_id="<abc@proveedor.com>",
        artifacts=[
            artifact("factura.zip", "zip", id="att0", detected_type="zip"),
            artifact("f.exe", "exe", id="att0/f.exe"),
        ],
        findings=[
            finding(
                "yara.AsyncRAT",
                artifact_id="att0/f.exe",
                severity=Severity.CRITICAL,
                score=95,
                family="AsyncRAT",
                category=FindingCategory.MALWARE,
                evidence={"strings": ["a", "b"], "offset": 12, "nested": {"x": [1, 2]}},
            ),
            finding(
                "headers.spf_fail",
                artifact_id=None,
                severity=Severity.MEDIUM,
                score=30,
                category=FindingCategory.SPOOFING,
            ),
        ],
        families=["AsyncRAT"],
        urls=[ExtractedUrl(url="http://evil.example/x", source="body_html", display_text="Ver factura")],
        errors=["clamav[att0]: timeout"],
        actions=["tag:test:keyword"],
    )
    r.artifacts[1].parent_id = "att0"
    r.artifacts[1].depth = 1
    assert await store.save_result(r) is True
    got = await store.get_result(r.id)
    assert got is not None
    assert got.id == r.id and got.ref == r.ref
    assert got.subject == r.subject and got.message_id == r.message_id
    assert got.received_at == r.received_at and got.received_at.tzinfo is not None
    assert got.analyzed_at == r.analyzed_at
    assert got.verdict == r.verdict
    assert [a.model_dump() for a in got.artifacts] == [a.model_dump() for a in r.artifacts]
    assert [f.model_dump() for f in got.findings] == [f.model_dump() for f in r.findings]
    assert got.urls == r.urls and got.errors == r.errors and got.actions == r.actions
    assert got.to == r.to and got.size == r.size and got.duration_ms == r.duration_ms
    assert got.truncated is False and got.false_positive is False
    assert got.false_positive_by is None and got.false_positive_note is None and got.false_positive_at is None


async def test_truncated_and_artifact_flags_roundtrip(store):
    zip_art = artifact("pago.zip", "zip-pw", id="att0", detected_type="zip").model_copy(
        update={"password_protected": True, "encrypted": True}
    )
    listed = ArtifactSummary(
        id="att0/pago.zip/pago.exe",
        filename="pago.exe",
        detected_type="unknown",
        size=999_999,
        depth=1,
        parent_id="att0",
        password_protected=True,
        listing_only=True,
        extraction_note="cifrado: no se pudo extraer",
    )
    r = make_result("big", level=VerdictLevel.SUSPICIOUS, score=35, artifacts=[zip_art, listed])
    r.truncated = True
    assert await store.save_result(r)
    got = await store.get_result(r.id)
    assert got.truncated is True
    assert [a.model_dump() for a in got.artifacts] == [a.model_dump() for a in r.artifacts]
    assert got.artifacts[1].listing_only is True and got.artifacts[1].sha256 == ""
    assert got.artifacts[0].password_protected is True and got.artifacts[0].listing_only is False


async def test_get_result_includes_false_positive_feedback(store):
    r = make_result("fp")
    await store.save_result(r)
    assert await store.set_false_positive(r.id, True, user="admin", note="confirmado por teléfono")
    got = await store.get_result(r.id)
    assert got.false_positive is True
    assert got.false_positive_by == "admin" and got.false_positive_note == "confirmado por teléfono"
    assert got.false_positive_at is not None and got.false_positive_at.tzinfo is not None
    assert utcnow() - got.false_positive_at < timedelta(minutes=1)
    # al quitar la marca queda registrado quién la quitó y cuándo (sin nota)
    assert await store.set_false_positive(r.id, False, user="otro")
    got = await store.get_result(r.id)
    assert got.false_positive is False
    assert got.false_positive_by == "otro" and got.false_positive_note is None
    assert got.false_positive_at is not None


async def test_get_missing_returns_none(store):
    assert await store.get_result(uuid.uuid4()) is None


async def test_duplicate_ref_is_not_saved_twice(store):
    first = make_result("dup")
    second = make_result("dup", subject="otro análisis del mismo mail")
    assert await store.save_result(first) is True
    assert await store.has_ref(first.ref) is True
    assert await store.save_result(second) is False
    assert await store.save_result(first) is False  # mismo id
    # misma remote_id en otro buzón / conector: es otro mensaje
    assert await store.save_result(make_result("dup", mailbox="compras@empresa.com")) is True
    assert await store.save_result(make_result("dup", connector="otro")) is True
    assert (
        await store.has_ref(MessageRef(connector="test", mailbox="ventas@empresa.com", remote_id="nope"))
        is False
    )
    items, total = await store.list_results(ResultFilter())
    assert total == 3
    assert (await store.get_result(second.id)) is None


async def test_concurrent_saves_and_concurrent_duplicates(store):
    results = [make_result(f"c{i}") for i in range(25)]
    assert all(await asyncio.gather(*(store.save_result(r) for r in results)))
    same = [make_result("race") for _ in range(8)]
    outcomes = await asyncio.gather(*(store.save_result(r) for r in same))
    assert outcomes.count(True) == 1
    _, total = await store.list_results(ResultFilter())
    assert total == 26


async def test_hostile_values_are_bounded_and_storable(store):
    deep: dict = {}
    cur = deep
    for _ in range(60):
        cur["n"] = {}
        cur = cur["n"]
    r = make_result(
        "r" * 5000,  # remote_id absurdo
        mailbox="x" * 1000 + "@empresa.com",
        subject="A" * 1_000_000 + "\x00\ud800",  # NUL y surrogate suelto (headers hostiles)
        from_display="Juan\x00 Pérez",
        artifacts=[artifact("n\x00ombre\udcff.exe", "hostil")],
        findings=[
            finding(
                evidence={
                    "big": "z" * 500_000,
                    "list": list(range(50_000)),
                    "deep": deep,
                    "raw": b"\x00\x01" * 1000,
                }
            ),
        ],
    )
    assert await store.save_result(r) is True
    assert await store.has_ref(r.ref) is True
    assert await store.save_result(make_result("r" * 5000, mailbox="x" * 1000 + "@empresa.com")) is False
    got = await store.get_result(r.id)
    assert got is not None
    assert len(got.subject) <= 2000 and "\x00" not in got.subject
    assert got.from_display == "Juan Pérez"
    assert got.artifacts[0].filename.startswith("nombre")
    ev = got.findings[0].evidence
    assert len(ev["big"]) <= 2001 and len(ev["list"]) <= 200


async def test_many_artifacts_and_findings(store):
    arts = [artifact(f"f{i}.txt", f"s{i}", id=f"att{i}", detected_type="text") for i in range(300)]
    fnds = [finding(f"r.{i}", artifact_id=f"att{i}", severity=Severity.LOW, score=5) for i in range(300)]
    r = make_result("many", artifacts=arts, findings=fnds)
    assert await store.save_result(r)
    got = await store.get_result(r.id)
    assert [a.id for a in got.artifacts] == [a.id for a in arts]
    assert len(got.findings) == 300


# --------------------------------------------------------------------------- listados y filtros


async def _seed(store: SqlResultStore) -> dict[str, object]:
    now = utcnow()
    clean = make_result(
        "1", subject="Reunión del lunes", from_addr="ana@cliente.com", received_at=now - timedelta(hours=5)
    )
    susp = make_result(
        "2",
        level=VerdictLevel.SUSPICIOUS,
        score=40,
        subject="Factura 100% pendiente",
        from_addr="cobranzas@proveedor-falso.example",
        mailbox="Compras@Empresa.com",
        received_at=now - timedelta(hours=3),
        artifacts=[artifact("factura.docm", "docm", detected_type="ooxml")],
        findings=[finding("office.vba.autoexec", severity=Severity.MEDIUM, score=40)],
    )
    mal = malicious_result(
        "3", received_at=now - timedelta(hours=1), subject="Comprobante de pago", connector="gmail"
    )
    err = make_result("4", level=VerdictLevel.ERROR, subject="Roto", received_at=now - timedelta(hours=2))
    for r in (clean, susp, mal, err):
        assert await store.save_result(r)
    return {"clean": clean, "susp": susp, "mal": mal, "err": err, "now": now}


async def test_list_results_order_counts_and_pagination(store):
    seeded = await _seed(store)
    items, total = await store.list_results(ResultFilter(), limit=2)
    assert total == 4
    assert [i.id for i in items] == [seeded["mal"].id, seeded["err"].id]
    mal_item = items[0]
    assert mal_item.artifact_count == 1 and mal_item.finding_count == 1
    assert mal_item.malware_families == ["AgentTesla"] and mal_item.level == VerdictLevel.MALICIOUS
    page2, total2 = await store.list_results(ResultFilter(), limit=2, offset=2)
    assert total2 == 4 and [i.id for i in page2] == [seeded["susp"].id, seeded["clean"].id]
    empty, _ = await store.list_results(ResultFilter(), limit=2, offset=100)
    assert empty == []
    clamped, _ = await store.list_results(ResultFilter(), limit=10_000, offset=-5)
    assert len(clamped) == 4


async def test_list_results_filters(store):
    s = await _seed(store)

    async def ids(**kw) -> set:
        items, total = await store.list_results(ResultFilter(**kw))
        assert total == len(items)
        return {i.id for i in items}

    assert await ids(level=VerdictLevel.SUSPICIOUS) == {s["susp"].id}
    assert await ids(min_level=VerdictLevel.SUSPICIOUS) == {s["susp"].id, s["mal"].id}
    assert await ids(min_level=VerdictLevel.ERROR) == {s["susp"].id, s["mal"].id, s["err"].id}
    assert await ids(connector="gmail") == {s["mal"].id}
    assert await ids(mailbox="compras@empresa.COM") == {s["susp"].id}
    # q: asunto, remitente, nombre de adjunto, sha256 (completo o prefijo), case-insensitive
    assert await ids(q="reunión") == {s["clean"].id}
    assert await ids(q="PROVEEDOR-FALSO") == {s["susp"].id}
    assert await ids(q="factura.pdf") == {s["mal"].id}
    assert await ids(q=sha("agenttesla-sample")) == {s["mal"].id}
    assert await ids(q=sha("agenttesla-sample")[:12].upper()) == {s["mal"].id}
    # los comodines de LIKE en la búsqueda son literales
    assert await ids(q="100%") == {s["susp"].id}
    assert await ids(q="%") == {s["susp"].id}  # literal: solo el asunto que contiene "%"
    assert await ids(q="F%a") == set()  # como comodín matchearía "Factura"
    assert await ids(q="_") == set()
    assert await ids(q="\x00") == {
        s["clean"].id,
        s["susp"].id,
        s["mal"].id,
        s["err"].id,
    }  # q vacío tras limpiar
    assert await ids(sha256=sha("agenttesla-sample").upper()) == {s["mal"].id}
    assert await ids(sha256="0" * 64) == set()
    assert await ids(family="agenttesla") == {s["mal"].id}
    assert await ids(family="Emotet") == set()
    now = s["now"]
    assert await ids(since=now - timedelta(hours=2, minutes=30)) == {s["mal"].id, s["err"].id}
    assert await ids(until=now - timedelta(hours=2, minutes=30)) == {s["clean"].id, s["susp"].id}
    # combinación
    assert await ids(min_level=VerdictLevel.SUSPICIOUS, q="comprobante") == {s["mal"].id}
    # ids explícitos (se combinan con el resto de los filtros); lista vacía = nada
    assert await ids(ids=[s["clean"].id, s["mal"].id]) == {s["clean"].id, s["mal"].id}
    assert await ids(ids=[s["clean"].id, s["mal"].id], min_level=VerdictLevel.SUSPICIOUS) == {s["mal"].id}
    assert await ids(ids=[s["susp"].id, s["susp"].id, uuid.uuid4()]) == {s["susp"].id}
    assert await ids(ids=[]) == set()
    with pytest.raises(ValueError, match="demasiados ids"):
        await store.list_results(ResultFilter(ids=[uuid.uuid4() for _ in range(MAX_FILTER_IDS + 1)]))


async def test_false_positive_feedback(store):
    s = await _seed(store)
    assert (
        await store.set_false_positive(s["susp"].id, True, user="admin", note="era una factura real") is True
    )
    assert await store.set_false_positive(uuid.uuid4(), True, user="admin") is False
    items, _ = await store.list_results(ResultFilter(min_level=VerdictLevel.SUSPICIOUS))
    assert {i.id: i.false_positive for i in items}[s["susp"].id] is True
    items, _ = await store.list_results(
        ResultFilter(min_level=VerdictLevel.SUSPICIOUS, include_false_positives=False)
    )
    assert {i.id for i in items} == {s["mal"].id}
    async with store.engine.connect() as conn:
        row = (await conn.execute(sa.select(analyses).where(analyses.c.id == s["susp"].id))).mappings().one()
    assert (
        row["fp_user"] == "admin"
        and row["fp_note"] == "era una factura real"
        and row["fp_at"].tzinfo is not None
    )
    assert await store.set_false_positive(s["susp"].id, False, user="admin") is True
    items, _ = await store.list_results(ResultFilter(include_false_positives=False))
    assert len(items) == 4


async def test_record_actions_merges_unique(store):
    r = make_result("a", actions=["tag:test:keyword"])
    await store.save_result(r)
    await store.record_actions(r.id, ["alert:telegram:ok", "tag:test:keyword"])
    await store.record_actions(r.id, ["alert:telegram:ok", "alert:email:dedup"])
    await store.record_actions(r.id, [])
    await store.record_actions(uuid.uuid4(), ["alert:x:ok"])  # id inexistente: no rompe
    got = await store.get_result(r.id)
    assert got.actions == ["tag:test:keyword", "alert:telegram:ok", "alert:email:dedup"]


async def test_concurrent_record_actions(store):
    r = make_result("ca")
    await store.save_result(r)
    await asyncio.gather(*(store.record_actions(r.id, [f"alert:c{i}:ok"]) for i in range(10)))
    got = await store.get_result(r.id)
    assert sorted(got.actions) == sorted(f"alert:c{i}:ok" for i in range(10))


# --------------------------------------------------------------------------- estadísticas


async def test_stats_counts_tops_and_timeline(store):
    s = await _seed(store)
    # un segundo malicioso del mismo remitente para top_senders
    await store.save_result(malicious_result("5", received_at=s["now"] - timedelta(minutes=10), seed="otro"))
    await store.save_result(
        make_result(
            "old", level=VerdictLevel.MALICIOUS, received_at=s["now"] - timedelta(days=10), families=["Viejo"]
        )
    )
    since = s["now"] - timedelta(hours=6)
    st = await store.stats(since, bucket="hour")
    assert st.total == 5
    assert st.by_level == {"clean": 1, "suspicious": 1, "malicious": 2, "error": 1}
    assert st.by_connector == {"test": 4, "gmail": 1}
    assert st.top_families == [("AgentTesla", 2)]
    assert st.top_senders[0] == ("juan@proveedor.com", 2)
    assert ("ana@cliente.com", 1) not in st.top_senders  # solo remitentes de mails sospechosos/maliciosos
    assert dict(st.top_rules)["yara.AgentTesla"] == 2
    assert st.avg_duration_ms == pytest.approx(100.0)
    # timeline continua (con buckets vacíos) que suma lo mismo que el total
    assert 6 <= len(st.timeline) <= 8
    assert sum(b["clean"] + b["suspicious"] + b["malicious"] + b["error"] for b in st.timeline) == 5
    buckets = [datetime.fromisoformat(b["bucket"]) for b in st.timeline]
    assert buckets == sorted(buckets)
    assert all((b2 - b1) == timedelta(hours=1) for b1, b2 in zip(buckets, buckets[1:], strict=False))
    assert any(b["malicious"] == 2 for b in st.timeline) or sum(b["malicious"] for b in st.timeline) == 2

    st_day = await store.stats(s["now"] - timedelta(days=30), bucket="day")
    assert st_day.total == 6 and 30 <= len(st_day.timeline) <= 32
    assert sum(b["malicious"] for b in st_day.timeline) == 3
    assert dict(st_day.top_families) == {"AgentTesla": 2, "Viejo": 1}


async def test_stats_empty_and_invalid_bucket(store):
    st = await store.stats(utcnow() - timedelta(hours=2))
    assert st.total == 0 and st.by_level == {} and st.top_families == [] and len(st.timeline) in (2, 3)
    assert all(b["clean"] == 0 for b in st.timeline)
    assert (await store.stats(utcnow() + timedelta(days=1))).timeline == []
    with pytest.raises(ValueError):
        await store.stats(utcnow(), bucket="minute")


def test_bucketing_respects_timezone():
    art = timezone(timedelta(hours=-3))  # Argentina
    dt = datetime(2026, 10, 3, 2, 30, tzinfo=UTC)  # 23:30 del día anterior en Buenos Aires
    assert bucket_key(dt, "day", art) == "2026-10-02T00:00:00-03:00"
    assert bucket_key(dt, "hour", art) == "2026-10-02T23:00:00-03:00"
    assert bucket_key(dt, "day", UTC) == "2026-10-03T00:00:00+00:00"
    keys = bucket_keys(
        datetime(2026, 10, 1, 12, tzinfo=UTC), datetime(2026, 10, 3, 12, tzinfo=UTC), "day", art
    )
    assert keys == ["2026-10-01T00:00:00-03:00", "2026-10-02T00:00:00-03:00", "2026-10-03T00:00:00-03:00"]
    india = timezone(timedelta(hours=5, minutes=30))  # offset de media hora: buckets igual continuos
    hk = bucket_keys(datetime(2026, 1, 1, 0, tzinfo=UTC), datetime(2026, 1, 1, 3, tzinfo=UTC), "hour", india)
    assert len(hk) == 4 and len(set(hk)) == 4


async def test_stats_bucket_in_configured_timezone(tmp_path):
    from centinela.core.config import Settings

    s = Settings()
    s.general.timezone = "UTC"
    s.database_url = f"sqlite+aiosqlite:///{(tmp_path / 'tz.db').as_posix()}"
    st = SqlResultStore(s)
    st._tz = timezone(
        timedelta(hours=-3)
    )  # equivalente a America/Argentina/Buenos_Aires (sin tzdata en Windows)
    await st.init()
    now = utcnow()
    await st.save_result(make_result("tz", received_at=now - timedelta(minutes=5)))
    stats = await st.stats(now - timedelta(days=2), bucket="day")
    assert all(b["bucket"].endswith("-03:00") for b in stats.timeline)
    assert sum(b["clean"] for b in stats.timeline) == 1
    await st.close()


# --------------------------------------------------------------------------- campañas


async def test_campaigns_group_same_hash_across_mailboxes(store):
    now = utcnow()
    for i, mb in enumerate(["ventas@empresa.com", "compras@empresa.com", "rrhh@empresa.com"]):
        await store.save_result(
            malicious_result(f"camp{i}", mailbox=mb, received_at=now - timedelta(minutes=30 - i))
        )
    # el mismo hash en un mail que quedó limpio (no cuenta por defecto)
    await store.save_result(
        make_result(
            "camp-clean", artifacts=[artifact("factura.pdf.exe", "agenttesla-sample")], received_at=now
        )
    )
    # un hash que aparece una sola vez: no es campaña
    await store.save_result(malicious_result("single", seed="unico"))
    # logo de firma repetido en mails limpios: solo aparece con include_clean
    for i in range(4):
        await store.save_result(
            make_result(f"logo{i}", artifacts=[artifact("logo.png", "logo", detected_type="image/png")])
        )
    # fuera de rango temporal
    await store.save_result(malicious_result("viejo", seed="viejo", received_at=now - timedelta(days=60)))
    await store.save_result(malicious_result("viejo2", seed="viejo", received_at=now - timedelta(days=59)))

    camps = await store.campaigns(now - timedelta(days=7))
    assert len(camps) == 1
    c = camps[0]
    assert c.sha256 == sha("agenttesla-sample")
    assert c.message_count == 3
    assert c.mailboxes == ["compras@empresa.com", "rrhh@empresa.com", "ventas@empresa.com"]
    assert c.max_level == VerdictLevel.MALICIOUS
    assert c.malware_families == ["AgentTesla"]
    assert c.filename == "factura.pdf.exe" and c.detected_type == "pe"
    assert c.first_seen < c.last_seen and c.first_seen.tzinfo is not None

    assert await store.campaigns(now - timedelta(days=7), min_messages=4) == []
    with_clean = {c.sha256: c for c in await store.campaigns(now - timedelta(days=7), include_clean=True)}
    assert with_clean[sha("agenttesla-sample")].message_count == 4
    assert with_clean[sha("logo")].max_level == VerdictLevel.CLEAN
    assert len(await store.campaigns(now - timedelta(days=90))) == 2
    assert len(await store.campaigns(now - timedelta(days=90), limit=1)) == 1


async def test_campaigns_ignore_false_positives(store):
    r1, r2 = malicious_result("fp1"), malicious_result("fp2", mailbox="otro@empresa.com")
    await store.save_result(r1)
    await store.save_result(r2)
    assert len(await store.campaigns(utcnow() - timedelta(days=1))) == 1
    await store.set_false_positive(r2.id, True, user="admin")
    assert await store.campaigns(utcnow() - timedelta(days=1)) == []


# --------------------------------------------------------------------------- retención


async def test_purge_older_than_removes_children(store):
    now = utcnow()
    old = [malicious_result(f"old{i}", received_at=now - timedelta(days=200)) for i in range(7)]
    new = malicious_result("new", received_at=now - timedelta(days=1))
    for r in [*old, new]:
        await store.save_result(r)
    assert await _count(store, artifacts) == 8 and await _count(store, findings) == 8
    assert await store.purge_older_than(now - timedelta(days=180)) == 7
    assert await store.purge_older_than(now - timedelta(days=180)) == 0
    assert await _count(store, artifacts) == 1 and await _count(store, findings) == 1
    assert await store.get_result(new.id) is not None
    assert await store.get_result(old[0].id) is None
    assert await store.has_ref(old[0].ref) is False  # se puede volver a analizar si reaparece


async def test_purge_in_batches(store, monkeypatch):
    import centinela.storage.db as db_mod

    monkeypatch.setattr(db_mod, "PURGE_BATCH", 3)
    now = utcnow()
    for i in range(10):
        await store.save_result(make_result(f"b{i}", received_at=now - timedelta(days=400)))
    assert await store.purge_older_than(now) == 10


async def test_two_processes_record_actions_without_lost_updates(settings, store):
    """Dos engines sobre el mismo archivo SQLite (ingest + worker): el BEGIN explícito + reintento
    evita perder acciones en lectura-modificación-escritura concurrente."""
    other = SqlResultStore(settings)
    await other.init()
    r = make_result("x-proc")
    await store.save_result(r)
    await asyncio.gather(
        *(store.record_actions(r.id, [f"alert:a{i}:ok"]) for i in range(4)),
        *(other.record_actions(r.id, [f"alert:b{i}:ok"]) for i in range(4)),
    )
    await other.close()
    got = await store.get_result(r.id)
    assert sorted(got.actions) == sorted(
        [f"alert:a{i}:ok" for i in range(4)] + [f"alert:b{i}:ok" for i in range(4)]
    )
