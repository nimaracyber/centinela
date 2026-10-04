from __future__ import annotations

import asyncio
import os
import time
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

import centinela.connectors.directory as dir_mod
from centinela.connectors import connector_class
from centinela.connectors.directory import DirectoryConnector
from centinela.core.config import DirectoryConnectorConfig, TagConfig
from centinela.core.models import AnalysisResult, Verdict, VerdictLevel
from centinela.core.state import MemoryStateStore
from centinela.metrics import REGISTRY
from tests.helpers import build_eml

NAME = "carpeta"


def make_conn(settings, path: Path, **kw) -> DirectoryConnector:
    cfg = DirectoryConnectorConfig.model_validate(
        {"type": "directory", "name": NAME, "path": str(path), **kw}
    )
    conn = DirectoryConnector(cfg, settings, MemoryStateStore())
    conn.BACKOFF_BASE_S = 0.01
    conn.BACKOFF_CAP_S = 0.05
    return conn


def put(path: Path, name: str, data: bytes, age_s: float = 10.0) -> Path:
    p = path / name
    p.write_bytes(data)
    t = time.time() - age_s
    os.utime(p, (t, t))
    return p


class Collector:
    def __init__(self) -> None:
        self.items = []
        self.fail_next = 0

    async def __call__(self, raw):
        if self.fail_next:
            self.fail_next -= 1
            raise RuntimeError("cola caída")
        self.items.append(raw)


def names(items) -> list[str]:
    """Nombre de archivo de cada remote_id (`<nombre>@<mtime_ns>`)."""
    return [r.ref.remote_id.rsplit("@", 1)[0] for r in items]


async def run_until(conn, emit, cond, within=5.0):
    stop = asyncio.Event()
    task = asyncio.create_task(conn.run(emit, stop))
    deadline = time.monotonic() + within
    try:
        while not cond():
            if time.monotonic() > deadline:
                raise AssertionError("timeout")
            if task.done():
                task.result()
            await asyncio.sleep(0.01)
    finally:
        stop.set()
        await asyncio.wait_for(task, 5)


@pytest.fixture
def inbox(tmp_path) -> Path:
    p = tmp_path / "entrada"
    p.mkdir()
    return p


def test_registry_resolves_directory_connector():
    assert connector_class("directory") is DirectoryConnector


async def test_processes_in_mtime_order_and_moves_to_processed(settings, inbox):
    put(inbox, "b.eml", build_eml(subject="segundo"), age_s=20)
    put(inbox, "a.eml", build_eml(subject="tercero"), age_s=10)
    put(inbox, "c.EML", build_eml(subject="primero"), age_s=30)
    conn = make_conn(settings, inbox)
    emit = Collector()
    await asyncio.to_thread(conn._ensure_dirs)
    more = await conn._scan_once(emit, asyncio.Event())
    assert more is False
    assert names(emit.items) == ["c.EML", "b.eml", "a.eml"]
    first = emit.items[0]
    assert first.ref.connector == NAME and first.ref.folder is None
    moved = inbox / ".processed" / "c.EML"
    assert first.ref.remote_id == f"c.EML@{moved.stat().st_mtime_ns}"  # mover conserva el mtime
    assert first.raw == moved.read_bytes() and first.truncated is False and first.original_size is None
    assert first.received_at.tzinfo is not None and first.received_at < datetime.now(UTC)
    assert sorted(p.name for p in (inbox / ".processed").iterdir()) == ["a.eml", "b.eml", "c.EML"]
    assert not any(p.is_file() for p in inbox.iterdir())
    assert conn.processed == 3


async def test_ignores_recent_hidden_and_non_eml_files(settings, inbox):
    put(inbox, "escribiendo.eml", build_eml(), age_s=0)  # modificado hace < 2 s
    put(inbox, ".temporal.eml", build_eml(), age_s=30)
    put(inbox, "nota.txt", b"hola", age_s=30)
    put(inbox, "mail.eml.part", build_eml(), age_s=30)
    (inbox / "sub.eml").mkdir()
    conn = make_conn(settings, inbox)
    emit = Collector()
    await asyncio.to_thread(conn._ensure_dirs)
    await conn._scan_once(emit, asyncio.Event())
    assert emit.items == []
    assert (inbox / "escribiendo.eml").exists() and (inbox / "nota.txt").exists()
    # cuando el archivo "se asienta", se procesa
    t = time.time() - 5
    os.utime(inbox / "escribiendo.eml", (t, t))
    await conn._scan_once(emit, asyncio.Event())
    assert names(emit.items) == ["escribiendo.eml"]


async def test_unreadable_files_go_to_failed(settings, inbox, monkeypatch):
    settings.limits.max_message_bytes = 1000
    put(inbox, "vacio.eml", b"   \r\n", age_s=30)
    put(inbox, "bloqueado.eml", build_eml(), age_s=28)
    put(inbox, "bueno.eml", build_eml(), age_s=27)
    real_open = os.open

    def fake_open(path, flags, *args, **kwargs):
        if str(path).endswith("bloqueado.eml"):
            raise PermissionError(13, "Permission denied")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(dir_mod.os, "open", fake_open)
    conn = make_conn(settings, inbox)
    emit = Collector()
    await asyncio.to_thread(conn._ensure_dirs)
    await conn._scan_once(emit, asyncio.Event())
    assert names(emit.items) == ["bueno.eml"]
    assert sorted(p.name for p in (inbox / ".failed").iterdir()) == ["bloqueado.eml", "vacio.eml"]
    assert conn.failed == 2 and conn.processed == 1


async def test_oversize_file_is_emitted_headers_only(settings, inbox, caplog):
    settings.limits.max_message_bytes = 4000
    eml = build_eml(
        subject="Pesado", attachments=[("factura.zip", b"PK\x03\x04" + b"\0" * 20_000, "application/zip")]
    )
    put(inbox, "enorme.eml", eml, age_s=30)
    put(inbox, "basura.eml", b"x" * 50_000, age_s=29)  # sin headers reconocibles: igual se emite
    conn = make_conn(settings, inbox)
    emit = Collector()
    await asyncio.to_thread(conn._ensure_dirs)
    with caplog.at_level("WARNING"):
        await conn._scan_once(emit, asyncio.Event())
    assert names(emit.items) == ["enorme.eml", "basura.eml"]
    big, junk = emit.items
    assert big.truncated is True and big.original_size == len(eml)
    head = eml.split(b"\n\n", 1)[0]
    assert big.raw.startswith(head) and b"Subject: Pesado" in big.raw
    assert b"factura.zip" not in big.raw and len(big.raw) <= 4000  # solo headers, acotados
    assert junk.truncated is True and junk.original_size == 50_000 and len(junk.raw) <= 4000
    assert sorted(p.name for p in (inbox / ".processed").iterdir()) == ["basura.eml", "enorme.eml"]
    assert conn.truncated == 2 and conn.failed == 0
    assert (await conn.healthcheck())["truncated_too_large"] == 2
    assert "solo los encabezados" in caplog.text


async def test_file_growing_past_the_limit_after_fstat_is_truncated(settings, inbox, monkeypatch):
    settings.limits.max_message_bytes = 1000
    eml = build_eml(subject="Crece", text="A" * 5000)
    put(inbox, "crece.eml", eml)
    real_fstat = os.fstat

    def small_fstat(fd):  # fstat dice 10 bytes; el read encuentra mucho más
        st = real_fstat(fd)
        return SimpleNamespace(st_mode=st.st_mode, st_size=10)

    monkeypatch.setattr(dir_mod.os, "fstat", small_fstat)
    conn = make_conn(settings, inbox)
    emit = Collector()
    await asyncio.to_thread(conn._ensure_dirs)
    await conn._scan_once(emit, asyncio.Event())
    (raw,) = emit.items
    assert raw.truncated is True and raw.original_size == 1001  # cota inferior: límite + 1
    assert b"Subject: Crece" in raw.raw and b"AAAA" not in raw.raw


async def test_reused_filename_gets_a_new_remote_id(settings, inbox):
    """Un exportador que reutiliza `mail.eml` no debe hacer que el storage descarte el mail nuevo."""
    conn = make_conn(settings, inbox)
    emit = Collector()
    await asyncio.to_thread(conn._ensure_dirs)
    put(inbox, "mail.eml", build_eml(subject="primero"), age_s=60)
    await conn._scan_once(emit, asyncio.Event())
    put(inbox, "mail.eml", build_eml(subject="segundo"), age_s=10)
    await conn._scan_once(emit, asyncio.Event())
    first, second = emit.items
    assert names(emit.items) == ["mail.eml", "mail.eml"]
    assert first.ref.remote_id != second.ref.remote_id
    assert b"segundo" in second.raw


async def test_symlink_goes_to_failed_without_reading_target(settings, inbox, tmp_path):
    secret = tmp_path / "secreto.txt"
    secret.write_bytes(b"From: x\r\n\r\nno deberia leerse")
    link = inbox / "link.eml"
    try:
        link.symlink_to(secret)
    except (OSError, NotImplementedError):
        pytest.skip("no se pueden crear symlinks en este sistema")
    t = time.time() - 30
    os.utime(link, (t, t), follow_symlinks=False)
    conn = make_conn(settings, inbox)
    emit = Collector()
    await asyncio.to_thread(conn._ensure_dirs)
    await conn._scan_once(emit, asyncio.Event())
    assert emit.items == []
    assert (inbox / ".failed" / "link.eml").is_symlink()
    assert secret.exists()


async def test_emit_failure_keeps_file_and_retries(settings, inbox):
    put(inbox, "uno.eml", build_eml())
    conn = make_conn(settings, inbox, poll_interval_s=0)
    emit = Collector()
    emit.fail_next = 2
    await run_until(conn, emit, lambda: len(emit.items) == 1)
    assert (inbox / ".processed" / "uno.eml").exists()
    assert not (inbox / "uno.eml").exists()
    h = await conn.healthcheck()
    assert "cola caída" in h["last_error"]


async def test_name_collision_in_processed_keeps_both(settings, inbox):
    (inbox / ".processed").mkdir()
    (inbox / ".processed" / "dup.eml").write_bytes(b"anterior")
    put(inbox, "dup.eml", build_eml(subject="nuevo"))
    conn = make_conn(settings, inbox)
    emit = Collector()
    await asyncio.to_thread(conn._ensure_dirs)
    await conn._scan_once(emit, asyncio.Event())
    names = sorted(p.name for p in (inbox / ".processed").iterdir())
    assert len(names) == 2 and "dup.eml" in names
    assert (inbox / ".processed" / "dup.eml").read_bytes() == b"anterior"


async def test_move_failure_does_not_reemit_forever(settings, inbox, monkeypatch):
    put(inbox, "pegado.eml", build_eml())
    conn = make_conn(settings, inbox)

    def boom(src, dest_dir):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(conn, "_move", boom)
    emit = Collector()
    await asyncio.to_thread(conn._ensure_dirs)
    for _ in range(3):
        await conn._scan_once(emit, asyncio.Event())
    assert len(emit.items) == 1


async def test_batch_limit_reports_more_pending(settings, inbox):
    for i in range(5):
        put(inbox, f"m{i}.eml", build_eml(subject=str(i)), age_s=30 - i)
    conn = make_conn(settings, inbox)
    conn.MAX_FILES_PER_SCAN = 2
    emit = Collector()
    await asyncio.to_thread(conn._ensure_dirs)
    assert await conn._scan_once(emit, asyncio.Event()) is True
    assert names(emit.items) == ["m0.eml", "m1.eml"]


async def test_run_creates_missing_dir_and_processes_new_files(settings, tmp_path):
    path = tmp_path / "no" / "existe"
    conn = make_conn(settings, path, poll_interval_s=0)
    emit = Collector()
    stop = asyncio.Event()
    task = asyncio.create_task(conn.run(emit, stop))
    try:
        deadline = time.monotonic() + 5
        while not (path / ".processed").is_dir():
            assert time.monotonic() < deadline
            await asyncio.sleep(0.01)
        assert REGISTRY.get_sample_value("centinela_connector_up", {"connector": NAME}) == 1
        put(path, "nuevo.eml", build_eml(), age_s=5)
        while not emit.items:
            assert time.monotonic() < deadline
            await asyncio.sleep(0.01)
        h = await conn.healthcheck()
        assert h["ok"] is True and h["processed"] == 1 and h["last_scan"]
    finally:
        stop.set()
        await asyncio.wait_for(task, 5)
    assert (path / ".failed").is_dir()
    assert REGISTRY.get_sample_value("centinela_connector_up", {"connector": NAME}) == 0


async def test_path_is_a_file_reports_error_without_crashing(settings, tmp_path):
    bogus = tmp_path / "archivo"
    bogus.write_text("no soy una carpeta")
    conn = make_conn(settings, bogus, poll_interval_s=0)
    emit = Collector()
    stop = asyncio.Event()
    task = asyncio.create_task(conn.run(emit, stop))
    deadline = time.monotonic() + 5
    while conn._last_error is None:
        assert time.monotonic() < deadline and not task.done()
        await asyncio.sleep(0.01)
    stop.set()
    await asyncio.wait_for(task, 5)
    assert (await conn.healthcheck())["ok"] is False


async def test_stop_is_prompt_with_long_poll_interval(settings, inbox):
    conn = make_conn(settings, inbox, poll_interval_s=300)
    stop = asyncio.Event()
    task = asyncio.create_task(conn.run(Collector(), stop))
    await asyncio.sleep(0.1)
    t0 = time.monotonic()
    stop.set()
    await asyncio.wait_for(task, 5)
    assert time.monotonic() - t0 < 1


async def test_apply_verdict_is_noop(settings, inbox):
    conn = make_conn(settings, inbox)
    from tests.helpers import make_ref

    ref = make_ref()
    res = AnalysisResult(
        ref=ref,
        received_at=datetime.now(UTC),
        verdict=Verdict(level=VerdictLevel.MALICIOUS, score=99, summary="x"),
    )
    assert await conn.apply_verdict(ref, res, TagConfig()) is None
