"""Conector de carpeta: analiza los `.eml` que aparecen en un directorio.

Sirve para integraciones caseras (un script que exporta mails), pruebas y análisis de exportes.

- Cada `poll_interval_s` lista `<path>/*.eml` (extensión sin distinguir mayúsculas) y los procesa del más
  viejo al más nuevo (mtime).
- Ignora archivos modificados hace menos de 2 s (todavía se están escribiendo), archivos ocultos
  (empiezan con '.'; patrón típico de escritura atómica) y todo lo que no sea un archivo regular.
- Después de `emit` mueve el archivo a `<path>/.processed/`. Si no se puede leer (permisos, vacío,
  symlink) lo mueve a `<path>/.failed/`. Si `emit` falla, el archivo queda donde está y se reintenta en
  la próxima pasada (al-menos-una-vez).
- Un archivo más grande que `limits.max_message_bytes` NO se descarta (sería una evasión trivial): se
  leen solo sus headers y se emite con `truncated=True` + `original_size`.
- `remote_id` = `<nombre>@<mtime en ns>`: un exportador que reutiliza nombres (`mail.eml` una y otra vez)
  no hace que el storage descarte el mail nuevo como duplicado. No etiqueta nada (no hay buzón de origen).
"""

from __future__ import annotations

import asyncio
import logging
import os
import stat
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from centinela.connectors._backoff import Backoff, sleep_or_stop
from centinela.connectors._headers import header_cap, header_section, oversize_raw
from centinela.connectors.base import Connector
from centinela.core.models import MessageRef, RawMessage
from centinela.metrics import CONNECTOR_UP

if TYPE_CHECKING:
    from centinela.connectors.base import EmitFn
    from centinela.core.config import DirectoryConnectorConfig, Settings
    from centinela.core.state import StateStore

log = logging.getLogger(__name__)

__all__ = ["DirectoryConnector"]

PROCESSED_DIR = ".processed"
FAILED_DIR = ".failed"


class _UnreadableFile(Exception):
    """El archivo existe pero no se puede analizar: va a .failed/."""


@dataclass(frozen=True)
class _Candidate:
    name: str
    mtime_ns: int
    size: int  # -1 = enlace simbólico

    @property
    def key(self) -> tuple[str, int, int]:
        return (self.name, self.mtime_ns, self.size)

    @property
    def remote_id(self) -> str:
        return f"{self.name}@{self.mtime_ns}"


@dataclass(frozen=True)
class _Content:
    data: bytes
    original_size: int | None = None  # != None: superaba el límite y `data` son solo los headers


class DirectoryConnector(Connector):
    type: ClassVar[str] = "directory"

    MIN_AGE_S: ClassVar[float] = 2.0  # escrituras parciales
    MAX_FILES_PER_SCAN: ClassVar[int] = 200
    BACKOFF_BASE_S: ClassVar[float] = 1.0
    BACKOFF_CAP_S: ClassVar[float] = 300.0
    MAX_NAME_COLLISIONS: ClassVar[int] = 1000

    config: DirectoryConnectorConfig

    def __init__(self, config: DirectoryConnectorConfig, settings: Settings, state: StateStore) -> None:
        super().__init__(config, settings, state)
        self.path = Path(config.path)
        self.processed_dir = self.path / PROCESSED_DIR
        self.failed_dir = self.path / FAILED_DIR
        # archivos ya tratados que no se pudieron mover (permisos): no re-procesarlos en cada pasada
        self._stuck: set[tuple[str, int, int]] = set()
        self._last_scan: datetime | None = None
        self._last_error: str | None = None
        self._last_error_at: datetime | None = None
        self._up = False
        self.processed = 0
        self.failed = 0
        self.truncated = 0

    # ------------------------------------------------------------------ run

    async def run(self, emit: EmitFn, stop: asyncio.Event) -> None:
        backoff = Backoff(self.BACKOFF_BASE_S, self.BACKOFF_CAP_S)
        interval = max(0.1, float(self.config.poll_interval_s))
        try:
            while not stop.is_set():
                try:
                    await asyncio.to_thread(self._ensure_dirs)
                    more = await self._scan_once(emit, stop)
                    self._set_up(True)
                    backoff.reset()
                    delay = 0.0 if more else interval
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001 - nunca tirar el proceso
                    self._set_up(False)
                    self._last_error = f"{type(exc).__name__}: {' '.join(str(exc).split())}"[:300]
                    self._last_error_at = datetime.now(UTC)
                    delay = backoff.next()
                    log.warning(
                        "directory[%s]: error procesando %s: %s; reintento en %.0f s",
                        self.name,
                        self.path,
                        self._last_error,
                        delay,
                    )
                if await sleep_or_stop(stop, delay):
                    break
        finally:
            self._set_up(False)

    def _set_up(self, up: bool) -> None:
        self._up = up
        CONNECTOR_UP.labels(connector=self.name).set(1 if up else 0)

    def _ensure_dirs(self) -> None:
        if not self.path.exists():
            log.warning("directory[%s]: la carpeta %s no existe; se crea", self.name, self.path)
        self.path.mkdir(parents=True, exist_ok=True)
        if not self.path.is_dir():
            raise NotADirectoryError(str(self.path))
        self.processed_dir.mkdir(exist_ok=True)
        self.failed_dir.mkdir(exist_ok=True)

    async def _scan_once(self, emit: EmitFn, stop: asyncio.Event) -> bool:
        """Procesa una tanda. Devuelve True si quedaron archivos listos sin procesar (seguir sin esperar)."""
        candidates, more = await asyncio.to_thread(self._list_candidates)
        self._last_scan = datetime.now(UTC)
        for cand in candidates:
            if stop.is_set():
                return False
            await self._handle(cand, emit)
        return more

    def _list_candidates(self) -> tuple[list[_Candidate], bool]:
        now = time.time()
        found: list[_Candidate] = []
        with os.scandir(self.path) as it:
            for entry in it:
                name = entry.name
                if name.startswith(".") or not name.lower().endswith(".eml"):
                    continue
                try:
                    st = entry.stat(follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if now - st.st_mtime < self.MIN_AGE_S:
                    continue  # se está escribiendo
                if stat.S_ISLNK(st.st_mode):
                    cand = _Candidate(name, st.st_mtime_ns, -1)  # -1: symlink -> .failed
                elif stat.S_ISREG(st.st_mode):
                    cand = _Candidate(name, st.st_mtime_ns, st.st_size)
                else:
                    continue
                if cand.key not in self._stuck:
                    found.append(cand)
        found.sort(key=lambda c: (c.mtime_ns, c.name))
        limit = self.MAX_FILES_PER_SCAN
        return found[:limit], len(found) > limit

    async def _handle(self, cand: _Candidate, emit: EmitFn) -> None:
        src = self.path / cand.name
        try:
            content = await asyncio.to_thread(self._read, src, cand)
        except FileNotFoundError:
            return  # lo movió/borró otro proceso
        except _UnreadableFile as exc:
            self.failed += 1
            log.warning(
                "directory[%s]: %s no se puede analizar (%s); se mueve a %s",
                self.name,
                cand.name,
                exc,
                FAILED_DIR,
            )
            if not await self._move_quietly(src, self.failed_dir):
                self._stuck.add(cand.key)
            return

        ref = MessageRef(connector=self.name, mailbox=self.path.as_posix(), remote_id=cand.remote_id)
        received_at = datetime.fromtimestamp(cand.mtime_ns / 1e9, UTC)
        limit = int(self.settings.limits.max_message_bytes)
        if content.original_size is not None:
            log.warning(
                "directory[%s]: %s pesa %d bytes y supera el límite de %d; se analizan solo los encabezados",
                self.name,
                cand.name,
                content.original_size,
                limit,
            )
            raw = oversize_raw(
                ref, content.data, original_size=content.original_size, limit=limit, received_at=received_at
            )
        else:
            raw = RawMessage(ref=ref, raw=content.data, received_at=received_at)
        await emit(raw)  # si falla, el archivo queda y se reintenta
        self.processed += 1
        if raw.truncated:
            self.truncated += 1
        if not await self._move_quietly(src, self.processed_dir):
            self._stuck.add(cand.key)  # ya se emitió: no re-emitirlo en cada pasada

    def _read(self, src: Path, cand: _Candidate) -> _Content:
        if cand.size < 0:
            raise _UnreadableFile("es un enlace simbólico")
        limit = int(self.settings.limits.max_message_bytes)
        hcap = header_cap(limit)
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(src, flags)  # O_NOFOLLOW (POSIX): no seguir un symlink puesto a último momento
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise _UnreadableFile(f"no se pudo abrir: {exc.strerror or exc}") from None
        try:
            fh = os.fdopen(fd, "rb")
        except BaseException:
            os.close(fd)
            raise
        try:
            with fh:
                st = os.fstat(fh.fileno())
                if not stat.S_ISREG(st.st_mode):
                    raise _UnreadableFile("no es un archivo regular")
                if st.st_size > limit:  # demasiado grande: solo los headers (lectura acotada)
                    head = header_section(fh.read(hcap), hcap)
                    return _Content(head, original_size=st.st_size)
                data = fh.read(limit + 1)  # lectura acotada aunque el archivo crezca entre fstat y read
        except OSError as exc:
            raise _UnreadableFile(f"error de lectura: {exc.strerror or exc}") from None
        if len(data) > limit:  # creció entre fstat y read
            return _Content(header_section(data, hcap), original_size=max(st.st_size, len(data)))
        if not data.strip():
            raise _UnreadableFile("archivo vacío")
        return _Content(data)

    async def _move_quietly(self, src: Path, dest_dir: Path) -> bool:
        try:
            await asyncio.to_thread(self._move, src, dest_dir)
            return True
        except FileNotFoundError:
            return True
        except OSError as exc:
            log.error("directory[%s]: no se pudo mover %s a %s: %s", self.name, src.name, dest_dir.name, exc)
            return False

    def _move(self, src: Path, dest_dir: Path) -> Path:
        dest_dir.mkdir(exist_ok=True)
        dest = dest_dir / src.name
        if dest.exists() or dest.is_symlink():
            stem, suffix = Path(src.name).stem, Path(src.name).suffix
            stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
            for i in range(1, self.MAX_NAME_COLLISIONS + 1):
                dest = dest_dir / f"{stem}.{stamp}-{i}{suffix}"
                if not (dest.exists() or dest.is_symlink()):
                    break
            else:
                raise FileExistsError(f"demasiados archivos con el nombre {src.name}")
        os.replace(src, dest)
        return dest

    # ------------------------------------------------------------------ salud

    async def healthcheck(self) -> dict[str, Any]:
        return {
            "ok": self._up,
            "type": self.type,
            "path": str(self.path),
            "last_scan": self._last_scan.isoformat() if self._last_scan else None,
            "last_error": self._last_error,
            "last_error_at": self._last_error_at.isoformat() if self._last_error_at else None,
            "processed": self.processed,
            "failed": self.failed,
            "truncated_too_large": self.truncated,
        }
