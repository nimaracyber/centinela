"""Desempaquetado defensivo de contenedores, 100% en memoria.

`expand(artifact, limits, passwords, budget)` devuelve los HIJOS DIRECTOS de un contenedor (un nivel);
`parsing/mime.py` recorre recursivamente. Nada toca el disco: los nombres internos son solo etiquetas
(un "../../Windows/x.exe" dentro de un zip NO se escribe en ningún lado).

Soporta: zip (ZipCrypto con contraseñas candidatas, WinZip AES si está `cryptography`), 7z (py7zr,
con contraseñas), rar (rarfile: entradas "stored" en Python puro; comprimidas solo si hay unrar/7z en el
sistema), gzip/bzip2/xz (un stream), tar, iso/udf (pycdlib), ooxml (solo partes `*/embeddings/*`; el
vbaProject.bin lo mira el analizador de Office), pdf (/EmbeddedFiles y anotaciones FileAttachment),
onenote (FileDataStoreObject), cab (MSZIP / sin compresión), TNEF (winmail.dat) y OLE2: payloads de
objetos Package (Ole10Native, también dentro de `word/embeddings/oleObject*.bin`), adjuntos de un .msg de
Outlook y streams con ejecutables/CABs/scripts dentro de un .msi. `jar` NO se expande.
vhd/vhdx/img y cab con LZX/Quantum quedan con nota "contenedor no soportado para extracción".

RAR: listar (incluso con cabeceras cifradas) y extraer entradas "stored" sin contraseña es Python puro.
Para entradas comprimidas o cifradas rarfile necesita una herramienta externa (unrar/unar/7z/bsdtar) que
recibe los bytes del adjunto por un archivo temporal que rarfile crea y borra; si no está instalada, las
entradas quedan "solo listadas" con la nota "rar no soportado". Con `limits.allow_external_unrar = False`
los .rar SOLO se listan (nombres y tamaños): no se extrae ninguna entrada ni se llama nunca a
`RarFile.open` (ni herramienta externa ni archivo temporal).

Defensas (anti zip-bomb y anti input hostil):
- tamaño declarado Y real (se lee como mucho `límite + 1` bytes), ratio de compresión por entrada,
  presupuesto total de bytes y de cantidad de artifacts compartido por todo el mensaje
  (`ExtractionBudget`), profundidad máxima, deadline de tiempo,
- contenedores repetidos (mismo SHA-256) se expanden una sola vez (quines tipo "zip que se contiene a sí
  mismo", 42.zip),
- enlaces simbólicos ignorados, rutas absolutas/traversal marcadas como sospechosas, nombres repetidos
  desambiguados ("a.exe", "a.exe~2").

Artifacts "solo listado": cuando una entrada no se puede extraer (cifrada sin contraseña, compresión no
soportada, demasiado grande) igual se crea el hijo con `listing_only=True`, `filename`, `size` declarado,
`data=b""`, hashes VACÍOS (nunca el hash de b"", que confundiría a la reputación) y `extraction_note`;
así los analizadores ven, por ejemplo, un "factura.exe" dentro de un zip cifrado.

Contraseñas: las banderas van en el CONTENEDOR, no en cada entrada (una sola contraseña no debe contar N
veces): `password_protected=True` si tenía contraseña (se haya podido abrir o no) y `encrypted=True` solo
si quedó contenido protegido SIN abrir. Un PDF que abre con contraseña de usuario vacía (solo restringe
permisos, típico de facturas legítimas) no cuenta como protegido. Las contraseñas candidatas NUNCA se
guardan ni se loguean.
"""

from __future__ import annotations

import bz2
import contextlib
import hashlib
import hmac
import io
import logging
import lzma
import re
import struct
import tarfile
import time
import zipfile
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from centinela.core.models import Artifact
from centinela.parsing.filetype import detect_type

if TYPE_CHECKING:
    from centinela.core.config import LimitsConfig

__all__ = [
    "EXPANDABLE_TYPES",
    "ChildBuilder",
    "ExtractionStopped",
    "NOTE_CORRUPT",
    "NOTE_DEPTH",
    "NOTE_DUPLICATE",
    "NOTE_ENCRYPTED",
    "NOTE_MAX_ARTIFACTS",
    "NOTE_MSG_BODY",
    "NOTE_NOT_EXTRACTED",
    "NOTE_RAR_DISABLED",
    "NOTE_RAR_UNSUPPORTED",
    "NOTE_SUSPICIOUS_PATH",
    "NOTE_SYMLINK",
    "NOTE_TIMEOUT",
    "NOTE_TOO_LARGE",
    "NOTE_UNSUPPORTED",
    "NOTE_ZIP_BOMB",
    "ExtractionBudget",
    "add_note",
    "build_artifact",
    "can_expand",
    "child_label",
    "expand",
    "is_tnef",
    "password_candidates",
]

log = logging.getLogger(__name__)

# --------------------------------------------------------------------------- notas (vocabulario estable)

NOTE_ZIP_BOMB = "posible zip-bomb: límite de descompresión alcanzado"
NOTE_DEPTH = "límite de profundidad alcanzado"
NOTE_MAX_ARTIFACTS = "límite de cantidad de archivos alcanzado"
NOTE_TIMEOUT = "tiempo de extracción agotado"
NOTE_UNSUPPORTED = "contenedor no soportado para extracción"
NOTE_RAR_UNSUPPORTED = "rar no soportado"
# sin palabras como "límite"/"tamaño": es una decisión de configuración, no un tope de seguridad alcanzado
NOTE_RAR_DISABLED = "extracción de .rar desactivada en la configuración (allow_external_unrar)"
NOTE_ENCRYPTED = "cifrado con contraseña"
NOTE_MSG_BODY = "cuerpo de texto del mensaje de Outlook"
NOTE_TOO_LARGE = "archivo demasiado grande para analizar"
NOTE_DUPLICATE = "contenedor repetido"
NOTE_CORRUPT = "contenedor dañado o ilegible"
NOTE_SUSPICIOUS_PATH = "ruta sospechosa dentro del contenedor"
NOTE_SYMLINK = "enlace simbólico ignorado"
NOTE_NOT_EXTRACTED = "no extraído"

_MAX_NOTE_LEN = 1000
_RATIO_FLOOR = (
    1024 * 1024
)  # el ratio solo se aplica a salidas > 1 MiB (archivos chicos muy comprimibles son normales)
_MAX_PASSWORD_ATTEMPTS = 16
_MAX_LABEL = 120
_MAX_ENTRIES_SCANNED = 100_000
_MAX_LOCKED_RETRIES = 2  # entradas cifradas que fallan con todas las candidatas antes de dejar de probar
_DEFAULT_TIME_BUDGET_S = 120.0


# --------------------------------------------------------------------------- presupuesto


@dataclass
class ExtractionBudget:
    """Presupuesto compartido por TODO el mensaje (todas las ramas del árbol de adjuntos)."""

    remaining_bytes: int
    remaining_artifacts: int
    max_depth: int
    max_ratio: int
    deadline: float | None = None  # time.monotonic() a partir del cual no se expande más
    max_artifact_bytes: int | None = None  # tope por archivo extraído (default: limits.max_artifact_bytes)
    expanded: dict[str, str] = field(default_factory=dict)  # sha256 -> id del contenedor ya expandido

    @classmethod
    def from_limits(cls, limits: LimitsConfig, *, time_budget_s: float | None = None) -> ExtractionBudget:
        if time_budget_s is None:
            time_budget_s = max(5.0, min(_DEFAULT_TIME_BUDGET_S, limits.message_timeout_s / 2))
        return cls(
            remaining_bytes=limits.max_total_extracted_bytes,
            remaining_artifacts=limits.max_artifacts,
            max_depth=limits.max_archive_depth,
            max_ratio=limits.max_compression_ratio,
            deadline=time.monotonic() + time_budget_s,
            max_artifact_bytes=limits.max_artifact_bytes,
        )

    def time_exceeded(self) -> bool:
        return self.deadline is not None and time.monotonic() > self.deadline

    def take_artifact(self) -> bool:
        """Reserva un lugar para un artifact nuevo. False si se agotó el cupo."""
        if self.remaining_artifacts <= 0:
            return False
        self.remaining_artifacts -= 1
        return True


# --------------------------------------------------------------------------- helpers públicos


def add_note(artifact: Artifact, note: str) -> None:
    """Agrega una nota a `artifact.extraction_note` (sin duplicar, con tope de largo)."""
    note = note.strip()
    if not note:
        return
    current = artifact.extraction_note
    if current:
        if note in current.split("; "):
            return
        note = f"{current}; {note}"
    if len(note) > _MAX_NOTE_LEN:
        note = note[: _MAX_NOTE_LEN - 1] + "…"
    artifact.extraction_note = note


def hashes(data: bytes) -> tuple[str, str, str]:
    """(md5, sha1, sha256) en hex."""
    return (
        hashlib.md5(data, usedforsecurity=False).hexdigest(),
        hashlib.sha1(data, usedforsecurity=False).hexdigest(),
        hashlib.sha256(data).hexdigest(),
    )


def build_artifact(
    *,
    id: str,  # noqa: A002 - mismo nombre que el campo del modelo
    data: bytes,
    filename: str | None,
    depth: int,
    parent_id: str | None,
    declared_content_type: str | None = None,
    detected_type: str | None = None,
    note: str | None = None,
    listing_size: int | None = None,
) -> Artifact:
    """Crea un Artifact con hashes y tipo detectado.

    `listing_size` => artifact "solo listado" (`listing_only=True`): sin datos y con los hashes VACÍOS
    (no el hash de b"": no hay contenido que buscar en reputación)."""
    if listing_size is not None:
        art = Artifact(
            id=id,
            filename=filename,
            declared_content_type=declared_content_type,
            detected_type=detected_type or "unknown",
            size=max(0, int(listing_size)),
            depth=depth,
            parent_id=parent_id,
            listing_only=True,
        )
    else:
        md5, sha1, sha256 = hashes(data)
        art = Artifact(
            id=id,
            filename=filename,
            declared_content_type=declared_content_type,
            detected_type=detected_type or detect_type(data, filename),
            size=len(data),
            sha256=sha256,
            sha1=sha1,
            md5=md5,
            depth=depth,
            parent_id=parent_id,
            data=data,
        )
    if note:
        add_note(art, note)
    return art


_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")


def child_label(name: str | None, index: int) -> tuple[str, str | None, bool]:
    """(etiqueta para el id, filename, ruta_sospechosa) a partir del nombre interno de una entrada.

    El nombre es solo una etiqueta: se descartan directorios, `..`, rutas absolutas y unidades de Windows,
    se quitan caracteres de control (pero se conservan RTLO y otros unicode: importan para el análisis)."""
    raw = _CTRL_RE.sub("", name or "")
    norm = raw.replace("\\", "/")
    segments = norm.split("/")
    suspicious = norm.startswith("/") or bool(_DRIVE_RE.match(norm)) or ".." in segments
    parts = [p for p in segments if p not in ("", ".", "..")]
    base = parts[-1] if parts else ""
    if _DRIVE_RE.match(base):
        base = base[2:]
        suspicious = True
    base = base.strip()
    filename = base[:255] or None
    label = (base or f"entrada{index}")[:_MAX_LABEL]
    return label, filename, suspicious


def password_candidates(passwords: list[str], limits: LimitsConfig | None = None) -> list[str]:
    """Candidatas en orden (primero las del mensaje), sin duplicados, con tope de intentos."""
    out: list[str] = []
    seen: set[str] = set()
    pool = list(passwords or []) + list(limits.archive_passwords if limits else [])
    for p in pool:
        if not isinstance(p, str) or not p or p in seen or len(p) > 128:
            continue
        seen.add(p)
        out.append(p)
        if len(out) >= _MAX_PASSWORD_ATTEMPTS:
            break
    return out


def _pwd_bytes(pwd: str) -> list[bytes]:
    variants = [pwd.encode("utf-8")]
    for enc in ("cp1252", "cp850"):
        try:
            b = pwd.encode(enc)
        except UnicodeEncodeError:
            continue
        if b not in variants:
            variants.append(b)
    return variants


# --------------------------------------------------------------------------- contexto de extracción


class ExtractionStopped(Exception):
    """Corta la extracción de este contenedor (presupuesto agotado)."""


class ChildBuilder:
    """Crea los hijos de UN contenedor aplicando el presupuesto compartido, ids únicos
    ("padre/nombre", "padre/nombre~2") y notas en el padre. También lo usa `mime.py` para los adjuntos
    de un mail adjunto (.eml)."""

    def __init__(
        self, parent: Artifact, limits: LimitsConfig, passwords: list[str], budget: ExtractionBudget
    ):
        self.parent = parent
        self.limits = limits
        self.budget = budget
        self.passwords = password_candidates(passwords, limits)
        self.children: list[Artifact] = []
        self.stopped = False
        self._labels: set[str] = set()
        self._index = 0
        self.max_entry = min(
            budget.max_artifact_bytes or limits.max_artifact_bytes,
            limits.max_artifact_bytes,
        )

    # -- notas
    def note(self, text: str) -> None:
        add_note(self.parent, text)

    def check_time(self) -> bool:
        if self.budget.time_exceeded():
            self.note(NOTE_TIMEOUT)
            self.stopped = True
            return False
        return True

    # -- límites
    def entry_limit(self, compressed_size: int | None, declared_size: int | None = None) -> tuple[int, str]:
        """(bytes máximos a leer para esta entrada, motivo si se excede: size|budget|ratio).

        Si se conoce el tamaño declarado, el motivo es el MÁS grave que ese tamaño viola (un ratio
        absurdo es una bomba aunque además supere el tope por archivo)."""
        budget_limit = max(0, self.budget.remaining_bytes)
        ratio_limit: int | None = None
        if compressed_size is not None and compressed_size >= 0:
            ratio_limit = max(compressed_size * self.budget.max_ratio, _RATIO_FLOOR)
        limit, reason = self.max_entry, "size"
        if budget_limit < limit:
            limit, reason = budget_limit, "budget"
        if ratio_limit is not None and ratio_limit < limit:
            limit, reason = ratio_limit, "ratio"
        if declared_size is not None and declared_size > limit:
            if ratio_limit is not None and declared_size > ratio_limit:
                reason = "ratio"
            elif declared_size > budget_limit:
                reason = "budget"
        return limit, reason

    def over_limit(self, reason: str, name: str | None, declared: int | None = None) -> None:
        """Una entrada excede el límite: si es por tamaño queda "solo listada"; si no, es una bomba."""
        if reason == "size":
            mb = self.max_entry // (1024 * 1024)
            self.add_listing(
                name,
                declared if declared is not None else self.max_entry + 1,
                note=f"{NOTE_TOO_LARGE} (más de {mb} MB)",
            )
            return
        self.note(NOTE_ZIP_BOMB)
        if reason == "budget":
            self.stopped = True
            raise ExtractionStopped
        # ratio sospechoso: la entrada queda listada (sin datos) y se sigue con las demás
        self.add_listing(name, declared if declared is not None else 0, note=NOTE_ZIP_BOMB)

    # -- hijos
    def _new_id(self, name: str | None) -> tuple[str, str | None, bool]:
        label, filename, suspicious = child_label(name, self._index)
        self._index += 1
        candidate = label
        n = 2
        while candidate in self._labels:
            candidate = f"{label}~{n}"
            n += 1
        self._labels.add(candidate)
        return f"{self.parent.id}/{candidate}", filename, suspicious

    def _reserve(self, nbytes: int) -> None:
        if self.stopped:
            raise ExtractionStopped
        if not self.budget.take_artifact():
            self.note(NOTE_MAX_ARTIFACTS)
            self.stopped = True
            raise ExtractionStopped
        if nbytes > self.budget.remaining_bytes:
            self.budget.remaining_artifacts += 1
            self.note(NOTE_ZIP_BOMB)
            self.stopped = True
            raise ExtractionStopped
        self.budget.remaining_bytes -= nbytes

    def add(
        self,
        name: str | None,
        data: bytes,
        *,
        note: str | None = None,
        declared_content_type: str | None = None,
        hash_only: bool = False,
    ) -> Artifact:
        """Hijo extraído. `hash_only=True`: los bytes ya están en memoria pero superan el tope por archivo:
        se calculan hashes y tipo y NO se conservan los datos (no consume presupuesto de bytes)."""
        self._reserve(0 if hash_only else len(data))
        art_id, filename, suspicious = self._new_id(name)
        art = build_artifact(
            id=art_id,
            data=data,
            filename=filename,
            depth=self.parent.depth + 1,
            parent_id=self.parent.id,
            declared_content_type=declared_content_type,
            note=note,
        )
        if hash_only:
            art.data = b""
        if suspicious:
            add_note(art, f"{NOTE_SUSPICIOUS_PATH}: {_CTRL_RE.sub('', name or '')[:200]}")
        self.children.append(art)
        return art

    def add_listing(self, name: str | None, size: int, *, note: str) -> Artifact:
        """Hijo "solo listado": se conoce el nombre (y el tamaño declarado) pero no el contenido."""
        self._reserve(0)
        art_id, filename, suspicious = self._new_id(name)
        art = build_artifact(
            id=art_id,
            data=b"",
            filename=filename,
            depth=self.parent.depth + 1,
            parent_id=self.parent.id,
            note=f"{NOTE_NOT_EXTRACTED}: {note}",
            listing_size=size,
        )
        if suspicious:
            add_note(art, f"{NOTE_SUSPICIOUS_PATH}: {_CTRL_RE.sub('', name or '')[:200]}")
        self.children.append(art)
        return art


class _LimitedWriter(io.RawIOBase):
    """Destino de escritura que deja de acumular al pasar `limit` (marca overflow)."""

    def __init__(self, limit: int) -> None:
        super().__init__()
        self.limit = limit
        self.buf = bytearray()
        self.overflow = False

    def writable(self) -> bool:
        return True

    def write(self, b: Any) -> int:
        n = len(b)
        if self.overflow:
            return n
        if len(self.buf) + n > self.limit:
            self.overflow = True
            self.buf = bytearray()
            return n
        self.buf += bytes(b)
        return n

    def getvalue(self) -> bytes:
        return bytes(self.buf)


# --------------------------------------------------------------------------- API


def is_tnef(data: bytes) -> bool:
    return data[:4] == b"\x78\x9f\x3e\x22"


def _unsupported(ex: ChildBuilder) -> None:
    ex.note(f"{NOTE_UNSUPPORTED} ({ex.parent.detected_type})")


def can_expand(artifact: Artifact) -> bool:
    """True si `expand` sabe (o intenta) sacar algo de este artifact."""
    if not artifact.data:
        return False
    return artifact.detected_type in _HANDLERS or is_tnef(artifact.data)


def expand(
    artifact: Artifact,
    limits: LimitsConfig,
    passwords: list[str],
    budget: ExtractionBudget,
) -> list[Artifact]:
    """Hijos directos de `artifact` (id "padre/nombre", depth+1, parent_id, hashes, detected_type,
    datos solo en memoria). Nunca lanza: los problemas quedan en `artifact.extraction_note`."""
    if not artifact.data:
        return []
    handler = _HANDLERS.get(artifact.detected_type)
    if handler is None:
        if not is_tnef(artifact.data):
            return []
        handler = _expand_tnef
    ex = ChildBuilder(artifact, limits, passwords, budget)
    if handler is _unsupported:
        _unsupported(ex)
        return []
    if artifact.depth >= budget.max_depth:
        ex.note(f"{NOTE_DEPTH} ({budget.max_depth} niveles)")
        return []
    if budget.remaining_artifacts <= 0:
        ex.note(NOTE_MAX_ARTIFACTS)
        return []
    if not ex.check_time():
        return []
    if artifact.sha256:
        previous = budget.expanded.get(artifact.sha256)
        if previous is not None:
            ex.note(f"{NOTE_DUPLICATE}: idéntico a {previous}")
            return []
        budget.expanded[artifact.sha256] = artifact.id
    try:
        handler(ex)
    except ExtractionStopped:
        pass
    except Exception as exc:  # noqa: BLE001 - input hostil: nunca tumbar el parseo
        log.debug("no se pudo expandir %s (%s)", artifact.id, artifact.detected_type, exc_info=True)
        ex.note(f"{NOTE_CORRUPT} ({artifact.detected_type}: {type(exc).__name__})")
    return ex.children


# --------------------------------------------------------------------------- ZIP

_ZIP_AES = 99


def _zip_is_symlink(info: zipfile.ZipInfo) -> bool:
    return info.create_system == 3 and ((info.external_attr >> 16) & 0o170000) == 0o120000


def _zip_read_plain(zf: zipfile.ZipFile, info: zipfile.ZipInfo, pwd: bytes | None, limit: int) -> bytes:
    with zf.open(info, pwd=pwd) as fh:
        if hasattr(fh, "_expected_crc"):
            fh._expected_crc = None  # verificamos el CRC nosotros (para conservar datos con CRC roto)
        return fh.read(limit + 1)


def _zip_raw_payload(data: bytes, info: zipfile.ZipInfo) -> bytes:
    off = info.header_offset
    if off < 0 or data[off : off + 4] != b"PK\x03\x04":
        raise zipfile.BadZipFile("local header inválido")
    n, m = struct.unpack_from("<HH", data, off + 26)
    start = off + 30 + n + m
    payload = data[start : start + info.compress_size]
    if len(payload) != info.compress_size:
        raise zipfile.BadZipFile("datos truncados")
    return payload


def _zip_extra_fields(extra: bytes) -> dict[int, bytes]:
    out: dict[int, bytes] = {}
    pos = 0
    while pos + 4 <= len(extra):
        hid, size = struct.unpack_from("<HH", extra, pos)
        out.setdefault(hid, extra[pos + 4 : pos + 4 + size])
        pos += 4 + size
    return out


def _decompress_bounded(method: int, payload: bytes, limit: int) -> bytes | None:
    """Descomprime (stored/deflate/bzip2) leyendo como mucho limit+1 bytes. None si no soportado."""
    if method == zipfile.ZIP_STORED:
        return payload[: limit + 1]
    if method == zipfile.ZIP_DEFLATED:
        return zlib.decompressobj(-15).decompress(payload, limit + 1)
    if method == zipfile.ZIP_BZIP2:
        return bz2.BZ2Decompressor().decompress(payload, limit + 1)
    return None


def _aes_ctr_le(key: bytes, data: bytes) -> bytes:
    """AES-CTR al estilo WinZip (contador little-endian que arranca en 1)."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()  # noqa: S305 - ECB solo para generar el keystream CTR
    out = bytearray()
    nblocks = (len(data) + 15) // 16
    chunk = 4096
    for start in range(0, nblocks, chunk):
        n = min(chunk, nblocks - start)
        counters = b"".join(i.to_bytes(16, "little") for i in range(start + 1, start + 1 + n))
        ks = enc.update(counters)
        seg = data[start * 16 : (start + n) * 16]
        x = int.from_bytes(seg, "little") ^ int.from_bytes(ks[: len(seg)], "little")
        out += x.to_bytes(len(seg), "little")
    return bytes(out)


class _AesUnavailable(Exception):
    pass


def _zip_aes_read(data: bytes, info: zipfile.ZipInfo, pwd: bytes, limit: int) -> bytes | None:
    """Descifra una entrada WinZip AES (AE-1/AE-2). None si la contraseña no corresponde."""
    try:
        import cryptography  # noqa: F401
    except ImportError as exc:  # pragma: no cover - cryptography es dependencia del proyecto
        raise _AesUnavailable from exc
    extra = _zip_extra_fields(info.extra).get(0x9901)
    if not extra or len(extra) < 7:
        raise zipfile.BadZipFile("falta el campo extra AES")
    vendor_version, _vendor, strength, method = struct.unpack_from("<H2sBH", extra, 0)
    if strength not in (1, 2, 3):
        raise zipfile.BadZipFile("fuerza AES inválida")
    key_len = 8 * (strength + 1)
    salt_len = key_len // 2
    payload = _zip_raw_payload(data, info)
    if len(payload) < salt_len + 2 + 10:
        raise zipfile.BadZipFile("entrada AES truncada")
    salt = payload[:salt_len]
    verifier = payload[salt_len : salt_len + 2]
    ciphertext = payload[salt_len + 2 : -10]
    mac = payload[-10:]
    dk = hashlib.pbkdf2_hmac("sha1", pwd, salt, 1000, 2 * key_len + 2)
    if dk[-2:] != verifier:
        return None
    if not hmac.compare_digest(hmac.new(dk[key_len : 2 * key_len], ciphertext, "sha1").digest()[:10], mac):
        return None
    plain = _aes_ctr_le(dk[:key_len], ciphertext)
    content = _decompress_bounded(method, plain, limit)
    if content is None:
        raise NotImplementedError(f"método de compresión {method}")
    if vendor_version == 1 and len(content) == info.file_size and zlib.crc32(content) != info.CRC:
        return None
    return content


def _expand_zip(ex: ChildBuilder, *, embeddings_only: bool = False) -> None:
    data = ex.parent.data
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        infos = zf.infolist()
        good_pwd: str | None = None
        locked = 0
        opened = 0
        symlinks = 0
        for info in infos[:_MAX_ENTRIES_SCANNED]:
            if ex.stopped or not ex.check_time():
                break
            if info.is_dir():
                continue
            name = info.filename
            if embeddings_only and "/embeddings/" not in "/" + name.replace("\\", "/").lower():
                continue
            if _zip_is_symlink(info):
                symlinks += 1
                continue
            encrypted = bool(info.flag_bits & 0x1)
            if encrypted:
                ex.parent.password_protected = True  # aunque la entrada después no se lea (muy grande, etc.)
            limit, reason = ex.entry_limit(info.compress_size, info.file_size)
            if info.file_size > limit:
                ex.over_limit(reason, name, info.file_size)
                continue
            if not encrypted:
                if info.compress_type == _ZIP_AES:  # AES sin bit de cifrado: archivo malformado
                    ex.add_listing(name, info.file_size, note="entrada AES malformada")
                    continue
                try:
                    content = _zip_read_plain(zf, info, None, limit)
                except NotImplementedError:
                    ex.add_listing(
                        name, info.file_size, note=f"método de compresión no soportado ({info.compress_type})"
                    )
                    continue
                except (zipfile.BadZipFile, zlib.error, EOFError, OSError, lzma.LZMAError, ValueError) as exc:
                    ex.add_listing(name, info.file_size, note=f"entrada dañada ({type(exc).__name__})")
                    continue
                if len(content) > limit:
                    ex.over_limit(reason, name, info.file_size)
                    continue
                crc_note = None
                if len(content) == info.file_size and zlib.crc32(content) != info.CRC:
                    crc_note = "CRC inválido (archivo dañado o manipulado)"
                ex.add(name, content, note=crc_note)
                continue

            # --- entrada cifrada
            candidates = ex.passwords
            if good_pwd is not None:
                candidates = [good_pwd] + [p for p in candidates if p != good_pwd]
            elif locked >= _MAX_LOCKED_RETRIES:
                candidates = []  # ninguna candidata sirvió en las anteriores: no repetir (AES = PBKDF2 por intento)
            content = None
            unsupported = False
            for pwd in candidates:
                for pb in _pwd_bytes(pwd):
                    try:
                        if info.compress_type == _ZIP_AES:
                            got = _zip_aes_read(data, info, pb, limit)
                        else:
                            got = _zip_read_plain(zf, info, pb, limit)
                            if len(got) == info.file_size and zlib.crc32(got) != info.CRC:
                                got = None  # el byte de verificación pasó por casualidad (1/256)
                    except (_AesUnavailable, NotImplementedError):
                        unsupported = True
                        break
                    except RuntimeError:  # "Bad password for file"
                        continue
                    except (zipfile.BadZipFile, zlib.error, EOFError, OSError, ValueError, lzma.LZMAError):
                        continue
                    if got is not None:
                        content = got
                        good_pwd = pwd
                        break
                if content is not None or unsupported:
                    break
            if content is None:
                locked += 1
                why = "cifrado no soportado" if unsupported else "no se encontró la contraseña"
                ex.add_listing(name, info.file_size, note=f"{NOTE_ENCRYPTED}: {why}")
                continue
            if len(content) > limit:
                ex.over_limit(reason, name, info.file_size)
                continue
            opened += 1
            ex.add(name, content, note=f"{NOTE_ENCRYPTED}: abierto con una contraseña candidata")
        if symlinks:
            ex.note(f"{NOTE_SYMLINK} ({symlinks})")
        if locked:
            ex.parent.encrypted = True
            ex.note(f"{NOTE_ENCRYPTED}: {locked} archivo(s) no se pudieron abrir")
        elif opened:
            ex.note(f"{NOTE_ENCRYPTED}: se abrió con una contraseña candidata")


def _expand_ooxml(ex: ChildBuilder) -> None:
    _expand_zip(ex, embeddings_only=True)


# --------------------------------------------------------------------------- 7z


def _expand_7z(ex: ChildBuilder) -> None:
    try:
        import py7zr
        from py7zr.exceptions import PasswordRequired
        from py7zr.io import Py7zIO, WriterFactory
    except ImportError:  # pragma: no cover - dependencia opcional
        ex.note(f"{NOTE_UNSUPPORTED} (7z: falta py7zr)")
        return
    try:
        from py7zr.helpers import get_sanitized_output_path
    except ImportError:  # pragma: no cover
        get_sanitized_output_path = None

    data = ex.parent.data

    class _Out(Py7zIO):
        def __init__(self, limit: int) -> None:
            self.w = _LimitedWriter(limit)
            self._pos = 0

        def write(self, s: bytes | bytearray) -> int:
            return self.w.write(s)

        def read(self, size: int | None = None) -> bytes:
            buf = self.w.getvalue()
            end = len(buf) if size is None or size < 0 else self._pos + size
            chunk = buf[self._pos : end]
            self._pos += len(chunk)
            return chunk

        def seek(self, offset: int, whence: int = 0) -> int:
            base = {0: 0, 1: self._pos, 2: len(self.w.buf)}.get(whence, 0)
            self._pos = max(0, base + offset)
            return self._pos

        def flush(self) -> None:
            return None

        def size(self) -> int:
            return len(self.w.buf)

    class _Factory(WriterFactory):
        def __init__(self, limit: int) -> None:
            self.limit = limit
            self.products: dict[str, _Out] = {}

        def create(self, filename: str) -> Py7zIO:
            out = _Out(self.limit)
            self.products[filename] = out
            return out

    def _open(pwd: str | None, max_extract: int | None = None):
        return py7zr.SevenZipFile(io.BytesIO(data), mode="r", password=pwd, max_extract_size=max_extract)

    good_pwd: str | None = None
    try:
        archive = _open(None)
    except PasswordRequired:
        ex.parent.password_protected = True  # cabeceras cifradas (7z -mhe): ni los nombres se ven
        archive = None
        for pwd in ex.passwords:
            try:
                archive = _open(pwd)
                good_pwd = pwd
                break
            except Exception:  # noqa: BLE001, S112 - contraseña incorrecta: probar la siguiente
                continue
        if archive is None:
            ex.parent.encrypted = True
            ex.note(f"{NOTE_ENCRYPTED}: 7z con nombres cifrados, no se encontró la contraseña")
            return

    with archive:
        needs_pwd = archive.needs_password()
        files = list(archive.files)
    if needs_pwd:
        ex.parent.password_protected = True

    per_entry_limit, _ = ex.entry_limit(None)
    seen_names: dict[str, int] = {}
    targets: list[str] = []
    expected: dict[str, tuple[str, int]] = {}  # clave de py7zr -> (nombre, tamaño)
    total = 0
    for f in files[:_MAX_ENTRIES_SCANNED]:
        if f.is_directory:
            continue
        name = f.filename
        if name not in seen_names:
            outname = name
            seen_names[name] = 0
        else:
            outname = f"{name}_{seen_names[name]}"
            seen_names[name] += 1
        size = int(f.uncompressed or 0)
        if f.is_symlink or getattr(f, "is_junction", False):
            ex.note(NOTE_SYMLINK)
            continue
        key: str | None
        try:
            key = (
                get_sanitized_output_path(outname, None).as_posix() if get_sanitized_output_path else outname
            )
        except Exception:  # noqa: BLE001 - nombre con traversal/unidad: py7zr se niega a extraerlo
            key = None
        if key is None:
            ex.add_listing(name, size, note=f"{NOTE_SUSPICIOUS_PATH} (no se puede extraer)")
            continue
        if size > per_entry_limit:
            mb = ex.max_entry // (1024 * 1024)
            ex.add_listing(name, size, note=f"{NOTE_TOO_LARGE} (más de {mb} MB)")
            continue
        targets.append(name)
        expected[key] = (name, size)
        total += size

    if not targets:
        return
    if total > ex.budget.remaining_bytes or (
        total > _RATIO_FLOOR and total > len(data) * ex.budget.max_ratio
    ):
        ex.note(NOTE_ZIP_BOMB)
        for name, size in expected.values():
            ex.add_listing(name, size, note=NOTE_ZIP_BOMB)
        return

    attempts: list[str | None] = [None]
    if needs_pwd:
        attempts = [good_pwd] if good_pwd else []
        attempts += [p for p in ex.passwords if p != good_pwd]
    factory: _Factory | None = None
    ok = False
    for pwd in attempts:
        if not ex.check_time():
            break
        factory = _Factory(per_entry_limit)
        try:
            with _open(pwd, max_extract=max(1, min(ex.budget.remaining_bytes, total + 1024))) as z:
                z.extract(targets=targets, factory=factory)
            ok = True
            break
        except Exception as exc:  # noqa: BLE001
            if type(exc).__name__ == "DecompressionBombError":
                ex.note(NOTE_ZIP_BOMB)
                break
            if needs_pwd:
                factory = None
                continue
            ex.note(f"{NOTE_CORRUPT} (7z: {type(exc).__name__})")
            break

    products = factory.products if factory else {}
    added: set[str] = set()
    for key, out in products.items():
        if ex.stopped:
            break
        name, size = expected.get(key, (key, -1))
        content = out.w.getvalue()
        if out.w.overflow or (size >= 0 and len(content) != size and not ok):
            continue
        note = f"{NOTE_ENCRYPTED}: abierto con una contraseña candidata" if needs_pwd and ok else None
        ex.add(name, content, note=note)
        added.add(key)
    for key, (name, size) in expected.items():
        if key in added or ex.stopped:
            continue
        if needs_pwd and not ok:
            ex.add_listing(name, size, note=f"{NOTE_ENCRYPTED}: no se encontró la contraseña")
        else:
            ex.add_listing(name, size, note="no se pudo descomprimir")
    if needs_pwd:
        if ok:
            ex.note(f"{NOTE_ENCRYPTED}: se abrió con una contraseña candidata")
        else:
            ex.parent.encrypted = True
            ex.note(f"{NOTE_ENCRYPTED}: no se encontró la contraseña")


# --------------------------------------------------------------------------- RAR


def _expand_rar(ex: ChildBuilder) -> None:
    try:
        import rarfile
    except ImportError:  # pragma: no cover
        ex.note(f"{NOTE_RAR_UNSUPPORTED} (falta rarfile)")
        return
    data = ex.parent.data
    allow_tool = ex.limits.allow_external_unrar
    rf = rarfile.RarFile(io.BytesIO(data))
    rar_pwd: str | None = None
    try:
        if rf.needs_password() and not rf.infolist():  # cabeceras cifradas (rar -hp): Python puro
            ex.parent.password_protected = True
            for pwd in ex.passwords:
                try:
                    rf.setpassword(pwd)
                    if rf.infolist():
                        rar_pwd = pwd
                        break
                except Exception:  # noqa: BLE001, S112 - contraseña incorrecta: probar la siguiente
                    continue
            if rar_pwd is None:
                ex.parent.encrypted = True
                ex.note(f"{NOTE_ENCRYPTED}: rar con nombres cifrados, no se encontró la contraseña")
                return
        no_tool = 0
        disabled = 0
        locked = 0  # entradas con contraseña en las que fallaron todas las candidatas
        unopened = 0  # entradas con contraseña que quedaron sin abrir (por el motivo que sea)
        opened = 0
        for info in rf.infolist()[:_MAX_ENTRIES_SCANNED]:
            if ex.stopped or not ex.check_time():
                break
            if info.is_dir():
                continue
            if info.is_symlink() or info.file_redir:
                ex.note(NOTE_SYMLINK)
                continue
            name = info.filename
            size = int(info.file_size or 0)
            needs_pwd = info.needs_password()
            if needs_pwd:
                ex.parent.password_protected = True
            limit, reason = ex.entry_limit(info.compress_size, size)
            if size > limit:
                ex.over_limit(reason, name, size)
                continue
            if not allow_tool:
                # ni siquiera las entradas "stored": la configuración pide no extraer .rar
                disabled += 1
                unopened += int(needs_pwd)
                ex.add_listing(name, size, note=NOTE_RAR_DISABLED)
                continue
            if no_tool and (info.compress_type != rarfile.RAR_M0 or needs_pwd):
                no_tool += 1
                unopened += int(needs_pwd)
                ex.add_listing(name, size, note=f"{NOTE_RAR_UNSUPPORTED} (falta unrar en el servidor)")
                continue
            content = None
            attempts: list[str | None] = [None]
            if needs_pwd:
                if rar_pwd is not None:
                    attempts = [rar_pwd] + [p for p in ex.passwords if p != rar_pwd]
                elif locked >= _MAX_LOCKED_RETRIES:
                    attempts = []
                else:
                    attempts = list(ex.passwords)
            tool_missing = False
            for pwd in attempts:
                try:
                    with rf.open(info, pwd=pwd) as fh:
                        content = fh.read(limit + 1)
                    if pwd is not None:
                        rar_pwd = pwd
                    break
                except rarfile.RarCannotExec:
                    tool_missing = True
                    break
                except (rarfile.Error, OSError, ValueError, zlib.error):
                    continue
            if tool_missing:
                no_tool += 1
                unopened += int(needs_pwd)
                ex.add_listing(name, size, note=f"{NOTE_RAR_UNSUPPORTED} (falta unrar en el servidor)")
                continue
            if content is None:
                if needs_pwd:
                    locked += 1
                    unopened += 1
                    ex.add_listing(name, size, note=f"{NOTE_ENCRYPTED}: no se encontró la contraseña")
                else:
                    ex.add_listing(name, size, note="entrada dañada")
                continue
            if len(content) > limit:
                ex.over_limit(reason, name, size)
                continue
            if needs_pwd:
                opened += 1
            ex.add(
                name,
                content,
                note=f"{NOTE_ENCRYPTED}: abierto con una contraseña candidata" if needs_pwd else None,
            )
        if disabled:
            ex.note(f"{NOTE_RAR_DISABLED}: {disabled} archivo(s) solo listados")
        if no_tool:
            ex.note(
                f"{NOTE_RAR_UNSUPPORTED}: falta la herramienta unrar en el servidor; {no_tool} archivo(s) solo listados"
            )
        if unopened:
            ex.parent.encrypted = True
            ex.note(f"{NOTE_ENCRYPTED}: {unopened} archivo(s) no se pudieron abrir")
        elif opened or rar_pwd is not None:
            ex.note(f"{NOTE_ENCRYPTED}: se abrió con una contraseña candidata")
    finally:
        with contextlib.suppress(Exception):
            rf.close()


# --------------------------------------------------------------------------- gzip / bzip2 / xz

_SUFFIXES = (
    (".tgz", ".tar"),
    (".taz", ".tar"),
    (".tbz2", ".tar"),
    (".tbz", ".tar"),
    (".txz", ".tar"),
    (".gzip", ""),
    (".gz", ""),
    (".z", ""),
    (".bz2", ""),
    (".bz", ""),
    (".xz", ""),
    (".lzma", ""),
)


def _gzip_member_name(data: bytes) -> str | None:
    """Nombre original guardado en la cabecera gzip (FNAME), si existe."""
    if len(data) < 10 or data[3] & 0x08 == 0:
        return None
    pos = 10
    if data[3] & 0x04:  # FEXTRA
        if pos + 2 > len(data):
            return None
        xlen = struct.unpack_from("<H", data, pos)[0]
        pos += 2 + xlen
    end = data.find(b"\x00", pos, pos + 1024)
    if end < 0:
        return None
    return data[pos:end].decode("latin-1") or None


def _stream_child_name(parent: Artifact, kind: str) -> str:
    if kind == "gzip":
        inner = _gzip_member_name(parent.data)
        if inner:
            return inner
    base = (parent.filename or "archivo").replace("\\", "/").rsplit("/", 1)[-1] or "archivo"
    low = base.lower()
    for suffix, repl in _SUFFIXES:
        if low.endswith(suffix) and len(base) > len(suffix):
            return base[: -len(suffix)] + repl
    return f"{base}.contenido"


def _expand_stream(ex: ChildBuilder) -> None:
    kind = ex.parent.detected_type
    data = ex.parent.data
    limit, reason = ex.entry_limit(len(data))
    name = _stream_child_name(ex.parent, kind)
    if kind == "gzip":
        d: Any = zlib.decompressobj(16 + zlib.MAX_WBITS)
        out = d.decompress(data, limit + 1)
        eof = d.eof
        extra = d.unused_data if eof else b""
    elif kind == "bzip2":
        d = bz2.BZ2Decompressor()
        out = d.decompress(data, limit + 1)
        eof = d.eof
        extra = d.unused_data if eof else b""
    else:
        d = lzma.LZMADecompressor()
        out = d.decompress(data, limit + 1)
        eof = d.eof
        extra = d.unused_data if eof else b""
    if len(out) > limit:
        ex.over_limit(reason, name)
        return
    note = None
    if not eof:
        note = "stream comprimido truncado"
    elif extra.strip(b"\x00"):
        ex.note("datos extra después del stream comprimido (no analizados)")
    ex.add(name, out, note=note)


# --------------------------------------------------------------------------- TAR


def _expand_tar(ex: ChildBuilder) -> None:
    with tarfile.open(fileobj=io.BytesIO(ex.parent.data), mode="r:") as tf:
        scanned = 0
        while not ex.stopped and ex.check_time():
            try:
                member = tf.next()
            except tarfile.TarError as exc:
                ex.note(f"{NOTE_CORRUPT} (tar: {type(exc).__name__})")
                break
            if member is None:
                break
            scanned += 1
            if scanned > _MAX_ENTRIES_SCANNED:
                break
            if member.isdir():
                continue
            if member.issym() or member.islnk():
                ex.note(NOTE_SYMLINK)
                continue
            if not member.isreg():
                continue
            limit, reason = ex.entry_limit(None, member.size)
            if member.size > limit:
                ex.over_limit(reason, member.name, member.size)
                continue
            fh = tf.extractfile(member)
            if fh is None:
                continue
            content = fh.read(limit + 1)
            if len(content) > limit:
                ex.over_limit(reason, member.name, member.size)
                continue
            ex.add(member.name, content)


# --------------------------------------------------------------------------- ISO / UDF


def _expand_iso(ex: ChildBuilder) -> None:
    try:
        import pycdlib
    except ImportError:  # pragma: no cover
        ex.note(f"{NOTE_UNSUPPORTED} (falta pycdlib)")
        return
    iso = pycdlib.PyCdlib()
    try:
        iso.open_fp(io.BytesIO(ex.parent.data))
    except Exception as exc:  # noqa: BLE001 - imagen hostil/no soportada (UDF puro, etc.)
        ex.note(f"{NOTE_UNSUPPORTED} ({ex.parent.detected_type}: {type(exc).__name__})")
        return
    try:
        if iso.has_udf():
            key = "udf_path"
        elif iso.has_joliet():
            key = "joliet_path"
        elif iso.has_rock_ridge():
            key = "rr_path"
        else:
            key = "iso_path"
        dirs = 0
        for dirpath, _dirlist, filelist in iso.walk(**{key: "/"}):
            dirs += 1
            if dirs > 10_000 or ex.stopped or not ex.check_time():
                break
            for fname in filelist:
                if ex.stopped or not ex.check_time():
                    return
                path = dirpath.rstrip("/") + "/" + fname
                shown = fname.split(";", 1)[0] if key == "iso_path" else fname
                try:
                    size = int(iso.get_record(**{key: path}).get_data_length())
                except Exception as exc:  # noqa: BLE001
                    ex.add_listing(shown, 0, note=f"entrada ilegible ({type(exc).__name__})")
                    continue
                limit, reason = ex.entry_limit(None, size)
                if size > limit:
                    ex.over_limit(reason, shown, size)
                    continue
                writer = _LimitedWriter(limit)
                try:
                    iso.get_file_from_iso_fp(writer, **{key: path})
                except Exception as exc:  # noqa: BLE001
                    ex.add_listing(shown, size, note=f"entrada ilegible ({type(exc).__name__})")
                    continue
                if writer.overflow:
                    ex.over_limit(reason, shown, size)
                    continue
                ex.add(shown, writer.getvalue())
    finally:
        with contextlib.suppress(Exception):
            iso.close()


# --------------------------------------------------------------------------- PDF


def _pdf_resolve(obj: Any, depth: int = 0) -> Any:
    try:
        while obj is not None and hasattr(obj, "get_object") and depth < 16:
            nxt = obj.get_object()
            if nxt is obj:
                break
            obj, depth = nxt, depth + 1
    except Exception:  # noqa: BLE001
        return None
    return obj


def _pdf_get(d: Any, key: str) -> Any:
    try:
        if d is None or not hasattr(d, "get"):
            return None
        return _pdf_resolve(d.get(key))
    except Exception:  # noqa: BLE001
        return None


def _pdf_stream_bytes(stream: Any, limit: int) -> bytes:
    filt = _pdf_get(stream, "/Filter")
    if isinstance(filt, list) and len(filt) == 1:
        filt = _pdf_resolve(filt[0])
    params = _pdf_get(stream, "/DecodeParms")
    raw = getattr(stream, "_data", None)
    if isinstance(raw, bytes):
        if filt is None:
            return raw[: limit + 1]
        if str(filt) == "/FlateDecode" and not params:
            try:
                return zlib.decompressobj().decompress(raw, limit + 1)
            except zlib.error:
                pass  # pypdf tiene recuperación para streams rotos
    return stream.get_data()  # pypdf aplica sus propios topes (75 MB) a la descompresión


def _expand_pdf(ex: ChildBuilder) -> None:
    try:
        from pypdf import PdfReader
        from pypdf.generic import IndirectObject, StreamObject
    except ImportError:  # pragma: no cover
        ex.note(f"{NOTE_UNSUPPORTED} (falta pypdf)")
        return
    reader = PdfReader(io.BytesIO(ex.parent.data), strict=False)
    if reader.is_encrypted:
        # contraseña de usuario vacía = solo restringe permisos (imprimir, copiar): NO es "con contraseña"
        opened_with: str | None = None
        for pwd in ["", *ex.passwords]:
            try:
                if reader.decrypt(pwd):
                    opened_with = pwd
                    break
            except Exception:  # noqa: BLE001 - algoritmo no soportado / pdf roto
                break
        if opened_with != "":
            ex.parent.password_protected = True
        if opened_with is None:
            ex.parent.encrypted = True
            ex.note(f"{NOTE_ENCRYPTED}: PDF cifrado, no se pudo abrir")
            return
        if opened_with:
            ex.note(f"{NOTE_ENCRYPTED}: se abrió con una contraseña candidata")

    root = _pdf_resolve(reader.trailer.get("/Root"))
    specs: list[tuple[str | None, Any]] = []
    # 1) árbol de nombres /Names /EmbeddedFiles (con detección de ciclos y topes)
    ef_root = _pdf_get(_pdf_get(root, "/Names"), "/EmbeddedFiles")
    stack: list[tuple[Any, int]] = [(ef_root, 0)] if ef_root is not None else []
    visited: set[int] = set()
    nodes = 0
    while stack and nodes < 10_000 and len(specs) < 10_000:
        node, depth = stack.pop()
        if node is None or depth > 32 or id(node) in visited:
            continue
        visited.add(id(node))
        nodes += 1
        names = _pdf_get(node, "/Names")
        if isinstance(names, list):
            for i in range(0, len(names) - 1, 2):
                key = _pdf_resolve(names[i])
                specs.append((str(key) if key is not None else None, names[i + 1]))
        kids = _pdf_get(node, "/Kids")
        if isinstance(kids, list):
            for kid in reversed(kids[:10_000]):
                stack.append((_pdf_resolve(kid), depth + 1))
    # 2) anotaciones /FileAttachment en las páginas
    try:
        for page_index, page in enumerate(reader.pages):
            if page_index >= 500 or not ex.check_time():
                break
            annots = _pdf_get(page, "/Annots")
            if not isinstance(annots, list):
                continue
            for annot in annots[:1000]:
                a = _pdf_resolve(annot)
                if str(_pdf_get(a, "/Subtype")) == "/FileAttachment":
                    specs.append((None, a.get("/FS") if hasattr(a, "get") else None))
    except Exception:  # noqa: BLE001 - árbol de páginas roto: seguimos con lo que haya
        log.debug("pdf: no se pudieron recorrer las páginas", exc_info=True)

    seen: set[Any] = set()
    for index, (hint, spec_ref) in enumerate(specs):
        if ex.stopped or not ex.check_time():
            break
        ref_key: Any = (
            (spec_ref.idnum, spec_ref.generation) if isinstance(spec_ref, IndirectObject) else id(spec_ref)
        )
        if ref_key in seen:
            continue
        seen.add(ref_key)
        spec = _pdf_resolve(spec_ref)
        ef = _pdf_get(spec, "/EF")
        stream = _pdf_get(ef, "/F") or _pdf_get(ef, "/UF")
        if not isinstance(stream, StreamObject):
            continue
        name_obj = _pdf_get(spec, "/UF") or _pdf_get(spec, "/F") or hint
        name = str(name_obj) if name_obj is not None else f"embebido{index}"
        raw = getattr(stream, "_data", b"") or b""
        declared = _pdf_get(_pdf_get(stream, "/Params"), "/Size")
        limit, reason = ex.entry_limit(
            len(raw) if isinstance(raw, bytes) else None, int(declared) if isinstance(declared, int) else None
        )
        if isinstance(declared, int) and declared > limit:
            ex.over_limit(reason, name, int(declared))
            continue
        try:
            content = _pdf_stream_bytes(stream, limit)
        except Exception as exc:  # noqa: BLE001
            ex.add_listing(
                name,
                int(declared) if isinstance(declared, int) else 0,
                note=f"stream ilegible ({type(exc).__name__})",
            )
            continue
        if len(content) > limit:
            ex.over_limit(reason, name, len(content))
            continue
        ex.add(name, content)


# --------------------------------------------------------------------------- OneNote

_ONE_FDSO_HEADER = bytes.fromhex("E716E3BD65261145A4C48D4D0B7A9EAC")  # {BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC}


def _expand_onenote(ex: ChildBuilder) -> None:
    """FileDataStoreObject ([MS-ONESTORE] 2.6.13): guidHeader(16) cbLength(8) unused(4) reserved(8) FileData."""
    data = ex.parent.data
    pos = 0
    index = 0
    while not ex.stopped and ex.check_time():
        pos = data.find(_ONE_FDSO_HEADER, pos)
        if pos < 0 or pos + 36 > len(data):
            break
        length = struct.unpack_from("<Q", data, pos + 16)[0]
        start = pos + 36
        if length > len(data) - start:
            ex.note("objeto embebido de OneNote truncado")
            pos += 16
            continue
        limit, reason = ex.entry_limit(None, length)
        name = f"embebido{index}"
        index += 1
        if length > limit:
            ex.over_limit(reason, name, length)
        else:
            ex.add(name, data[start : start + length])
        pos = start + length


# --------------------------------------------------------------------------- CAB (MSZIP / sin compresión)


def _expand_cab(ex: ChildBuilder) -> None:
    data = ex.parent.data
    if len(data) < 36:
        raise ValueError("cab truncado")
    coff_files = struct.unpack_from("<I", data, 16)[0]
    n_folders, n_files, flags = struct.unpack_from("<HHH", data, 26)
    pos = 36
    cb_folder_res = cb_data_res = 0
    if flags & 0x0004:
        cb_header_res, cb_folder_res, cb_data_res = struct.unpack_from("<HBB", data, 36)
        pos = 40 + cb_header_res
    for flag in (0x0001, 0x0002):  # cabinet anterior / siguiente: dos strings terminados en NUL c/u
        if flags & flag:
            for _ in range(2):
                end = data.find(b"\x00", pos, pos + 256)
                if end < 0:
                    raise ValueError("cab: cabecera inválida")
                pos = end + 1
    folders: list[tuple[int, int, int]] = []
    for _ in range(min(n_folders, 1000)):
        off, cdata, ctype = struct.unpack_from("<IHH", data, pos)
        folders.append((off, cdata, ctype))
        pos += 8 + cb_folder_res
    entries: list[tuple[str, int, int, int]] = []
    pos = coff_files
    for _ in range(min(n_files, _MAX_ENTRIES_SCANNED)):
        size, uoff, ifolder, _date, _time, attribs = struct.unpack_from("<IIHHHH", data, pos)
        end = data.find(b"\x00", pos + 16, pos + 16 + 1024)
        if end < 0:
            break
        raw_name = data[pos + 16 : end]
        name = raw_name.decode("utf-8" if attribs & 0x80 else "cp1252", "replace")
        entries.append((name, size, uoff, ifolder))
        pos = end + 1

    cache: dict[int, tuple[bytes | None, str]] = {}
    need_by_folder: dict[int, int] = {}
    for _name, size, uoff, ifolder in entries:
        if size <= ex.max_entry:
            need_by_folder[ifolder] = max(need_by_folder.get(ifolder, 0), uoff + size)
    cap = min(ex.budget.remaining_bytes + ex.max_entry, max(len(data) * ex.budget.max_ratio, _RATIO_FLOOR))
    if any(n > cap for n in need_by_folder.values()):
        ex.note(NOTE_ZIP_BOMB)

    def folder_bytes(i: int) -> tuple[bytes | None, str]:
        if i in cache:
            return cache[i]
        off, n_blocks, ctype = folders[i]
        method = ctype & 0x000F
        if method not in (0, 1):
            cache[i] = (None, "compresión LZX/Quantum no soportada")
            return cache[i]
        # el stream del folder se descomprime una vez, acotado a lo que piden sus archivos y al presupuesto
        needed = min(need_by_folder.get(i, 0), cap)
        out = bytearray()
        p = off
        prev = b""
        for _ in range(n_blocks):
            if p + 8 > len(data):
                break
            _csum, cb_data, _cb_uncomp = struct.unpack_from("<IHH", data, p)
            p += 8 + cb_data_res
            block = data[p : p + cb_data]
            p += cb_data
            if method == 0:
                chunk = block
            else:
                if block[:2] != b"CK":
                    raise ValueError("cab: bloque MSZIP inválido")
                d = zlib.decompressobj(-15, zdict=prev) if prev else zlib.decompressobj(-15)
                chunk = d.decompress(block[2:], 32768 + 1)
            out += chunk
            prev = bytes(out[-32768:])
            if len(out) >= needed:
                break
        cache[i] = (bytes(out), "")
        return cache[i]

    for name, size, uoff, ifolder in entries:
        if ex.stopped or not ex.check_time():
            break
        limit, reason = ex.entry_limit(None, size)
        if size > limit:
            ex.over_limit(reason, name, size)
            continue
        if ifolder >= len(folders):
            ex.add_listing(name, size, note="continúa en otro cabinet")
            continue
        content, why = folder_bytes(ifolder)
        if content is None:
            ex.add_listing(name, size, note=f"{NOTE_UNSUPPORTED} ({why})")
            continue
        piece = content[uoff : uoff + size]
        ex.add(name, piece, note=None if len(piece) == size else "datos truncados")
    if any((f[2] & 0x0F) not in (0, 1) for f in folders):
        ex.note(f"{NOTE_UNSUPPORTED} (cab con compresión LZX/Quantum)")


# --------------------------------------------------------------------------- OLE2 (paquetes, .msg, .msi)

_MSI_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._"
_MSI_PAYLOAD_TYPES = {"pe", "cab", "zip", "7z", "rar", "msi", "ole", "ooxml", "jar", "lnk", "html", "eml"}
_MAX_OLE_STREAMS = 10_000


def _msi_stream_name(name: str) -> str:
    """Decodifica nombres de stream de MSI (codificación base64-like de Windows Installer)."""
    out: list[str] = []
    for ch in name:
        c = ord(ch)
        if 0x3800 <= c < 0x4800:
            c -= 0x3800
            out.append(_MSI_ALPHABET[c & 0x3F])
            out.append(_MSI_ALPHABET[(c >> 6) & 0x3F])
        elif 0x4800 <= c < 0x4840:
            out.append(_MSI_ALPHABET[c - 0x4800])
        elif c == 0x4840:
            out.append("!")  # prefijo de tablas internas
        else:
            out.append(ch)
    return "".join(out)


def _ole10native(blob: bytes) -> tuple[str | None, bytes] | None:
    """Payload de un objeto "Package" ([MS-OLEDS] 2.3.6 OLENativeStream): (nombre, datos) o None."""

    def zstr(pos: int) -> tuple[str, int]:
        end = blob.find(b"\x00", pos, pos + 1024)
        if end < 0:
            raise ValueError("string sin terminar")
        return blob[pos:end].decode("cp1252", "replace"), end + 1

    try:
        pos = 4 + 2  # tamaño nativo + flags
        label, pos = zstr(pos)
        src_path, pos = zstr(pos)
        pos += 8
        _temp_path, pos = zstr(pos)
        size = struct.unpack_from("<I", blob, pos)[0]
        pos += 4
    except (ValueError, struct.error):
        return None
    payload = blob[pos : pos + size]
    name = src_path.replace("\\", "/").rsplit("/", 1)[-1] or label or None
    return name, payload


def _ole_read(ole: Any, path: list[str], limit: int) -> bytes | None:
    if ole.get_size(path) > limit:
        return None
    with ole.openstream(path) as fh:
        data = fh.read(limit + 1)
    return data if len(data) <= limit else None


def _ole_stream(ex: ChildBuilder, ole: Any, path: list[str], is_msi: bool) -> None:
    leaf = path[-1]
    size = int(ole.get_size(path))
    if leaf == "\x01Ole10Native":
        limit, reason = ex.entry_limit(None, size)
        if size > limit + 4096:
            ex.over_limit(reason, "paquete_ole", size)
            return
        blob = _ole_read(ole, path, limit + 4096)
        parsed = _ole10native(blob) if blob else None
        if parsed is None:
            return
        name, payload = parsed
        if len(payload) > limit:
            ex.over_limit(reason, name, len(payload))
            return
        ex.add(name or "paquete_ole", payload, note="objeto OLE Package embebido")
    elif is_msi and len(path) == 1:
        limit, _reason = ex.entry_limit(None, size)
        if size > limit:
            return  # en un MSI solo interesan los payloads; streams enormes se ignoran
        blob = _ole_read(ole, path, limit)
        if not blob:
            return
        name = _msi_stream_name(leaf)
        kind = detect_type(blob, name)
        if kind in _MSI_PAYLOAD_TYPES or kind.startswith("script/"):
            ex.add(name, blob, note="stream embebido en el instalador MSI")


def _expand_ole(ex: ChildBuilder) -> None:
    """OLE2/CFB: payloads de objetos Package (Ole10Native), adjuntos de un .msg de Outlook y streams con
    contenido ejecutable/contenedores dentro de un .msi (CABs embebidos, DLL/EXE de custom actions)."""
    try:
        import olefile
    except ImportError:  # pragma: no cover - olefile viene con oletools
        return
    is_msi = ex.parent.detected_type == "msi"
    ole = olefile.OleFileIO(io.BytesIO(ex.parent.data))
    try:
        entries = ole.listdir(streams=True, storages=False)[:_MAX_OLE_STREAMS]
        names = {"/".join(e) for e in entries}
        is_msg = any(n.startswith("__substg1.0_") or n.startswith("__attach_version1.0_") for n in names)

        for path in entries:
            if ex.stopped or not ex.check_time():
                return
            try:
                _ole_stream(ex, ole, path, is_msi)
            except ExtractionStopped:
                raise
            except Exception as exc:  # noqa: BLE001 - un stream roto no invalida el resto
                ex.note(f"stream OLE ilegible ({type(exc).__name__})")

        if is_msg:
            _expand_msg(ex, ole, names)
    finally:
        with contextlib.suppress(Exception):
            ole.close()


def _msg_string(ole: Any, names: set[str], prefix: str, prop: str) -> str | None:
    for suffix, enc in (("001F", "utf-16-le"), ("001E", "cp1252")):
        path = f"{prefix}__substg1.0_{prop}{suffix}"
        if path in names:
            data = _ole_read(ole, path.split("/"), 64 * 1024)
            if data:
                return data.decode(enc, "replace").rstrip("\x00") or None
    return None


def _expand_msg(ex: ChildBuilder, ole: Any, names: set[str]) -> None:
    """Adjuntos de un .msg de Outlook ([MS-OXMSG]): storages __attach_version1.0_#XXXXXXXX."""
    attach_dirs = sorted({n.split("/", 1)[0] for n in names if n.startswith("__attach_version1.0_")})
    for adir in attach_dirs[:1000]:
        if ex.stopped or not ex.check_time():
            return
        prefix = adir + "/"
        name = (
            _msg_string(ole, names, prefix, "3707")
            or _msg_string(ole, names, prefix, "3704")
            or _msg_string(ole, names, prefix, "3001")
        )
        data_path = f"{prefix}__substg1.0_37010102"
        if data_path in names:
            size = ole.get_size(data_path.split("/"))
            limit, reason = ex.entry_limit(None, size)
            if size > limit:
                ex.over_limit(reason, name, size)
                continue
            blob = _ole_read(ole, data_path.split("/"), limit)
            if blob is not None:
                ex.add(name, blob, note="adjunto de un mensaje de Outlook (.msg)")
        elif any(n.startswith(f"{prefix}__substg1.0_3701000D/") for n in names):
            ex.add_listing(name or "mensaje_embebido.msg", 0, note="mensaje de Outlook embebido")
    body = _msg_string(ole, names, "", "1000")
    if body and not ex.stopped:
        # NOTE_MSG_BODY marca este hijo: mime.py busca ahí contraseñas candidatas (como en un .eml adjunto)
        ex.add("cuerpo_mensaje.txt", body.encode("utf-8"), note=NOTE_MSG_BODY)


# --------------------------------------------------------------------------- TNEF (winmail.dat)

_TNEF_ATTACH_RENDDATA = 0x00069002
_TNEF_ATTACH_TITLE = 0x00018010
_TNEF_ATTACH_DATA = 0x0006800F
_TNEF_ATTACHMENT = 0x00069005
_TNEF_OEMCODEPAGE = 0x00069007
_MAPI_FIXED = {
    0x0002: 2,
    0x000B: 2,
    0x0003: 4,
    0x0004: 4,
    0x000A: 4,
    0x0005: 8,
    0x0006: 8,
    0x0007: 8,
    0x0014: 8,
    0x0040: 8,
    0x0048: 16,
    0x0001: 0,
}
_MAPI_VAR = {0x001E, 0x001F, 0x0102, 0x000D}
_PR_ATTACH_DATA = 0x3701
_PR_ATTACH_LONG_FILENAME = 0x3707
_PR_ATTACH_FILENAME = 0x3704
_PR_DISPLAY_NAME = 0x3001


def _pad4(n: int) -> int:
    return (n + 3) & ~3


def _mapi_props(buf: bytes) -> dict[int, tuple[int, list[bytes]]]:
    """Parseo mínimo de una lista de propiedades MAPI encapsulada en TNEF ([MS-OXTNEF] 2.1.3.4)."""
    props: dict[int, tuple[int, list[bytes]]] = {}
    pos = 4
    count = struct.unpack_from("<I", buf, 0)[0] if len(buf) >= 4 else 0
    for _ in range(min(count, 5000)):
        if pos + 4 > len(buf):
            break
        ptype, pid = struct.unpack_from("<HH", buf, pos)
        pos += 4
        if pid >= 0x8000:  # propiedad con nombre: GUID + (id | nombre UTF-16)
            pos += 16
            kind = struct.unpack_from("<I", buf, pos)[0]
            pos += 4
            if kind == 0:
                pos += 4
            else:
                nlen = struct.unpack_from("<I", buf, pos)[0]
                pos += 4 + _pad4(nlen)
        multi = bool(ptype & 0x1000)
        base = ptype & 0x0FFF
        nvals = 1
        if multi or base in _MAPI_VAR:
            nvals = struct.unpack_from("<I", buf, pos)[0]
            pos += 4
        values: list[bytes] = []
        for _ in range(min(nvals, 10_000)):
            if base in _MAPI_VAR:
                vlen = struct.unpack_from("<I", buf, pos)[0]
                pos += 4
                values.append(buf[pos : pos + vlen])
                pos += _pad4(vlen)
            elif base in _MAPI_FIXED:
                size = _MAPI_FIXED[base]
                values.append(buf[pos : pos + size])
                pos += size
            else:
                return props  # tipo desconocido: no se puede seguir alineado
        if base in (0x0002, 0x000B) and nvals % 2:
            pos += 2
        props[pid] = (base, values)
    return props


def _mapi_str(entry: tuple[int, list[bytes]] | None, codepage: str) -> str | None:
    if not entry or not entry[1]:
        return None
    base, values = entry
    raw = values[0]
    if base == 0x001F:
        return raw.decode("utf-16-le", "replace").rstrip("\x00") or None
    if base == 0x001E:
        return raw.decode(codepage, "replace").rstrip("\x00") or None
    return None


def _expand_tnef(ex: ChildBuilder) -> None:
    data = ex.parent.data
    if len(data) < 6 or not is_tnef(data):
        return
    pos = 6
    codepage = "cp1252"
    attachments: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    count = 0
    while pos + 9 <= len(data) and count < 100_000:
        level = data[pos]
        attr_id, length = struct.unpack_from("<II", data, pos + 1)
        start = pos + 9
        end = start + length
        if end > len(data):
            ex.note("TNEF truncado")
            break
        value = data[start:end]
        pos = end + 2  # checksum
        count += 1
        if level == 1 and attr_id == _TNEF_OEMCODEPAGE and length >= 4:
            cp = struct.unpack_from("<I", value, 0)[0]
            codepage = f"cp{cp}"
            try:
                "".encode(codepage)
            except LookupError:
                codepage = "cp1252"
        if level != 2:
            continue
        if attr_id == _TNEF_ATTACH_RENDDATA:
            current = {}
            attachments.append(current)
        elif current is None:
            continue
        elif attr_id == _TNEF_ATTACH_TITLE:
            current["title"] = value.split(b"\x00", 1)[0].decode(codepage, "replace")
        elif attr_id == _TNEF_ATTACH_DATA:
            current["data"] = value
        elif attr_id == _TNEF_ATTACHMENT:
            try:
                props = _mapi_props(value)
            except (struct.error, IndexError):
                props = {}
            long_name = _mapi_str(props.get(_PR_ATTACH_LONG_FILENAME), codepage) or _mapi_str(
                props.get(_PR_ATTACH_FILENAME), codepage
            )
            if long_name:
                current["long_name"] = long_name
            if "data" not in current and _PR_ATTACH_DATA in props:
                base, values = props[_PR_ATTACH_DATA]
                if values:
                    blob = values[0]
                    if base == 0x000D:  # objeto: IID (16 bytes) + datos (ej: mensaje embebido en TNEF)
                        blob = blob[16:]
                        current.setdefault("long_name", "mensaje_embebido.tnef")
                    current["data"] = blob
    for i, att in enumerate(attachments):
        if ex.stopped:
            break
        name = att.get("long_name") or att.get("title") or f"adjunto{i}"
        blob = att.get("data")
        if blob is None:
            continue
        limit, reason = ex.entry_limit(None, len(blob))
        if len(blob) > limit:
            ex.over_limit(reason, name, len(blob))
            continue
        ex.add(name, blob)


# --------------------------------------------------------------------------- registro

_HANDLERS: dict[str, Callable[[ChildBuilder], None]] = {
    "zip": _expand_zip,
    "ooxml": _expand_ooxml,
    "7z": _expand_7z,
    "rar": _expand_rar,
    "gzip": _expand_stream,
    "bzip2": _expand_stream,
    "xz": _expand_stream,
    "tar": _expand_tar,
    "iso": _expand_iso,
    "udf": _expand_iso,
    "pdf": _expand_pdf,
    "onenote": _expand_onenote,
    "cab": _expand_cab,
    "vhd": _unsupported,
    "vhdx": _unsupported,
    "img": _unsupported,
    "ole": _expand_ole,
    "msi": _expand_ole,
}

EXPANDABLE_TYPES: frozenset[str] = frozenset(_HANDLERS)
