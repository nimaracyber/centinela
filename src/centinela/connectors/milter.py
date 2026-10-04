"""Conector milter: Postfix / Sendmail le pasan cada mail a Centinela mientras lo reciben.

Implementa el protocolo milter de Sendmail (versión 6, la que usa Postfix >= 2.6) en asyncio puro,
sin libmilter. Es **pasivo**: SIEMPRE termina aceptando el mail (``SMFIR_ACCEPT``); nunca rechaza,
demora (tempfail) ni descarta. Lo único que puede hacer es:

- agregar headers ``X-Centinela-Verdict`` / ``X-Centinela-Score`` / ``X-Centinela-Families`` /
  ``X-Centinela-Id`` (si ``add_headers``) cuando el análisis termina dentro de ``inline_timeout_s``;
- anteponer ``subject_prefix`` al asunto de los mails sospechosos/maliciosos (si está configurado);
- borrar headers ``X-Centinela-*`` que ya vengan en el mail (un atacante podría falsificarlos para
  que el destinatario crea que el mail fue revisado y está "limpio").

Si el análisis tarda más que ``inline_timeout_s`` el mail se acepta sin headers de veredicto y el
análisis sigue en segundo plano: las alertas llegan igual, un rato después. Con ``tag: false`` el
conector no modifica nada del mail (solo alertas).

Formato de cada paquete (ambos sentidos): longitud uint32 big-endian (incluye el byte de comando)
+ 1 byte de comando + datos. Negociamos solo las acciones SMFIF_ADDHDRS | SMFIF_CHGHDRS y pedimos
al MTA que no mande los eventos que no usamos (connect, helo, mail, data, eoh, comandos desconocidos)
ni espere respuesta a cada header / chunk de cuerpo / rcpt (flags SMFIP_NR_*), siempre que el MTA
los ofrezca. Si el MTA no los ofrece, respondemos SMFIR_CONTINUE a cada comando como corresponde.

Configuración de Postfix (main.cf)::

    # Centinela escucha en el puerto 8899 (listen_port). "centinela" = nombre del contenedor/host.
    smtpd_milters = inet:centinela:8899
    non_smtpd_milters = $smtpd_milters
    # MUY IMPORTANTE: si Centinela no responde, el mail pasa igual (el default de Postfix es tempfail)
    milter_default_action = accept
    milter_protocol = 6
    milter_connect_timeout = 10s
    milter_command_timeout = 30s
    # Debe ser mayor que inline_timeout_s (default 15s) para que Postfix espere los headers:
    milter_content_timeout = 60s
    # El queue id (macro "i") llega al final del mensaje; {rcpt_addr} con cada destinatario:
    milter_end_of_data_macros = i
    milter_rcpt_macros = i {rcpt_addr}

Para no analizar el correo SALIENTE de los usuarios (submission), se puede desactivar el milter
en ese servicio de master.cf: ``submission inet n - n - - smtpd -o smtpd_milters=``.

Sendmail (sendmail.mc)::

    INPUT_MAIL_FILTER(`centinela', `S=inet:8899@centinela, F=, T=C:10s;S:30s;R:30s;E:60s')dnl

(``F=`` vacío = si el filtro no está disponible, el mail sigue su curso normalmente.)

Nota: Postfix le oculta al milter su propio header ``Received:`` (compatibilidad con Sendmail),
así que el mensaje reconstruido para el análisis no lo incluye.

Referencia del mensaje: ``mailbox`` = primer destinatario (RCPT TO); ``remote_id`` =
``<queue id>#<sha256 corto del mensaje>`` (uuid4 si el MTA no manda la macro ``i``). El hash va
porque los queue id cortos de Postfix se repiten con el tiempo y el storage deduplica por ref.
Si el mensaje supera ``limits.max_message_bytes`` se analiza truncado (los headers y el comienzo del
cuerpo que entra en el límite), se agrega ``X-Centinela-Truncated: yes`` y el ``RawMessage`` va con
``truncated=True`` + ``original_size`` (el pipeline agrega el hallazgo ``policy.message_too_large``).
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import struct
import uuid
from email.header import Header, decode_header, make_header
from typing import TYPE_CHECKING, Any, ClassVar

from centinela.connectors.base import Connector
from centinela.core.models import AnalysisResult, MessageRef, RawMessage, VerdictLevel
from centinela.metrics import CONNECTOR_UP

if TYPE_CHECKING:
    from centinela.connectors.base import EmitFn
    from centinela.core.config import MilterConnectorConfig, Settings
    from centinela.core.state import StateStore

log = logging.getLogger(__name__)

# --------------------------------------------------------------------------- constantes (mfdef.h)

SMFI_PROT_VERSION = 6
SMFI_PROT_VERSION_MIN = 2

# Comandos MTA -> milter
SMFIC_ABORT = b"A"
SMFIC_BODY = b"B"
SMFIC_CONNECT = b"C"
SMFIC_MACRO = b"D"
SMFIC_BODYEOB = b"E"
SMFIC_HELO = b"H"
SMFIC_QUIT_NC = b"K"
SMFIC_HEADER = b"L"
SMFIC_MAIL = b"M"
SMFIC_EOH = b"N"
SMFIC_OPTNEG = b"O"
SMFIC_QUIT = b"Q"
SMFIC_RCPT = b"R"
SMFIC_DATA = b"T"
SMFIC_UNKNOWN = b"U"

# Respuestas milter -> MTA (solo las que usamos: nunca reject/tempfail/discard)
SMFIR_ACCEPT = b"a"
SMFIR_CONTINUE = b"c"
SMFIR_ADDHEADER = b"h"
SMFIR_CHGHEADER = b"m"

# Acciones (mfapi.h)
SMFIF_ADDHDRS = 0x01
SMFIF_CHGBODY = 0x02
SMFIF_ADDRCPT = 0x04
SMFIF_DELRCPT = 0x08
SMFIF_CHGHDRS = 0x10
SMFIF_QUARANTINE = 0x20

# Flags de protocolo
SMFIP_NOCONNECT = 0x01
SMFIP_NOHELO = 0x02
SMFIP_NOMAIL = 0x04
SMFIP_NORCPT = 0x08
SMFIP_NOBODY = 0x10
SMFIP_NOHDRS = 0x20
SMFIP_NOEOH = 0x40
SMFIP_NR_HDR = 0x80
SMFIP_NOUNKNOWN = 0x100
SMFIP_NODATA = 0x200
SMFIP_SKIP = 0x400
SMFIP_RCPT_REJ = 0x800
SMFIP_NR_CONN = 0x1000
SMFIP_NR_HELO = 0x2000
SMFIP_NR_MAIL = 0x4000
SMFIP_NR_RCPT = 0x8000
SMFIP_NR_DATA = 0x10000
SMFIP_NR_UNKN = 0x20000
SMFIP_NR_EOH = 0x40000
SMFIP_NR_BODY = 0x80000
SMFIP_HDR_LEADSPC = 0x100000

#: Lo único que le pedimos al MTA poder hacer: agregar y cambiar/borrar headers.
WANTED_ACTIONS = SMFIF_ADDHDRS | SMFIF_CHGHDRS
#: Eventos que no necesitamos + "no esperes respuesta" en todo lo que no sea fin de mensaje.
WANTED_PROTOCOL = (
    SMFIP_NOCONNECT
    | SMFIP_NOHELO
    | SMFIP_NOMAIL
    | SMFIP_NODATA
    | SMFIP_NOEOH
    | SMFIP_NOUNKNOWN
    | SMFIP_NR_HDR
    | SMFIP_NR_CONN
    | SMFIP_NR_HELO
    | SMFIP_NR_MAIL
    | SMFIP_NR_RCPT
    | SMFIP_NR_DATA
    | SMFIP_NR_UNKN
    | SMFIP_NR_EOH
    | SMFIP_NR_BODY
)

_LEN = struct.Struct("!I")
_OPTNEG = struct.Struct("!III")

#: Etapas de macros que pertenecen a un mensaje (se descartan al terminar/abortar el mensaje).
_MESSAGE_STAGES = frozenset("MRTLNBE")
#: Orden de búsqueda de macros: la etapa más reciente primero.
_MACRO_LOOKUP_ORDER = "ENLBTRMHC"

_HEADER_PREFIX = b"x-centinela-"
_UNKNOWN_MAILBOX = "desconocido"
_SUBJECT_DECODE_LIMIT = 4096


class _ProtocolError(Exception):
    """El MTA (o alguien que se hace pasar por él) mandó algo que no respeta el protocolo."""


# --------------------------------------------------------------------------- helpers puros


def _split_nul(data: bytes) -> list[bytes]:
    """Separa campos terminados en NUL (el último NUL es opcional)."""
    if data.endswith(b"\0"):
        data = data[:-1]
    return data.split(b"\0") if data else []


def _clean_header_name(name: bytes) -> bytes:
    """Nombre de header válido según RFC 5322 (ASCII imprimible sin ':'), o b"" si no queda nada."""
    return bytes(c for c in name if 33 <= c <= 126 and c != 58)


def _fold_crlf(value: bytes) -> bytes:
    """Valor de header del MTA (líneas separadas por LF) -> líneas RFC 5322 separadas por CRLF.

    Cada línea de continuación tiene que empezar con espacio/tab; si no (valor malformado) se le
    agrega uno para que el mensaje reconstruido tenga exactamente los mismos headers que vio el MTA.
    """
    v = value.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    lines = v.split(b"\n")
    out = [lines[0]]
    out.extend(line if line[:1] in (b" ", b"\t") else b" " + line for line in lines[1:])
    return b"\r\n".join(out)


def _fold_lf(value: bytes) -> bytes:
    """Valor para devolverle al MTA: continuaciones separadas solo por LF (convención libmilter)."""
    v = value.replace(b"\r\n", b"\n").replace(b"\r", b"\n").replace(b"\0", b"")
    lines = v.split(b"\n")
    out = [lines[0]]
    out.extend(line if line[:1] in (b" ", b"\t") else b" " + line for line in lines[1:])
    return b"\n".join(out)


def _ascii_header_value(text: str, max_len: int = 200) -> bytes:
    """Valor de header seguro: ASCII imprimible, una sola línea, largo acotado."""
    clean = "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in text)
    return clean[:max_len].strip().encode("ascii")


def _decode_subject(value: bytes) -> str:
    # Solo se usa para ver si el asunto YA empieza con el prefijo: alcanza con el comienzo, y así
    # un asunto hostil enorme no frena el event loop (decode_header no es lineal en el peor caso).
    text = value[:_SUBJECT_DECODE_LIMIT].decode("utf-8", "replace").replace("\r", "").replace("\n", "")
    try:
        return str(make_header(decode_header(text)))
    except Exception:  # noqa: BLE001 - encoded-words rotos: comparamos el texto crudo
        return text


def _encode_prefix(prefix: str) -> bytes:
    """Prefijo de asunto como bytes de header: tal cual si es ASCII, si no como encoded-word RFC 2047."""
    try:
        return prefix.encode("ascii")
    except UnicodeEncodeError:
        return Header(prefix, "utf-8").encode(linesep="\n").encode("ascii")


def prefixed_subject(prefix: str, original: bytes) -> bytes | None:
    """Asunto nuevo = prefijo + asunto original. None si el asunto ya empieza con el prefijo.

    `original` es el valor tal como lo mandó el MTA (puede tener encoded-words y continuaciones LF).
    """
    prefix = prefix.replace("\r", "").replace("\n", "").replace("\0", "")
    marker = prefix.strip()
    if not marker:
        return None
    if _decode_subject(original).lstrip().startswith(marker):
        return None
    orig = _fold_lf(original)
    try:
        return prefix.encode("ascii") + orig
    except UnicodeEncodeError:
        pass
    # Prefijo no ASCII: va como encoded-word, que tiene que estar separado por espacio del resto.
    # El espacio entre dos encoded-words adyacentes no se muestra, así que si el asunto original
    # empieza con un encoded-word el espacio del prefijo tiene que viajar DENTRO del encoded-word.
    starts_with_ew = orig.lstrip().startswith(b"=?")
    text = prefix if starts_with_ew else prefix.rstrip()
    encoded = Header(text, "utf-8").encode(linesep="\n").encode("ascii")
    return encoded + b" " + orig.lstrip()


async def _remote_id(queue_id: str | None, raw: bytes) -> str:
    """`<queue id>#<sha256[:12]>`, o un uuid4 si el MTA no mandó la macro "i".

    El hash corto evita colisiones: los queue id cortos de Postfix (inodo + microsegundos, el default
    sin ``enable_long_queue_ids``) se repiten con el tiempo, y el storage deduplica por ref: un id
    repetido haría que un mail nuevo se descarte como "ya analizado".
    """
    qid = "".join(ch for ch in (queue_id or "") if ch.isprintable() and not ch.isspace())[:128]
    if not qid:
        return uuid.uuid4().hex
    if len(raw) > 1024 * 1024:
        digest = (await asyncio.to_thread(hashlib.sha256, raw)).hexdigest()
    else:
        digest = hashlib.sha256(raw).hexdigest()
    return f"{qid}#{digest[:12]}"


def _normalize_addr(raw: bytes | str) -> str:
    s = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
    s = s.strip().strip("<>").strip()
    return s[:320].lower()


# --------------------------------------------------------------------------- sesión (una conexión)


class _MilterSession:
    """Estado de UNA conexión del MTA. Una conexión puede transportar varios mensajes."""

    def __init__(
        self,
        connector: MilterConnector,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self.c = connector
        self.reader = reader
        self.writer = writer
        self.peer = writer.get_extra_info("peername")
        self.task: asyncio.Task[Any] | None = None
        # resultado de la negociación (antes de negociar: responder todo, no modificar nada)
        self.version = 0
        self.actions = 0
        self.pflags = 0
        self.negotiated = False
        self.macros: dict[str, dict[str, str]] = {}
        self._macro_count = 0
        self._reset_message(drop_macros=True)

    # ------------------------------------------------------------------ estado por mensaje

    def _reset_message(self, *, drop_macros: bool) -> None:
        self.rcpts: list[str] = []
        self.headers: list[tuple[bytes, bytes]] = []  # (nombre, valor tal cual vino del MTA)
        self.header_block = bytearray()
        self.forged: dict[bytes, list[Any]] = {}  # nombre en minúsculas -> [nombre original, cantidad]
        self.body = bytearray()
        self.size = 0  # bytes guardados (acotado por max_message_bytes)
        self.total_size = 0  # bytes que mandó el MTA (headers + cuerpo), aunque se hayan descartado
        self.truncated = False  # se descartó algo (por tamaño o por cantidad de headers)
        if drop_macros:
            for stage in _MESSAGE_STAGES:
                removed = self.macros.pop(stage, None)
                if removed:
                    self._macro_count -= len(removed)

    def _reset_connection(self) -> None:
        self.macros.clear()
        self._macro_count = 0
        self._reset_message(drop_macros=True)

    def macro(self, name: str) -> str | None:
        for stage in _MACRO_LOOKUP_ORDER:
            value = self.macros.get(stage, {}).get(name)
            if value:
                return value
        return None

    # ------------------------------------------------------------------ I/O

    async def _read_packet(self) -> tuple[bytes, bytes]:
        head = await asyncio.wait_for(self.reader.readexactly(_LEN.size), self.c.idle_timeout_s)
        (length,) = _LEN.unpack(head)
        if length < 1 or length > self.c.max_packet_bytes:
            raise _ProtocolError(f"tamaño de paquete inválido: {length} bytes")
        payload = await asyncio.wait_for(self.reader.readexactly(length), self.c.read_timeout_s)
        return payload[:1], payload[1:]

    def _write(self, cmd: bytes, data: bytes = b"") -> None:
        self.writer.write(_LEN.pack(len(data) + 1) + cmd + data)

    async def _drain(self) -> None:
        await asyncio.wait_for(self.writer.drain(), self.c.write_timeout_s)

    async def _ack(self, no_reply_flag: int) -> None:
        """Responde SMFIR_CONTINUE salvo que hayamos negociado no responder a este comando."""
        if not self.pflags & no_reply_flag:
            self._write(SMFIR_CONTINUE)
            await self._drain()

    # ------------------------------------------------------------------ loop

    async def serve(self) -> None:
        while True:
            cmd, data = await self._read_packet()
            if not await self._dispatch(cmd, data):
                return

    async def _dispatch(self, cmd: bytes, data: bytes) -> bool:
        if cmd == SMFIC_OPTNEG:
            await self._optneg(data)
        elif cmd == SMFIC_MACRO:
            self._safe(self._on_macro, data)
        elif cmd == SMFIC_RCPT:
            self._safe(self._on_rcpt, data)
            await self._ack(SMFIP_NR_RCPT)
        elif cmd == SMFIC_HEADER:
            self._safe(self._on_header, data)
            await self._ack(SMFIP_NR_HDR)
        elif cmd == SMFIC_BODY:
            self._add_body(data)
            await self._ack(SMFIP_NR_BODY)
        elif cmd == SMFIC_BODYEOB:
            await self._on_eob(data)
        elif cmd == SMFIC_MAIL:
            # comienzo de un mensaje nuevo (solo llega si el MTA no aceptó SMFIP_NOMAIL)
            self._reset_message(drop_macros=False)
            await self._ack(SMFIP_NR_MAIL)
        elif cmd == SMFIC_CONNECT:
            await self._ack(SMFIP_NR_CONN)
        elif cmd == SMFIC_HELO:
            await self._ack(SMFIP_NR_HELO)
        elif cmd == SMFIC_DATA:
            await self._ack(SMFIP_NR_DATA)
        elif cmd == SMFIC_EOH:
            await self._ack(SMFIP_NR_EOH)
        elif cmd == SMFIC_UNKNOWN:
            await self._ack(SMFIP_NR_UNKN)
        elif cmd == SMFIC_ABORT:
            self._reset_message(drop_macros=True)
        elif cmd == SMFIC_QUIT_NC:
            # el MTA reutiliza esta conexión para otra sesión SMTP
            self._reset_connection()
        elif cmd == SMFIC_QUIT:
            return False
        else:
            raise _ProtocolError(f"comando desconocido {cmd!r}")
        return True

    def _safe(self, fn: Any, data: bytes) -> None:
        """Errores al interpretar un comando no deben desincronizar el protocolo."""
        try:
            fn(data)
        except Exception:  # noqa: BLE001
            log.warning(
                "milter: no se pudo interpretar un comando de %s; se ignora", self.peer, exc_info=True
            )

    # ------------------------------------------------------------------ comandos

    async def _optneg(self, data: bytes) -> None:
        if len(data) < _OPTNEG.size:
            raise _ProtocolError("SMFIC_OPTNEG demasiado corto")
        mta_version, mta_actions, mta_pflags = _OPTNEG.unpack_from(data)
        if mta_version < SMFI_PROT_VERSION_MIN:
            raise _ProtocolError(f"versión de protocolo milter no soportada: {mta_version}")
        self.version = min(mta_version, SMFI_PROT_VERSION)
        # Siempre un subconjunto de lo que ofrece el MTA (si no, libmilter/Postfix cortan la conexión).
        self.actions = WANTED_ACTIONS & mta_actions
        self.pflags = WANTED_PROTOCOL & mta_pflags
        self.negotiated = True
        self._reset_connection()
        self._write(SMFIC_OPTNEG, _OPTNEG.pack(self.version, self.actions, self.pflags))
        await self._drain()
        log.debug(
            "milter: negociado con %s v%d acciones=0x%x protocolo=0x%x",
            self.peer,
            self.version,
            self.actions,
            self.pflags,
        )

    def _on_macro(self, data: bytes) -> None:
        if not data:
            return
        stage = chr(data[0])
        fields = _split_nul(data[1:])
        old = self.macros.pop(stage, None)
        if old:
            self._macro_count -= len(old)
        values: dict[str, str] = {}
        for i in range(0, len(fields) - 1, 2):
            if self._macro_count + len(values) >= self.c.max_macros:
                break
            name = fields[i].decode("ascii", "replace").strip().strip("{}")[:64]
            if not name:
                continue
            values[name] = fields[i + 1][: self.c.max_macro_value].decode("utf-8", "replace")
        if values:
            self.macros[stage] = values
            self._macro_count += len(values)

    def _on_rcpt(self, data: bytes) -> None:
        if len(self.rcpts) >= self.c.max_recipients:
            return
        args = _split_nul(data)
        addr = _normalize_addr(args[0]) if args else ""
        if not addr:
            addr = _normalize_addr(self.macros.get("R", {}).get("rcpt_addr", ""))
        if addr:
            self.rcpts.append(addr)

    def _on_header(self, data: bytes) -> None:
        parts = data.split(b"\0", 2)
        name = _clean_header_name(parts[0])
        value = parts[1] if len(parts) > 1 else b""
        if not name:
            return
        low = name.lower()
        if low.startswith(_HEADER_PREFIX):
            # se cuentan SIEMPRE (aunque el mensaje se trunque) para borrarlos con el índice correcto
            entry = self.forged.setdefault(low, [name, 0])
            entry[1] += 1
        line = name + b": " + _fold_crlf(value) + b"\r\n"
        self.total_size += len(line)
        if (
            self.truncated  # una vez descartado un header no se agregan más (no dejar huecos)
            or len(self.headers) >= self.c.max_headers
            or self.size + len(line) + 2 > self.c.max_message_bytes
        ):
            self.truncated = True
            return
        self.headers.append((name, value))
        self.header_block += line
        self.size += len(line)

    def _add_body(self, chunk: bytes) -> None:
        if not chunk:
            return
        self.total_size += len(chunk)
        room = self.c.max_message_bytes - self.size - 2  # 2 = línea en blanco entre headers y cuerpo
        if room <= 0:
            self.truncated = True
            return
        if len(chunk) > room:
            chunk = chunk[:room]
            self.truncated = True
        self.body += chunk
        self.size += len(chunk)

    def _build_raw(self) -> bytes | None:
        if not self.headers and not self.body:
            return None
        return bytes(self.header_block) + b"\r\n" + bytes(self.body)

    @property
    def original_size(self) -> int:
        return self.total_size + 2  # + línea en blanco entre headers y cuerpo

    async def _on_eob(self, data: bytes) -> None:
        replied = False
        try:
            self._add_body(data)
            raw_bytes = self._build_raw()
            result: AnalysisResult | None = None
            if raw_bytes is not None:
                ref = MessageRef(
                    connector=self.c.name,
                    mailbox=self.rcpts[0] if self.rcpts else _UNKNOWN_MAILBOX,
                    remote_id=await _remote_id(self.macro("i"), raw_bytes),
                )
                # solo "demasiado grande" si superó el límite de bytes (no por el tope de cantidad de headers)
                too_large = self.original_size > self.c.max_message_bytes
                if self.truncated:
                    log.warning(
                        "milter: mensaje %s (%d bytes) supera los límites (%d bytes, %d headers); "
                        "se analiza truncado",
                        ref.remote_id,
                        self.original_size,
                        self.c.max_message_bytes,
                        self.c.max_headers,
                    )
                if too_large:
                    self.c.truncated_too_large += 1
                raw = RawMessage(
                    ref=ref,
                    raw=raw_bytes,
                    truncated=too_large,
                    original_size=self.original_size if too_large else None,
                )
                result = await self.c._analyze_inline(raw)
                log.info(
                    "milter: mensaje %s (%d bytes, %d destinatarios) -> %s",
                    ref.remote_id,
                    len(raw_bytes),
                    len(self.rcpts),
                    result.verdict.level.value if result else "sin veredicto a tiempo",
                )
            for cmd, payload in self._modifications(result):
                self._write(cmd, payload)
            self._write(SMFIR_ACCEPT)
            replied = True
            await self._drain()
        except (ConnectionError, TimeoutError):
            raise
        except Exception:
            log.exception("milter: error al cerrar el mensaje; se acepta sin cambios")
            if not replied:
                self._write(SMFIR_ACCEPT)
                await self._drain()
        finally:
            self._reset_message(drop_macros=True)

    # ------------------------------------------------------------------ modificaciones

    def _modifications(self, result: AnalysisResult | None) -> list[tuple[bytes, bytes]]:
        cfg = self.c.config
        mods: list[tuple[bytes, bytes]] = []
        if not cfg.tag:
            return mods
        can_change = bool(self.actions & SMFIF_CHGHDRS)
        can_add = bool(self.actions & SMFIF_ADDHDRS)

        # 1) Borrar X-Centinela-* que trajo el mail. Índice 1-based por nombre; del último al primero
        #    para que borrar uno no corra el índice de los que faltan.
        if can_change:
            for name, count in self.forged.values():
                for index in range(count, 0, -1):
                    mods.append((SMFIR_CHGHEADER, _LEN.pack(index) + name + b"\0" + b"\0"))
            if self.forged:
                log.warning(
                    "milter: el mensaje traía %d header(s) X-Centinela-* falsificados; se eliminan",
                    sum(c for _, c in self.forged.values()),
                )

        if result is None:
            return mods
        verdict = result.verdict

        # 2) Headers de veredicto
        if cfg.add_headers and can_add:
            mods.append((SMFIR_ADDHEADER, b"X-Centinela-Verdict\0" + verdict.level.value.encode() + b"\0"))
            mods.append((SMFIR_ADDHEADER, b"X-Centinela-Score\0" + str(int(verdict.score)).encode() + b"\0"))
            if verdict.malware_families:
                families = _ascii_header_value(", ".join(verdict.malware_families))
                if families:
                    mods.append((SMFIR_ADDHEADER, b"X-Centinela-Families\0" + families + b"\0"))
            mods.append((SMFIR_ADDHEADER, b"X-Centinela-Id\0" + str(result.id).encode() + b"\0"))
            if self.truncated:
                mods.append((SMFIR_ADDHEADER, b"X-Centinela-Truncated\0yes\0"))

        # 3) Prefijo en el asunto, solo si es sospechoso o malicioso
        prefix = cfg.subject_prefix
        if prefix and prefix.strip() and verdict.level in (VerdictLevel.SUSPICIOUS, VerdictLevel.MALICIOUS):
            subject = next((v for n, v in self.headers if n.lower() == b"subject"), None)
            if subject is not None:
                new_value = prefixed_subject(prefix, subject)
                if new_value is not None and can_change:
                    mods.append((SMFIR_CHGHEADER, _LEN.pack(1) + b"Subject\0" + new_value + b"\0"))
            elif can_add and not self.truncated:
                # sin Subject (si el mensaje se truncó no sabemos si había uno: no inventamos)
                value = _encode_prefix(prefix.replace("\r", "").replace("\n", "").strip())
                mods.append((SMFIR_ADDHEADER, b"Subject\0" + value + b"\0"))
        return mods


# --------------------------------------------------------------------------- conector


class MilterConnector(Connector):
    """Servidor milter (Postfix/Sendmail). Ver docstring del módulo para la configuración del MTA."""

    type: ClassVar[str] = "milter"
    inline: ClassVar[bool] = True

    # Límites defensivos (atributos de clase para poder ajustarlos en tests o subclases).
    max_packet_bytes: int = 1024 * 1024  # los chunks de cuerpo son <= 64 KiB; headers <= 100 KiB en Postfix
    max_connections: int = 256
    max_recipients: int = 1000
    max_headers: int = 5000
    max_macros: int = 256
    max_macro_value: int = 1024
    idle_timeout_s: float = 900.0  # entre comandos (Postfix espera hasta smtpd_timeout=300s al cliente SMTP)
    read_timeout_s: float = 60.0  # para completar un paquete ya empezado
    write_timeout_s: float = 30.0
    shutdown_grace_s: float = 10.0  # al apagar: cuánto esperar los análisis que siguen en segundo plano

    def __init__(self, config: MilterConnectorConfig, settings: Settings, state: StateStore) -> None:
        super().__init__(config, settings, state)
        self.max_message_bytes = settings.limits.max_message_bytes
        self.ready = asyncio.Event()
        self.port: int | None = None
        self._emit: EmitFn | None = None
        self._server: asyncio.Server | None = None
        self._sessions: set[_MilterSession] = set()
        self._pending: set[asyncio.Task[Any]] = set()
        self.truncated_too_large = 0  # mensajes que superaban max_message_bytes

    # ------------------------------------------------------------------ análisis inline

    async def _analyze_inline(self, raw: RawMessage) -> AnalysisResult | None:
        """Lanza el análisis como tarea y espera hasta inline_timeout_s. Nunca cancela ni lanza."""
        emit = self._emit
        if emit is None:
            return None
        task = asyncio.create_task(self._run_emit(emit, raw), name=f"milter-emit-{raw.ref.remote_id}")
        self._pending.add(task)
        task.add_done_callback(self._pending.discard)
        timeout = max(0.0, float(self.config.inline_timeout_s))
        done, _ = await asyncio.wait({task}, timeout=timeout)
        if task not in done:
            log.info(
                "milter: el análisis de %s supera %.1fs; se acepta sin headers y sigue en segundo plano",
                raw.ref.remote_id,
                timeout,
            )
            return None
        if task.cancelled():
            return None
        result = task.result()
        return result if isinstance(result, AnalysisResult) else None

    @staticmethod
    async def _run_emit(emit: EmitFn, raw: RawMessage) -> AnalysisResult | None:
        try:
            return await emit(raw)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("milter: falló el análisis del mensaje %s", raw.ref.remote_id)
            return None

    # ------------------------------------------------------------------ servidor

    async def _on_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        if len(self._sessions) >= self.max_connections:
            log.warning(
                "milter: demasiadas conexiones (%d); se cierra %s (el MTA aplica milter_default_action)",
                len(self._sessions),
                peer,
            )
            writer.close()
            return
        session = _MilterSession(self, reader, writer)
        session.task = asyncio.current_task()
        self._sessions.add(session)
        try:
            await session.serve()
        except asyncio.CancelledError:
            raise
        except (asyncio.IncompleteReadError, ConnectionError) as exc:
            log.debug("milter: %s cerró la conexión (%s)", peer, type(exc).__name__)
        except TimeoutError:
            log.info("milter: conexión de %s inactiva; se cierra", peer)
        except _ProtocolError as exc:
            log.warning("milter: protocolo inválido desde %s: %s; se cierra la conexión", peer, exc)
        except Exception:
            log.exception("milter: error inesperado con %s; se cierra la conexión", peer)
        finally:
            self._sessions.discard(session)
            writer.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(writer.wait_closed(), 2)

    async def run(self, emit: EmitFn, stop: asyncio.Event) -> None:
        self._emit = emit
        host, port = self.config.listen_host, self.config.listen_port
        backoff = 1.0
        while not stop.is_set():
            try:
                server = await asyncio.start_server(self._on_client, host, port)
            except OSError as exc:
                log.error(
                    "milter: no se pudo escuchar en %s:%s (%s); reintento en %.0fs", host, port, exc, backoff
                )
                await _wait_or_stop(stop, backoff)
                backoff = min(backoff * 2, 60.0)
                continue
            self._server = server
            sockets = server.sockets or ()
            self.port = sockets[0].getsockname()[1] if sockets else port
            CONNECTOR_UP.labels(connector=self.name).set(1)
            log.info("milter: escuchando en %s:%s", host, self.port)
            self.ready.set()
            try:
                await stop.wait()
            finally:
                await self._shutdown(server)
            return

    async def _shutdown(self, server: asyncio.Server) -> None:
        CONNECTOR_UP.labels(connector=self.name).set(0)
        self.ready.clear()
        server.close()
        for session in list(self._sessions):
            session.writer.close()
        tasks = [s.task for s in self._sessions if s.task is not None and not s.task.done()]
        if tasks:
            _, still = await asyncio.wait(tasks, timeout=2)
            for t in still:
                t.cancel()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(server.wait_closed(), 5)
        self._server = None
        await self._drain_pending(self.shutdown_grace_s)

    async def _drain_pending(self, grace: float) -> None:
        pending = [t for t in self._pending if not t.done()]
        if not pending:
            return
        _, still = await asyncio.wait(pending, timeout=grace)
        if still:
            log.warning("milter: se cancelan %d análisis pendientes al apagar", len(still))
            for t in still:
                t.cancel()
            await asyncio.wait(still, timeout=2)

    async def healthcheck(self) -> dict[str, Any]:
        serving = self._server is not None and self._server.is_serving()
        return {
            "ok": serving,
            "listen": f"{self.config.listen_host}:{self.port or self.config.listen_port}",
            "connections": len(self._sessions),
            "pending_analyses": sum(1 for t in self._pending if not t.done()),
            "truncated_too_large": self.truncated_too_large,
        }

    async def close(self) -> None:
        for t in list(self._pending):
            t.cancel()


async def _wait_or_stop(stop: asyncio.Event, seconds: float) -> None:
    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(stop.wait(), seconds)


__all__ = ["MilterConnector", "prefixed_subject"]
