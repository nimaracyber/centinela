"""Conector SMTP de copias (BCC / journaling / reenvío automático).

Centinela levanta un servidor SMTP mínimo (aiosmtpd) que SOLO recibe copias de los mails de la
empresa: nunca reenvía (relay) nada a ningún lado. Sirve con cualquier proveedor que permita mandar
una copia a otra dirección:

- **Microsoft 365 / Exchange**: regla de journaling hacia ``journal@<host-de-centinela>`` (Exchange
  manda un "journal report" con el mail original adjunto; con ``unwrap_journal: true`` Centinela
  analiza el mail original y toma los destinatarios reales del reporte).
- **Google Workspace**: regla de enrutamiento "Agregar más destinatarios" (copia BCC).
- **Postfix propio**: ``always_bcc = centinela@<host>`` o ``recipient_bcc_maps``.
- **cPanel / Plesk / otros**: reenvío automático con copia.

Como recibe copias, no puede etiquetar el mail original: solo alerta (``tag: false``).

Quién puede entregar copias (``allowed_senders``): lista de IPs o redes CIDR. Si está vacía solo se
aceptan conexiones desde loopback (127.0.0.0/8, ::1) y redes privadas RFC 1918 (10/8, 172.16/12,
192.168/16) y ULA IPv6 (fc00::/7), que es lo esperable con Centinela en la misma LAN o en Docker.
Para recibir journaling de Microsoft 365 por Internet hay que listar explícitamente los rangos de
Exchange Online (y conviene ``require_tls: true`` con certificado). Los nombres de host no se aceptan.
OJO con Docker: si el puerto se publica con el "userland proxy" (Docker Desktop, IPv6), todas las
conexiones parecen venir del gateway del bridge (172.17.0.1, privada) y la lista vacía las aceptaría:
no publicar este puerto a Internet sin una lista ``allowed_senders`` explícita.

Dedupe: ``remote_id`` = ``<Message-ID>#<sha256 corto del mail>`` (o el sha256 completo si no hay
Message-ID). El Message-ID solo lo controla el remitente: si fuera el id a secas, un atacante podría
reutilizar el Message-ID de un mail viejo para que el storage lo descarte como duplicado y no se analice.

Tamaño: una copia más grande que ``limits.max_message_bytes`` NO se rechaza (sería una evasión trivial):
se acepta hasta un tope duro (``hard_cap_factor`` x el límite) y se emite solo con sus headers
(``truncated=True`` + ``original_size``; el pipeline agrega ``policy.message_too_large``). Por encima del
tope duro aiosmtpd responde ``552`` (no se puede guardar en memoria sin límite).

La config se valida al cargarla (``SmtpJournalConnectorConfig``). Si igual llega una inválida (por ejemplo
construida sin validar), el conector no tira abajo el proceso: falla cerrado (no acepta copias de nadie /
rechaza todo sin TLS) y lo deja en el log.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import functools
import hashlib
import ipaddress
import logging
import quopri
import re
import ssl
import weakref
from dataclasses import dataclass, field
from email.header import decode_header, make_header
from email.message import Message
from email.parser import BytesHeaderParser
from email.policy import compat32
from typing import TYPE_CHECKING, Any, ClassVar

from aiosmtpd.smtp import SMTP

from centinela.connectors._headers import header_cap, header_section, oversize_raw
from centinela.connectors.base import Connector
from centinela.core.models import MessageRef, RawMessage
from centinela.metrics import CONNECTOR_UP

if TYPE_CHECKING:
    from centinela.connectors.base import EmitFn
    from centinela.core.config import Settings, SmtpJournalConnectorConfig
    from centinela.core.state import StateStore

log = logging.getLogger(__name__)

IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

#: Redes permitidas cuando `allowed_senders` está vacío: loopback + privadas (RFC 1918 / ULA).
DEFAULT_ALLOWED_NETWORKS: tuple[IpNetwork, ...] = tuple(
    ipaddress.ip_network(n)
    for n in ("127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
)

#: Headers con los que Exchange marca un journal report (sin valor: alcanza con que existan).
JOURNAL_HEADERS = ("x-ms-journal-report", "x-ms-exchange-organization-journal-report")

_UNKNOWN_MAILBOX = "desconocido"
_MAX_HEADER_BLOCK = 512 * 1024
_MAX_REPORT_TEXT = 4 * 1024 * 1024
_MAX_REPORT_LINES = 20000
_MAX_PARTS = 64
_MAX_RECIPIENTS = 1000

_BLANK_LINE_RE = re.compile(rb"\r?\n\r?\n")
_REPORT_FIELD_RE = re.compile(
    r"^(sender|subject|message-id|to|cc|bcc|recipient|on-behalf-of)[ \t]*:(.*)$", re.IGNORECASE
)
# cuantificadores acotados y sin anidar: sin backtracking catastrófico
_ADDR_RE = re.compile(r"[^\s@<>,;:\"()\[\]\\]{1,128}@[A-Za-z0-9][A-Za-z0-9.-]{0,253}")
_SUBFIELD_RE = re.compile(r"(expanded|forwarded)[ \t]*:[ \t]*<?([^<>\s]{1,400})>?", re.IGNORECASE)
_MSGID_RE = re.compile(r"<?[^<>\s]{1,994}>?")
_WS_RE = re.compile(r"\s+")
_B64_JUNK_RE = re.compile(rb"[^A-Za-z0-9+/=]")


# --------------------------------------------------------------------------- red / permisos


def parse_allowed_networks(entries: list[str]) -> tuple[IpNetwork, ...]:
    """IPs o CIDRs -> redes. Lista vacía -> loopback + privadas. Entradas inválidas -> ValueError."""
    if not entries:
        return DEFAULT_ALLOWED_NETWORKS
    nets: list[IpNetwork] = []
    for entry in entries:
        try:
            nets.append(ipaddress.ip_network(str(entry).strip(), strict=False))
        except ValueError as exc:
            raise ValueError(f"allowed_senders: '{entry}' no es una IP ni una red CIDR válida") from exc
    return tuple(nets)


def peer_ip(peer: Any) -> IpAddress | None:
    """IP del peer de aiosmtpd (tupla de getpeername), normalizando IPv4-mapeada en IPv6."""
    if isinstance(peer, (tuple, list)) and peer:
        host = peer[0]
    elif isinstance(peer, str):
        host = peer
    else:
        return None
    host = str(host).split("%", 1)[0]  # zona IPv6 (fe80::1%eth0)
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def peer_allowed(peer: Any, networks: tuple[IpNetwork, ...]) -> bool:
    ip = peer_ip(peer)
    if ip is None:
        return False
    return any(ip.version == net.version and ip in net for net in networks)


# --------------------------------------------------------------------------- MIME crudo (sin re-serializar)


def _split_head(data: bytes) -> tuple[bytes, bytes]:
    """Separa headers y cuerpo en la primera línea en blanco, sin tocar los bytes."""
    if data.startswith(b"\r\n"):
        return b"", data[2:]
    if data.startswith(b"\n"):
        return b"", data[1:]
    m = _BLANK_LINE_RE.search(data, 0, _MAX_HEADER_BLOCK + 4)
    if m is None:
        return (data, b"") if len(data) <= _MAX_HEADER_BLOCK else (b"", b"")
    first_nl = data.index(b"\n", m.start()) + 1
    return data[:first_nl], data[m.end() :]


def _parse_headers(head: bytes) -> Message:
    return BytesHeaderParser(policy=compat32).parsebytes(head[:_MAX_HEADER_BLOCK])


def _split_multipart(body: bytes, boundary: bytes) -> list[bytes] | None:
    """Partes de un multipart (RFC 2046) como bytes exactos. None si está malformado o es enorme."""
    delim = b"--" + boundary
    n = len(body)
    marks: list[tuple[int, int, bool]] = []  # (inicio de la línea delimitadora, fin de la línea, es cierre)
    pos = 0
    while pos < n:
        j = body.find(delim, pos)
        if j < 0:
            break
        eol = body.find(b"\n", j)
        line_end = n if eol < 0 else eol + 1
        if j == 0 or body[j - 1 : j] == b"\n":
            rest = body[j + len(delim) : line_end].rstrip(b"\r\n").rstrip(b" \t")
            if rest in (b"", b"--"):
                marks.append((j, line_end, rest == b"--"))
                if rest == b"--":
                    break
                if len(marks) > _MAX_PARTS:
                    return None
        pos = line_end
    if not marks or marks[0][2]:
        return None
    parts: list[bytes] = []
    for (_, start, closing), nxt in zip(marks, [*marks[1:], None], strict=True):
        if closing:
            break
        if nxt is None:
            part = body[start:]  # sin delimitador de cierre: tolerante, hasta el final
        else:
            part = body[start : nxt[0]]
            # el CRLF previo al delimitador pertenece al delimitador
            if part.endswith(b"\r\n"):
                part = part[:-2]
            elif part.endswith(b"\n"):
                part = part[:-1]
        parts.append(part)
    return parts


def _decode_cte(data: bytes, cte: str | None) -> bytes:
    """Decodifica Content-Transfer-Encoding. base64 roto -> b"" (el llamador no desenvuelve)."""
    cte = (cte or "").strip().lower()
    if cte == "base64":
        clean = _B64_JUNK_RE.sub(b"", data).rstrip(b"=")
        clean = clean[: len(clean) - len(clean) % 4] if len(clean) % 4 == 1 else clean
        try:
            return base64.b64decode(clean + b"=" * (-len(clean) % 4), validate=False)
        except (binascii.Error, ValueError):
            return b""
    if cte == "quoted-printable":
        return quopri.decodestring(data)
    return data


def _raw_header(msg: Message, name: str) -> str | None:
    """Valor crudo del primer header `name` (compat32 guarda los bytes 8-bit como surrogates)."""
    name = name.lower()
    for key, value in msg.raw_items():
        if key.lower() == name:
            text = str(value)
            # surrogates (bytes 8-bit sin declarar) -> UTF-8 best effort
            return text.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    return None


def _decode_text(data: bytes, charset: str | None) -> str:
    try:
        return data.decode(charset or "utf-8", "replace")
    except LookupError:
        return data.decode("utf-8", "replace")


def _norm_text(s: str) -> str:
    return _WS_RE.sub(" ", s).strip().casefold()


def _header_text(msg: Message, name: str) -> str | None:
    raw = _raw_header(msg, name)
    if raw is None:
        return None
    try:
        return str(make_header(decode_header(raw)))
    except Exception:  # noqa: BLE001 - encoded-words rotos
        return raw


def message_id_of(raw: bytes) -> str | None:
    head, _ = _split_head(raw)
    if not head:
        return None
    value = _raw_header(_parse_headers(head), "Message-ID")
    if not value:
        return None
    mid = _WS_RE.sub("", value)[:250]
    return mid or None


def remote_id_for(raw: bytes) -> str:
    """`<Message-ID>#<sha256[:16]>` (anti-evasión del dedupe) o el sha256 completo si no hay Message-ID."""
    digest = hashlib.sha256(raw).hexdigest()
    mid = message_id_of(raw)
    return f"{mid}#{digest[:16]}" if mid else digest


# --------------------------------------------------------------------------- journal report de Exchange


@dataclass
class JournalUnwrap:
    inner: bytes  # el mail original, bytes tal cual venían adjuntos
    recipients: list[str] = field(default_factory=list)  # destinatarios reales según el reporte


def _addr(token: str) -> str | None:
    token = token.strip().strip("<>").strip()
    return token.lower() if _ADDR_RE.fullmatch(token) else None


def _parse_report(text: str) -> dict[str, Any] | None:
    """Interpreta el cuerpo del journal report. None si tiene CUALQUIER cosa que no sea un campo válido.

    Formato (Exchange): una línea por valor, p. ej.::

        Sender: juan@proveedor.com
        Subject: Factura
        Message-Id: <abc@proveedor.com>
        To: ventas@empresa.com
        To: maria@empresa.com, Expanded: todos@empresa.com
        Cc: jose@empresa.com, Forwarded: pedro@empresa.com
        Recipient: compras@empresa.com

    Somos estrictos a propósito: si un atacante arma un mail que "parece" journal report, no queremos
    que el texto del "reporte" (que el usuario sí ve) quede fuera del análisis.
    """
    if len(text) > _MAX_REPORT_TEXT:
        return None
    lines = text.split("\n")
    if len(lines) > _MAX_REPORT_LINES:
        return None
    out: dict[str, Any] = {"recipients": [], "subject": None, "message_id": None}
    for line in lines:
        line = line.rstrip("\r")
        if not line.strip():
            continue
        m = _REPORT_FIELD_RE.match(line)
        if m is None:
            return None
        key, value = m.group(1).lower(), m.group(2).strip(" \t")
        if key == "subject":
            out["subject"] = value
        elif key == "message-id":
            if value and not _MSGID_RE.fullmatch(value):
                return None
            out["message_id"] = value or None
        elif key in ("sender", "on-behalf-of"):
            if value and _addr(value) is None:
                return None
        else:  # to / cc / bcc / recipient
            segments = [s.strip() for s in value.split(",")]
            if not segments or len(segments) > 3:
                return None
            primary = _addr(segments[0])
            if primary is None:
                return None
            for extra in segments[1:]:  # ", Expanded: <grupo>" / ", Forwarded: <buzón>"
                sub = _SUBFIELD_RE.fullmatch(extra)
                if sub is None or _addr(sub.group(2)) is None:
                    return None
            if primary not in out["recipients"] and len(out["recipients"]) < _MAX_RECIPIENTS:
                out["recipients"].append(primary)
    return out


def unwrap_journal(raw: bytes) -> JournalUnwrap | None:
    """Si `raw` es un journal report de Exchange, devuelve el mail original y sus destinatarios.

    Condiciones (todas): header X-MS-Journal-Report (o X-MS-Exchange-Organization-Journal-Report),
    multipart/mixed con exactamente UNA parte message/rfc822 y como mucho una parte text/plain
    (el reporte) que valide estrictamente y sea coherente con el mail adjunto (Message-Id y Subject).
    Cualquier otra cosa -> None (se analiza el mail completo tal como llegó: el parser igual
    desarma el message/rfc822 adjunto, así que nada queda sin analizar).
    """
    head, body = _split_head(raw)
    if not head:
        return None
    outer = _parse_headers(head)
    if not any(outer.get(h) is not None for h in JOURNAL_HEADERS):
        return None
    if outer.get_content_type() != "multipart/mixed":
        return None
    boundary = outer.get_param("boundary")
    if not isinstance(boundary, str) or not boundary or len(boundary) > 200:
        return None
    parts = _split_multipart(body, boundary.encode("utf-8", "surrogateescape"))
    if parts is None:
        return None

    inner: bytes | None = None
    report: str | None = None
    for part in parts:
        p_head, p_body = _split_head(part)
        p_msg = _parse_headers(p_head) if p_head else Message()
        ctype = p_msg.get_content_type() if p_head else "text/plain"
        cte = p_msg.get("Content-Transfer-Encoding")
        if ctype == "message/rfc822":
            if inner is not None:
                return None
            inner = _decode_cte(p_body, cte)
        elif ctype == "text/plain" and report is None:
            report = _decode_text(_decode_cte(p_body, cte), p_msg.get_content_charset())
        else:
            return None
    if not inner or not inner.strip():
        return None

    recipients: list[str] = []
    if report is not None:
        fields = _parse_report(report)
        if fields is None:
            return None
        inner_head, _ = _split_head(inner)
        inner_msg = _parse_headers(inner_head) if inner_head else Message()
        report_mid, inner_mid = fields["message_id"], _raw_header(inner_msg, "Message-ID")
        if (
            report_mid
            and inner_mid
            and _WS_RE.sub("", report_mid).lower() != _WS_RE.sub("", str(inner_mid)).lower()
        ):
            return None
        if fields["subject"]:
            inner_subject = _header_text(inner_msg, "Subject")
            if inner_subject is None or _norm_text(inner_subject) != _norm_text(fields["subject"]):
                return None
        recipients = fields["recipients"]
    return JournalUnwrap(inner=inner, recipients=recipients)


def choose_mailbox(original: list[str], envelope: list[str], company_domains: list[str]) -> str:
    """Buzón a reportar: primero un destinatario de la empresa, si no el primero que haya."""
    candidates = [a.strip().strip("<>").lower() for a in (original or envelope) if a and a.strip()]
    domains = [d.strip().lower().lstrip("@").rstrip(".") for d in company_domains if d.strip()]
    for addr in candidates:
        dom = addr.rpartition("@")[2]
        if any(dom == d or dom.endswith("." + d) for d in domains):
            return addr[:320]
    return candidates[0][:320] if candidates else _UNKNOWN_MAILBOX


# --------------------------------------------------------------------------- servidor SMTP


class _CopySMTP(SMTP):
    """aiosmtpd con líneas largas toleradas: rechazar un mail con una línea de > 1000 bytes
    significaría perder la copia (y un NDR al administrador). El tamaño total sigue acotado."""

    line_length_limit = 1024 * 1024


class _Handler:
    """Hooks de aiosmtpd. Nunca hace relay: solo entrega el mail a `emit`."""

    def __init__(self, connector: SmtpJournalConnector) -> None:
        self.c = connector

    async def handle_MAIL(
        self, server: SMTP, session: Any, envelope: Any, address: str, mail_options: list[str]
    ) -> str:
        if not peer_allowed(session.peer, self.c.networks):
            log.warning("smtp_journal: conexión no autorizada desde %s", peer_ip(session.peer))
            return "550 5.7.1 no autorizado"
        envelope.mail_from = address
        envelope.mail_options.extend(mail_options)
        return "250 OK"

    async def handle_RCPT(
        self, server: SMTP, session: Any, envelope: Any, address: str, rcpt_options: list[str]
    ) -> str:
        if len(envelope.rcpt_tos) >= self.c.max_recipients:
            return "452 4.5.3 demasiados destinatarios"
        envelope.rcpt_tos.append(address)
        envelope.rcpt_options.extend(rcpt_options)
        return "250 OK"

    async def handle_DATA(self, server: SMTP, session: Any, envelope: Any) -> str:
        if not peer_allowed(session.peer, self.c.networks):
            log.warning("smtp_journal: DATA no autorizado desde %s", peer_ip(session.peer))
            return "550 5.7.1 no autorizado"
        if self.c.config.require_tls and session.ssl is None:
            return "530 5.7.0 Must issue a STARTTLS command first"
        content = envelope.original_content
        if content is None:
            content = envelope.content if isinstance(envelope.content, bytes) else b""
        return await self.c._ingest(bytes(content), list(envelope.rcpt_tos))


class SmtpJournalConnector(Connector):
    """Recibe copias por SMTP y las manda a analizar. Solo alerta (no puede etiquetar el original)."""

    type: ClassVar[str] = "smtp_journal"
    inline: ClassVar[bool] = False

    max_recipients: int = _MAX_RECIPIENTS
    smtp_timeout_s: float = 300.0  # inactividad de la sesión SMTP
    emit_timeout_s: float = 120.0  # cuánto esperamos a que emit encole antes de responder igual 250
    shutdown_grace_s: float = 10.0
    #: Tope duro de DATA = factor x max_message_bytes. Entre el límite y el tope: se analizan solo los headers.
    hard_cap_factor: int = 2

    def __init__(self, config: SmtpJournalConnectorConfig, settings: Settings, state: StateStore) -> None:
        super().__init__(config, settings, state)
        # SmtpJournalConnectorConfig ya valida todo esto al cargar la config; acá solo por si llega una
        # config sin validar: nunca lanzar (tiraría abajo el proceso) y fallar CERRADO.
        try:
            self.networks = parse_allowed_networks(list(config.allowed_senders))
        except ValueError as exc:
            log.error(
                "smtp_journal '%s': %s; no se aceptan copias de nadie hasta corregir la configuración",
                config.name,
                exc,
            )
            self.networks = ()
        has_cert, has_key = config.tls_cert_file is not None, config.tls_key_file is not None
        if has_cert != has_key:
            log.error(
                "smtp_journal '%s': tls_cert_file y tls_key_file van juntos; TLS desactivado", config.name
            )
        if config.require_tls and not (has_cert and has_key):
            log.error(
                "smtp_journal '%s': require_tls sin certificado; se rechazan todas las copias (530)",
                config.name,
            )
        self.max_message_bytes = int(settings.limits.max_message_bytes)
        self.hard_cap_bytes = max(self.max_message_bytes + 1, self.max_message_bytes * self.hard_cap_factor)
        self.truncated_too_large = 0
        self.ready = asyncio.Event()
        self.port: int | None = None
        self._emit: EmitFn | None = None
        self._server: asyncio.Server | None = None
        self._protocols: weakref.WeakSet[SMTP] = (
            weakref.WeakSet()
        )  # sesiones vivas (para cerrarlas al apagar)
        self._pending: set[asyncio.Task[Any]] = set()

    # ------------------------------------------------------------------ ingesta

    async def _build_raw(self, content: bytes, rcpt_tos: list[str]) -> RawMessage:
        original_rcpts: list[str] = []
        raw_bytes = content
        if self.config.unwrap_journal:
            try:
                unwrapped = await asyncio.to_thread(unwrap_journal, content)
            except Exception:  # noqa: BLE001 - mail hostil/malformado: se analiza completo
                log.warning("smtp_journal: no se pudo interpretar un posible journal report", exc_info=True)
                unwrapped = None
            if unwrapped is not None:
                raw_bytes, original_rcpts = unwrapped.inner, unwrapped.recipients
                log.debug("smtp_journal: journal report desenvuelto (%d destinatarios)", len(original_rcpts))
        mailbox = choose_mailbox(original_rcpts, rcpt_tos, self.settings.general.company_domains)
        remote_id = await asyncio.to_thread(remote_id_for, raw_bytes)  # sobre el mail completo
        ref = MessageRef(connector=self.name, mailbox=mailbox, remote_id=remote_id)
        limit = self.max_message_bytes
        if len(raw_bytes) > limit:
            self.truncated_too_large += 1
            log.warning(
                "smtp_journal: copia de %d bytes supera max_message_bytes=%d; se analizan solo los encabezados",
                len(raw_bytes),
                limit,
            )
            return oversize_raw(
                ref, header_section(raw_bytes, header_cap(limit)), original_size=len(raw_bytes), limit=limit
            )
        return RawMessage(ref=ref, raw=raw_bytes)

    async def _ingest(self, content: bytes, rcpt_tos: list[str]) -> str:
        if len(content) > self.hard_cap_bytes:  # aiosmtpd ya lo rechaza con data_size_limit
            return "552 5.3.4 mensaje demasiado grande"
        emit = self._emit
        if emit is None:
            return "451 4.3.0 servicio no disponible, reintentar"
        try:
            raw = await self._build_raw(content, rcpt_tos)
        except Exception:
            log.exception("smtp_journal: error preparando el mensaje")
            return "451 4.3.0 error temporal, reintentar"
        task = asyncio.create_task(emit(raw), name=f"smtp-journal-emit-{raw.ref.remote_id[:40]}")
        self._pending.add(task)
        task.add_done_callback(self._emit_done)
        done, _ = await asyncio.wait({task}, timeout=self.emit_timeout_s)
        if task in done and (task.cancelled() or task.exception() is not None):
            # el remitente reintenta: entrega al-menos-una-vez
            return "451 4.3.0 error temporal, reintentar"
        log.info("smtp_journal: copia recibida para %s (%d bytes)", raw.ref.mailbox, len(raw.raw))
        return "250 OK"

    def _emit_done(self, task: asyncio.Task[Any]) -> None:
        self._pending.discard(task)
        if not task.cancelled() and task.exception() is not None:
            log.error("smtp_journal: falló la entrega del mensaje al análisis", exc_info=task.exception())

    # ------------------------------------------------------------------ servidor

    def _tls_context(self) -> ssl.SSLContext | None:
        cert, key = self.config.tls_cert_file, self.config.tls_key_file
        if cert is None or key is None:
            return None
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(str(cert), str(key))
        return ctx

    def _make_protocol(self, loop: asyncio.AbstractEventLoop, tls: ssl.SSLContext | None) -> SMTP:
        proto = _CopySMTP(
            _Handler(self),
            data_size_limit=self.hard_cap_bytes,  # entre el límite y el tope: solo headers (no se rechaza)
            enable_SMTPUTF8=True,
            decode_data=False,
            hostname="centinela",
            ident="Centinela",
            tls_context=tls,
            require_starttls=bool(tls and self.config.require_tls),
            timeout=self.smtp_timeout_s,
            command_call_limit=None,
            loop=loop,
        )
        self._protocols.add(proto)
        return proto

    async def run(self, emit: EmitFn, stop: asyncio.Event) -> None:
        self._emit = emit
        loop = asyncio.get_running_loop()
        host, port = self.config.listen_host, self.config.listen_port
        backoff = 1.0
        while not stop.is_set():
            try:
                tls = self._tls_context()
                server = await loop.create_server(
                    functools.partial(self._make_protocol, loop, tls), host, port
                )
            except (OSError, ssl.SSLError) as exc:
                log.error(
                    "smtp_journal: no se pudo escuchar en %s:%s (%s); reintento en %.0fs",
                    host,
                    port,
                    exc,
                    backoff,
                )
                await _wait_or_stop(stop, backoff)
                backoff = min(backoff * 2, 60.0)
                continue
            self._server = server
            sockets = server.sockets or ()
            self.port = sockets[0].getsockname()[1] if sockets else port
            CONNECTOR_UP.labels(connector=self.name).set(1)
            log.info("smtp_journal: escuchando en %s:%s (TLS %s)", host, self.port, "sí" if tls else "no")
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
        for proto in list(self._protocols):
            transport = proto.transport
            if transport is not None:
                with contextlib.suppress(Exception):
                    transport.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(server.wait_closed(), 5)
        self._server = None
        pending = [t for t in self._pending if not t.done()]
        if pending:
            _, still = await asyncio.wait(pending, timeout=self.shutdown_grace_s)
            for t in still:
                t.cancel()

    async def healthcheck(self) -> dict[str, Any]:
        serving = self._server is not None and self._server.is_serving()
        return {
            "ok": serving,
            "listen": f"{self.config.listen_host}:{self.port or self.config.listen_port}",
            "pending": sum(1 for t in self._pending if not t.done()),
            "truncated_too_large": self.truncated_too_large,
        }

    async def close(self) -> None:
        for t in list(self._pending):
            t.cancel()


async def _wait_or_stop(stop: asyncio.Event, seconds: float) -> None:
    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(stop.wait(), seconds)


__all__ = [
    "DEFAULT_ALLOWED_NETWORKS",
    "JournalUnwrap",
    "SmtpJournalConnector",
    "choose_mailbox",
    "parse_allowed_networks",
    "peer_allowed",
    "remote_id_for",
    "unwrap_journal",
]
