from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import random
import smtplib
import ssl
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from centinela.connectors import connector_class
from centinela.connectors import smtp_journal as sj
from centinela.connectors.smtp_journal import (
    SmtpJournalConnector,
    choose_mailbox,
    parse_allowed_networks,
    peer_allowed,
    remote_id_for,
    unwrap_journal,
)
from centinela.core.config import SmtpJournalConnectorConfig
from centinela.core.models import RawMessage
from centinela.core.state import MemoryStateStore
from tests.helpers import build_eml


class RecordingEmit:
    def __init__(self, *, delay: float = 0.0, exc: Exception | None = None) -> None:
        self.delay, self.exc = delay, exc
        self.received: list[RawMessage] = []
        self.finished = asyncio.Event()

    async def __call__(self, raw: RawMessage) -> None:
        self.received.append(raw)
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.exc:
            raise self.exc
        self.finished.set()


@pytest.fixture
async def start_journal(settings):
    running: list[tuple[SmtpJournalConnector, asyncio.Event, asyncio.Task]] = []

    async def _start(emit, **overrides) -> SmtpJournalConnector:
        cfg = SmtpJournalConnectorConfig(
            type="smtp_journal", name="copias", listen_host="127.0.0.1", listen_port=0, **overrides
        )
        conn = SmtpJournalConnector(cfg, settings, MemoryStateStore())
        stop = asyncio.Event()
        task = asyncio.create_task(conn.run(emit, stop))
        await asyncio.wait_for(conn.ready.wait(), 5)
        running.append((conn, stop, task))
        return conn

    yield _start
    for _, stop, task in running:
        stop.set()
        await asyncio.wait_for(task, 20)


def _sendmail(port: int, from_: str, to: list[str], msg: bytes, *, tls: bool = False) -> dict:
    with smtplib.SMTP("127.0.0.1", port, timeout=10) as s:
        s.ehlo("mx.empresa.com")
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s.starttls(context=ctx)
            s.ehlo("mx.empresa.com")
        return s.sendmail(from_, to, msg)


def _crlf(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")


INNER = _crlf(
    build_eml(
        subject="Factura 123",
        to="ventas@empresa.com",
        text="Adjunto factura",
        attachments=[("factura.pdf", b"%PDF-1.4 inerte", "application/pdf")],
    )
)
REPORT = (
    "Sender: juan@proveedor.com\r\n"
    "Subject: Factura 123\r\n"
    "Message-Id: <test-1@proveedor.com>\r\n"
    "Recipient: otro@externo.com\r\n"
    "To: ventas@empresa.com, Expanded: todos@empresa.com\r\n"
    "Cc: jefe@empresa.com, Forwarded: asistente@empresa.com\r\n"
)


def build_journal(
    inner: bytes = INNER,
    report: str | None = REPORT,
    *,
    journal_header: str | None = "X-MS-Journal-Report",
    boundary: str = "b1_journal_xyz",
    inner_cte: str | None = None,
    extra_parts: list[bytes] | None = None,
    close: bool = True,
) -> bytes:
    head = [
        "From: Microsoft Outlook <MicrosoftExchange329e71ec88ae4615bbc36ab6ce41109e@empresa.com>",
        "To: journal@centinela.local",
        "Subject: Factura 123",
        "MIME-Version: 1.0",
        f'Content-Type: multipart/mixed; boundary="{boundary}"',
    ]
    if journal_header:
        head.append(f"{journal_header}:")
    out = ("\r\n".join(head) + "\r\n\r\n").encode()
    if report is not None:
        out += f"--{boundary}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n".encode()
        out += report.encode("utf-8") + b"\r\n"
    for part in extra_parts or []:
        out += f"--{boundary}\r\n".encode() + part + b"\r\n"
    out += f"--{boundary}\r\nContent-Type: message/rfc822\r\n".encode()
    if inner_cte:
        out += f"Content-Transfer-Encoding: {inner_cte}\r\n".encode()
    out += b"Content-Disposition: attachment\r\n\r\n"
    if inner_cte == "base64":
        out += base64.encodebytes(inner).replace(b"\n", b"\r\n")
    else:
        out += inner
    if close:
        out += f"\r\n--{boundary}--\r\n".encode()
    return out


# --------------------------------------------------------------------------- SMTP extremo a extremo


async def test_registry_resolves_smtp_journal_type():
    assert connector_class("smtp_journal") is SmtpJournalConnector
    assert SmtpJournalConnector.inline is False


async def test_plain_copy_from_loopback_is_accepted(start_journal):
    emit = RecordingEmit()
    conn = await start_journal(emit)
    # smtplib manda los bytes tal cual: como un MTA real, en CRLF
    eml = _crlf(build_eml(subject="Hola", text="Linea normal\n.linea que empieza con punto\n"))
    refused = await asyncio.to_thread(
        _sendmail, conn.port, "juan@proveedor.com", ["Ventas@Empresa.com", "otro@externo.com"], eml
    )
    assert refused == {}
    assert len(emit.received) == 1
    raw = emit.received[0]
    assert raw.raw == eml  # bytes intactos (dot-stuffing deshecho)
    assert b"\r\n.linea que empieza con punto" in raw.raw
    assert raw.ref.connector == "copias"
    assert raw.ref.mailbox == "ventas@empresa.com"
    digest = hashlib.sha256(raw.raw).hexdigest()
    assert raw.ref.remote_id == f"<test-1@proveedor.com>#{digest[:16]}"


async def test_denied_peer_is_rejected_at_mail(start_journal):
    emit = RecordingEmit()
    conn = await start_journal(emit, allowed_senders=["10.0.0.0/8", "192.0.2.10"])
    with pytest.raises(smtplib.SMTPSenderRefused) as info:
        await asyncio.to_thread(
            _sendmail, conn.port, "juan@proveedor.com", ["ventas@empresa.com"], build_eml()
        )
    assert info.value.smtp_code == 550
    assert emit.received == []


async def test_explicit_allowed_sender_is_accepted(start_journal):
    emit = RecordingEmit()
    conn = await start_journal(emit, allowed_senders=["127.0.0.1"])
    await asyncio.to_thread(_sendmail, conn.port, "a@proveedor.com", ["ventas@empresa.com"], build_eml())
    assert len(emit.received) == 1


async def test_data_hook_rechecks_peer(settings):
    """Defensa en profundidad: aunque se saltee MAIL, DATA vuelve a verificar la IP."""
    cfg = SmtpJournalConnectorConfig(type="smtp_journal", name="copias")
    conn = SmtpJournalConnector(cfg, settings, MemoryStateStore())
    emit = RecordingEmit()
    conn._emit = emit
    handler = sj._Handler(conn)
    envelope = SimpleNamespace(
        original_content=_crlf(build_eml()), content=None, rcpt_tos=["ventas@empresa.com"]
    )
    denied = await handler.handle_DATA(None, SimpleNamespace(peer=("203.0.113.9", 4000), ssl=None), envelope)
    assert denied.startswith("550")
    assert emit.received == []
    ok = await handler.handle_DATA(None, SimpleNamespace(peer=("192.168.1.20", 4000), ssl=None), envelope)
    assert ok == "250 OK"
    assert len(emit.received) == 1


async def test_exchange_journal_report_is_unwrapped(start_journal):
    emit = RecordingEmit()
    conn = await start_journal(emit)
    journal = build_journal()
    await asyncio.to_thread(
        _sendmail, conn.port, "postmaster@empresa.com", ["journal@centinela.local"], journal
    )
    raw = emit.received[0]
    assert raw.raw == INNER  # el original, byte a byte
    assert raw.ref.mailbox == "ventas@empresa.com"  # destinatario real de la empresa, no el del journal
    assert raw.ref.remote_id.startswith("<test-1@proveedor.com>#")


async def test_journal_not_unwrapped_when_disabled(start_journal):
    emit = RecordingEmit()
    conn = await start_journal(emit, unwrap_journal=False)
    journal = build_journal()
    await asyncio.to_thread(
        _sendmail, conn.port, "postmaster@empresa.com", ["journal@centinela.local"], journal
    )
    raw = emit.received[0]
    assert raw.raw == journal
    assert raw.ref.mailbox == "journal@centinela.local"


async def test_forged_journal_with_hidden_content_is_not_unwrapped(start_journal):
    emit = RecordingEmit()
    conn = await start_journal(emit)
    forged = build_journal(
        report=REPORT + "Ingrese aqui para validar su cuenta: http://phish.example/login\r\n"
    )
    await asyncio.to_thread(_sendmail, conn.port, "x@proveedor.com", ["ventas@empresa.com"], forged)
    assert emit.received[0].raw == forged  # se analiza el envoltorio completo, con el texto del "reporte"


async def test_message_between_limit_and_hard_cap_is_analyzed_headers_only(start_journal, settings, caplog):
    settings.limits.max_message_bytes = 4096  # tope duro = 2 x 4096
    emit = RecordingEmit()
    conn = await start_journal(emit)
    assert conn.hard_cap_bytes == 8192
    eml = _crlf(build_eml(subject="Pesado", text="A" * 5000))
    assert 4096 < len(eml) <= 8192
    refused = await asyncio.to_thread(_sendmail, conn.port, "a@proveedor.com", ["ventas@empresa.com"], eml)
    assert refused == {}  # NO se rechaza: un mail enorme no puede esquivar el análisis
    (raw,) = emit.received
    assert raw.truncated is True and raw.original_size == len(eml)
    assert raw.raw == eml.split(b"\r\n\r\n", 1)[0] + b"\r\n\r\n"  # solo los headers
    # el dedupe usa el hash del mail COMPLETO
    assert raw.ref.remote_id == f"<test-1@proveedor.com>#{hashlib.sha256(eml).hexdigest()[:16]}"
    assert raw.ref.mailbox == "ventas@empresa.com"
    assert (await conn.healthcheck())["truncated_too_large"] == 1
    assert "solo los encabezados" in caplog.text


async def test_oversized_journal_report_keeps_original_headers(start_journal, settings):
    settings.limits.max_message_bytes = 4096
    emit = RecordingEmit()
    conn = await start_journal(emit)
    inner = _crlf(build_eml(subject="Factura 123", to="ventas@empresa.com", text="A" * 4500))
    journal = build_journal(inner=inner)
    assert len(inner) > 4096 and len(journal) <= conn.hard_cap_bytes
    await asyncio.to_thread(
        _sendmail, conn.port, "postmaster@empresa.com", ["journal@centinela.local"], journal
    )
    (raw,) = emit.received
    assert raw.truncated is True and raw.original_size == len(inner)
    assert raw.raw.startswith(b"Subject: Factura 123\r\n") and raw.raw.endswith(b"\r\n\r\n")
    assert b"MicrosoftExchange" not in raw.raw  # headers del mail original, no del envoltorio
    assert raw.ref.mailbox == "ventas@empresa.com"


async def test_message_over_hard_cap_is_rejected(start_journal, settings):
    settings.limits.max_message_bytes = 4096
    emit = RecordingEmit()
    conn = await start_journal(emit)
    big = build_eml(text="A" * 10_000)
    assert len(big) > conn.hard_cap_bytes
    # smtplib declara SIZE= y aiosmtpd rechaza en MAIL FROM
    with pytest.raises(smtplib.SMTPSenderRefused) as info:
        await asyncio.to_thread(_sendmail, conn.port, "a@proveedor.com", ["ventas@empresa.com"], big)
    assert info.value.smtp_code == 552

    # sin SIZE: el límite se aplica mientras llega el DATA
    def _no_size() -> tuple[int, bytes]:
        with smtplib.SMTP("127.0.0.1", conn.port, timeout=10) as s:
            s.ehlo("mx.empresa.com")
            s.mail("a@proveedor.com")
            s.rcpt("ventas@empresa.com")
            return s.data(big)

    code, _ = await asyncio.to_thread(_no_size)
    assert code == 552
    assert emit.received == []


async def test_emit_failure_returns_tempfail(start_journal):
    emit = RecordingEmit(exc=RuntimeError("cola caída"))
    conn = await start_journal(emit)
    with pytest.raises(smtplib.SMTPDataError) as info:
        await asyncio.to_thread(_sendmail, conn.port, "a@proveedor.com", ["ventas@empresa.com"], build_eml())
    assert info.value.smtp_code == 451  # el remitente reintenta: no se pierde la copia


async def test_slow_emit_answers_250_and_keeps_running(start_journal):
    emit = RecordingEmit(delay=0.5)
    conn = await start_journal(emit)
    conn.emit_timeout_s = 0.05
    refused = await asyncio.to_thread(
        _sendmail, conn.port, "a@proveedor.com", ["ventas@empresa.com"], build_eml()
    )
    assert refused == {}
    assert not emit.finished.is_set()
    await asyncio.wait_for(emit.finished.wait(), 5)


async def test_recipient_limit(start_journal):
    emit = RecordingEmit()
    conn = await start_journal(emit)
    conn.max_recipients = 2
    refused = await asyncio.to_thread(
        _sendmail,
        conn.port,
        "a@proveedor.com",
        ["a@empresa.com", "b@empresa.com", "c@empresa.com"],
        build_eml(),
    )
    assert list(refused) == ["c@empresa.com"]
    assert refused["c@empresa.com"][0] == 452
    assert len(emit.received) == 1


async def test_hostile_journal_lookalike_does_not_break_ingest(start_journal):
    emit = RecordingEmit()
    conn = await start_journal(emit)
    rnd = random.Random(7)
    garbage = (
        b"X-MS-Journal-Report:\r\nContent-Type: multipart/mixed; boundary=zz\r\n\r\n--zz\r\n"
        + base64.b64encode(rnd.randbytes(3000))
        + b"\r\n--zz\r\nContent-Type: message/rfc822\r\nContent-Transfer-Encoding: base64\r\n\r\n!!!$$$\r\n--zz--\r\n"
    )
    await asyncio.to_thread(_sendmail, conn.port, "a@proveedor.com", ["ventas@empresa.com"], garbage)
    assert emit.received[0].raw == garbage
    assert len(emit.received[0].ref.remote_id) == 64  # sin Message-ID: sha256


# --------------------------------------------------------------------------- TLS


def _make_cert(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "centinela.test")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("centinela.test")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_file, key_file = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    return cert_file, key_file


async def test_require_tls(start_journal, tmp_path):
    cert_file, key_file = _make_cert(tmp_path)
    emit = RecordingEmit()
    conn = await start_journal(emit, require_tls=True, tls_cert_file=cert_file, tls_key_file=key_file)
    with pytest.raises(smtplib.SMTPSenderRefused) as info:
        await asyncio.to_thread(_sendmail, conn.port, "a@proveedor.com", ["ventas@empresa.com"], build_eml())
    assert info.value.smtp_code == 530
    assert emit.received == []
    refused = await asyncio.to_thread(
        _sendmail, conn.port, "a@proveedor.com", ["ventas@empresa.com"], build_eml(), tls=True
    )
    assert refused == {}
    assert len(emit.received) == 1


async def test_data_hook_enforces_tls_when_required(settings, tmp_path):
    cert_file, key_file = _make_cert(tmp_path)
    cfg = SmtpJournalConnectorConfig(
        type="smtp_journal", name="copias", require_tls=True, tls_cert_file=cert_file, tls_key_file=key_file
    )
    conn = SmtpJournalConnector(cfg, settings, MemoryStateStore())
    conn._emit = RecordingEmit()
    envelope = SimpleNamespace(
        original_content=b"Subject: x\r\n\r\nx\r\n", content=None, rcpt_tos=["a@empresa.com"]
    )
    reply = await sj._Handler(conn).handle_DATA(
        None, SimpleNamespace(peer=("127.0.0.1", 1), ssl=None), envelope
    )
    assert reply.startswith("530")


def test_config_validation_happens_when_loading_config(tmp_path):
    """Los errores de config se detectan al cargarla (validadores de SmtpJournalConnectorConfig)."""
    with pytest.raises(ValidationError, match="allowed_senders"):
        SmtpJournalConnectorConfig(type="smtp_journal", name="c", allowed_senders=["mail.proveedor.com"])
    with pytest.raises(ValidationError, match="require_tls"):
        SmtpJournalConnectorConfig(type="smtp_journal", name="c", require_tls=True)
    with pytest.raises(ValidationError, match="juntos"):
        SmtpJournalConnectorConfig(type="smtp_journal", name="c", tls_cert_file=tmp_path / "c.pem")


async def test_unvalidated_config_fails_closed_without_raising(settings, tmp_path, caplog):
    """Una config que se saltee la validación no tira abajo el proceso: el conector falla CERRADO."""
    bad_senders = SmtpJournalConnectorConfig.model_construct(
        type="smtp_journal", name="c", allowed_senders=["mail.proveedor.com"]
    )
    conn = SmtpJournalConnector(bad_senders, settings, MemoryStateStore())
    assert conn.networks == ()
    conn._emit = RecordingEmit()
    envelope = SimpleNamespace(original_content=_crlf(build_eml()), content=None, rcpt_tos=["a@empresa.com"])
    for peer in (("127.0.0.1", 1), ("192.168.1.20", 1)):  # ni siquiera loopback/privadas
        reply = await sj._Handler(conn).handle_DATA(None, SimpleNamespace(peer=peer, ssl=None), envelope)
        assert reply.startswith("550")
    assert conn._emit.received == []

    no_cert = SmtpJournalConnectorConfig.model_construct(type="smtp_journal", name="c", require_tls=True)
    conn = SmtpJournalConnector(no_cert, settings, MemoryStateStore())
    conn._emit = RecordingEmit()
    assert conn._tls_context() is None
    reply = await sj._Handler(conn).handle_DATA(
        None, SimpleNamespace(peer=("127.0.0.1", 1), ssl=None), envelope
    )
    assert reply.startswith("530")  # sin TLS posible: se rechaza todo, nunca se acepta en claro

    half = SmtpJournalConnectorConfig.model_construct(
        type="smtp_journal", name="c", tls_cert_file=tmp_path / "c.pem"
    )
    assert SmtpJournalConnector(half, settings, MemoryStateStore())._tls_context() is None
    assert "allowed_senders" in caplog.text and "require_tls" in caplog.text and "juntos" in caplog.text


async def test_run_stop_and_healthcheck(settings):
    cfg = SmtpJournalConnectorConfig(
        type="smtp_journal", name="copias", listen_host="127.0.0.1", listen_port=0
    )
    conn = SmtpJournalConnector(cfg, settings, MemoryStateStore())
    stop = asyncio.Event()
    task = asyncio.create_task(conn.run(RecordingEmit(), stop))
    await asyncio.wait_for(conn.ready.wait(), 5)
    assert (await conn.healthcheck())["ok"] is True
    reader, writer = await asyncio.open_connection("127.0.0.1", conn.port)
    assert (await asyncio.wait_for(reader.readline(), 5)).startswith(b"220 ")
    stop.set()  # con una sesión SMTP abierta
    await asyncio.wait_for(task, 10)
    assert (await conn.healthcheck())["ok"] is False
    writer.close()


# --------------------------------------------------------------------------- permisos de red


def test_default_networks_are_loopback_and_private():
    nets = parse_allowed_networks([])
    allowed = [
        ("127.0.0.1", 25),
        ("::1", 25, 0, 0),
        ("10.1.2.3", 25),
        ("172.20.0.1", 25),
        ("192.168.0.9", 25),
        ("fd12:3456::1", 25, 0, 0),
        ("::ffff:192.168.1.5", 25, 0, 0),
    ]
    denied = [
        ("8.8.8.8", 25),
        ("172.32.0.1", 25),
        ("2001:db8::1", 25, 0, 0),
        ("::ffff:8.8.8.8", 25, 0, 0),
        ("169.254.1.1", 25),
        ("100.64.0.1", 25),
    ]
    for peer in allowed:
        assert peer_allowed(peer, nets), peer
    for peer in denied:
        assert not peer_allowed(peer, nets), peer


def test_explicit_networks_and_garbage_peers():
    nets = parse_allowed_networks(["203.0.113.0/24", "2001:db8::/32", " 198.51.100.7 "])
    assert peer_allowed(("203.0.113.200", 1), nets)
    assert peer_allowed(("198.51.100.7", 1), nets)
    assert peer_allowed(("2001:db8::5%eth0", 1, 0, 0), nets)
    assert not peer_allowed(("127.0.0.1", 1), nets)  # lista explícita: loopback ya no entra solo
    for peer in (None, "", ("no-es-ip", 1), (), 12345):
        assert not peer_allowed(peer, nets)
    assert ipaddress.ip_network("10.0.0.0/8") in parse_allowed_networks([])


# --------------------------------------------------------------------------- unwrap_journal (puro)


def test_unwrap_valid_report():
    result = unwrap_journal(build_journal())
    assert result is not None
    assert result.inner == INNER
    assert result.recipients == ["otro@externo.com", "ventas@empresa.com", "jefe@empresa.com"]


def test_unwrap_organization_header_and_base64_inner():
    result = unwrap_journal(
        build_journal(journal_header="X-MS-Exchange-Organization-Journal-Report", inner_cte="base64")
    )
    assert result is not None and result.inner == INNER


def test_unwrap_without_report_part():
    result = unwrap_journal(build_journal(report=None))
    assert result is not None and result.inner == INNER and result.recipients == []


def test_unwrap_non_ascii_subject():
    inner = _crlf(build_eml(subject="Factura mañana"))  # EmailMessage lo codifica como encoded-word
    report = "Sender: juan@proveedor.com\r\nSubject: Factura mañana\r\nTo: ventas@empresa.com\r\n"
    result = unwrap_journal(build_journal(inner=inner, report=report))
    assert result is not None and result.inner == inner


def test_unwrap_tolerates_missing_close_delimiter():
    result = unwrap_journal(build_journal(close=False))
    assert result is not None
    assert result.inner.startswith(INNER[:200])


@pytest.mark.parametrize(
    "kwargs",
    [
        {"journal_header": None},  # sin header de journaling: es un mail común con un .eml adjunto
        {"report": REPORT + "Haga clic: http://phish.example\r\n"},  # texto libre escondido
        {"report": REPORT.replace("Subject: Factura 123", "Subject: Otra cosa http://phish.example")},
        {"report": REPORT.replace("<test-1@proveedor.com>", "<otro@proveedor.com>")},  # Message-Id distinto
        {"report": "To: http://phish.example\r\n"},  # destinatario que no es dirección
        {"report": "To: ventas@empresa.com, Clic: http://x\r\n"},  # subcampo desconocido
        {"report": "Sender: no es un mail\r\n"},
        {"extra_parts": [b"Content-Type: application/octet-stream\r\n\r\nMZ\x90\x00"]},  # adjunto extra
        {"extra_parts": [b"Content-Type: message/rfc822\r\n\r\n" + INNER]},  # dos mails adjuntos
        {"inner": b""},  # rfc822 vacío
        {"inner_cte": "base64", "inner": b""},
    ],
)
def test_unwrap_rejects_suspicious_or_invalid_envelopes(kwargs):
    assert unwrap_journal(build_journal(**kwargs)) is None


def test_unwrap_report_whitespace_is_tolerated_and_linear():
    report = "Sender:   juan@proveedor.com  \r\nTo:" + " " * 200_000 + "ventas@empresa.com\t\r\n"
    result = unwrap_journal(build_journal(report=report))
    assert result is not None and result.recipients == ["ventas@empresa.com"]


def test_unwrap_rejects_too_many_parts():
    parts = [b"Content-Type: text/plain\r\n\r\nx"] * 100
    assert unwrap_journal(build_journal(extra_parts=parts)) is None


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\r\n\r\n",
        b"X-MS-Journal-Report:\r\n\r\nhola",  # no es multipart
        b"X-MS-Journal-Report:\r\nContent-Type: multipart/mixed\r\n\r\n--x\r\n",  # sin boundary
        b"X-MS-Journal-Report:\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\nsin delimitadores",
        b"X-MS-Journal-Report:\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n--x--\r\n",  # solo cierre
        b"X-MS-Journal-Report:" + b"A" * 2_000_000,  # header gigante sin línea en blanco
    ],
    ids=["empty", "blank", "not-multipart", "no-boundary", "no-delimiters", "only-close", "giant-header"],
)
def test_unwrap_malformed_returns_none(raw):
    assert unwrap_journal(raw) is None


def test_unwrap_random_garbage_never_raises():
    rnd = random.Random(99)
    prefix = b"X-MS-Journal-Report:\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n"
    for _ in range(200):
        blob = prefix + rnd.randbytes(rnd.randint(0, 2000)).replace(b"\x00", b"--b\r\n")
        unwrap_journal(blob)  # no debe lanzar


# --------------------------------------------------------------------------- helpers


def test_choose_mailbox_prefers_company_domain():
    assert (
        choose_mailbox(["otro@externo.com", "Ventas@Empresa.com"], [], ["empresa.com"])
        == "ventas@empresa.com"
    )
    assert choose_mailbox(["a@sub.empresa.com"], [], ["empresa.com"]) == "a@sub.empresa.com"
    assert choose_mailbox([], ["<journal@centinela.local>"], ["empresa.com"]) == "journal@centinela.local"
    assert choose_mailbox([], [], ["empresa.com"]) == "desconocido"
    assert choose_mailbox(["x@noempresa.com"], [], ["empresa.com"]) == "x@noempresa.com"


def test_remote_id_resists_message_id_reuse():
    a = b"Message-ID: <same@x>\r\n\r\nbenigno\r\n"
    b = b"Message-ID: <same@x>\r\n\r\nmalicioso\r\n"
    assert remote_id_for(a) != remote_id_for(b)
    assert remote_id_for(a).startswith("<same@x>#")
    assert remote_id_for(a) == remote_id_for(a)
    no_id = b"Subject: x\r\n\r\ny"
    assert remote_id_for(no_id) == hashlib.sha256(no_id).hexdigest()
