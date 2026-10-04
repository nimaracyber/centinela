"""EmailChannel contra un servidor SMTP local (aiosmtpd en 127.0.0.1, puerto efímero)."""

from __future__ import annotations

import ipaddress
import logging
import socket
import ssl
import traceback
from datetime import UTC, datetime, timedelta
from email import message_from_bytes, policy

import pytest
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult, LoginPassword
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from centinela.actions.alerts import AlertDeliveryError
from centinela.actions.alerts.email import EmailChannel
from centinela.core.config import EmailAlertConfig
from tests.alerts.conftest import BODY_SECRET, PHISH_URL, SHA_EXE, stealer_result

PASSWORD = "clave-smtp-SECRETA-123"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Capture:
    """Handler de aiosmtpd: guarda cada mensaje; puede rechazar destinatarios."""

    def __init__(self, reject: set[str] | None = None) -> None:
        self.messages: list[tuple[str, list[str], bytes]] = []
        self.reject = {r.lower() for r in reject or set()}

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        if address.lower() in self.reject:
            return "550 5.1.1 No such user"
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        self.messages.append((envelope.mail_from, list(envelope.rcpt_tos), envelope.content))
        return "250 Message accepted for delivery"


class Smtpd:
    def __init__(self, handler: Capture, **kwargs) -> None:
        self.port = free_port()
        self.controller = Controller(handler, hostname="127.0.0.1", port=self.port, **kwargs)

    def __enter__(self) -> Smtpd:
        self.controller.start()
        return self

    def __exit__(self, *exc) -> None:
        self.controller.stop()


def make_channel(settings, http, port: int, **kw) -> EmailChannel:
    data = {
        "type": "email",
        "name": "mail",
        "smtp_host": "127.0.0.1",
        "smtp_port": port,
        "security": "none",
        "from_addr": "centinela@empresa.com",
        "to": ["it@empresa.com"],
    }
    data.update(kw)
    return EmailChannel(EmailAlertConfig(**data), settings, http)


def parse(raw: bytes):
    return message_from_bytes(raw, policy=policy.default)


# --------------------------------------------------------------------------- TLS de prueba


@pytest.fixture(scope="module")
def tls_files(tmp_path_factory):
    """CA propia + certificado de servidor para 127.0.0.1 (generados en el test, nunca reales)."""
    return _issue_tls(
        tmp_path_factory.mktemp("tls"),
        [x509.IPAddress(ipaddress.ip_address("127.0.0.1")), x509.DNSName("localhost")],
        "127.0.0.1",
    )


@pytest.fixture(scope="module")
def wrong_name_tls(tmp_path_factory):
    """CA propia + certificado válido pero emitido para OTRO nombre (no para 127.0.0.1)."""
    return _issue_tls(tmp_path_factory.mktemp("tls-otro"), [x509.DNSName("otro.example")], "otro.example")


def _issue_tls(d, sans: list, common_name: str):
    now = datetime.now(UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Centinela Test CA")])
    ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(ca_ski, critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    ca_file, cert_file, key_file = d / "ca.pem", d / "server.pem", d / "server.key"
    ca_file.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    return ca_file, cert_file, key_file


def server_ctx(tls_files) -> ssl.SSLContext:
    _, cert_file, key_file = tls_files
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_file, key_file)
    return ctx


def trusting(channel: EmailChannel, ca_file) -> EmailChannel:
    """El canal verifica certificados igual que en producción, pero confiando en la CA de prueba."""
    channel._ssl_context = lambda: ssl.create_default_context(cafile=str(ca_file))  # type: ignore[method-assign]
    return channel


class Auth:
    def __init__(self) -> None:
        self.seen: list[tuple[bytes, bytes]] = []

    def __call__(self, server, session, envelope, mechanism, auth_data):
        if isinstance(auth_data, LoginPassword):
            self.seen.append((auth_data.login, auth_data.password))
            if auth_data.login == b"alertas@empresa.com" and auth_data.password == PASSWORD.encode():
                return AuthResult(success=True)
        return AuthResult(success=False, handled=False)


# --------------------------------------------------------------------------- tests


async def test_sends_multipart_alert(alert_settings, http):
    handler = Capture()
    with Smtpd(handler) as srv:
        await make_channel(alert_settings, http, srv.port).send(stealer_result())
    assert len(handler.messages) == 1
    mail_from, rcpts, raw = handler.messages[0]
    assert mail_from == "centinela@empresa.com"
    assert rcpts == ["it@empresa.com"]
    msg = parse(raw)
    assert msg["Subject"] == "[Centinela] 🔴 Mail malicioso: Factura vencida N° 4471"
    assert msg["From"] == "Centinela <centinela@empresa.com>"
    assert msg["Auto-Submitted"] == "auto-generated"
    assert msg["X-Auto-Response-Suppress"] == "All"
    assert msg["X-Centinela-Verdict"] == "malicious"
    assert msg["Importance"] == "high"
    assert msg.get_content_type() == "multipart/alternative"
    parts = [p.get_content_type() for p in msg.iter_parts()]
    assert parts == ["text/plain", "text/html"]
    text = msg.get_body(("plain",)).get_content()
    html = msg.get_body(("html",)).get_content()
    assert "QUÉ HACER" in text and SHA_EXE in text
    assert "<!DOCTYPE html>" in html and "Qué hacer" in html
    for content in (text, html, raw.decode("utf-8", "replace")):
        assert BODY_SECRET not in content
        assert PHISH_URL not in content
    assert "hxxps://pagos-afip[.]com" in text


async def test_notify_recipient_sends_soft_variant_to_company_recipients(alert_settings, http):
    handler = Capture()
    with Smtpd(handler) as srv:
        ch = make_channel(
            alert_settings,
            http,
            srv.port,
            notify_recipient=True,
            to=["it@empresa.com", "Ventas <ventas@empresa.com>"],
        )
        await ch.send(
            stealer_result(
                to=[
                    "ventas@empresa.com",
                    "Juan <juan@empresa.com>",
                    "cliente@externo.com",
                    "x@sub.empresa.com",
                    "malo\r\nBcc: a@b.com",
                ]
            )
        )
    assert len(handler.messages) == 2
    _, admin_rcpts, _ = handler.messages[0]
    assert admin_rcpts == ["it@empresa.com", "ventas@empresa.com"]
    _, rcpts, raw = handler.messages[1]
    # solo destinatarios de la empresa que no son ya admins; nunca externos
    assert rcpts == ["juan@empresa.com", "x@sub.empresa.com"]
    msg = parse(raw)
    assert msg["Subject"].startswith("[Centinela] 🔴 Cuidado con este mail:")
    body = msg.get_body(("plain",)).get_content()
    assert "Hola:" in body and "Ferretería El Tornillo" in body
    assert "SHA-256" not in body and SHA_EXE not in body


async def test_notify_recipient_disabled_or_no_company_domains(settings, http):
    handler = Capture()
    settings.general.company_domains = []
    with Smtpd(handler) as srv:
        await make_channel(settings, http, srv.port, notify_recipient=True).send(stealer_result())
    assert len(handler.messages) == 1


async def test_recipient_failure_does_not_fail_admin_alert(alert_settings, http, caplog):
    handler = Capture(reject={"juan@empresa.com"})
    with Smtpd(handler) as srv:
        ch = make_channel(alert_settings, http, srv.port, notify_recipient=True)
        with caplog.at_level(logging.WARNING):
            await ch.send(stealer_result(to=["juan@empresa.com"]))
    assert len(handler.messages) == 1  # la alerta principal salió
    assert "no se pudo avisar al destinatario" in caplog.text


async def test_starttls_with_auth_and_cert_verification(alert_settings, http, tls_files):
    ca_file, _, _ = tls_files
    handler, auth = Capture(), Auth()
    with Smtpd(
        handler,
        tls_context=server_ctx(tls_files),
        require_starttls=True,
        auth_required=True,
        auth_require_tls=True,
        authenticator=auth,
    ) as srv:
        ch = make_channel(
            alert_settings,
            http,
            srv.port,
            security="starttls",
            username="alertas@empresa.com",
            password=PASSWORD,
        )
        await trusting(ch, ca_file).send(stealer_result())
    assert auth.seen == [(b"alertas@empresa.com", PASSWORD.encode())]
    assert len(handler.messages) == 1


async def test_starttls_rejects_untrusted_certificate(alert_settings, http, tls_files):
    handler = Capture()
    with Smtpd(handler, tls_context=server_ctx(tls_files), require_starttls=True) as srv:
        ch = make_channel(
            alert_settings,
            http,
            srv.port,
            security="starttls",
            username="alertas@empresa.com",
            password=PASSWORD,
        )
        with pytest.raises(AlertDeliveryError) as ei:
            await ch.send(stealer_result())  # contexto por defecto: la CA de prueba no es confiable
    assert "TLS" in str(ei.value) or "certific" in str(ei.value).lower()
    assert "ca_file" in str(ei.value)  # pista para relays con CA propia
    assert ei.value.retryable is False  # reintentar no arregla un certificado inválido
    assert PASSWORD not in "".join(traceback.format_exception(ei.value))
    assert handler.messages == []


async def test_ca_file_trusts_internal_ca_for_starttls(alert_settings, http, tls_files):
    """Relay interno con certificado de una CA propia: con ca_file se verifica y se entrega."""
    ca_file, _, _ = tls_files
    handler, auth = Capture(), Auth()
    with Smtpd(
        handler,
        tls_context=server_ctx(tls_files),
        require_starttls=True,
        auth_required=True,
        auth_require_tls=True,
        authenticator=auth,
    ) as srv:
        ch = make_channel(
            alert_settings,
            http,
            srv.port,
            security="starttls",
            username="alertas@empresa.com",
            password=PASSWORD,
            ca_file=str(ca_file),
        )
        await ch.send(stealer_result())  # sin parchear _ssl_context: usa la config real
    assert len(handler.messages) == 1


async def test_ca_file_with_implicit_ssl(alert_settings, http, tls_files):
    ca_file, _, _ = tls_files
    handler = Capture()
    with Smtpd(handler, ssl_context=server_ctx(tls_files)) as srv:
        ch = make_channel(alert_settings, http, srv.port, security="ssl", ca_file=str(ca_file))
        await ch.send(stealer_result())
    assert len(handler.messages) == 1


async def test_ca_file_still_verifies_hostname(alert_settings, http, wrong_name_tls):
    """La CA propia no desactiva la verificación: un certificado de esa CA para OTRO nombre se rechaza."""
    ca_file, _, _ = wrong_name_tls
    handler = Capture()
    with Smtpd(handler, tls_context=server_ctx(wrong_name_tls), require_starttls=True) as srv:
        ch = make_channel(alert_settings, http, srv.port, security="starttls", ca_file=str(ca_file))
        with pytest.raises(AlertDeliveryError) as ei:
            await ch.send(stealer_result())
    assert ei.value.retryable is False
    assert "certificado" in str(ei.value)
    assert handler.messages == []


def test_ca_file_missing_or_invalid_rejected_at_startup(settings, http, tmp_path):
    with pytest.raises(ValueError, match="ca_file"):
        make_channel(settings, http, 587, security="starttls", ca_file=str(tmp_path / "no-existe.pem"))
    bad = tmp_path / "roto.pem"
    bad.write_text("esto no es un certificado", encoding="utf-8")
    with pytest.raises(ValueError, match="ca_file"):
        make_channel(settings, http, 587, security="starttls", ca_file=str(bad))
    with pytest.raises(ValueError, match="ca_file"):
        make_channel(settings, http, 587, security="starttls", ca_file=str(tmp_path))  # un directorio


async def test_starttls_required_but_not_offered(alert_settings, http):
    handler = Capture()
    with Smtpd(handler) as srv:  # sin tls_context: el server no anuncia STARTTLS
        ch = make_channel(alert_settings, http, srv.port, security="starttls")
        with pytest.raises(AlertDeliveryError):
            await ch.send(stealer_result())
    assert handler.messages == []


async def test_implicit_ssl(alert_settings, http, tls_files):
    ca_file, _, _ = tls_files
    handler = Capture()
    with Smtpd(handler, ssl_context=server_ctx(tls_files)) as srv:
        ch = make_channel(alert_settings, http, srv.port, security="ssl")
        await trusting(ch, ca_file).send(stealer_result())
    assert len(handler.messages) == 1


async def test_bad_credentials_not_retryable_and_password_hidden(alert_settings, http, tls_files):
    ca_file, _, _ = tls_files
    handler, auth = Capture(), Auth()
    with Smtpd(handler, tls_context=server_ctx(tls_files), auth_required=True, authenticator=auth) as srv:
        ch = make_channel(
            alert_settings,
            http,
            srv.port,
            security="starttls",
            username="alertas@empresa.com",
            password="otra-clave-mala",
        )
        with pytest.raises(AlertDeliveryError) as ei:
            await trusting(ch, ca_file).send(stealer_result())
    assert ei.value.retryable is False
    assert "otra-clave-mala" not in "".join(traceback.format_exception(ei.value))


async def test_connection_refused(alert_settings, http):
    ch = make_channel(alert_settings, http, free_port())
    with pytest.raises(AlertDeliveryError) as ei:
        await ch.send(stealer_result())
    assert "no se pudo conectar" in str(ei.value)


def test_no_credentials_over_plaintext(settings, http):
    with pytest.raises(ValueError, match="sin cifrar"):
        make_channel(settings, http, 25, security="none", username="u", password="p")


@pytest.mark.parametrize(
    "kw",
    [
        {"from_addr": "no-es-mail"},
        {"to": []},
        {"to": ["ok@empresa.com", "roto\r\nBcc: x@y.com"]},
    ],
)
def test_invalid_addresses_rejected(settings, http, kw):
    with pytest.raises(ValueError):
        make_channel(settings, http, 25, **kw)


def test_subject_never_contains_newlines(alert_settings, http):
    ch = make_channel(alert_settings, http, 25)
    from centinela.actions.alerts.format import build_alert

    alert = build_alert(stealer_result(subject="hola\r\nBcc: victima@x.com\r\n\r\ncuerpo"), alert_settings)
    msg = ch.build_admin_message(alert)
    assert "\n" not in msg["Subject"] and "\r" not in msg["Subject"]
    assert msg["Bcc"] is None
