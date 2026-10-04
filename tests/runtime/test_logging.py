from __future__ import annotations

import io
import json
import logging
import time

import pytest

from centinela.core.config import Settings
from centinela.logging_setup import MAX_RECORD_CHARS, REDACTED, RedactingFilter, redact, setup_logging

TG_TOKEN = "123456789:AAHfakeTokenForTestsOnly_abcdefghijklmn"


@pytest.fixture
def restore_logging():
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    levels = {n: logging.getLogger(n).level for n in ("httpx", "httpcore", "msal", "sqlalchemy.engine")}
    yield
    for h in list(root.handlers):
        if h not in handlers:
            root.removeHandler(h)
    root.setLevel(level)
    for n, lvl in levels.items():
        logging.getLogger(n).setLevel(lvl)


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("login con password=hunter2 falló", "hunter2"),
        ('{"client_secret": "s3cr3t-valor", "x": 1}', "s3cr3t-valor"),
        ("Authorization: Bearer eyabc.def.ghi-token-largo", "eyabc.def.ghi-token-largo"),
        ("authorization=Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
        ("headers={'Authorization': 'Bearer abcdefgh12345678'}", "abcdefgh12345678"),
        (f"POST https://api.telegram.org/bot{TG_TOKEN}/sendMessage", TG_TOKEN.split(":")[1]),
        (f"token suelto {TG_TOKEN}", TG_TOKEN.split(":")[1]),
        ("conectando a postgresql+asyncpg://centinela:SuperSecreta@db:5432/c", "SuperSecreta"),
        ("redis://:otraClave99@redis:6379/0", "otraClave99"),
        ("https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXX"),
        ("https://discord.com/api/webhooks/1234/abcDEF-ghi", "abcDEF-ghi"),
        (
            "https://empresa.webhook.office.com/webhookb2/abc@def/IncomingWebhook/123/456",
            "IncomingWebhook/123",
        ),
        ("jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLXRlc3Q", "c2lnbmF0dXJlLXRlc3Q"),
        ("google key AIzaSyA-1234567890abcdefghijklmnopqrstu", "AIzaSyA-1234567890abcdefghijklmnopqrstu"),
        ("oauth ya29.a0AfH6SMfakefakefakefake", "a0AfH6SMfakefakefakefake"),
        ("refresh 1//0gFakeRefreshTokenForTestsOnly", "0gFakeRefreshTokenForTestsOnly"),
        ("MB_API_KEY=0123456789abcdef0123456789abcdef", "0123456789abcdef0123456789abcdef"),
        ("x-apikey: vt-0123456789abcdef", "vt-0123456789abcdef"),
        ("?access_token=abc123xyz&foo=bar", "abc123xyz"),
        ("AUTH PLAIN AGp1YW4AY2xhdmVzZWNyZXRh", "AGp1YW4AY2xhdmVzZWNyZXRh"),
        ("-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nabc\n-----END RSA PRIVATE KEY-----", "MIIEow"),
    ],
)
def test_redact_hides_secrets(text, secret):
    out = redact(text)
    assert secret not in out
    assert REDACTED in out


@pytest.mark.parametrize(
    "text",
    [
        "mensaje analizado: 5f1c... nivel=malicious score=95 hallazgos=3 250ms",
        "Centinela 0.1.0 listo (rol=all, base=sqlite, cola=memoria)",
        "sha256=" + "a" * 64,
        "conector imap1 reconectando a imap.gmail.com:993",
        "no se pudo renovar el token del conector",
    ],
)
def test_redact_keeps_harmless_text(text):
    assert redact(text) == text


def test_redact_is_linear_on_hostile_input():
    hostile = [
        "password" * 3000,
        "a" * 20000,
        "token=" + "x" * 20000,
        "bot" + "1" * 20000,
        "-----BEGIN RSA PRIVATE KEY-----" * 500,
        "authorization:" * 2000,
        ("Bearer " + "A" * 50 + " ") * 400,
        "postgres://" + "u" * 5000 + ":" + "p" * 5000,
    ]
    for text in hostile:
        t0 = time.perf_counter()
        redact(text)
        assert time.perf_counter() - t0 < 1.0, text[:40]


def test_redact_truncates_huge_messages():
    out = redact("x" * (MAX_RECORD_CHARS * 3))
    assert len(out) < MAX_RECORD_CHARS + 100 and "truncado" in out


def test_json_logging_redacts_message_args_extra_and_traceback(restore_logging):
    stream = io.StringIO()
    setup_logging(Settings(), stream=stream)
    log = logging.getLogger("centinela.test")
    log.info(
        "conectando con %s",
        "password=hunter2",
        extra={"api_key": "k-123", "mailbox": "ventas@empresa.com", "raw": b"\x00" * 50},
    )
    try:
        raise RuntimeError(f"falló https://api.telegram.org/bot{TG_TOKEN}/getMe")
    except RuntimeError:
        log.exception("error del canal")
    lines = [json.loads(line) for line in stream.getvalue().splitlines()]
    assert len(lines) == 2
    first, second = lines
    assert first["level"] == "INFO" and first["logger"] == "centinela.test"
    assert "hunter2" not in first["msg"] and REDACTED in first["msg"]
    assert first["api_key"] == REDACTED and first["mailbox"] == "ventas@empresa.com"
    assert first["raw"] == "<50 bytes>"
    assert "ts" in first and first["ts"].endswith("+00:00")
    assert TG_TOKEN not in json.dumps(second) and "RuntimeError" in second["exc"]


def test_plain_logging_and_idempotent_setup(restore_logging):
    stream = io.StringIO()
    s = Settings()
    s.general.log_json = False
    s.general.log_level = "warning"
    setup_logging(s, stream=io.StringIO())
    handler = setup_logging(s, stream=stream)
    root = logging.getLogger()
    ours = [h for h in root.handlers if getattr(h, "_centinela_handler", False)]
    assert ours == [handler]
    assert root.level == logging.WARNING
    logging.getLogger("x").info("no se ve")
    logging.getLogger("x").warning("token=abc123 visible")
    out = stream.getvalue()
    assert "no se ve" not in out and "WARNING" in out and "abc123" not in out
    assert logging.getLogger("httpx").level >= logging.WARNING


def test_unknown_level_falls_back_to_info(restore_logging):
    setup_logging(level="RARO", json_format=True, stream=io.StringIO())
    assert logging.getLogger().level == logging.INFO


def test_filter_handles_broken_format_args():
    record = logging.LogRecord("x", logging.INFO, __file__, 1, "valor %d %d", ("uno",), None)
    assert RedactingFilter().filter(record) is True
    assert "args no formateables" in record.getMessage()
