from __future__ import annotations

import logging

import pytest

from centinela.actions.alerts import (
    CHANNEL_TYPES,
    AlertChannel,
    AlertDeliveryError,
    AlertRateLimitedError,
    build_channels,
    channel_class,
    describe_exception,
    meets_min_level,
    parse_retry_after,
    redact,
    register_secret,
)
from centinela.actions.alerts.email import EmailChannel
from centinela.actions.alerts.syslog import SyslogChannel
from centinela.actions.alerts.telegram import TelegramChannel
from centinela.actions.alerts.webhook import WebhookChannel
from centinela.core.config import Settings
from centinela.core.models import VerdictLevel

TG_TOKEN = "987654321:AAFakeTokenForRegistryTests_abcdef"


def settings_with(channels: list[dict]) -> Settings:
    return Settings.model_validate({"actions": {"alerts": {"channels": channels}}})


MIXED = [
    {
        "type": "email",
        "name": "mail-it",
        "smtp_host": "smtp.empresa.com",
        "from_addr": "centinela@empresa.com",
        "to": ["it@empresa.com"],
        "username": "centinela@empresa.com",
        "password": "x",
    },
    {"type": "telegram", "name": "tg", "bot_token": TG_TOKEN, "chat_id": "-100123"},
    {
        "type": "webhook",
        "name": "slack",
        "url": "https://hooks.slack.com/services/T/B/XXXXXXXXXXXX",
        "format": "slack",
    },
    {
        "type": "webhook",
        "name": "teams",
        "url": "https://prod.westus.logic.azure.com/workflows/abc/triggers/manual/paths/invoke?sig=ZZZZ",
        "format": "teams",
    },
    {"type": "syslog", "name": "wazuh", "host": "10.0.0.9", "protocol": "tcp", "min_level": "malicious"},
    {"type": "telegram", "name": "apagado", "bot_token": TG_TOKEN, "chat_id": "1", "enabled": False},
]


def test_build_channels_mixed(http):
    channels = build_channels(settings_with(MIXED), http)
    assert [type(c) for c in channels] == [
        EmailChannel,
        TelegramChannel,
        WebhookChannel,
        WebhookChannel,
        SyslogChannel,
    ]
    assert [c.name for c in channels] == ["mail-it", "tg", "slack", "teams", "wazuh"]
    assert all(isinstance(c, AlertChannel) for c in channels)
    assert channels[-1].config.min_level == "malicious"
    assert channels[2].config.format == "slack"


def test_build_channels_empty(http):
    assert build_channels(Settings(), http) == []


def test_broken_channel_is_skipped_and_logged_without_secret(http, caplog):
    bad_token = "malo/token?con=cosas-raras-y-largas-1234567890"
    cfg = [
        {"type": "telegram", "name": "roto", "bot_token": bad_token, "chat_id": "-1"},
        {"type": "syslog", "name": "siem", "host": "127.0.0.1"},
        {"type": "webhook", "name": "wh", "url": "ftp://nope.example.com/secret-path-abc"},
        {
            "type": "email",
            "name": "plano",
            "smtp_host": "h",
            "security": "none",
            "username": "u",
            "password": "p",
            "from_addr": "a@b.com",
            "to": ["c@d.com"],
        },
    ]
    with caplog.at_level(logging.ERROR):
        channels = build_channels(settings_with(cfg), http)
    assert [c.name for c in channels] == ["siem"]
    assert "roto" in caplog.text and "wh" in caplog.text and "plano" in caplog.text
    assert bad_token not in caplog.text
    assert "secret-path-abc" not in caplog.text


def test_duplicate_names_warn(http, caplog):
    cfg = [
        {"type": "syslog", "name": "dup", "host": "127.0.0.1"},
        {"type": "syslog", "name": "dup", "host": "127.0.0.2"},
    ]
    with caplog.at_level(logging.WARNING):
        channels = build_channels(settings_with(cfg), http)
    assert len(channels) == 2
    assert "más de un canal" in caplog.text


def test_channel_class_registry():
    assert set(CHANNEL_TYPES) == {"email", "telegram", "webhook", "syslog"}
    assert channel_class("webhook") is WebhookChannel
    assert channel_class("email").type == "email"
    with pytest.raises(KeyError):
        channel_class("sms")


@pytest.mark.parametrize(
    ("level", "min_level", "expected"),
    [
        (VerdictLevel.MALICIOUS, "suspicious", True),
        (VerdictLevel.SUSPICIOUS, "suspicious", True),
        (VerdictLevel.SUSPICIOUS, "malicious", False),
        (VerdictLevel.MALICIOUS, "malicious", True),
        (VerdictLevel.CLEAN, "suspicious", False),
        (VerdictLevel.ERROR, "suspicious", False),
        ("malicious", "suspicious", True),
    ],
)
def test_meets_min_level(level, min_level, expected):
    assert meets_min_level(level, min_level) is expected


def test_parse_retry_after():
    assert parse_retry_after(None, "12") == 12
    assert parse_retry_after("x", 1.5) == 1.5
    assert parse_retry_after(float("nan"), float("inf"), -3, True) == 30.0
    assert parse_retry_after(999_999) == 3600.0
    assert parse_retry_after(default=5) == 5


def test_redaction_helpers_and_log_filter(caplog):
    secret = "tok-1234567890-ultra"
    assert redact(f"url/{secret}/x", [secret, None, "ab"]) == "url/***/x"
    register_secret(secret)
    register_secret(secret)  # idempotente
    register_secret("corto")  # se ignora (demasiado corto para taparlo sin falsos positivos)
    with caplog.at_level(logging.INFO, logger="httpx"):
        logging.getLogger("httpx").info("HTTP Request: POST %s", f"https://api.example.com/bot{secret}/send")
    assert secret not in caplog.text and "***" in caplog.text
    assert describe_exception(ValueError(f"fallo {secret}"), [secret]) == "ValueError: fallo ***"


def test_exception_types():
    e = AlertRateLimitedError("x", channel="tg", status=429, retry_after=3.0)
    assert isinstance(e, AlertDeliveryError) and e.retryable and e.retry_after == 3.0
    assert AlertDeliveryError("y", retryable=False).retryable is False
