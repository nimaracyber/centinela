from __future__ import annotations

import json
import logging
import traceback

import httpx
import pytest
import respx

from centinela.actions.alerts import AlertDeliveryError, AlertRateLimitedError
from centinela.actions.alerts.telegram import TelegramChannel
from centinela.core.config import TelegramAlertConfig
from tests.alerts.conftest import stealer_result

TOKEN = "123456789:AAH-sup3rSecretTokenValue_xyz0123456"
URL = f"https://api.telegram.org/bot{TOKEN}/sendMessage"


def make_channel(settings, http, **kw) -> TelegramChannel:
    cfg = TelegramAlertConfig(
        type="telegram",
        name="tg",
        bot_token=kw.pop("token", TOKEN),
        chat_id=kw.pop("chat_id", "-1001234567890"),
        **kw,
    )
    return TelegramChannel(cfg, settings, http)


def assert_no_token(text: str) -> None:
    assert TOKEN not in text
    assert "sup3rSecret" not in text


@respx.mock
async def test_send_payload_shape(alert_settings, http):
    route = respx.post(URL).mock(
        return_value=httpx.Response(200, json={"ok": True, "result": {"message_id": 1}})
    )
    ch = make_channel(alert_settings, http)
    await ch.send(stealer_result())
    assert route.call_count == 1
    body = json.loads(route.calls[0].request.content)
    assert body["chat_id"] == -1001234567890
    assert body["parse_mode"] == "HTML"
    assert body["disable_web_page_preview"] is True
    assert body["link_preview_options"] == {"is_disabled": True}
    assert body["text"].startswith("<b>🔴 Mail malicioso detectado en ventas@empresa.com</b>")
    assert "hxxps://pagos-afip[.]com" in body["text"]
    assert len(body["text"].encode("utf-16-le")) // 2 <= 4096


@respx.mock
async def test_message_thread_id_sent_only_when_configured(alert_settings, http):
    route = respx.post(URL).mock(return_value=httpx.Response(200, json={"ok": True}))
    await make_channel(alert_settings, http).send(stealer_result())
    assert "message_thread_id" not in json.loads(route.calls[0].request.content)
    await make_channel(alert_settings, http, message_thread_id=42).send(stealer_result())
    assert json.loads(route.calls[1].request.content)["message_thread_id"] == 42


@respx.mock
async def test_message_thread_id_kept_in_plain_text_fallback(alert_settings, http):
    route = respx.post(URL).mock(
        side_effect=[
            httpx.Response(400, json={"ok": False, "description": "Bad Request: can't parse entities"}),
            httpx.Response(200, json={"ok": True}),
        ]
    )
    await make_channel(alert_settings, http, message_thread_id=7).send(stealer_result())
    assert json.loads(route.calls[1].request.content)["message_thread_id"] == 7


@respx.mock
async def test_unknown_thread_is_not_retryable(alert_settings, http):
    respx.post(URL).mock(
        return_value=httpx.Response(
            400, json={"ok": False, "error_code": 400, "description": "Bad Request: message thread not found"}
        )
    )
    with pytest.raises(AlertDeliveryError) as ei:
        await make_channel(alert_settings, http, message_thread_id=99).send(stealer_result())
    assert "message_thread_id=99" in str(ei.value) and ei.value.retryable is False


@pytest.mark.parametrize("bad", [0, -5, 2**40])
def test_invalid_thread_id_rejected(settings, http, bad):
    with pytest.raises(ValueError, match="message_thread_id"):
        make_channel(settings, http, message_thread_id=bad)


@respx.mock
async def test_channel_username_chat_id(alert_settings, http):
    route = respx.post(URL).mock(return_value=httpx.Response(200, json={"ok": True}))
    ch = make_channel(alert_settings, http, chat_id="@alertas_pyme")
    await ch.send(stealer_result())
    assert json.loads(route.calls[0].request.content)["chat_id"] == "@alertas_pyme"


@respx.mock
async def test_rate_limited_raises_with_retry_after(alert_settings, http):
    respx.post(URL).mock(
        return_value=httpx.Response(
            429,
            json={
                "ok": False,
                "error_code": 429,
                "description": "Too Many Requests: retry after 17",
                "parameters": {"retry_after": 17},
            },
        )
    )
    ch = make_channel(alert_settings, http)
    with pytest.raises(AlertRateLimitedError) as ei:
        await ch.send(stealer_result())
    assert ei.value.retry_after == 17
    assert ei.value.status == 429
    assert "17" in str(ei.value)
    assert_no_token(str(ei.value))


@respx.mock
async def test_parse_error_falls_back_to_plain_text(alert_settings, http):
    route = respx.post(URL).mock(
        side_effect=[
            httpx.Response(
                400,
                json={"ok": False, "error_code": 400, "description": "Bad Request: can't parse entities: x"},
            ),
            httpx.Response(200, json={"ok": True}),
        ]
    )
    ch = make_channel(alert_settings, http)
    await ch.send(stealer_result())
    assert route.call_count == 2
    second = json.loads(route.calls[1].request.content)
    assert "parse_mode" not in second
    assert second["text"].startswith("🔴 Mail malicioso detectado")
    assert "<b>" not in second["text"]


@respx.mock
async def test_error_never_leaks_token(alert_settings, http):
    respx.post(URL).mock(
        return_value=httpx.Response(
            401, json={"ok": False, "error_code": 401, "description": f"Unauthorized bot{TOKEN}"}
        )
    )
    ch = make_channel(alert_settings, http)
    with pytest.raises(AlertDeliveryError) as ei:
        await ch.send(stealer_result())
    assert ei.value.status == 401
    assert ei.value.retryable is False
    assert_no_token(str(ei.value))
    assert_no_token("".join(traceback.format_exception(ei.value)))


@respx.mock
async def test_network_error_redacted_and_unchained(alert_settings, http):
    respx.post(URL).mock(side_effect=httpx.ConnectError(f"no route to {URL}"))
    ch = make_channel(alert_settings, http)
    with pytest.raises(AlertDeliveryError) as ei:
        await ch.send(stealer_result())
    assert "error de red" in str(ei.value)
    assert_no_token(str(ei.value))
    assert ei.value.__cause__ is None and ei.value.__suppress_context__
    assert_no_token("".join(traceback.format_exception(ei.value)))


@respx.mock
async def test_supergroup_migration(alert_settings, http):
    respx.post(URL).mock(
        return_value=httpx.Response(
            400,
            json={
                "ok": False,
                "error_code": 400,
                "description": "Bad Request: group chat was upgraded",
                "parameters": {"migrate_to_chat_id": -100999},
            },
        )
    )
    with pytest.raises(AlertDeliveryError) as ei:
        await make_channel(alert_settings, http).send(stealer_result())
    assert "-100999" in str(ei.value) and ei.value.retryable is False


@respx.mock
async def test_server_error_is_retryable_and_non_json_body(alert_settings, http):
    respx.post(URL).mock(return_value=httpx.Response(502, text="<html>Bad gateway</html>"))
    with pytest.raises(AlertDeliveryError) as ei:
        await make_channel(alert_settings, http).send(stealer_result())
    assert ei.value.retryable is True and ei.value.status == 502


@respx.mock
async def test_httpx_request_log_does_not_contain_token(alert_settings, http, caplog):
    respx.post(URL).mock(return_value=httpx.Response(200, json={"ok": True}))
    ch = make_channel(alert_settings, http)
    with caplog.at_level(logging.DEBUG):
        await ch.send(stealer_result())
    assert any("HTTP Request" in r.getMessage() for r in caplog.records)  # httpx sí logueó el request...
    assert_no_token(caplog.text)  # ...pero con el token tapado


@pytest.mark.parametrize("bad", ["", "abc", "123:abc/../../x", "123:abc?x=1", "tok en con espacios"])
def test_invalid_token_rejected(settings, http, bad):
    with pytest.raises(ValueError) as ei:
        make_channel(settings, http, token=bad)
    if bad:
        assert bad not in str(ei.value)


@pytest.mark.parametrize("bad", ["", "abc def", "12a", "@x"])
def test_invalid_chat_id_rejected(settings, http, bad):
    with pytest.raises(ValueError):
        make_channel(settings, http, chat_id=bad)
