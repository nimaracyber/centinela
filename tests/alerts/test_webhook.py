from __future__ import annotations

import hashlib
import hmac
import json
import traceback
from datetime import UTC, datetime

import httpx
import pytest
import respx

from centinela.actions.alerts import AlertDeliveryError, AlertRateLimitedError
from centinela.actions.alerts.webhook import WebhookChannel, sign_body
from centinela.core.config import WebhookAlertConfig
from tests.alerts.conftest import BODY_SECRET, PHISH_URL, SHA_EXE, bec_result, stealer_result
from tests.alerts.test_format import hostile_result

HOOK = "https://hooks.example.com/services/T000/B000/SuperSecretWebhookPath123"
SECRET = "s3cr3t-hmac-key"


def make_channel(settings, http, fmt="json", url=HOOK, hmac_secret=None) -> WebhookChannel:
    cfg = WebhookAlertConfig(type="webhook", name=f"wh-{fmt}", url=url, format=fmt, hmac_secret=hmac_secret)
    return WebhookChannel(cfg, settings, http)


async def post_and_capture(settings, http, fmt, result, **kw):
    with respx.mock:
        route = respx.post(HOOK).mock(return_value=httpx.Response(200, text="ok"))
        await make_channel(settings, http, fmt, **kw).send(result)
        assert route.call_count == 1
        req = route.calls[0].request
        return req, json.loads(req.content)


# --------------------------------------------------------------------------- json + HMAC


async def test_json_payload_and_hmac_signature(alert_settings, http):
    result = stealer_result()
    req, body = await post_and_capture(alert_settings, http, "json", result, hmac_secret=SECRET)
    expected = "sha256=" + hmac.new(SECRET.encode(), req.content, hashlib.sha256).hexdigest()
    assert req.headers["X-Centinela-Signature"] == expected
    assert hmac.compare_digest(req.headers["X-Centinela-Signature"], sign_body(SECRET, req.content))
    assert req.headers["X-Centinela-Timestamp"] == str(body["timestamp"])
    assert req.headers["X-Centinela-Alert-Id"] == str(result.id)
    assert req.headers["Content-Type"].startswith("application/json")
    assert body["event"] == "centinela.alert"
    assert body["schema"] == "centinela.alert/v1"
    assert body["level"] == "malicious" and body["score"] == 97
    assert body["title"] == "Mail malicioso detectado en ventas@empresa.com"
    assert body["message"]["mailbox"] == "ventas@empresa.com"
    assert {f["rule"] for f in body["findings"]} == {
        "yara.AgentTesla",
        "file.double_extension",
        "url.lookalike_domain",
        "headers.info",
    }
    assert len(body["artifacts"]) == 2
    assert body["dangerous_attachments"][0]["sha256"] == SHA_EXE
    assert body["urls_defanged"] == ["hxxps://pagos-afip[.]com/login[.]php?token=XYZ"]
    assert body["text"].startswith("🔴 Mail malicioso")
    raw = req.content.decode()
    assert BODY_SECRET not in raw and PHISH_URL not in raw and "evidence" not in raw


async def test_json_signature_detects_tampering(alert_settings, http):
    req, _ = await post_and_capture(alert_settings, http, "json", stealer_result(), hmac_secret=SECRET)
    tampered = req.content.replace(b'"score":97', b'"score":1')
    assert tampered != req.content
    assert sign_body(SECRET, tampered) != req.headers["X-Centinela-Signature"]


async def test_json_without_secret_has_no_signature(alert_settings, http):
    req, _ = await post_and_capture(alert_settings, http, "json", stealer_result())
    assert "X-Centinela-Signature" not in req.headers
    assert "X-Centinela-Timestamp" in req.headers


# --------------------------------------------------------------------------- Slack / Teams / Discord / Google Chat


async def test_slack_blocks(alert_settings, http):
    result = stealer_result()
    req, body = await post_and_capture(alert_settings, http, "slack", result)
    assert "X-Centinela-Signature" not in req.headers
    types = [b["type"] for b in body["blocks"]]
    assert types[0] == "header" and "context" in types and types[-1] == "actions"
    assert body["blocks"][0]["text"]["type"] == "plain_text"
    assert len(body["blocks"][0]["text"]["text"]) <= 150
    button = body["blocks"][-1]["elements"][0]
    assert (
        button["type"] == "button" and button["url"] == f"https://centinela.empresa.com/messages/{result.id}"
    )
    assert button["style"] == "danger"
    assert body["text"].startswith("🔴 Mail malicioso")
    for b in body["blocks"]:
        if b["type"] == "section" and "text" in b:
            assert b["text"]["type"] == "mrkdwn" and len(b["text"]["text"]) <= 3000
    joined = json.dumps(body, ensure_ascii=False)
    assert "*Qué hacer*" in joined and SHA_EXE in joined


async def test_slack_without_dashboard_has_no_button(settings, http):
    _, body = await post_and_capture(settings, http, "slack", bec_result())
    assert all(b["type"] != "actions" for b in body["blocks"])


async def test_slack_escapes_mentions(alert_settings, http):
    _, body = await post_and_capture(alert_settings, http, "slack", hostile_result())
    joined = json.dumps(body, ensure_ascii=False)
    assert "<!channel>" not in joined and "&lt;!channel&gt;" in joined
    assert len(body["blocks"]) <= 50


async def test_teams_adaptive_card(alert_settings, http):
    result = stealer_result()
    _, body = await post_and_capture(alert_settings, http, "teams", result)
    assert body["type"] == "message"
    att = body["attachments"][0]
    assert att["contentType"] == "application/vnd.microsoft.card.adaptive"
    assert att["contentUrl"] is None
    card = att["content"]
    assert card["type"] == "AdaptiveCard" and card["version"] == "1.4"
    assert card["$schema"] == "http://adaptivecards.io/schemas/adaptive-card.json"
    assert card["actions"] == [
        {
            "type": "Action.OpenUrl",
            "title": "Ver detalle en Centinela",
            "url": f"https://centinela.empresa.com/messages/{result.id}",
        }
    ]
    assert card["body"][0]["style"] == "attention"
    facts = next(b for b in card["body"] if b["type"] == "FactSet")["facts"]
    assert facts[0] == {"title": "De", "value": "AFIP Cobranzas <cobranzas@pagos-afip[.]com>"}


async def test_teams_payload_stays_under_28kb_and_breaks_md_links(alert_settings, http):
    req, body = await post_and_capture(alert_settings, http, "teams", hostile_result())
    assert len(req.content) <= 27_000
    raw = json.dumps(body, ensure_ascii=False)
    assert "](hxxps" not in raw and "](https" not in raw


async def test_discord_embed(alert_settings, http):
    result = stealer_result()
    _, body = await post_and_capture(alert_settings, http, "discord", result)
    assert body["allowed_mentions"] == {"parse": []}
    emb = body["embeds"][0]
    assert emb["color"] == 0xB91C1C
    assert emb["url"] == f"https://centinela.empresa.com/messages/{result.id}"
    assert emb["title"].startswith("🔴 Mail malicioso")
    assert "Qué hacer" in emb["description"]
    assert {f["name"] for f in emb["fields"]} == {"De", "Para", "Asunto", "Fecha", "Riesgo"}


async def test_discord_limits_with_hostile_input(alert_settings, http):
    _, body = await post_and_capture(alert_settings, http, "discord", hostile_result())
    emb = body["embeds"][0]
    total = len(emb["title"]) + len(emb["description"]) + len(emb["footer"]["text"])
    total += sum(len(f["name"]) + len(f["value"]) for f in emb["fields"])
    assert total <= 6000
    assert len(emb["description"]) <= 4096
    assert all(len(f["value"]) <= 1024 for f in emb["fields"])
    assert len(body["content"]) <= 2000
    assert "@everyone" not in emb["description"].replace("\\@everyone", "")
    assert body["allowed_mentions"] == {"parse": []}


async def test_google_chat_card(alert_settings, http):
    result = stealer_result()
    _, body = await post_and_capture(alert_settings, http, "google_chat", result)
    assert body["fallbackText"].startswith("🔴 Mail malicioso")
    card = body["cardsV2"][0]["card"]
    assert card["header"]["title"].startswith("🔴 Mail malicioso")
    assert "riesgo 97/100" in card["header"]["subtitle"]
    headers = [s.get("header") for s in card["sections"]]
    assert "Qué hacer" in headers and "Adjuntos peligrosos" in headers
    buttons = card["sections"][-1]["widgets"][0]["buttonList"]["buttons"]
    assert buttons[0]["onClick"]["openLink"]["url"] == f"https://centinela.empresa.com/messages/{result.id}"


async def test_google_chat_escapes_html(alert_settings, http):
    req, _ = await post_and_capture(alert_settings, http, "google_chat", hostile_result())
    raw = req.content.decode()
    assert "<script>" not in raw and "<img" not in raw
    assert len(req.content) <= 30_000


# --------------------------------------------------------------------------- errores


@respx.mock
async def test_non_2xx_raises_without_leaking_url(alert_settings, http):
    respx.post(HOOK).mock(return_value=httpx.Response(404, text=f"no_service for {HOOK}"))
    with pytest.raises(AlertDeliveryError) as ei:
        await make_channel(alert_settings, http, "slack").send(stealer_result())
    msg = str(ei.value)
    assert ei.value.status == 404 and ei.value.retryable is False
    assert "SuperSecretWebhookPath123" not in msg
    assert "no_service" in msg


@respx.mock
async def test_teams_202_accepted_is_ok(alert_settings, http):
    respx.post(HOOK).mock(return_value=httpx.Response(202))
    await make_channel(alert_settings, http, "teams").send(stealer_result())


@respx.mock
async def test_rate_limit_retry_after_header(alert_settings, http):
    respx.post(HOOK).mock(return_value=httpx.Response(429, headers={"Retry-After": "12"}, text="slow down"))
    with pytest.raises(AlertRateLimitedError) as ei:
        await make_channel(alert_settings, http, "slack").send(stealer_result())
    assert ei.value.retry_after == 12


@respx.mock
async def test_rate_limit_discord_json_retry_after(alert_settings, http):
    respx.post(HOOK).mock(
        return_value=httpx.Response(
            429, json={"message": "You are being rate limited.", "retry_after": 1.5, "global": False}
        )
    )
    with pytest.raises(AlertRateLimitedError) as ei:
        await make_channel(alert_settings, http, "discord").send(stealer_result())
    assert ei.value.retry_after == 1.5


@respx.mock
async def test_network_error_redacted(alert_settings, http):
    respx.post(HOOK).mock(side_effect=httpx.ConnectTimeout(f"timeout connecting to {HOOK}"))
    with pytest.raises(AlertDeliveryError) as ei:
        await make_channel(alert_settings, http, "json").send(stealer_result())
    assert "SuperSecretWebhookPath123" not in "".join(traceback.format_exception(ei.value))
    assert ei.value.retryable is True


@respx.mock
async def test_huge_error_body_is_bounded(alert_settings, http):
    respx.post(HOOK).mock(return_value=httpx.Response(500, content=b"E" * 5_000_000))
    with pytest.raises(AlertDeliveryError) as ei:
        await make_channel(alert_settings, http, "json").send(stealer_result())
    assert len(str(ei.value)) < 400


@pytest.mark.parametrize("bad", ["ftp://hooks.example.com/x", "not a url", "https://", "file:///etc/passwd"])
def test_invalid_url_rejected(settings, http, bad):
    with pytest.raises(ValueError) as ei:
        make_channel(settings, http, url=bad)
    assert bad not in str(ei.value) or bad == "https://"


def test_build_request_is_deterministic_with_now(alert_settings, http):
    ch = make_channel(alert_settings, http, "json", hmac_secret=SECRET)
    body, headers = ch.build_request(stealer_result(), now=1_791_000_000)
    assert headers["X-Centinela-Timestamp"] == "1791000000"
    expected = datetime.fromtimestamp(1_791_000_000, UTC).isoformat().replace("+00:00", "Z")
    assert json.loads(body)["sent_at"] == expected
    assert json.loads(body)["timestamp"] == 1_791_000_000
    assert headers["X-Centinela-Signature"] == sign_body(SECRET, body)
