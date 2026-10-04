"""Alertas por webhook: JSON genérico (firmado con HMAC) o con el formato de Slack, Microsoft Teams,
Discord o Google Chat.

Formatos (`WebhookAlertConfig.format`):
- `json`: payload completo para máquinas (resumen del resultado + hallazgos + artifacts, sin cuerpo ni
  contenido de adjuntos). Con `hmac_secret` se agrega `X-Centinela-Signature: sha256=<hex>` = HMAC-SHA256
  del cuerpo crudo, y `X-Centinela-Timestamp` (segundos Unix). El mismo timestamp va DENTRO del cuerpo
  (`timestamp`), así queda cubierto por la firma: el receptor debe verificar la firma con
  `hmac.compare_digest`, que `timestamp` del cuerpo coincida con el header y que sea reciente (anti-replay).
  `X-Centinela-Alert-Id` es estable entre reintentos (sirve para idempotencia).
- `slack`: Incoming Webhook con Block Kit (header, section mrkdwn, context, botón al dashboard).
- `teams`: webhook de Workflows (Power Automate, "Send webhook alerts to a channel"), que reemplaza a los
  conectores de Office 365 retirados: `{"type":"message","attachments":[{"contentType":
  "application/vnd.microsoft.card.adaptive","contentUrl":null,"content":<AdaptiveCard 1.4>}]}`; límite 28 KB.
- `discord`: embed con color; `allowed_mentions` vacío para que un asunto con "@everyone" no notifique a nadie.
- `google_chat`: tarjeta `cardsV2` + `fallbackText` (lo que se ve en la notificación).

La URL del webhook es un secreto (Slack/Discord/Teams/Google Chat llevan el token en la URL): nunca se
loguea ni aparece en mensajes de error. Respuesta no-2xx => excepción; 429 => `AlertRateLimitedError`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import httpx

from centinela import __version__
from centinela.actions.alerts import (
    AlertDeliveryError,
    AlertRateLimitedError,
    describe_exception,
    parse_retry_after,
    redact,
    register_secret,
)
from centinela.actions.alerts.base import AlertChannel
from centinela.actions.alerts.format import (
    DETAIL_STEPS,
    Alert,
    Detail,
    build_alert,
    escape_discord,
    escape_html,
    escape_slack,
    truncate,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from centinela.core.config import Settings, WebhookAlertConfig
    from centinela.core.models import AnalysisResult

log = logging.getLogger(__name__)

FOOTER = "Aviso automático de Centinela. El mail no fue borrado ni movido."
DASHBOARD_LABEL = "Ver detalle en Centinela"

# tope del cuerpo JSON por formato (bytes); si se pasa, se rearma con menos detalle
_MAX_BODY = {
    "json": 900_000,
    "slack": 40_000,
    "teams": 27_000,  # límite documentado: 28 KB
    "discord": 20_000,
    "google_chat": 30_000,  # límite documentado: 32 KB
}
_MAX_RESPONSE_BYTES = 4096


# --------------------------------------------------------------------------- payloads


def build_json_payload(alert: Alert, *, timestamp: int, detail: Detail | None = None) -> dict[str, Any]:
    """Payload para máquinas (SIEM, n8n, SOAR...). `detail` reducido => menos artifacts/hallazgos."""
    payload: dict[str, Any] = {
        "event": "centinela.alert",
        "timestamp": int(timestamp),
        "sent_at": datetime.fromtimestamp(int(timestamp), UTC).isoformat().replace("+00:00", "Z"),
        **alert.machine,
        "emoji": alert.emoji,
        "headline": alert.headline,
        "text": alert.to_text(),
    }
    if detail is not None and detail != DETAIL_STEPS[0]:
        payload["findings"] = payload["findings"][:20]
        payload["artifacts"] = payload["artifacts"][:50]
        payload["truncated"] = True
    return payload


def build_slack_payload(alert: Alert, detail: Detail | None = None) -> dict[str, Any]:
    d = detail or Detail()
    parts = alert.markdown_parts("slack", d)

    def section(text: str) -> dict[str, Any]:
        return {"type": "section", "text": {"type": "mrkdwn", "text": truncate(text, 3000)}}

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": truncate(alert.headline, 150), "emoji": True},
        },
        section(parts["summary"]),
    ]
    if "recommendations" in parts:
        blocks.append(section("*Qué hacer*\n" + parts["recommendations"]))
    blocks.append(
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": truncate(f"*{k}:*\n{escape_slack(v)}", 2000)}
                for k, v in alert.fact_pairs(d)
            ][:10],
        }
    )
    if "attachments" in parts:
        blocks.append(section("*Adjuntos peligrosos*\n" + parts["attachments"]))
    if "families" in parts:
        blocks.append(section(f"*{alert.families_heading()}:* {parts['families']}"))
    if "findings" in parts:
        shown = min(len(alert.findings), d.findings)
        blocks.append(section(f"*{escape_slack(alert.findings_heading(shown))}*\n" + parts["findings"]))
    if "urls" in parts:
        blocks.append(section("*Links sospechosos (no hacer clic)*\n" + parts["urls"]))
    blocks.append(
        {
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": escape_slack(f"Riesgo {alert.score}/100 · {FOOTER}")}],
        }
    )
    if alert.dashboard_url:
        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": DASHBOARD_LABEL, "emoji": True},
                        "url": alert.dashboard_url,
                        "action_id": "centinela_open_dashboard",
                        "style": "danger" if alert.level == "malicious" else "primary",
                    }
                ],
            }
        )
    return {"text": escape_slack(truncate(alert.headline, 300)), "blocks": blocks[:50]}


def _teams_text(text: str) -> str:
    """Las TextBlock de Adaptive Cards interpretan markdown: se rompe la sintaxis de link `[x](y)`."""
    return text.replace("](", "] (")


def build_teams_payload(alert: Alert, detail: Detail | None = None) -> dict[str, Any]:
    d = detail or Detail()

    def tb(text: str, **extra: Any) -> dict[str, Any]:
        return {"type": "TextBlock", "text": _teams_text(text), "wrap": True, **extra}

    def heading(text: str) -> dict[str, Any]:
        return tb(text, weight="Bolder", spacing="Medium")

    style = {"malicious": "attention", "suspicious": "warning"}.get(alert.level, "emphasis")
    body: list[dict[str, Any]] = [
        {
            "type": "Container",
            "style": style,
            "bleed": True,
            "items": [tb(alert.headline, weight="Bolder", size="Medium")],
        },
        tb(alert.summary, spacing="Medium"),
    ]
    recs = alert.recommendations[: d.recommendations]
    if recs:
        body += [heading("Qué hacer"), tb("\r".join(f"{i}. {r}" for i, r in enumerate(recs, 1)))]
    body.append(
        {
            "type": "FactSet",
            "spacing": "Medium",
            "facts": [{"title": k, "value": _teams_text(v)} for k, v in alert.fact_pairs(d)],
        }
    )
    atts = alert.attachments[: d.attachments]
    if atts:
        body.append(heading("Adjuntos peligrosos"))
        for a in atts:
            body.append(tb(f"**{alert.attachment_line(a)}**", spacing="Small"))
            body.append(
                tb(
                    f"SHA-256: {a.sha256 or '-'}",
                    fontType="Monospace",
                    size="Small",
                    isSubtle=True,
                    spacing="None",
                )
            )
    if alert.families:
        body += [heading(alert.families_heading()), tb(", ".join(alert.families))]
    fnds = alert.findings[: d.findings]
    if fnds:
        body.append(heading(alert.findings_heading(len(fnds))))
        body.append(tb("\r".join(f"- **{f.severity_label}** · {alert.finding_line(f)}" for f in fnds)))
    urls = alert.urls[: d.urls]
    if urls:
        body.append(heading("Links sospechosos (no hacer clic)"))
        body += [tb(u, fontType="Monospace", size="Small", spacing="None") for u in urls]
    body.append(tb(FOOTER, size="Small", isSubtle=True, spacing="Medium"))
    card: dict[str, Any] = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "msteams": {"width": "Full"},
        "body": body,
    }
    if alert.dashboard_url:
        card["actions"] = [{"type": "Action.OpenUrl", "title": DASHBOARD_LABEL, "url": alert.dashboard_url}]
    return {
        "type": "message",
        "attachments": [
            {"contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None, "content": card}
        ],
    }


def build_discord_payload(alert: Alert, detail: Detail | None = None) -> dict[str, Any]:
    d = detail or Detail()
    parts = alert.markdown_parts("discord", d)
    chunks = [parts["summary"]]
    if "recommendations" in parts:
        chunks.append("**Qué hacer**\n" + parts["recommendations"])
    if "attachments" in parts:
        chunks.append("**Adjuntos peligrosos**\n" + parts["attachments"])
    if "families" in parts:
        chunks.append(f"**{alert.families_heading()}:** {parts['families']}")
    if "findings" in parts:
        shown = min(len(alert.findings), d.findings)
        chunks.append(f"**{escape_discord(alert.findings_heading(shown))}**\n" + parts["findings"])
    if "urls" in parts:
        chunks.append("**Links sospechosos (no hacer clic)**\n" + parts["urls"])
    link = f"\n\n[{DASHBOARD_LABEL}]({alert.dashboard_url})" if alert.dashboard_url else ""
    fields = [
        {"name": k, "value": truncate(escape_discord(v), 1024) or "-", "inline": k in ("Fecha", "Riesgo")}
        for k, v in alert.fact_pairs(d)
    ]
    title = truncate(alert.headline, 256)
    footer = FOOTER
    # límite total de un embed: 6000 caracteres entre título, descripción, campos y pie
    budget = (
        5800 - len(title) - len(footer) - sum(len(f["name"]) + len(f["value"]) for f in fields) - len(link)
    )
    description = truncate("\n\n".join(chunks), max(200, min(4000 - len(link), budget))) + link
    embed: dict[str, Any] = {
        "title": title,
        "description": description,
        "color": alert.color_int,
        "fields": fields,
        "footer": {"text": footer},
        "timestamp": alert.analyzed_at.astimezone(UTC).isoformat(),
    }
    if alert.dashboard_url:
        embed["url"] = alert.dashboard_url
    return {
        "username": "Centinela",
        "content": truncate(escape_discord(alert.headline), 2000),
        "embeds": [embed],
        "allowed_mentions": {"parse": []},
    }


def build_google_chat_payload(alert: Alert, detail: Detail | None = None) -> dict[str, Any]:
    d = detail or Detail()
    h = escape_html

    def para(text_html: str) -> dict[str, Any]:
        return {"textParagraph": {"text": text_html}}

    sections: list[dict[str, Any]] = [{"widgets": [para(h(alert.summary))]}]
    recs = alert.recommendations[: d.recommendations]
    if recs:
        sections.append(
            {
                "header": "Qué hacer",
                "widgets": [para("<br>".join(f"{i}. {h(r)}" for i, r in enumerate(recs, 1)))],
            }
        )
    sections.append(
        {
            "header": "Datos del mail",
            "widgets": [
                {"decoratedText": {"topLabel": k, "text": h(v), "wrapText": True}}
                for k, v in alert.fact_pairs(d)
            ],
        }
    )
    atts = alert.attachments[: d.attachments]
    if atts:
        sections.append(
            {
                "header": "Adjuntos peligrosos",
                "widgets": [
                    para(
                        f"<b>{h(a.display_name)}</b> — {h(a.type_label)}"
                        f"{', con contraseña' if a.encrypted else ''}<br>"
                        f'<font color="#6B7280">SHA-256: {h(a.sha256 or "-")}</font>'
                    )
                    for a in atts
                ],
            }
        )
    if alert.families:
        sections.append(
            {
                "header": h(alert.families_heading()),
                "widgets": [para(f"<b>{h(', '.join(alert.families))}</b>")],
            }
        )
    fnds = alert.findings[: d.findings]
    if fnds:
        lines = "<br>".join(f"<b>{h(f.severity_label)}</b> · {h(alert.finding_line(f))}" for f in fnds)
        sections.append({"header": h(alert.findings_heading(len(fnds))), "widgets": [para(lines)]})
    urls = alert.urls[: d.urls]
    if urls:
        sections.append(
            {
                "header": "Links sospechosos (no hacer clic)",
                "widgets": [para("<br>".join(h(u) for u in urls))],
            }
        )
    footer_widgets: list[dict[str, Any]] = [para(f'<font color="#6B7280">{h(FOOTER)}</font>')]
    if alert.dashboard_url:
        footer_widgets.insert(
            0,
            {
                "buttonList": {
                    "buttons": [
                        {"text": DASHBOARD_LABEL, "onClick": {"openLink": {"url": alert.dashboard_url}}}
                    ]
                }
            },
        )
    sections.append({"widgets": footer_widgets})
    return {
        "fallbackText": truncate(alert.headline, 300),
        "cardsV2": [
            {
                "cardId": f"centinela-{alert.result_id}",
                "card": {
                    "header": {
                        "title": truncate(alert.headline, 200),
                        "subtitle": f"Centinela · riesgo {alert.score}/100",
                    },
                    "sections": sections,
                },
            }
        ],
    }


_BUILDERS: dict[str, Callable[[Alert, Detail | None], dict[str, Any]]] = {
    "slack": build_slack_payload,
    "teams": build_teams_payload,
    "discord": build_discord_payload,
    "google_chat": build_google_chat_payload,
}


def sign_body(secret: str, body: bytes) -> str:
    """Valor de `X-Centinela-Signature` para un cuerpo crudo."""
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def _dumps(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


# --------------------------------------------------------------------------- canal


class WebhookChannel(AlertChannel):
    type = "webhook"
    timeout = httpx.Timeout(15.0, connect=10.0)

    def __init__(self, config: WebhookAlertConfig, settings: Settings, http: httpx.AsyncClient) -> None:
        super().__init__(config, settings, http)
        url = config.url.get_secret_value().strip()
        try:
            parsed = httpx.URL(url)
        except Exception:  # noqa: BLE001 - el mensaje de httpx podría contener la URL
            raise ValueError(f"canal {config.name!r}: la URL del webhook no es válida") from None
        if parsed.scheme not in ("http", "https") or not parsed.host:
            raise ValueError(f"canal {config.name!r}: la URL del webhook debe ser http(s)://...")
        if parsed.scheme == "http" and parsed.host not in ("localhost", "127.0.0.1", "::1"):
            log.warning("canal %r: el webhook no usa HTTPS (la alerta viaja sin cifrar)", config.name)
        if config.hmac_secret and config.format != "json":
            log.warning("canal %r: hmac_secret solo se usa con format=json; se ignora", config.name)
        self._url = url
        self._secrets = [url, str(parsed)]
        path_query = parsed.raw_path.decode("ascii", "replace")
        if len(path_query) >= 12:
            self._secrets.append(path_query)
        for s in self._secrets:
            register_secret(s)
        self._hmac = config.hmac_secret.get_secret_value() if config.hmac_secret else None

    def build_request(
        self, result: AnalysisResult, *, now: float | None = None
    ) -> tuple[bytes, dict[str, str]]:
        """Cuerpo y headers del POST (separado de `send` para poder testearlo sin red)."""
        alert = build_alert(result, self.settings)
        fmt = self.config.format
        ts = int(now if now is not None else time.time())
        limit = _MAX_BODY.get(fmt, 100_000)
        body = b""
        for d in (DETAIL_STEPS[0], DETAIL_STEPS[2], DETAIL_STEPS[-1]):
            payload = (
                build_json_payload(alert, timestamp=ts, detail=d)
                if fmt == "json"
                else _BUILDERS[fmt](alert, d)
            )
            body = _dumps(payload)
            if len(body) <= limit:
                break
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": f"Centinela/{__version__}",
        }
        if fmt == "json":
            headers["X-Centinela-Event"] = "alert"
            headers["X-Centinela-Alert-Id"] = alert.result_id
            headers["X-Centinela-Timestamp"] = str(ts)
            if self._hmac:
                headers["X-Centinela-Signature"] = sign_body(self._hmac, body)
        return body, headers

    async def send(self, result: AnalysisResult) -> None:
        body, headers = self.build_request(result)
        fmt = self.config.format
        try:
            async with self.http.stream(
                "POST", self._url, content=body, headers=headers, timeout=self.timeout
            ) as resp:
                status = resp.status_code
                raw = await _read_limited(resp, _MAX_RESPONSE_BYTES)
                retry_header = resp.headers.get("Retry-After")
        except httpx.HTTPError as exc:
            raise AlertDeliveryError(
                f"webhook ({fmt}): error de red ({describe_exception(exc, self._secrets)})", channel=self.name
            ) from None
        if 200 <= status < 300:
            return
        snippet = redact(raw.decode("utf-8", "replace").strip().replace("\n", " ")[:200], self._secrets)
        if status == 429:
            retry_json = None
            try:
                data = json.loads(raw)
                if isinstance(data, dict):
                    retry_json = data.get("retry_after")
            except ValueError:
                pass
            retry_after = parse_retry_after(retry_header, retry_json)
            raise AlertRateLimitedError(
                f"webhook ({fmt}): demasiadas solicitudes (429); reintentar en {retry_after:g} s",
                channel=self.name,
                status=429,
                retry_after=retry_after,
            )
        raise AlertDeliveryError(
            f"webhook ({fmt}) respondió {status}" + (f": {snippet}" if snippet else ""),
            channel=self.name,
            status=status,
            retryable=status >= 500 or status == 408,
        )


async def _read_limited(resp: httpx.Response, limit: int) -> bytes:
    buf = bytearray()
    async for chunk in resp.aiter_bytes():
        buf += chunk
        if len(buf) >= limit:
            break
    return bytes(buf[:limit])
