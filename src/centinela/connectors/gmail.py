"""Conector Gmail / Google Workspace vía Gmail API (REST con httpx, sin googleapiclient).

Cómo funciona
-------------
- Un loop por buzón. Cursor = `historyId` de Gmail guardado en el state store
  (`connector:<nombre>:gmail:<buzón>:history_id`), siempre DESPUÉS de entregar los mails (`emit`).
- Primera vez: `users.getProfile` -> historyId actual (no se re-analiza el buzón entero). Si
  `backfill_hours > 0`, además se analizan los mails de las últimas N horas (`messages.list` con
  `after:<epoch>`; Gmail no soporta horas en `newer_than:`).
- Después: `users.history.list(startHistoryId, historyTypes=messageAdded)` paginado. Se analizan los
  mails agregados con label INBOX o SPAM (según `label_query`) y nunca los SENT/DRAFT (salientes).
- Si el historyId expiró (HTTP 404, Gmail guarda ~1 semana de historia) se re-sincroniza desde
  `getProfile`, con una recuperación acotada (`messages.list` desde la última sincronización, máximo
  2 días y 2000 mails); el storage deduplica lo que ya se había analizado.
- Tamaño: antes de bajar el mail crudo se pide `sizeEstimate` (formato minimal); `format=raw` solo si
  entra en `limits.max_message_bytes` (la descarga además tiene un tope duro de bytes). Un mail más
  grande NO se omite (sería una evasión trivial): se piden sus headers con `format=metadata`, se arma un
  bloque RFC 5322 y se emite con `truncated=True` + `original_size` (el pipeline agrega el hallazgo
  `policy.message_too_large`).
- Tiempo real (opcional): con `pubsub_topic` + `pubsub_subscription` se llama `users.watch`
  (renovado cada 24 h; Google lo vence a los 7 días) y se hace *pull* de la suscripción Pub/Sub por
  REST como señal para sincronizar en el momento (no requiere exponer ninguna URL pública).
  Sin Pub/Sub: polling de history cada `poll_interval_s` (muy barato: 2 unidades de cuota).

Etiquetado (`apply_verdict`)
----------------------------
Busca o crea el label de usuario (`actions.tag.label_malicious` / `label_suspicious`, con color) y lo
AGREGA con `messages.modify`. Nunca saca labels, nunca manda a la papelera, nunca toca INBOX/UNREAD.

Permisos mínimos
----------------
- Solo alertas (`tag: false`): `https://www.googleapis.com/auth/gmail.readonly`.
- Con etiquetado: `https://www.googleapis.com/auth/gmail.modify` (agregar labels; Centinela no usa
  la capacidad de borrar/mover que ese scope también otorga).
- Workspace (`auth: service_account`): cuenta de servicio con *delegación de todo el dominio*; en la
  consola de administración (Seguridad > Controles de API > Delegación de todo el dominio) autorizar
  el Client ID de la cuenta de servicio con el scope de arriba. Solo se accede a los buzones listados.
- Gmail personal (`auth: oauth_user`): `centinela auth gmail <conector>` (ver `oauth_cloud.py`).
- Pub/Sub: el tópico debe dar rol *Pub/Sub Publisher* a `gmail-api-push@system.gserviceaccount.com`;
  quien hace pull (la cuenta de servicio, o el usuario OAuth si no hay cuenta de servicio) necesita
  *Pub/Sub Subscriber* sobre la suscripción. Usar UNA suscripción exclusiva por conector (Centinela
  hace ack de todo lo que recibe).
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import logging
import random
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

import httpx

from centinela.connectors import _http as http
from centinela.connectors._headers import header_cap, header_section, headers_from_api, oversize_raw
from centinela.connectors._http import RecentIds, label_for_level
from centinela.connectors.base import Connector
from centinela.core.models import MessageRef, RawMessage, VerdictLevel, utcnow
from centinela.metrics import CONNECTOR_UP

if TYPE_CHECKING:
    from centinela.connectors.base import EmitFn
    from centinela.core.config import GmailConnectorConfig, Settings, TagConfig
    from centinela.core.models import AnalysisResult
    from centinela.core.state import StateStore

log = logging.getLogger(__name__)

GMAIL_API = "https://gmail.googleapis.com/gmail/v1"
PUBSUB_API = "https://pubsub.googleapis.com/v1"
SCOPE_READONLY = "https://www.googleapis.com/auth/gmail.readonly"
SCOPE_MODIFY = "https://www.googleapis.com/auth/gmail.modify"
SCOPE_PUBSUB = "https://www.googleapis.com/auth/pubsub"

_PUBSUB_KEY = "__pubsub__"
_TOPIC_RE = re.compile(r"^projects/[a-z][a-z0-9.:-]{3,62}/topics/[A-Za-z][A-Za-z0-9._~%+-]{2,254}$")
_SUBSCRIPTION_RE = re.compile(
    r"^projects/[a-z][a-z0-9.:-]{3,62}/subscriptions/[A-Za-z][A-Za-z0-9._~%+-]{2,254}$"
)
_GMAIL_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_OUTGOING = frozenset({"SENT", "DRAFT"})
_LABEL_COLORS = {
    VerdictLevel.MALICIOUS: {"backgroundColor": "#cc3a21", "textColor": "#ffffff"},
    VerdictLevel.SUSPICIOUS: {"backgroundColor": "#ffad47", "textColor": "#000000"},
}
_RATE_LIMIT_REASONS = frozenset({"rateLimitExceeded", "userRateLimitExceeded", "RATE_LIMIT_EXCEEDED"})


class GmailAuthError(RuntimeError):
    """No se pudo obtener un token de Google (mensaje en español, sin secretos)."""


class _HistoryExpired(Exception):
    pass


def oauth_mailboxes_key(connector_name: str) -> str:
    """Clave (state, sin cifrar) con la lista JSON de buzones autorizados vía OAuth de usuario."""
    return f"connector:{connector_name}:gmail_oauth_mailboxes"


def refresh_token_key(connector_name: str, mailbox: str) -> str:
    """Clave (secreto cifrado) del refresh token OAuth de un buzón."""
    return f"connector:{connector_name}:gmail_refresh_token:{mailbox}"


@dataclass
class _MailboxStatus:
    ok: bool = False
    error: str | None = None
    last_sync: datetime | None = None
    watching: bool = False
    watch_expiration: datetime | None = None
    watch_next_at: float = 0.0  # time.monotonic() de la próxima renovación de watch


def _load_client_secrets(path: Any) -> dict[str, str]:
    """Lee el JSON de cliente OAuth ("Desktop app") descargado de Google Cloud Console."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise GmailAuthError("el archivo de cliente OAuth no es un JSON de credenciales de Google válido")
    section = data.get("installed") or data.get("web") or {}
    client_id = section.get("client_id")
    client_secret = section.get("client_secret")
    if not client_id or not client_secret:
        raise GmailAuthError(
            "el archivo de cliente OAuth no tiene client_id/client_secret (¿es un JSON de tipo 'Desktop app'?)"
        )
    return {
        "client_id": str(client_id),
        "client_secret": str(client_secret),
        "token_uri": str(section.get("token_uri") or "https://oauth2.googleapis.com/token"),
    }


def _refresh_sync(creds: Any) -> None:
    from google.auth.transport.requests import Request

    creds.refresh(Request())


def _auth_hint(exc: BaseException, mailbox: str | None, auth: str, scopes: list[str]) -> str:
    text = str(exc)
    low = text.lower()
    who = f"el buzón {mailbox}" if mailbox else "Pub/Sub"
    if "unauthorized_client" in low:
        return (
            f"Google rechazó la delegación para {who}: en la consola de administración de Workspace "
            f"(Seguridad > Controles de API > Delegación de todo el dominio) autorizá el Client ID de la "
            f"cuenta de servicio con los scopes: {', '.join(scopes)}"
        )
    if "invalid_grant" in low:
        if auth == "oauth_user":
            return (
                f"El acceso de {who} fue revocado o venció. Volvé a autorizar con "
                f"`centinela auth gmail <conector>`."
            )
        return f"Google rechazó la cuenta de servicio para {who} (¿el buzón existe y es del dominio? ¿reloj del servidor en hora?)."
    return f"No se pudo obtener un token de Google para {who}: {type(exc).__name__}: {text[:200]}"


def _b64decode_any(value: str) -> bytes:
    """base64 estándar o url-safe, con o sin padding."""
    s = value.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def _decode_raw_response(content: bytes) -> tuple[bytes, Any]:
    """JSON de `messages.get(format=raw)` -> (bytes RFC 5322, internalDate). CPU: correr en thread."""
    data = json.loads(content)
    if not isinstance(data, dict) or not isinstance(data.get("raw"), str):
        raise ValueError("respuesta de Gmail sin campo 'raw'")
    raw = data["raw"]
    return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)), data.get("internalDate")


def _is_gmail_rate_limited(resp: http.HttpResponse) -> bool:
    return resp.status_code == 403 and resp.error_code() in _RATE_LIMIT_REASONS


class GmailConnector(Connector):
    type = "gmail"

    # Ajustables (los tests los achican).
    min_poll_s: float = 1.0
    start_jitter_s: float = 3.0
    stop_grace_s: float = 5.0
    watch_renew_s: float = 24 * 3600.0
    watch_retry_s: float = 3600.0
    pubsub_safety_poll_s: float = 300.0
    pubsub_pull_timeout_s: float = 60.0
    pubsub_idle_s: float = 1.0
    max_history_pages: int = 200
    max_catchup_messages: int = 2000
    catchup_window_s: float = 2 * 86400.0
    auth_error_backoff_cap_s: float = 900.0
    error_backoff_cap_s: float = 300.0

    config: GmailConnectorConfig

    def __init__(self, config: GmailConnectorConfig, settings: Settings, state: StateStore) -> None:
        super().__init__(config, settings, state)
        self._client_obj: httpx.AsyncClient | None = None
        self._creds: dict[str, Any] = {}
        self._cred_locks: dict[str, asyncio.Lock] = {}
        self._label_ids: dict[tuple[str, str], str] = {}
        self._label_lock = asyncio.Lock()
        self._wake: dict[str, asyncio.Event] = {}
        self._status: dict[str, _MailboxStatus] = {}
        self._recent: dict[str, RecentIds] = {}
        self._last_sync_written: dict[str, float] = {}
        self._mailboxes: list[str] = []
        self._pubsub_ok: bool | None = None
        self.truncated_too_large = 0  # mails que superaban max_message_bytes: se analizaron solo los headers

    # ------------------------------------------------------------------ configuración

    @property
    def tag_enabled(self) -> bool:
        return bool(self.config.tag) and bool(self.settings.actions.tag.enabled)

    @property
    def gmail_scopes(self) -> list[str]:
        return [SCOPE_MODIFY if self.tag_enabled else SCOPE_READONLY]

    @property
    def pubsub_enabled(self) -> bool:
        return bool(self.config.pubsub_topic and self.config.pubsub_subscription)

    @property
    def max_message_bytes(self) -> int:
        return int(self.settings.limits.max_message_bytes)

    def watched_labels(self) -> frozenset[str]:
        """Labels de sistema a vigilar, derivados de `label_query` (por defecto INBOX y SPAM)."""
        q = (self.config.label_query or "").lower()
        labels: set[str] = set()
        if re.search(r"(?:\bin|\blabel):inbox\b", q):
            labels.add("INBOX")
        if re.search(r"(?:\bin|\blabel):spam\b", q):
            labels.add("SPAM")
        return frozenset(labels or {"INBOX", "SPAM"})

    def validate(self) -> None:
        cfg = self.config
        if cfg.auth == "service_account":
            if not cfg.service_account_file:
                raise ValueError(f"conector gmail '{self.name}': falta service_account_file")
            if not cfg.mailboxes:
                raise ValueError(
                    f"conector gmail '{self.name}': con service_account hay que listar los buzones en `mailboxes`"
                )
        elif not cfg.oauth_client_file:
            raise ValueError(f"conector gmail '{self.name}': falta oauth_client_file para auth oauth_user")
        if bool(cfg.pubsub_topic) != bool(cfg.pubsub_subscription):
            raise ValueError(f"conector gmail '{self.name}': pubsub_topic y pubsub_subscription van juntos")
        if cfg.pubsub_topic and not _TOPIC_RE.match(cfg.pubsub_topic):
            raise ValueError(
                f"conector gmail '{self.name}': pubsub_topic debe ser projects/<proyecto>/topics/<tópico>"
            )
        if cfg.pubsub_subscription and not _SUBSCRIPTION_RE.match(cfg.pubsub_subscription):
            raise ValueError(
                f"conector gmail '{self.name}': pubsub_subscription debe ser projects/<proyecto>/subscriptions/<nombre>"
            )

    async def resolve_mailboxes(self) -> list[str]:
        boxes = http.dedup_casefold(list(self.config.mailboxes))
        if not boxes and self.config.auth == "oauth_user":
            raw = await self.state.get(oauth_mailboxes_key(self.name))
            try:
                stored = json.loads(raw) if raw else []
            except ValueError:
                stored = []
            boxes = http.dedup_casefold(
                [m for m in stored if isinstance(m, str)] if isinstance(stored, list) else []
            )
        return boxes

    # ------------------------------------------------------------------ credenciales

    def _client(self) -> httpx.AsyncClient:
        if self._client_obj is None or self._client_obj.is_closed:
            self._client_obj = http.new_client()
        return self._client_obj

    def build_credentials(self, key: str, refresh_token: str | None = None) -> Any:
        """Crea las credenciales google-auth para un buzón (o para Pub/Sub). Bloqueante: usar en thread."""
        cfg = self.config
        if key == _PUBSUB_KEY and cfg.service_account_file:
            from google.oauth2 import service_account

            return service_account.Credentials.from_service_account_file(
                str(cfg.service_account_file), scopes=[SCOPE_PUBSUB]
            )
        if cfg.auth == "service_account":
            from google.oauth2 import service_account

            creds = service_account.Credentials.from_service_account_file(
                str(cfg.service_account_file), scopes=self.gmail_scopes
            )
            return creds.with_subject(key)
        from google.oauth2.credentials import Credentials

        if not refresh_token:
            raise GmailAuthError(
                f"El buzón {key} no está autorizado todavía: ejecutá `centinela auth gmail {self.name}`."
            )
        secrets = _load_client_secrets(cfg.oauth_client_file)
        # Sin `scopes`: el refresh devuelve un token con los scopes que el usuario otorgó en el login.
        return Credentials(
            token=None,
            refresh_token=refresh_token,
            token_uri=secrets["token_uri"],
            client_id=secrets["client_id"],
            client_secret=secrets["client_secret"],
        )

    async def _make_credentials(self, key: str) -> Any:
        refresh_token: str | None = None
        if self.config.auth == "oauth_user" and not (key == _PUBSUB_KEY and self.config.service_account_file):
            mailbox = key
            if key == _PUBSUB_KEY:
                boxes = self._mailboxes or await self.resolve_mailboxes()
                if not boxes:
                    raise GmailAuthError("No hay buzón autorizado para leer Pub/Sub.")
                mailbox = boxes[0]
            refresh_token = await self.state.get_secret(refresh_token_key(self.name, mailbox))
            if refresh_token is None and mailbox != mailbox.lower():
                refresh_token = await self.state.get_secret(refresh_token_key(self.name, mailbox.lower()))
            if refresh_token is None:
                raise GmailAuthError(
                    f"El buzón {mailbox} no está autorizado todavía: ejecutá `centinela auth gmail {self.name}`."
                )
        try:
            return await asyncio.to_thread(self.build_credentials, key, refresh_token)
        except GmailAuthError:
            raise
        except (OSError, ValueError) as exc:
            raise GmailAuthError(
                f"No se pudo leer el archivo de credenciales de Google: {type(exc).__name__}: {exc}"
            ) from exc

    async def _access_token(self, key: str, force: bool = False) -> str:
        lock = self._cred_locks.setdefault(key, asyncio.Lock())
        async with lock:
            creds = self._creds.get(key)
            if creds is None:
                creds = await self._make_credentials(key)
                self._creds[key] = creds
            if force or not getattr(creds, "valid", False) or not getattr(creds, "token", None):
                try:
                    await asyncio.to_thread(_refresh_sync, creds)
                except Exception as exc:  # google.auth.exceptions.RefreshError / TransportError
                    # se descartan: si el usuario re-autoriza (`centinela auth gmail`), se relee el state
                    self._creds.pop(key, None)
                    mailbox = None if key == _PUBSUB_KEY else key
                    scopes = [SCOPE_PUBSUB] if key == _PUBSUB_KEY else self.gmail_scopes
                    raise GmailAuthError(_auth_hint(exc, mailbox, self.config.auth, scopes)) from None
            token = getattr(creds, "token", None)
            if not token:
                raise GmailAuthError("Google no devolvió un access token.")
            return str(token)

    def _token_fn(self, key: str) -> http.TokenFn:
        async def token(force: bool) -> str:
            return await self._access_token(key, force)

        return token

    # ------------------------------------------------------------------ API helpers

    def _user_url(self, mailbox: str, path: str) -> str:
        return f"{GMAIL_API}/users/{quote(mailbox, safe='@')}/{path}"

    async def _api(
        self,
        mailbox: str,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
        max_body: int = http.DEFAULT_MAX_BODY,
        total_timeout: float = 180.0,
        stop: asyncio.Event | None = None,
    ) -> http.HttpResponse:
        return await http.request(
            self._client(),
            method,
            self._user_url(mailbox, path),
            params=params,
            json=json_body,
            token=self._token_fn(mailbox),
            max_body=max_body,
            total_timeout=total_timeout,
            retry_if=_is_gmail_rate_limited,
            stop=stop,
        )

    def _ck(self, mailbox: str, what: str) -> str:
        return f"gmail:{mailbox.lower()}:{what}"

    def _recent_for(self, mailbox: str) -> RecentIds:
        return self._recent.setdefault(mailbox.lower(), RecentIds())

    async def get_profile(self, mailbox: str, stop: asyncio.Event | None = None) -> dict[str, Any]:
        resp = await self._api(mailbox, "GET", "profile", stop=stop)
        resp.raise_for_status(f"getProfile {mailbox}")
        data = resp.json()
        if not isinstance(data, dict) or not str(data.get("historyId", "")).isdigit():
            raise http.HttpError(f"getProfile {mailbox}: respuesta sin historyId válido")
        return data

    # ------------------------------------------------------------------ sincronización

    async def sync_mailbox(self, mailbox: str, emit: EmitFn, stop: asyncio.Event) -> None:
        """Una pasada de sincronización de un buzón (público para tests y `centinela scan`)."""
        cursor = await self.get_cursor(self._ck(mailbox, "history_id"))
        if not cursor or not cursor.isdigit():
            await self._initial_sync(mailbox, emit, stop)
            return
        try:
            await self._history_sync(mailbox, cursor, emit, stop)
        except _HistoryExpired:
            log.warning(
                "Gmail %s: el historyId guardado expiró (Gmail guarda la historia por tiempo limitado); "
                "se resincroniza y se recuperan los mails recientes",
                mailbox,
            )
            await self._resync(mailbox, emit, stop)

    async def _initial_sync(self, mailbox: str, emit: EmitFn, stop: asyncio.Event) -> None:
        profile = await self.get_profile(mailbox, stop)
        history_id = str(profile["historyId"])
        if self.config.backfill_hours > 0:
            since = utcnow() - timedelta(hours=self.config.backfill_hours)
            log.info(
                "Gmail %s: primera ejecución, analizando mails de las últimas %d h",
                mailbox,
                self.config.backfill_hours,
            )
            if not await self._emit_query(mailbox, since, emit, stop):
                return  # interrumpido: no se guarda cursor, se repite la próxima vez
        else:
            log.info("Gmail %s: primera ejecución, se analizan los mails que lleguen desde ahora", mailbox)
        await self.set_cursor(self._ck(mailbox, "history_id"), history_id)
        await self._mark_synced(mailbox, force=True)

    async def _resync(self, mailbox: str, emit: EmitFn, stop: asyncio.Event) -> None:
        profile = await self.get_profile(mailbox, stop)
        history_id = str(profile["historyId"])
        now = utcnow()
        floor = now - timedelta(seconds=self.catchup_window_s)
        since = floor
        last = await self.get_cursor(self._ck(mailbox, "last_sync"))
        if last and last.isdigit():
            last_dt = datetime.fromtimestamp(int(last), tz=UTC) - timedelta(hours=1)
            since = max(floor, min(last_dt, now))
        if not await self._emit_query(mailbox, since, emit, stop):
            return
        await self.set_cursor(self._ck(mailbox, "history_id"), history_id)
        await self._mark_synced(mailbox, force=True)

    async def _emit_query(self, mailbox: str, since: datetime, emit: EmitFn, stop: asyncio.Event) -> bool:
        """Lista mails con `label_query` posteriores a `since` y los entrega (más viejo primero)."""
        query = f"({self.config.label_query}) after:{int(since.timestamp())}"
        ids: list[str] = []
        seen: set[str] = set()
        page_token: str | None = None
        truncated = False
        while True:
            params: dict[str, Any] = {"q": query, "maxResults": 500, "includeSpamTrash": "true"}
            if page_token:
                params["pageToken"] = page_token
            resp = await self._api(mailbox, "GET", "messages", params=params, stop=stop)
            resp.raise_for_status(f"messages.list {mailbox}")
            data = resp.json()
            for m in (data.get("messages") or []) if isinstance(data, dict) else []:
                mid = m.get("id") if isinstance(m, dict) else None
                if isinstance(mid, str) and _GMAIL_ID_RE.match(mid) and mid not in seen:
                    seen.add(mid)
                    ids.append(mid)
            page_token = data.get("nextPageToken") if isinstance(data, dict) else None
            if not isinstance(page_token, str) or not page_token:
                break
            if len(ids) >= self.max_catchup_messages:
                truncated = True
                break
        if truncated or len(ids) > self.max_catchup_messages:
            log.warning(
                "Gmail %s: hay más de %d mails para recuperar; se analizan solo los %d más recientes",
                mailbox,
                self.max_catchup_messages,
                self.max_catchup_messages,
            )
            ids = ids[: self.max_catchup_messages]
        for mid in reversed(ids):
            if stop.is_set():
                return False
            await self._process_message(mailbox, mid, None, emit, stop, require_labels=False)
        return True

    async def _history_sync(self, mailbox: str, start: str, emit: EmitFn, stop: asyncio.Event) -> None:
        watched = self.watched_labels()
        query_start = start  # el pageToken está atado a este startHistoryId: no cambiarlo entre páginas
        page_token: str | None = None
        pages = 0
        seen: set[str] = set()
        while True:
            params: dict[str, Any] = {
                "startHistoryId": query_start,
                "historyTypes": "messageAdded",
                "maxResults": 500,
            }
            if page_token:
                params["pageToken"] = page_token
            resp = await self._api(mailbox, "GET", "history", params=params, stop=stop)
            if resp.status_code == 404:
                raise _HistoryExpired()
            resp.raise_for_status(f"history.list {mailbox}")
            data = resp.json()
            if not isinstance(data, dict):
                raise http.HttpError(f"history.list {mailbox}: respuesta inesperada")
            max_record = 0
            for rec in data.get("history") or []:
                if not isinstance(rec, dict):
                    continue
                for added in rec.get("messagesAdded") or []:
                    msg = added.get("message") if isinstance(added, dict) else None
                    if not isinstance(msg, dict):
                        continue
                    mid = msg.get("id")
                    if not isinstance(mid, str) or not _GMAIL_ID_RE.match(mid) or mid in seen:
                        continue
                    seen.add(mid)
                    labels = msg.get("labelIds")
                    labels = [x for x in labels if isinstance(x, str)] if isinstance(labels, list) else None
                    if labels is not None and (_OUTGOING & set(labels) or not watched & set(labels)):
                        continue
                    if stop.is_set():
                        return  # sin checkpoint de esta página: se reprocesa (al-menos-una-vez)
                    await self._process_message(mailbox, mid, labels, emit, stop, require_labels=True)
                rid = str(rec.get("id", ""))
                if rid.isdigit():
                    max_record = max(max_record, int(rid))
            pages += 1
            nxt = data.get("nextPageToken")
            if isinstance(nxt, str) and nxt:
                if max_record:  # checkpoint intermedio: todo lo de esta página ya se entregó
                    start = str(max(int(start), max_record))
                    await self.set_cursor(self._ck(mailbox, "history_id"), start)
                if pages >= self.max_history_pages:
                    log.info("Gmail %s: muchas novedades; se continúa en la próxima pasada", mailbox)
                    self._wake_mailbox(mailbox)
                    await self._mark_synced(mailbox)
                    return
                page_token = nxt
                continue
            new = str(data.get("historyId", ""))
            final = max(int(start), max_record, int(new) if new.isdigit() else 0)
            if str(final) != start or max_record:
                await self.set_cursor(self._ck(mailbox, "history_id"), str(final))
                await self._mark_synced(mailbox, force=True)
            else:
                await self._mark_synced(mailbox)
            return

    async def _process_message(
        self,
        mailbox: str,
        mid: str,
        history_labels: list[str] | None,
        emit: EmitFn,
        stop: asyncio.Event,
        *,
        require_labels: bool,
    ) -> None:
        recent = self._recent_for(mailbox)
        if mid in recent:
            return
        meta_resp = await self._api(
            mailbox,
            "GET",
            f"messages/{quote(mid, safe='')}",
            params={"format": "minimal", "fields": "id,labelIds,sizeEstimate,internalDate"},
            stop=stop,
        )
        if meta_resp.status_code == 404:
            log.debug("Gmail %s: el mensaje ya no existe; se omite", mailbox)
            return
        meta_resp.raise_for_status(f"messages.get(minimal) {mailbox}")
        meta = meta_resp.json()
        if not isinstance(meta, dict):
            return
        now_labels = {x for x in (meta.get("labelIds") or []) if isinstance(x, str)}
        labels = now_labels | set(history_labels or [])
        if labels & _OUTGOING:
            return
        watched = self.watched_labels()
        if require_labels and not labels & watched:
            return
        if "SPAM" in now_labels:
            folder = "SPAM"
        elif "INBOX" in labels:
            folder = "INBOX"
        elif "SPAM" in labels:
            folder = "SPAM"
        else:
            folder = None
        limit = self.max_message_bytes
        try:
            size = int(meta.get("sizeEstimate") or 0)
        except (TypeError, ValueError):
            size = 0
        ref = MessageRef(connector=self.name, mailbox=mailbox, remote_id=mid, folder=folder)
        meta_received = http.utc_from_ms(meta.get("internalDate"))
        if size > limit:
            raw = await self._headers_only(ref, size, meta_received, stop)
            if raw is not None:
                await emit(raw)
            recent.add(mid)
            return
        try:
            raw_resp = await self._api(
                mailbox,
                "GET",
                f"messages/{quote(mid, safe='')}",
                params={"format": "raw", "fields": "raw,internalDate"},
                max_body=limit * 4 // 3 + 64 * 1024,
                total_timeout=600.0,
                stop=stop,
            )
        except http.ResponseTooLarge:
            # sizeEstimate mintió (o es solo una estimación): headers por metadata
            raw = await self._headers_only(ref, None, meta_received, stop)
            if raw is not None:
                await emit(raw)
            recent.add(mid)
            return
        if raw_resp.status_code == 404:
            log.debug("Gmail %s: el mensaje ya no existe; se omite", mailbox)
            return
        raw_resp.raise_for_status(f"messages.get(raw) {mailbox}")
        try:
            if len(raw_resp.content) > 1024 * 1024:
                raw_bytes, internal = await asyncio.to_thread(_decode_raw_response, raw_resp.content)
            else:
                raw_bytes, internal = _decode_raw_response(raw_resp.content)
        except (ValueError, binascii.Error, UnicodeDecodeError) as exc:
            log.warning(
                "Gmail %s: no se pudo decodificar un mensaje (%s); se omite", mailbox, type(exc).__name__
            )
            recent.add(mid)
            return
        received_at = http.utc_from_ms(internal) or meta_received or utcnow()
        if len(raw_bytes) > limit:
            # ya lo tenemos en memoria (acotado por max_body): los headers salen de ahí, sin otro request
            self._note_truncated(mailbox, len(raw_bytes))
            raw = oversize_raw(
                ref,
                header_section(raw_bytes, header_cap(limit)),
                original_size=len(raw_bytes),
                limit=limit,
                received_at=received_at,
            )
        else:
            raw = RawMessage(ref=ref, raw=raw_bytes, received_at=received_at)
        await emit(raw)
        recent.add(mid)

    async def _headers_only(
        self, ref: MessageRef, size: int | None, received: datetime | None, stop: asyncio.Event
    ) -> RawMessage | None:
        """Mail que supera max_message_bytes: solo sus headers (`format=metadata`). None si ya no existe."""
        mailbox, limit = ref.mailbox, self.max_message_bytes
        resp = await self._api(
            mailbox,
            "GET",
            f"messages/{quote(ref.remote_id, safe='')}",
            params={"format": "metadata", "fields": "payload/headers,internalDate,sizeEstimate"},
            stop=stop,
        )
        if resp.status_code == 404:
            log.debug("Gmail %s: el mensaje ya no existe; se omite", mailbox)
            return None
        resp.raise_for_status(f"messages.get(metadata) {mailbox}")
        data = resp.json()
        data = data if isinstance(data, dict) else {}
        payload = data.get("payload")
        fields = payload.get("headers") if isinstance(payload, dict) else None
        headers = headers_from_api(fields if isinstance(fields, list) else None, max_bytes=header_cap(limit))
        try:
            estimate = int(data.get("sizeEstimate") or 0)
        except (TypeError, ValueError):
            estimate = 0
        real = max(size or 0, estimate) or None
        self._note_truncated(mailbox, real)
        return oversize_raw(
            ref,
            headers,
            original_size=real,
            limit=limit,
            received_at=http.utc_from_ms(data.get("internalDate")) or received or utcnow(),
        )

    def _note_truncated(self, mailbox: str, size: int | None) -> None:
        self.truncated_too_large += 1
        log.warning(
            "Gmail %s: un mensaje de %s bytes supera max_message_bytes=%d; se analizan solo los encabezados",
            mailbox,
            size if size and size > self.max_message_bytes else f"más de {self.max_message_bytes}",
            self.max_message_bytes,
        )

    async def _mark_synced(self, mailbox: str, *, force: bool = False) -> None:
        now = time.time()
        last = self._last_sync_written.get(mailbox.lower(), 0.0)
        if force or now - last >= 600:
            await self.set_cursor(self._ck(mailbox, "last_sync"), str(int(now)))
            self._last_sync_written[mailbox.lower()] = now

    # ------------------------------------------------------------------ watch + Pub/Sub

    async def ensure_watch(self, mailbox: str, stop: asyncio.Event | None = None) -> None:
        if not self.pubsub_enabled:
            return
        st = self._status.setdefault(mailbox, _MailboxStatus())
        now = time.monotonic()
        if st.watch_next_at and now < st.watch_next_at:
            return
        body = {
            "topicName": self.config.pubsub_topic,
            "labelIds": sorted(self.watched_labels()),
            "labelFilterBehavior": "include",
        }
        try:
            resp = await self._api(mailbox, "POST", "watch", json_body=body, stop=stop)
            resp.raise_for_status(f"users.watch {mailbox}")
            data = resp.json()
        except http.HttpError as exc:
            st.watching = False
            retry = self.watch_retry_s if exc.status in (400, 403, 404) else min(self.watch_retry_s, 300.0)
            st.watch_next_at = now + retry
            log.warning(
                "Gmail %s: no se pudo activar el aviso en tiempo real (users.watch): %s. "
                "Revisá que el tópico exista y que gmail-api-push@system.gserviceaccount.com tenga rol "
                "Pub/Sub Publisher. Mientras tanto se usa polling.",
                mailbox,
                exc,
            )
            return
        st.watching = True
        st.watch_expiration = http.utc_from_ms(data.get("expiration")) if isinstance(data, dict) else None
        st.watch_next_at = now + self.watch_renew_s
        log.info("Gmail %s: aviso en tiempo real activo (vence %s)", mailbox, st.watch_expiration)

    def _wake_mailbox(self, mailbox: str | None) -> None:
        if mailbox:
            for m, ev in self._wake.items():
                if m.lower() == mailbox.lower():
                    ev.set()
                    return
        for ev in self._wake.values():  # desconocido: despertar a todos (barato)
            ev.set()

    def handle_notification(self, data: Any) -> str | None:
        """Procesa el `data` (base64) de un mensaje Pub/Sub de Gmail. Devuelve el buzón despertado."""
        mailbox: str | None = None
        if isinstance(data, str) and 0 < len(data) <= 8192:
            try:
                payload = json.loads(_b64decode_any(data))
                if isinstance(payload, dict) and isinstance(payload.get("emailAddress"), str):
                    mailbox = payload["emailAddress"][:320]
            except (ValueError, binascii.Error, UnicodeDecodeError):
                mailbox = None
        known = {m.lower(): m for m in self._wake}
        if mailbox and mailbox.lower() in known:
            self._wake_mailbox(mailbox)
            return known[mailbox.lower()]
        log.debug("Gmail Pub/Sub: notificación sin buzón reconocible; se sincronizan todos")
        self._wake_mailbox(None)
        return None

    async def pubsub_pull_once(self, stop: asyncio.Event | None = None) -> int:
        """Un pull de la suscripción + ack. Devuelve cuántos mensajes llegaron."""
        sub = self.config.pubsub_subscription
        timeout = httpx.Timeout(connect=10.0, read=self.pubsub_pull_timeout_s, write=30.0, pool=15.0)
        resp = await http.request(
            self._client(),
            "POST",
            f"{PUBSUB_API}/{sub}:pull",
            json={"maxMessages": 100},
            token=self._token_fn(_PUBSUB_KEY),
            timeouts=timeout,
            total_timeout=self.pubsub_pull_timeout_s + 30.0,
            policy=http.RetryPolicy(max_attempts=2),
            stop=stop,
        )
        resp.raise_for_status("Pub/Sub pull")
        data = resp.json()
        received = data.get("receivedMessages") if isinstance(data, dict) else None
        if not isinstance(received, list) or not received:
            return 0
        ack_ids: list[str] = []
        for rm in received[:1000]:
            if not isinstance(rm, dict):
                continue
            ack = rm.get("ackId")
            if isinstance(ack, str) and 0 < len(ack) <= 4096:
                ack_ids.append(ack)
            msg = rm.get("message")
            self.handle_notification(msg.get("data") if isinstance(msg, dict) else None)
        if ack_ids:
            ack_resp = await http.request(
                self._client(),
                "POST",
                f"{PUBSUB_API}/{sub}:acknowledge",
                json={"ackIds": ack_ids},
                token=self._token_fn(_PUBSUB_KEY),
                stop=stop,
            )
            ack_resp.raise_for_status("Pub/Sub acknowledge")
        return len(received)

    async def get_subscription(self) -> http.HttpResponse:
        """GET de la suscripción Pub/Sub (diagnóstico de permisos)."""
        return await http.request(
            self._client(),
            "GET",
            f"{PUBSUB_API}/{self.config.pubsub_subscription}",
            token=self._token_fn(_PUBSUB_KEY),
            policy=http.RetryPolicy(max_attempts=3),
        )

    async def _pubsub_loop(self, stop: asyncio.Event) -> None:
        backoff = http.Backoff(1.0, self.error_backoff_cap_s)
        while not stop.is_set():
            try:
                n = await self.pubsub_pull_once(stop)
            except http.Stopped:
                break
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                if isinstance(exc, http.HttpError) and isinstance(
                    exc.__cause__, (httpx.TimeoutException, TimeoutError)
                ):
                    # long-poll sin mensajes que superó el timeout de lectura: normal
                    self._pubsub_ok = True
                    continue
                self._pubsub_ok = False
                log.warning("Gmail Pub/Sub (%s): error haciendo pull: %s", self.name, exc)
                if await http.sleep_or_stop(backoff.next(), stop):
                    break
                continue
            self._pubsub_ok = True
            backoff.reset()
            if n == 0 and await http.sleep_or_stop(self.pubsub_idle_s, stop):
                break

    # ------------------------------------------------------------------ loop principal

    def _set_status(self, mailbox: str, ok: bool, error: str | None = None) -> None:
        st = self._status.setdefault(mailbox, _MailboxStatus())
        st.ok = ok
        st.error = error
        if ok:
            st.last_sync = utcnow()
        all_ok = bool(self._status) and all(s.ok for s in self._status.values())
        CONNECTOR_UP.labels(connector=self.name).set(1 if all_ok else 0)

    def _idle_timeout(self, mailbox: str) -> float:
        base = max(float(self.config.poll_interval_s), self.min_poll_s)
        st = self._status.get(mailbox)
        if self.pubsub_enabled and st is not None and st.watching and self._pubsub_ok:
            return max(base, self.pubsub_safety_poll_s)
        return base

    async def _mailbox_loop(self, mailbox: str, emit: EmitFn, stop: asyncio.Event) -> None:
        backoff = http.Backoff(2.0, self.error_backoff_cap_s)
        auth_backoff = http.Backoff(30.0, self.auth_error_backoff_cap_s)
        if self.start_jitter_s > 0 and await http.sleep_or_stop(random.uniform(0, self.start_jitter_s), stop):  # noqa: S311
            return
        last_start = 0.0
        while not stop.is_set():
            gap = time.monotonic() - last_start
            if gap < self.min_poll_s and await http.sleep_or_stop(self.min_poll_s - gap, stop):
                break
            last_start = time.monotonic()
            self._wake[mailbox].clear()
            try:
                await self.ensure_watch(mailbox, stop)
                await self.sync_mailbox(mailbox, emit, stop)
            except http.Stopped:
                break
            except asyncio.CancelledError:
                raise
            except GmailAuthError as exc:
                self._set_status(mailbox, False, str(exc)[:500])
                log.error("Gmail %s: %s", mailbox, exc)
                timeout = auth_backoff.next()
            except Exception as exc:
                self._set_status(mailbox, False, f"{type(exc).__name__}: {exc}"[:500])
                log.warning(
                    "Gmail %s: error sincronizando (%s); se reintenta",
                    mailbox,
                    exc,
                    exc_info=log.isEnabledFor(logging.DEBUG),
                )
                timeout = backoff.next()
                ra = getattr(exc, "retry_after", None)
                if isinstance(ra, (int, float)):
                    timeout = max(timeout, min(float(ra), 900.0))
            else:
                self._set_status(mailbox, True)
                backoff.reset()
                auth_backoff.reset()
                timeout = self._idle_timeout(mailbox)
            await http.wait_any(stop, self._wake[mailbox], timeout)

    async def run(self, emit: EmitFn, stop: asyncio.Event) -> None:
        self.validate()
        mailboxes = await self.resolve_mailboxes()
        if not mailboxes:
            raise ValueError(
                f"conector gmail '{self.name}': no hay buzones. Listalos en `mailboxes` o autorizá uno con "
                f"`centinela auth gmail {self.name}`."
            )
        self._mailboxes = mailboxes
        for m in mailboxes:
            self._wake.setdefault(m, asyncio.Event())
            self._status.setdefault(m, _MailboxStatus())
        CONNECTOR_UP.labels(connector=self.name).set(0)
        tasks = [
            asyncio.create_task(self._mailbox_loop(m, emit, stop), name=f"gmail:{self.name}:{m}")
            for m in mailboxes
        ]
        if self.pubsub_enabled:
            tasks.append(asyncio.create_task(self._pubsub_loop(stop), name=f"gmail:{self.name}:pubsub"))
        log.info(
            "Gmail '%s': vigilando %d buzón(es) (%s)",
            self.name,
            len(mailboxes),
            "tiempo real vía Pub/Sub"
            if self.pubsub_enabled
            else f"polling cada {self.config.poll_interval_s}s",
        )
        try:
            await stop.wait()
        except asyncio.CancelledError:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise
        else:
            await http.shutdown_tasks(tasks, self.stop_grace_s)
        finally:
            CONNECTOR_UP.labels(connector=self.name).set(0)

    # ------------------------------------------------------------------ etiquetado

    async def _list_labels(self, mailbox: str) -> dict[str, tuple[str, str]]:
        resp = await self._api(mailbox, "GET", "labels")
        resp.raise_for_status(f"labels.list {mailbox}")
        data = resp.json()
        out: dict[str, tuple[str, str]] = {}
        for lab in (data.get("labels") or []) if isinstance(data, dict) else []:
            if isinstance(lab, dict) and isinstance(lab.get("name"), str) and isinstance(lab.get("id"), str):
                out[lab["name"].lower()] = (lab["id"], lab["name"])
        return out

    async def _create_label(self, mailbox: str, name: str, color: dict[str, str] | None) -> str | None:
        body: dict[str, Any] = {
            "name": name,
            "labelListVisibility": "labelShow",
            "messageListVisibility": "show",
        }
        if color:
            body["color"] = color
        resp = await self._api(mailbox, "POST", "labels", json_body=body)
        if resp.status_code == 400 and color:
            body.pop("color", None)  # paleta rechazada: crear sin color
            resp = await self._api(mailbox, "POST", "labels", json_body=body)
        if resp.status_code == 409:  # ya existe (carrera con otro proceso o distinto uso de mayúsculas)
            existing = await self._list_labels(mailbox)
            hit = existing.get(name.lower())
            return hit[0] if hit else None
        resp.raise_for_status(f"labels.create {mailbox}")
        data = resp.json()
        lid = data.get("id") if isinstance(data, dict) else None
        return lid if isinstance(lid, str) else None

    async def ensure_label(self, mailbox: str, name: str, level: VerdictLevel | None = None) -> str:
        """Devuelve el id del label `name` en el buzón, creándolo si no existe (cacheado)."""
        key = (mailbox.lower(), name.lower())
        if key in self._label_ids:
            return self._label_ids[key]
        async with self._label_lock:
            if key in self._label_ids:
                return self._label_ids[key]
            existing = await self._list_labels(mailbox)
            hit = existing.get(name.lower())
            if hit:
                self._label_ids[key] = hit[0]
                return hit[0]
            if "/" in name:
                parent = name.rsplit("/", 1)[0].strip()
                if parent and parent.lower() not in existing:
                    try:  # label padre para que Gmail lo muestre anidado; no es crítico
                        await self._create_label(mailbox, parent, None)
                    except http.HttpError as exc:
                        log.debug("Gmail %s: no se pudo crear el label padre: %s", mailbox, exc)
            lid = await self._create_label(mailbox, name, _LABEL_COLORS.get(level) if level else None)
            if not lid:
                raise http.HttpError(f"Gmail {mailbox}: no se pudo crear el label {name!r}")
            log.info("Gmail %s: label %r creado", mailbox, name)
            self._label_ids[key] = lid
            return lid

    async def apply_verdict(self, ref: MessageRef, result: AnalysisResult, tag: TagConfig) -> str | None:
        if ref.connector != self.name or not self.config.tag or not tag.enabled:
            return None
        level = result.verdict.level
        name = label_for_level(level, tag)
        if not name or not _GMAIL_ID_RE.match(ref.remote_id):
            return None
        path = f"messages/{quote(ref.remote_id, safe='')}/modify"
        for attempt in range(2):
            label_id = await self.ensure_label(ref.mailbox, name, level)
            # SOLO addLabelIds: nunca se quitan labels (ni INBOX ni UNREAD), nunca se mueve ni se borra.
            resp = await self._api(ref.mailbox, "POST", path, json_body={"addLabelIds": [label_id]})
            if resp.status_code == 404:
                log.info("Gmail %s: el mensaje a etiquetar ya no existe", ref.mailbox)
                return None
            if resp.status_code == 400 and attempt == 0:
                # el label pudo haber sido borrado por el usuario: invalidar cache y recrear
                self._label_ids.pop((ref.mailbox.lower(), name.lower()), None)
                continue
            resp.raise_for_status(f"messages.modify {ref.mailbox}")
            return f"gmail:label:{name}"
        return None

    # ------------------------------------------------------------------ salud / cierre

    async def healthcheck(self) -> dict[str, Any]:
        boxes = {
            m: {
                "ok": st.ok,
                "error": st.error,
                "last_sync": st.last_sync.isoformat() if st.last_sync else None,
                "realtime": st.watching,
                "watch_expiration": st.watch_expiration.isoformat() if st.watch_expiration else None,
            }
            for m, st in self._status.items()
        }
        running = bool(self._status)
        out: dict[str, Any] = {
            "ok": (not running) or all(st.ok for st in self._status.values()),
            "running": running,
            "mailboxes": boxes,
            "truncated_too_large": self.truncated_too_large,
        }
        if self.pubsub_enabled:
            out["pubsub_ok"] = self._pubsub_ok
        return out

    async def close(self) -> None:
        if self._client_obj is not None:
            await self._client_obj.aclose()
            self._client_obj = None


__all__ = [
    "GMAIL_API",
    "PUBSUB_API",
    "SCOPE_MODIFY",
    "SCOPE_PUBSUB",
    "SCOPE_READONLY",
    "GmailAuthError",
    "GmailConnector",
    "oauth_mailboxes_key",
    "refresh_token_key",
]
