"""Conector Microsoft 365 / Exchange Online vía Microsoft Graph (client credentials, REST con httpx).

Cómo funciona
-------------
- Un loop por (buzón, carpeta) — por defecto `inbox` y `junkemail` — con *delta query*:
  `GET /v1.0/users/{buzón}/mailFolders/{carpeta}/messages/delta?$select=id,receivedDateTime,internetMessageId`
  siguiendo `@odata.nextLink` y guardando `@odata.deltaLink` en el state store DESPUÉS de entregar los mails.
- Primera vez: se pide el delta inicial con `$filter=receivedDateTime ge <ahora>` (el único `$filter`
  soportado en delta de mensajes), así obtener el deltaLink es barato aunque el buzón tenga 100.000
  mails. Con `backfill_hours > 0` el filtro arranca N horas atrás y esos mails se analizan
  (Graph limita un delta filtrado a 5.000 mensajes).
- Se pide `changeType=created` (solo mails nuevos o movidos a la carpeta; si el servidor no lo acepta
  junto con `$filter`, se usa el delta completo). Se ignoran las entradas `@removed` y los cambios de
  mails viejos (marcar leído genera entradas en el delta): solo se analizan mails con `receivedDateTime`
  dentro de la ventana vigilada (como mucho 14 días antes de la última ronda).
- Ids inmutables (`Prefer: IdType="ImmutableId"`): el id no cambia si el usuario mueve el mail de carpeta,
  así el etiquetado posterior sigue funcionando.
- MIME: `GET /users/{buzón}/messages/{id}/$value` en streaming con tope de `limits.max_message_bytes`.
  Un mail más grande NO se omite (sería una evasión trivial): se piden sus headers
  (`$select=internetMessageHeaders`, más el tamaño real vía la propiedad extendida PR_MESSAGE_SIZE) y se
  emite con `truncated=True` + `original_size`; el pipeline agrega `policy.message_too_large`.
- 410 Gone / `syncStateNotFound` (delta token vencido): resincronización con recuperación acotada
  (desde el último delta completo, máximo 2 días). 429/503 con `Retry-After`, 401 => token nuevo.
- Polling cada `poll_interval_s` (no hace falta exponer ninguna URL pública).

Etiquetado (`apply_verdict`)
----------------------------
Agrega una *categoría* de Outlook (`actions.tag.label_*`) a las existentes del mail (PATCH de
`categories` con la lista actual + la nueva). Nunca mueve, borra ni cambia el estado leído.
Si la app tiene `MailboxSettings.ReadWrite`, además crea la categoría en la lista maestra del buzón con
color (rojo = malicioso, naranja = sospechoso); sin ese permiso la categoría igual se aplica, sin color.

Permisos mínimos (Microsoft Entra ID > App registrations > API permissions > Microsoft Graph >
*Application permissions*, con consentimiento de administrador)
----------------------------------------------------------------------------------------------
- Solo alertas (`tag: false`): `Mail.Read`.
- Con etiquetado: `Mail.ReadWrite` (Graph no tiene un permiso más chico para escribir categorías).
- Opcional: `MailboxSettings.ReadWrite` (solo para crear las categorías con color en la lista maestra).
- MUY recomendado: limitar la app a los buzones vigilados. Los permisos de aplicación dan acceso a TODOS
  los buzones del tenant; restringilos con *RBAC for Applications* de Exchange Online
  (`New-ManagementScope` + `New-ManagementRoleAssignment -Role "Application Mail.Read"`), o con la
  anterior `New-ApplicationAccessPolicy -AccessRight RestrictAccess`.
- Credencial: `client_secret`, o mejor `certificate_file` (PEM con clave privada + certificado, o .pfx).
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import formataddr
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import quote, urlsplit

import httpx

from centinela.connectors import _http as http
from centinela.connectors._headers import header_cap, headers_from_api, oversize_raw
from centinela.connectors._http import RecentIds, label_for_level
from centinela.connectors.base import Connector
from centinela.core.models import MessageRef, RawMessage, VerdictLevel, utcnow
from centinela.metrics import CONNECTOR_UP

if TYPE_CHECKING:
    from centinela.connectors.base import EmitFn
    from centinela.core.config import GraphConnectorConfig, Settings, TagConfig
    from centinela.core.models import AnalysisResult
    from centinela.core.state import StateStore

log = logging.getLogger(__name__)

GRAPH_BASE = "https://graph.microsoft.com"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
LOGIN_BASE = "https://login.microsoftonline.com"

PREFER_IMMUTABLE = 'IdType="ImmutableId"'
_SYNC_STATE_CODES = frozenset(
    {
        "syncstatenotfound",
        "syncstateinvalid",
        "resyncrequired",
        "errorinvalidsyncstatedata",
        "invaliddeltatoken",
    }
)
_CATEGORY_COLORS = {VerdictLevel.MALICIOUS: "preset0", VerdictLevel.SUSPICIOUS: "preset1"}  # rojo / naranja
_MAX_ID_LEN = 1024
_MAX_LINK_LEN = 16384
_MAX_CERT_FILE = 1024 * 1024
# mail demasiado grande: headers + campos para armar unos mínimos si Exchange no guardó los de Internet
_HEADERS_SELECT = "internetMessageHeaders,receivedDateTime,subject,from,toRecipients,internetMessageId"
_PR_MESSAGE_SIZE = 0x0E08  # PidTagMessageSize: tamaño real del mail en el buzón
_SIZE_EXPAND = "singleValueExtendedProperties($filter=id eq 'Integer 0x0E08')"
_MAX_SYNTH_RECIPIENTS = 100


class GraphAuthError(RuntimeError):
    """No se pudo obtener un token de Microsoft Entra ID (mensaje en español, sin secretos)."""


def _extended_size(data: dict[str, Any]) -> int | None:
    """Valor de PR_MESSAGE_SIZE en `singleValueExtendedProperties` (Graph lo devuelve como texto)."""
    props = data.get("singleValueExtendedProperties")
    for prop in props if isinstance(props, list) else []:
        pid = prop.get("id") if isinstance(prop, dict) else None
        parts = pid.split() if isinstance(pid, str) else []
        if len(parts) != 2 or parts[0].lower() != "integer":
            continue
        try:
            if int(parts[1], 16) != _PR_MESSAGE_SIZE:
                continue
            value = int(str(prop.get("value"))[:20])
        except ValueError:
            continue
        return value if value > 0 else None
    return None


def _graph_address(obj: Any) -> str | None:
    email = obj.get("emailAddress") if isinstance(obj, dict) else None
    if not isinstance(email, dict):
        return None
    address, name = email.get("address"), email.get("name")
    if not isinstance(address, str) or not address.strip():
        return None
    try:
        return formataddr((name if isinstance(name, str) else "", address.strip()))
    except (UnicodeError, ValueError):
        return address.strip()


def _synthetic_headers(data: dict[str, Any]) -> list[dict[str, str]]:
    """Headers mínimos (From/To/Subject/Message-ID) para mails sin `internetMessageHeaders`
    (por ejemplo, mails internos de Exchange que nunca pasaron por SMTP)."""
    out: list[dict[str, str]] = []
    sender = _graph_address(data.get("from"))
    if sender:
        out.append({"name": "From", "value": sender})
    recipients = data.get("toRecipients")
    if isinstance(recipients, list):
        to = [a for a in (_graph_address(r) for r in recipients[:_MAX_SYNTH_RECIPIENTS]) if a]
        if to:
            out.append({"name": "To", "value": ", ".join(to)})
    for field, header in (("subject", "Subject"), ("internetMessageId", "Message-ID")):
        value = data.get(field)
        if isinstance(value, str) and value:
            out.append({"name": header, "value": value})
    return out


class _DeltaExpired(Exception):
    pass


class _ChangeTypeUnsupported(Exception):
    pass


# --------------------------------------------------------------------------- credenciales


def _pem_blocks(text: str) -> list[tuple[str, str]]:
    """Separa un archivo PEM en bloques (etiqueta, pem completo). Parser lineal, sin regex."""
    blocks: list[tuple[str, str]] = []
    label: str | None = None
    lines: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if label is None:
            if s.startswith("-----BEGIN ") and s.endswith("-----"):
                label = s[len("-----BEGIN ") : -5].strip()
                lines = [s]
        else:
            lines.append(s)
            if s == f"-----END {label}-----":
                blocks.append((label, "\n".join(lines) + "\n"))
                label = None
                lines = []
    return blocks


def load_certificate_credential(path: Path | str) -> dict[str, str]:
    """Arma el `client_credential` de MSAL a partir de un certificado.

    - `.pfx`/`.p12`: MSAL lo lee directamente (thumbprint SHA-256).
    - PEM (clave privada sin contraseña + certificado en el mismo archivo): se calcula el thumbprint SHA-1
      del certificado con `cryptography` (es el que muestra el portal de Entra ID).
    """
    p = Path(path)
    if p.suffix.lower() in (".pfx", ".p12"):
        if not p.is_file():
            raise GraphAuthError(f"no existe el certificado {p}")
        return {"private_key_pfx_path": str(p)}
    try:
        if p.stat().st_size > _MAX_CERT_FILE:
            raise GraphAuthError(f"el archivo de certificado {p} es demasiado grande")
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise GraphAuthError(f"no se pudo leer el certificado {p}: {exc.strerror or exc}") from None
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization

    blocks = _pem_blocks(text)
    cert_pem = next((b for lab, b in blocks if lab == "CERTIFICATE"), None)
    key_pem = next((b for lab, b in blocks if lab.endswith("PRIVATE KEY")), None)
    if cert_pem is None or key_pem is None:
        raise GraphAuthError(
            f"el archivo {p} debe tener la clave privada y el certificado en formato PEM "
            "(o usá un .pfx). Ej: cat clave.key cert.crt > centinela-graph.pem"
        )
    if "ENCRYPTED" in key_pem.split("\n", 2)[0] or "Proc-Type: 4,ENCRYPTED" in key_pem:
        raise GraphAuthError(
            "la clave privada del certificado tiene contraseña; usá una sin contraseña o un .pfx"
        )
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    except (ValueError, TypeError) as exc:
        raise GraphAuthError(f"certificado o clave inválidos en {p}: {type(exc).__name__}") from None
    thumbprint = cert.fingerprint(hashes.SHA1()).hex().upper()  # noqa: S303 - x5t que exige Entra ID
    private_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    return {"private_key": private_pem, "thumbprint": thumbprint}


def _describe_msal_error(result: dict[str, Any]) -> str:
    err = str(result.get("error") or "error_desconocido")
    desc = str(result.get("error_description") or "")
    first = desc.splitlines()[0][:300] if desc else ""
    codes = result.get("error_codes") or []
    hint = ""
    if 7000215 in codes or "AADSTS7000215" in desc:
        hint = " El client_secret es inválido (¿copiaste el 'Value' y no el 'Secret ID'?)."
    elif 7000222 in codes or "AADSTS7000222" in desc:
        hint = " El client_secret venció: generá uno nuevo en Entra ID."
    elif 700016 in codes or "AADSTS700016" in desc:
        hint = " No existe la app (client_id) en ese tenant."
    elif 90002 in codes or "AADSTS90002" in desc:
        hint = " El tenant_id no existe."
    elif 700027 in codes or "AADSTS700027" in desc:
        hint = " El certificado no coincide con el cargado en la app de Entra ID."
    return f"{err}: {first}{hint}"


class GraphTokenProvider:
    """Token de aplicación (client credentials) para Graph con MSAL; cache en memoria, refresh en thread.

    Se usa como `TokenFn`: `await provider(force_refresh)`.
    """

    def __init__(
        self, config: GraphConnectorConfig, *, authority_base: str = LOGIN_BASE, scope: str = GRAPH_SCOPE
    ) -> None:
        self.config = config
        self.authority = f"{authority_base.rstrip('/')}/{quote(config.tenant_id, safe='')}"
        self.scope = scope
        self._app: Any = None
        self._lock = asyncio.Lock()
        self._token: str | None = None
        self._expires_at = 0.0

    def _client_credential(self) -> Any:
        cfg = self.config
        if cfg.client_secret is not None and cfg.client_secret.get_secret_value():
            return cfg.client_secret.get_secret_value()
        if cfg.certificate_file:
            return load_certificate_credential(cfg.certificate_file)
        raise GraphAuthError(f"conector graph '{cfg.name}': falta client_secret o certificate_file")

    def _acquire_sync(self, force: bool) -> tuple[str, float]:
        import msal

        if self._app is None or force:
            # app nueva => cache nuevo (forzar refresh tras un 401)
            self._app = msal.ConfidentialClientApplication(
                self.config.client_id,
                client_credential=self._client_credential(),
                authority=self.authority,
                token_cache=msal.TokenCache(),
                timeout=30,
            )
        result = self._app.acquire_token_for_client(scopes=[self.scope])
        if not isinstance(result, dict) or "access_token" not in result:
            raise GraphAuthError(
                "Microsoft Entra ID rechazó la autenticación de la app: "
                + _describe_msal_error(result if isinstance(result, dict) else {})
            )
        try:
            expires_in = float(result.get("expires_in") or 3599)
        except (TypeError, ValueError):
            expires_in = 3599.0
        return str(result["access_token"]), expires_in

    async def __call__(self, force: bool = False) -> str:
        async with self._lock:
            if not force and self._token and time.monotonic() < self._expires_at:
                return self._token
            try:
                token, expires_in = await asyncio.to_thread(self._acquire_sync, force)
            except GraphAuthError:
                self._app = None
                raise
            except Exception as exc:  # errores de red de requests, certificado ilegible, etc.
                self._app = None
                raise GraphAuthError(
                    f"no se pudo obtener token de Microsoft Entra ID: {type(exc).__name__}: {str(exc)[:200]}"
                ) from None
            self._token = token
            self._expires_at = time.monotonic() + max(60.0, expires_in - 300.0)
            return token


# --------------------------------------------------------------------------- conector


@dataclass
class _FolderStatus:
    ok: bool = False
    error: str | None = None
    last_sync: datetime | None = None


class GraphConnector(Connector):
    type = "graph"

    graph_base: str = GRAPH_BASE
    page_size: int = 50
    max_pages_per_round: int = 2000
    catchup_window_s: float = 2 * 86400.0
    resync_slack_s: float = 600.0
    update_window_s: float = (
        14 * 86400.0
    )  # mails "movidos a la carpeta" más viejos que esto no se re-analizan
    per_mailbox_concurrency: int = 3  # Outlook permite 4 requests concurrentes por buzón y app
    min_poll_s: float = 1.0
    start_jitter_s: float = 3.0
    stop_grace_s: float = 5.0
    auth_error_backoff_cap_s: float = 900.0
    error_backoff_cap_s: float = 300.0

    config: GraphConnectorConfig

    def __init__(self, config: GraphConnectorConfig, settings: Settings, state: StateStore) -> None:
        super().__init__(config, settings, state)
        self.tokens: http.TokenFn = GraphTokenProvider(config)
        self._client_obj: httpx.AsyncClient | None = None
        self._status: dict[tuple[str, str], _FolderStatus] = {}
        self._recent: dict[str, RecentIds] = {}
        self._sems: dict[str, asyncio.Semaphore] = {}
        self._master_done: set[tuple[str, str]] = set()
        self._master_forbidden: set[str] = set()
        self.truncated_too_large = 0  # mails que superaban max_message_bytes: se analizaron solo los headers

    # ------------------------------------------------------------------ helpers

    @property
    def max_message_bytes(self) -> int:
        return int(self.settings.limits.max_message_bytes)

    def validate(self) -> None:
        cfg = self.config
        if not cfg.mailboxes:
            raise ValueError(f"conector graph '{self.name}': listá los buzones a vigilar en `mailboxes`")
        if not cfg.folders:
            raise ValueError(f"conector graph '{self.name}': `folders` no puede estar vacío")
        has_secret = cfg.client_secret is not None and bool(cfg.client_secret.get_secret_value())
        if not has_secret and not cfg.certificate_file:
            raise ValueError(f"conector graph '{self.name}': falta client_secret o certificate_file")

    def _client(self) -> httpx.AsyncClient:
        if self._client_obj is None or self._client_obj.is_closed:
            self._client_obj = http.new_client(max_connections=16)
        return self._client_obj

    def _sem(self, mailbox: str) -> asyncio.Semaphore:
        return self._sems.setdefault(mailbox.lower(), asyncio.Semaphore(self.per_mailbox_concurrency))

    def _user(self, mailbox: str) -> str:
        return f"{self.graph_base}/v1.0/users/{quote(mailbox, safe='@')}"

    def _valid_link(self, link: Any) -> bool:
        """Solo seguir nextLink/deltaLink hacia el mismo host de Graph (el token Bearer viaja en el request)."""
        if not isinstance(link, str) or not link or len(link) > _MAX_LINK_LEN:
            return False
        p, b = urlsplit(link), urlsplit(self.graph_base)
        return (
            p.scheme == "https" and p.netloc.lower() == b.netloc.lower() and not p.username and not p.password
        )

    async def _graph(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
        prefer: str = PREFER_IMMUTABLE,
        accept: str | None = None,
        max_body: int = http.DEFAULT_MAX_BODY,
        total_timeout: float = 180.0,
        stop: asyncio.Event | None = None,
    ) -> http.HttpResponse:
        headers = {"Prefer": prefer}
        if accept:
            headers["Accept"] = accept
        return await http.request(
            self._client(),
            method,
            url,
            params=params,
            json=json_body,
            headers=headers,
            token=self.tokens,
            max_body=max_body,
            total_timeout=total_timeout,
            stop=stop,
        )

    def _ck(self, mailbox: str, folder: str, what: str) -> str:
        return f"graph:{mailbox.lower()}:{folder}:{what}"

    def _recent_for(self, mailbox: str) -> RecentIds:
        return self._recent.setdefault(mailbox.lower(), RecentIds())

    # ------------------------------------------------------------------ sincronización

    async def sync_folder(self, mailbox: str, folder: str, emit: EmitFn, stop: asyncio.Event) -> None:
        """Una ronda de delta para (buzón, carpeta). Público para tests y `centinela scan`."""
        link = await self.get_cursor(self._ck(mailbox, folder, "delta"))
        since = http.parse_iso8601(await self.get_cursor(self._ck(mailbox, folder, "since")))
        if not link or since is None or not self._valid_link(link):
            await self._start_round(mailbox, folder, emit, stop, resync=False)
            return
        # Marca de agua deslizante: cambios sobre mails recibidos mucho antes de la última ronda
        # (marcar leído, mover un mail viejo) no son correo nuevo y no se re-descargan.
        skip_before = since
        checkpoint = http.parse_iso8601(await self.get_cursor(self._ck(mailbox, folder, "checkpoint")))
        if checkpoint is not None:
            skip_before = max(since, checkpoint - timedelta(seconds=self.update_window_s))
        try:
            await self._walk(mailbox, folder, link, since, emit, stop, skip_before=skip_before)
        except _DeltaExpired:
            log.warning(
                "Graph %s/%s: el delta token venció o fue invalidado; se resincroniza y se recuperan los mails recientes",
                mailbox,
                folder,
            )
            await self._start_round(mailbox, folder, emit, stop, resync=True)

    async def _start_round(
        self, mailbox: str, folder: str, emit: EmitFn, stop: asyncio.Event, *, resync: bool
    ) -> None:
        now = utcnow()
        if resync:
            floor = now - timedelta(seconds=self.catchup_window_s)
            checkpoint = http.parse_iso8601(await self.get_cursor(self._ck(mailbox, folder, "checkpoint")))
            emit_from = (
                max(floor, min(checkpoint, now) - timedelta(seconds=self.resync_slack_s))
                if checkpoint
                else floor
            )
        elif self.config.backfill_hours > 0:
            emit_from = now - timedelta(hours=self.config.backfill_hours)
            log.info(
                "Graph %s/%s: primera ejecución, analizando mails de las últimas %d h",
                mailbox,
                folder,
                self.config.backfill_hours,
            )
        else:
            emit_from = now
            log.info(
                "Graph %s/%s: primera ejecución, se analizan los mails que lleguen desde ahora",
                mailbox,
                folder,
            )
        emit_from = emit_from.replace(microsecond=0)
        no_ct_key = self._ck(mailbox, folder, "no_changetype")
        use_change_type = (await self.get_cursor(no_ct_key)) != "1"
        url = self._initial_delta_url(mailbox, folder, emit_from, change_type=use_change_type)
        try:
            await self._walk(mailbox, folder, url, emit_from, emit, stop, initial_change_type=use_change_type)
        except _ChangeTypeUnsupported:
            log.info(
                "Graph %s/%s: el servidor no aceptó changeType=created junto con $filter; se usa delta completo",
                mailbox,
                folder,
            )
            await self.set_cursor(no_ct_key, "1")
            url = self._initial_delta_url(mailbox, folder, emit_from, change_type=False)
            await self._walk(mailbox, folder, url, emit_from, emit, stop)

    def _initial_delta_url(self, mailbox: str, folder: str, emit_from: datetime, *, change_type: bool) -> str:
        # Query armada a mano: `$select`/`$filter` literales como en la documentación de Graph.
        # changeType=created: las rondas siguientes traen solo mails nuevos en la carpeta (incluye los
        # movidos a ella), no cambios de leído/no leído ni las categorías que pone Centinela.
        filt = quote(f"receivedDateTime ge {http.iso_utc(emit_from)}", safe="")
        ct = "changeType=created&" if change_type else ""
        return (
            f"{self._user(mailbox)}/mailFolders/{quote(folder, safe='')}/messages/delta"
            f"?{ct}$select=id,receivedDateTime,internetMessageId&$filter={filt}"
        )

    async def _walk(
        self,
        mailbox: str,
        folder: str,
        url: str,
        since: datetime,
        emit: EmitFn,
        stop: asyncio.Event,
        *,
        skip_before: datetime | None = None,
        initial_change_type: bool = False,
    ) -> bool:
        """Recorre una ronda de delta (nextLink...deltaLink). Devuelve False si se interrumpió por `stop`.

        `since` es el inicio de la ventana vigilada (se guarda junto al deltaLink); se omiten las entradas
        con `receivedDateTime` anterior a `skip_before` (por defecto `since`).
        """
        skip_before = skip_before or since
        round_start = utcnow()
        prefer = f"odata.maxpagesize={int(self.page_size)}, {PREFER_IMMUTABLE}"
        next_url: str = url
        pages = 0
        while True:
            resp = await self._graph("GET", next_url, prefer=prefer, stop=stop)
            code = (resp.error_code() or "").lower() if not resp.ok else ""
            if (
                initial_change_type
                and pages == 0
                and resp.status_code == 400
                and code not in _SYNC_STATE_CODES
            ):
                raise _ChangeTypeUnsupported()
            if resp.status_code == 410 or (resp.status_code in (400, 404) and code in _SYNC_STATE_CODES):
                raise _DeltaExpired()
            resp.raise_for_status(f"delta {mailbox}/{folder}")
            data = resp.json()
            if not isinstance(data, dict):
                raise http.HttpError(f"delta {mailbox}/{folder}: respuesta inesperada")
            items = data.get("value")
            for item in items if isinstance(items, list) else []:
                if stop.is_set():
                    return False  # sin guardar deltaLink: la ronda se repite (al-menos-una-vez)
                if not isinstance(item, dict) or "@removed" in item:
                    continue
                mid = item.get("id")
                if not isinstance(mid, str) or not mid or len(mid) > _MAX_ID_LEN:
                    continue
                received = http.parse_iso8601(item.get("receivedDateTime"))
                if received is not None and received < skip_before:
                    continue  # cambio de un mail viejo (ej. marcado como leído): no es correo nuevo
                await self._process_message(mailbox, folder, mid, received, emit, stop)
            pages += 1
            delta_link = data.get("@odata.deltaLink")
            next_link = data.get("@odata.nextLink")
            if delta_link is not None:
                if not self._valid_link(delta_link):
                    raise http.HttpError(
                        f"delta {mailbox}/{folder}: deltaLink con host inesperado; se ignora"
                    )
                await self.set_cursor(self._ck(mailbox, folder, "delta"), delta_link)
                await self.set_cursor(self._ck(mailbox, folder, "since"), http.iso_utc(since))
                await self.set_cursor(self._ck(mailbox, folder, "checkpoint"), http.iso_utc(round_start))
                return True
            if not self._valid_link(next_link):
                raise http.HttpError(f"delta {mailbox}/{folder}: respuesta sin nextLink/deltaLink válido")
            if pages >= self.max_pages_per_round:
                raise http.HttpError(f"delta {mailbox}/{folder}: demasiadas páginas en una ronda ({pages})")
            next_url = next_link

    async def _process_message(
        self,
        mailbox: str,
        folder: str,
        mid: str,
        received: datetime | None,
        emit: EmitFn,
        stop: asyncio.Event,
    ) -> None:
        recent = self._recent_for(mailbox)
        if mid in recent:
            return
        limit = self.max_message_bytes
        url = f"{self._user(mailbox)}/messages/{quote(mid, safe='=')}/$value"
        try:
            async with self._sem(mailbox):
                resp = await self._graph(
                    "GET", url, accept="*/*", max_body=limit, total_timeout=600.0, stop=stop
                )
        except http.ResponseTooLarge as exc:
            headers_only = await self._headers_only(mailbox, folder, mid, received, exc.size, stop)
            if headers_only is not None:
                await emit(headers_only)
            recent.add(mid)
            return
        if resp.status_code == 404:
            log.debug("Graph %s/%s: el mensaje ya no existe; se omite", mailbox, folder)
            return
        resp.raise_for_status(f"$value {mailbox}/{folder}")
        if not resp.content:
            log.debug("Graph %s/%s: MIME vacío; se omite", mailbox, folder)
            return
        raw = RawMessage(
            ref=MessageRef(connector=self.name, mailbox=mailbox, remote_id=mid, folder=folder),
            raw=resp.content,
            received_at=received or utcnow(),
        )
        await emit(raw)
        recent.add(mid)

    async def _headers_only(
        self,
        mailbox: str,
        folder: str,
        mid: str,
        received: datetime | None,
        size_hint: int | None,
        stop: asyncio.Event,
    ) -> RawMessage | None:
        """Mail que supera max_message_bytes: solo sus headers (truncated=True). None si ya no existe."""
        limit = self.max_message_bytes
        base = f"{self._user(mailbox)}/messages/{quote(mid, safe='=')}?$select={_HEADERS_SELECT}"
        async with self._sem(mailbox):
            resp = await self._graph(
                "GET", f"{base}&$expand={quote(_SIZE_EXPAND, safe='$()=')}", total_timeout=120.0, stop=stop
            )
            if resp.status_code == 400:  # sin soporte para la propiedad extendida: sin el tamaño real
                resp = await self._graph("GET", base, total_timeout=120.0, stop=stop)
        if resp.status_code == 404:
            log.debug("Graph %s/%s: el mensaje ya no existe; se omite", mailbox, folder)
            return None
        resp.raise_for_status(f"headers {mailbox}/{folder}")
        data = resp.json()
        data = data if isinstance(data, dict) else {}
        items = data.get("internetMessageHeaders")
        if not isinstance(items, list) or not items:
            items = _synthetic_headers(data)
        real = _extended_size(data) or size_hint
        self.truncated_too_large += 1
        log.warning(
            "Graph %s/%s: un mensaje de %s bytes supera max_message_bytes=%d; se analizan solo los encabezados",
            mailbox,
            folder,
            real if real and real > limit else f"más de {limit}",
            limit,
        )
        return oversize_raw(
            MessageRef(connector=self.name, mailbox=mailbox, remote_id=mid, folder=folder),
            headers_from_api(items, max_bytes=header_cap(limit)),
            original_size=real,
            limit=limit,
            received_at=received or http.parse_iso8601(data.get("receivedDateTime")) or utcnow(),
        )

    # ------------------------------------------------------------------ loop principal

    def _set_status(self, key: tuple[str, str], ok: bool, error: str | None = None) -> None:
        st = self._status.setdefault(key, _FolderStatus())
        st.ok = ok
        st.error = error
        if ok:
            st.last_sync = utcnow()
        all_ok = bool(self._status) and all(s.ok for s in self._status.values())
        CONNECTOR_UP.labels(connector=self.name).set(1 if all_ok else 0)

    async def _folder_loop(self, mailbox: str, folder: str, emit: EmitFn, stop: asyncio.Event) -> None:
        key = (mailbox, folder)
        backoff = http.Backoff(2.0, self.error_backoff_cap_s)
        auth_backoff = http.Backoff(30.0, self.auth_error_backoff_cap_s)
        if self.start_jitter_s > 0 and await http.sleep_or_stop(random.uniform(0, self.start_jitter_s), stop):  # noqa: S311
            return
        while not stop.is_set():
            try:
                await self.sync_folder(mailbox, folder, emit, stop)
            except http.Stopped:
                break
            except asyncio.CancelledError:
                raise
            except GraphAuthError as exc:
                self._set_status(key, False, str(exc)[:500])
                log.error("Graph %s/%s: %s", mailbox, folder, exc)
                timeout = auth_backoff.next()
            except Exception as exc:
                self._set_status(key, False, f"{type(exc).__name__}: {exc}"[:500])
                log.warning(
                    "Graph %s/%s: error sincronizando (%s); se reintenta",
                    mailbox,
                    folder,
                    exc,
                    exc_info=log.isEnabledFor(logging.DEBUG),
                )
                timeout = backoff.next()
                ra = getattr(exc, "retry_after", None)
                if isinstance(ra, (int, float)):
                    timeout = max(timeout, min(float(ra), 900.0))
            else:
                self._set_status(key, True)
                backoff.reset()
                auth_backoff.reset()
                timeout = max(float(self.config.poll_interval_s), self.min_poll_s)
            if await http.sleep_or_stop(timeout, stop):
                break

    async def run(self, emit: EmitFn, stop: asyncio.Event) -> None:
        self.validate()
        mailboxes = http.dedup_casefold(list(self.config.mailboxes))
        folders = list(dict.fromkeys(f.strip() for f in self.config.folders if f.strip()))
        for m in mailboxes:
            for f in folders:
                self._status.setdefault((m, f), _FolderStatus())
        CONNECTOR_UP.labels(connector=self.name).set(0)
        tasks = [
            asyncio.create_task(self._folder_loop(m, f, emit, stop), name=f"graph:{self.name}:{m}:{f}")
            for m in mailboxes
            for f in folders
        ]
        log.info(
            "Graph '%s': vigilando %d buzón(es) x %d carpeta(s), delta cada %ss",
            self.name,
            len(mailboxes),
            len(folders),
            self.config.poll_interval_s,
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

    async def ensure_master_category(self, mailbox: str, name: str, color: str) -> bool:
        """Crea la categoría en la lista maestra del buzón (con color). Best-effort: False si no se pudo."""
        key = (mailbox.lower(), name.lower())
        if key in self._master_done:
            return True
        if mailbox.lower() in self._master_forbidden:
            return False
        url = f"{self._user(mailbox)}/outlook/masterCategories"
        try:
            resp = await self._graph("GET", url)
            if resp.status_code in (401, 403):
                self._master_forbidden.add(mailbox.lower())
                log.info(
                    "Graph %s: sin permiso MailboxSettings.ReadWrite; las categorías se aplican sin color",
                    mailbox,
                )
                return False
            resp.raise_for_status(f"masterCategories {mailbox}")
            data = resp.json()
            names = {
                str(c.get("displayName", "")).lower()
                for c in ((data.get("value") or []) if isinstance(data, dict) else [])
                if isinstance(c, dict)
            }
            if name.lower() not in names:
                resp = await self._graph("POST", url, json_body={"displayName": name, "color": color})
                if resp.status_code in (401, 403):
                    self._master_forbidden.add(mailbox.lower())
                    log.info(
                        "Graph %s: sin permiso para crear categorías maestras; se aplican sin color", mailbox
                    )
                    return False
                if resp.status_code != 409:  # 409 = ya existe (carrera)
                    resp.raise_for_status(f"masterCategories.create {mailbox}")
                    log.info("Graph %s: categoría %r creada (%s)", mailbox, name, color)
        except http.HttpError as exc:
            log.warning("Graph %s: no se pudo asegurar la categoría maestra %r: %s", mailbox, name, exc)
            return False
        self._master_done.add(key)
        return True

    async def apply_verdict(self, ref: MessageRef, result: AnalysisResult, tag: TagConfig) -> str | None:
        if ref.connector != self.name or not self.config.tag or not tag.enabled:
            return None
        level = result.verdict.level
        name = label_for_level(level, tag)
        if not name or not ref.remote_id or len(ref.remote_id) > _MAX_ID_LEN:
            return None
        await self.ensure_master_category(ref.mailbox, name, _CATEGORY_COLORS.get(level, "preset1"))
        url = f"{self._user(ref.mailbox)}/messages/{quote(ref.remote_id, safe='=')}"
        resp = await self._graph("GET", f"{url}?$select=categories")
        if resp.status_code == 404:
            log.info("Graph %s: el mensaje a etiquetar ya no existe", ref.mailbox)
            return None
        resp.raise_for_status(f"get categories {ref.mailbox}")
        data = resp.json()
        current = data.get("categories") if isinstance(data, dict) else None
        cats = [c for c in current if isinstance(c, str)] if isinstance(current, list) else []
        if any(c.lower() == name.lower() for c in cats):
            return f"graph:category:{name}"
        # Se agrega a las existentes: nunca se quitan categorías del usuario.
        resp = await self._graph("PATCH", url, json_body={"categories": [*cats, name]})
        if resp.status_code == 404:
            log.info("Graph %s: el mensaje a etiquetar ya no existe", ref.mailbox)
            return None
        if resp.status_code == 403:
            raise http.HttpError(
                f"Graph {ref.mailbox}: acceso denegado al etiquetar; la app necesita el permiso de aplicación "
                "Mail.ReadWrite (o poné `tag: false` en el conector)",
                status=403,
                code=resp.error_code(),
            )
        resp.raise_for_status(f"patch categories {ref.mailbox}")
        return f"graph:category:{name}"

    # ------------------------------------------------------------------ salud / cierre

    async def healthcheck(self) -> dict[str, Any]:
        folders = {
            f"{m}/{f}": {
                "ok": st.ok,
                "error": st.error,
                "last_sync": st.last_sync.astimezone(UTC).isoformat() if st.last_sync else None,
            }
            for (m, f), st in self._status.items()
        }
        running = bool(self._status)
        return {
            "ok": (not running) or all(st.ok for st in self._status.values()),
            "running": running,
            "folders": folders,
            "truncated_too_large": self.truncated_too_large,
        }

    async def close(self) -> None:
        if self._client_obj is not None:
            await self._client_obj.aclose()
            self._client_obj = None


__all__ = [
    "GRAPH_BASE",
    "GRAPH_SCOPE",
    "GraphAuthError",
    "GraphConnector",
    "GraphTokenProvider",
    "load_certificate_credential",
]
