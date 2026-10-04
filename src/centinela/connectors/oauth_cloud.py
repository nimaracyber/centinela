"""Ayudantes interactivos de autenticación y diagnóstico para los conectores cloud (los usa `centinela auth`
y `centinela check-config`).

- `gmail_user_login(cfg, state)`: OAuth de usuario para Gmail personal. Abre el navegador con un servidor
  local en un puerto libre (loopback, el método que Google recomienda para apps de escritorio); si no hay
  navegador (servidor sin pantalla, contenedor Docker) cae a modo consola: muestra la URL, el usuario
  autoriza en cualquier navegador y pega la dirección a la que fue redirigido. Guarda el refresh token
  CIFRADO en el state store, por buzón.
- `graph_check(cfg)`: obtiene un token de aplicación y prueba el acceso a cada buzón/carpeta configurado;
  devuelve un diagnóstico en español con qué falta (permisos, consentimiento, alcance RBAC...).
- `gmail_check(cfg, state)`: lo mismo para Gmail (token por buzón + getProfile + suscripción Pub/Sub).
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import logging
import os
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, quote, urlsplit

import httpx

from centinela.connectors import _http as http
from centinela.connectors.gmail import (
    GMAIL_API,
    SCOPE_MODIFY,
    SCOPE_PUBSUB,
    SCOPE_READONLY,
    GmailAuthError,
    GmailConnector,
    oauth_mailboxes_key,
    refresh_token_key,
)
from centinela.connectors.graph import GRAPH_BASE, GraphAuthError, GraphTokenProvider

if TYPE_CHECKING:
    from centinela.core.config import GmailConnectorConfig, GraphConnectorConfig, Settings
    from centinela.core.state import StateStore

log = logging.getLogger(__name__)

CONSOLE_REDIRECT_URI = "http://localhost:53682/"  # loopback sin servidor: el usuario copia la URL de la barra
_OVERPRIVILEGED = frozenset(
    {
        "Mail.Send",
        "Mail.ReadWrite.All",
        "full_access_as_app",
        "Directory.ReadWrite.All",
        "User.ReadWrite.All",
        "Sites.FullControl.All",
        "Files.ReadWrite.All",
        "Application.ReadWrite.All",
    }
)


class Diagnostics(list[str]):
    """Líneas de diagnóstico legibles ("[OK] ...", "[ERROR] ...", "[AVISO] ..."), con `ok` global.

    Es una lista de strings (se puede iterar e imprimir línea por línea) y `str()` la une con saltos.
    """

    def __init__(self) -> None:
        super().__init__()
        self.ok = True

    def good(self, msg: str) -> None:
        self.append(f"[OK] {msg}")

    def fail(self, msg: str) -> None:
        self.ok = False
        self.append(f"[ERROR] {msg}")

    def warn(self, msg: str) -> None:
        self.append(f"[AVISO] {msg}")

    def info(self, msg: str) -> None:
        self.append(f"[INFO] {msg}")

    def __str__(self) -> str:
        return "\n".join(self)


# --------------------------------------------------------------------------- Gmail: login de usuario


def gmail_login_scopes(cfg: GmailConnectorConfig) -> list[str]:
    scopes = [SCOPE_MODIFY if cfg.tag else SCOPE_READONLY]
    if cfg.pubsub_subscription and not cfg.service_account_file:
        scopes.append(SCOPE_PUBSUB)  # el pull de Pub/Sub se hace con el mismo usuario
    return scopes


def _code_from_answer(answer: str, expected_state: str | None) -> str:
    """Extrae el `code` de la URL pegada por el usuario (o acepta el code solo). Valida `state`."""
    answer = (answer or "").strip()
    if not answer or len(answer) > 8192:
        raise GmailAuthError("No se ingresó ninguna dirección.")
    if "://" in answer or answer.startswith(("localhost", "127.0.0.1")) or "code=" in answer:
        query = urlsplit(answer if "://" in answer else f"http://{answer}").query
        qs = parse_qs(query)
        if "error" in qs:
            raise GmailAuthError(
                f"Google devolvió un error: {qs['error'][0][:100]} (¿se canceló la autorización?)"
            )
        code = (qs.get("code") or [""])[0]
        state = (qs.get("state") or [None])[0]
        if expected_state and state is not None and state != expected_state:
            raise GmailAuthError(
                "La dirección pegada no corresponde a este intento de autorización (state distinto)."
            )
    else:
        code = answer
    if not code or len(code) > 2048:
        raise GmailAuthError("No se encontró el código de autorización en lo que pegaste.")
    return code


def _run_flow_sync(
    client_file: Path,
    scopes: list[str],
    *,
    console: bool | None,
    open_browser: bool,
    timeout_s: int,
    input_fn: Callable[[str], str],
    print_fn: Callable[[str], None],
) -> Any:
    """Corre el flujo OAuth (bloqueante). Devuelve google.oauth2.credentials.Credentials."""
    from google_auth_oauthlib.flow import InstalledAppFlow

    flow = InstalledAppFlow.from_client_secrets_file(str(client_file), scopes=scopes)
    auth_kwargs = {
        "access_type": "offline",
        "prompt": "consent",
    }  # prompt=consent: siempre devuelve refresh token
    if console is not True:
        try:
            return flow.run_local_server(
                host="localhost",
                port=0,
                open_browser=open_browser,
                timeout_seconds=timeout_s,
                authorization_prompt_message="Abrí esta dirección en el navegador para autorizar a Centinela: {url}",
                success_message="Listo: Centinela quedó autorizado. Ya podés cerrar esta ventana.",
                **auth_kwargs,
            )
        except Exception as exc:  # sin navegador (webbrowser.Error), puerto ocupado, timeout...
            if console is False:
                raise GmailAuthError(
                    f"No se pudo completar la autorización en el navegador: {type(exc).__name__}"
                ) from None
            log.info(
                "OAuth Gmail: sin navegador/servidor local (%s); se usa modo consola", type(exc).__name__
            )
            flow = InstalledAppFlow.from_client_secrets_file(str(client_file), scopes=scopes)
    flow.redirect_uri = CONSOLE_REDIRECT_URI
    auth_url, state = flow.authorization_url(**auth_kwargs)
    print_fn(
        "\n1) Abrí esta dirección en un navegador (puede ser en otra computadora) e ingresá con la cuenta de Gmail:\n\n"
        f"   {auth_url}\n\n"
        "2) Al terminar, el navegador va a mostrar un error de conexión a 'localhost': es normal.\n"
        "   Copiá la dirección COMPLETA de la barra del navegador (empieza con http://localhost:53682/?state=...)\n"
    )
    answer = input_fn("Pegá acá la dirección: ")
    code = _code_from_answer(answer, state)
    flow.fetch_token(code=code)
    return flow.credentials


async def gmail_user_login(
    cfg: GmailConnectorConfig,
    state: StateStore,
    *,
    console: bool | None = None,
    open_browser: bool = True,
    timeout_s: int = 300,
    input_fn: Callable[[str], str] = input,
    print_fn: Callable[[str], None] = print,
    client: httpx.AsyncClient | None = None,
) -> str:
    """Autoriza un buzón de Gmail con OAuth de usuario y guarda el refresh token cifrado.

    `console=None` intenta navegador + servidor local y cae a modo consola si no se puede;
    `True` fuerza consola; `False` nunca usa consola. Devuelve la dirección autorizada.
    """
    if cfg.auth != "oauth_user":
        raise GmailAuthError(
            f"el conector '{cfg.name}' usa auth '{cfg.auth}'; el login interactivo es solo para oauth_user"
        )
    if not cfg.oauth_client_file:
        raise GmailAuthError(
            f"el conector '{cfg.name}' no tiene oauth_client_file (JSON de cliente OAuth 'Desktop app')"
        )
    client_file = Path(cfg.oauth_client_file)
    if not await asyncio.to_thread(client_file.is_file):
        raise GmailAuthError(f"no existe el archivo de cliente OAuth: {client_file}")
    scopes = gmail_login_scopes(cfg)
    if console is None and running_in_container():
        console = True  # dentro de Docker no hay navegador ni se llega al puerto local desde el host
    creds = await asyncio.to_thread(
        _run_flow_sync,
        client_file,
        scopes,
        console=console,
        open_browser=open_browser,
        timeout_s=timeout_s,
        input_fn=input_fn,
        print_fn=print_fn,
    )
    refresh_token = getattr(creds, "refresh_token", None)
    access_token = getattr(creds, "token", None)
    if not refresh_token or not access_token:
        raise GmailAuthError(
            "Google no devolvió un refresh token. Quitá el acceso de Centinela en "
            "https://myaccount.google.com/permissions y volvé a intentar."
        )
    granted = set(getattr(creds, "granted_scopes", None) or getattr(creds, "scopes", None) or [])
    if granted and not ({SCOPE_MODIFY, SCOPE_READONLY, "https://mail.google.com/"} & granted):
        raise GmailAuthError(
            "No se otorgó el permiso de lectura de Gmail; repetí la autorización marcando las casillas."
        )

    async def token(_force: bool) -> str:
        return str(access_token)

    own = client is None
    c = client or http.new_client()
    try:
        resp = await http.request(c, "GET", f"{GMAIL_API}/users/me/profile", token=token)
        resp.raise_for_status("getProfile")
        data = resp.json()
    finally:
        if own:
            await c.aclose()
    email = str(data.get("emailAddress") or "").strip().lower() if isinstance(data, dict) else ""
    if not email or "@" not in email or len(email) > 320:
        raise GmailAuthError("No se pudo identificar la cuenta de Gmail autorizada.")

    await state.set_secret(refresh_token_key(cfg.name, email), str(refresh_token))
    raw = await state.get(oauth_mailboxes_key(cfg.name))
    try:
        boxes = json.loads(raw) if raw else []
    except ValueError:
        boxes = []
    boxes = http.dedup_casefold([b for b in boxes if isinstance(b, str)] if isinstance(boxes, list) else [])
    if email not in [b.lower() for b in boxes]:
        boxes.append(email)
    await state.set(oauth_mailboxes_key(cfg.name), json.dumps(boxes))

    configured = [m.strip().lower() for m in cfg.mailboxes if m.strip()]
    if configured and email not in configured:
        print_fn(
            f"ATENCIÓN: autorizaste {email}, pero el conector '{cfg.name}' tiene configurados {', '.join(configured)}. "
            f"Agregá {email} a `mailboxes` o volvé a autorizar con la cuenta correcta."
        )
    print_fn(
        f"Listo: {email} quedó autorizado para el conector '{cfg.name}' ({'con' if cfg.tag else 'sin'} etiquetado)."
    )
    log.info("OAuth Gmail: buzón autorizado para el conector %s", cfg.name)
    return email


# --------------------------------------------------------------------------- Graph: diagnóstico


def _jwt_claims(token: str) -> dict[str, Any] | None:
    """Claims del access token (JWT) SIN verificar firma: solo para diagnosticar permisos propios."""
    parts = token.split(".")
    if len(parts) != 3 or len(parts[1]) > 64 * 1024:
        return None
    try:
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _graph_folder_problem(resp: http.HttpResponse, mailbox: str, folder: str) -> str:
    code = resp.error_code() or ""
    if resp.status_code == 401:
        return f"{mailbox}: Graph rechazó el token (401 {code}). Revisá tenant_id/client_id y que la app sea del mismo tenant."
    if resp.status_code == 403:
        return (
            f"{mailbox}: acceso denegado (403 {code}). Falta el permiso de aplicación Mail.Read/Mail.ReadWrite con "
            "consentimiento de administrador, o el buzón quedó fuera del alcance de RBAC for Applications / "
            "ApplicationAccessPolicy."
        )
    if resp.status_code == 404:
        if code.lower() in ("mailboxnotenabledforrestapi", "mailboxnotsupportedforrestapi"):
            return f"{mailbox}: el buzón no está en Exchange Online (sin licencia, inactivo u on-premises)."
        if code.lower() in ("erroritemnotfound", "errorinvalidfolderid", "resourcenotfound") and folder:
            return f"{mailbox}: no existe la carpeta '{folder}' (usá nombres conocidos como inbox/junkemail o el id)."
        return f"{mailbox}: no existe el usuario/buzón ({code or 'NotFound'}). Revisá la dirección."
    return f"{mailbox}/{folder}: error HTTP {resp.status_code} {code} {resp.error_message(150)}".strip()


async def graph_check(
    cfg: GraphConnectorConfig,
    *,
    token_provider: http.TokenFn | None = None,
    client: httpx.AsyncClient | None = None,
    graph_base: str = GRAPH_BASE,
) -> Diagnostics:
    """Valida la configuración de un conector Graph: token, permisos y acceso a cada buzón/carpeta."""
    diag = Diagnostics()
    has_secret = cfg.client_secret is not None and bool(cfg.client_secret.get_secret_value())
    if not has_secret and not cfg.certificate_file:
        diag.fail("Falta client_secret o certificate_file en el conector.")
        return diag
    provider = token_provider or GraphTokenProvider(cfg)
    try:
        token = await provider(False)
    except (GraphAuthError, http.HttpError) as exc:
        diag.fail(f"No se pudo obtener un token de Microsoft Entra ID: {exc}")
        return diag
    diag.good(f"Token de aplicación obtenido (app {cfg.client_id}, tenant {cfg.tenant_id}).")

    claims = _jwt_claims(token)
    roles = {r for r in (claims or {}).get("roles", []) if isinstance(r, str)} if claims else None
    if roles is not None:
        diag.info(f"Permisos de aplicación en el token: {', '.join(sorted(roles)) or '(ninguno)'}")
        if cfg.tag:
            if "Mail.ReadWrite" not in roles:
                diag.fail(
                    "Para etiquetar hace falta el permiso de aplicación Mail.ReadWrite (con consentimiento de "
                    "administrador). Agregalo o poné `tag: false` (solo alertas)."
                )
        elif not roles & {"Mail.Read", "Mail.ReadWrite"}:
            diag.fail("Falta el permiso de aplicación Mail.Read (con consentimiento de administrador).")
        elif "Mail.ReadWrite" in roles:
            diag.warn(
                "La app tiene Mail.ReadWrite pero el conector no etiqueta (`tag: false`): con Mail.Read alcanza."
            )
        if cfg.tag and "MailboxSettings.ReadWrite" not in roles:
            diag.info(
                "Sin MailboxSettings.ReadWrite: las categorías se aplican igual, pero sin color (opcional)."
            )
        extra = sorted(roles & _OVERPRIVILEGED)
        if extra:
            diag.warn(
                f"La app tiene permisos que Centinela NO necesita ({', '.join(extra)}). Quitalos: menos permisos = menos riesgo."
            )
        diag.info(
            "Recomendado: limitar la app a los buzones vigilados con RBAC for Applications de Exchange Online "
            "(o ApplicationAccessPolicy)."
        )

    if not cfg.mailboxes:
        diag.fail("No hay buzones en `mailboxes`.")
        return diag

    own = client is None
    c = client or http.new_client()
    try:
        for mailbox in http.dedup_casefold(list(cfg.mailboxes)):
            for folder in list(dict.fromkeys(f.strip() for f in cfg.folders if f.strip())) or ["inbox"]:
                url = (
                    f"{graph_base}/v1.0/users/{quote(mailbox, safe='@')}/mailFolders/{quote(folder, safe='')}"
                    "?$select=id,displayName,totalItemCount"
                )
                try:
                    resp = await http.request(
                        c, "GET", url, token=provider, policy=http.RetryPolicy(max_attempts=3)
                    )
                except http.HttpError as exc:
                    diag.fail(f"{mailbox}/{folder}: {exc}")
                    continue
                if resp.ok:
                    data = resp.json()
                    name = data.get("displayName", folder) if isinstance(data, dict) else folder
                    total = data.get("totalItemCount") if isinstance(data, dict) else None
                    diag.good(
                        f"{mailbox}: carpeta '{name}' accesible"
                        + (f" ({total} mensajes)." if total is not None else ".")
                    )
                else:
                    diag.fail(_graph_folder_problem(resp, mailbox, folder))
    finally:
        if own:
            await c.aclose()
    return diag


# --------------------------------------------------------------------------- Gmail: diagnóstico


async def gmail_check(
    cfg: GmailConnectorConfig,
    state: StateStore,
    *,
    settings: Settings | None = None,
    connector: GmailConnector | None = None,
) -> Diagnostics:
    """Valida un conector Gmail: credenciales, acceso a cada buzón y (si hay) la suscripción Pub/Sub."""
    from centinela.core.config import Settings as _Settings

    diag = Diagnostics()
    conn = connector or GmailConnector(cfg, settings or _Settings(), state)
    try:
        try:
            conn.validate()
        except ValueError as exc:
            diag.fail(str(exc))
            return diag
        for f in (cfg.service_account_file, cfg.oauth_client_file):
            if f is not None and not await asyncio.to_thread(Path(f).is_file):
                diag.fail(f"No existe el archivo {f}.")
        if not diag.ok:
            return diag
        mailboxes = await conn.resolve_mailboxes()
        if not mailboxes:
            diag.fail(
                f"No hay buzones: listalos en `mailboxes` o autorizá uno con `centinela auth gmail {cfg.name}`."
            )
            return diag
        diag.info(f"Permiso pedido a Google: {', '.join(conn.gmail_scopes)}")
        for mailbox in mailboxes:
            try:
                profile = await conn.get_profile(mailbox)
            except GmailAuthError as exc:
                diag.fail(f"{mailbox}: {exc}")
                continue
            except http.HttpError as exc:
                hint = ""
                if exc.status == 400 and (exc.code or "").lower() == "failedprecondition":
                    hint = " (¿el usuario tiene Gmail habilitado / licencia de Workspace?)"
                diag.fail(f"{mailbox}: {exc}{hint}")
                continue
            total = profile.get("messagesTotal")
            diag.good(f"{mailbox}: acceso OK" + (f" ({total} mensajes)." if total is not None else "."))
        if conn.pubsub_enabled:
            try:
                resp = await conn.get_subscription()
            except (GmailAuthError, http.HttpError) as exc:
                diag.fail(f"Pub/Sub: {exc}")
            else:
                if resp.ok:
                    data = resp.json()
                    topic = data.get("topic") if isinstance(data, dict) else None
                    if topic and topic != cfg.pubsub_topic:
                        diag.warn(f"La suscripción está asociada al tópico {topic}, no a {cfg.pubsub_topic}.")
                    diag.good("Suscripción Pub/Sub accesible (tiempo real disponible).")
                elif resp.status_code == 403:
                    diag.fail("Pub/Sub: acceso denegado; dale rol 'Pub/Sub Subscriber' sobre la suscripción.")
                elif resp.status_code == 404:
                    diag.fail(f"Pub/Sub: no existe la suscripción {cfg.pubsub_subscription}.")
                else:
                    diag.fail(f"Pub/Sub: HTTP {resp.status_code} {resp.error_code() or ''}".strip())
    finally:
        if connector is None:
            await conn.close()
    return diag


def running_in_container() -> bool:
    """Heurística para sugerir el modo consola en Docker."""
    return os.path.exists("/.dockerenv") or bool(os.environ.get("CENTINELA_IN_DOCKER"))


__all__ = [
    "CONSOLE_REDIRECT_URI",
    "Diagnostics",
    "gmail_check",
    "gmail_login_scopes",
    "gmail_user_login",
    "graph_check",
    "running_in_container",
]
