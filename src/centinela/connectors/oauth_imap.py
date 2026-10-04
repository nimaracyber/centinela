"""OAuth 2.0 (XOAUTH2) para el conector IMAP: Microsoft (Outlook.com / Microsoft 365) y Google (Gmail).

Dos piezas:

- `ImapTokenProvider`: usado por `ImapConnector` en runtime. Toma el refresh token guardado (cifrado) en el
  state store, pide un access token nuevo cuando hace falta, lo cachea hasta poco antes de que venza y
  persiste el refresh token rotado (Microsoft lo rota en cada uso).
- `interactive_login(cfg, state)`: usado por `centinela auth <conector>`. Microsoft con *device code flow*
  (sirve en un servidor sin navegador: el usuario abre una URL en el celular e ingresa un código);
  Google con *installed app flow* (servidor local en un puerto efímero, o modo consola copiando la URL).

Las librerías (msal, google-auth, google-auth-oauthlib) se importan de forma diferida: solo se cargan
si el conector usa OAuth. Nunca se loguean tokens ni secretos.
"""

from __future__ import annotations

import asyncio
import logging
import re
import secrets
import time
import webbrowser
from collections.abc import Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import parse_qs, urlsplit

if TYPE_CHECKING:
    from centinela.core.config import ImapConnectorConfig
    from centinela.core.state import StateStore

log = logging.getLogger(__name__)

__all__ = [
    "GOOGLE_IMAP_SCOPE",
    "MS_IMAP_SCOPE",
    "ImapOAuthError",
    "ImapOAuthReauthRequired",
    "ImapTokenProvider",
    "interactive_login",
    "refresh_token_key",
]

# Microsoft: msal agrega solo los scopes reservados (offline_access, openid, profile) y lanza ValueError
# si se los pasamos explícitamente; el pedido efectivo es "IMAP.AccessAsUser.All offline_access".
MS_IMAP_SCOPE = "https://outlook.office.com/IMAP.AccessAsUser.All"
MS_AUTHORITY_BASE = "https://login.microsoftonline.com/"
GOOGLE_IMAP_SCOPE = "https://mail.google.com/"
GOOGLE_AUTH_URI = "https://accounts.google.com/o/oauth2/auth"
GOOGLE_TOKEN_URI = "https://oauth2.googleapis.com/token"  # noqa: S105 - es una URL, no un secreto

HTTP_TIMEOUT_S = 20.0
_TENANT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,99}$")
_REAUTH_ERRORS = (
    "invalid_grant",
    "interaction_required",
    "invalid_client",
    "unauthorized_client",
    "consent_required",
)
_MAX_PASTE = 8192


class ImapOAuthError(RuntimeError):
    """Error de OAuth con un mensaje en español apto para mostrar al usuario."""


class ImapOAuthReauthRequired(ImapOAuthError):
    """No hay refresh token o fue revocado/venció: hay que correr `centinela auth <conector>`."""


def refresh_token_key(connector_name: str) -> str:
    """Clave del state store (secreto cifrado) donde vive el refresh token del conector."""
    return f"connector:{connector_name}:imap_refresh_token"


def _authority(tenant: str) -> str:
    tenant = (tenant or "consumers").strip()
    if not _TENANT_RE.match(tenant):
        raise ImapOAuthError(f"tenant de Microsoft inválido: {tenant[:60]!r}")
    return MS_AUTHORITY_BASE + tenant


def _short(text: object, limit: int = 200) -> str:
    s = str(text or "").strip().splitlines()
    return (s[0] if s else "")[:limit]


def _reauth_hint(name: str) -> str:
    return f"ejecutá `centinela auth {name}` para volver a autorizar el acceso al buzón"


# --------------------------------------------------------------------------- runtime: tokens


class ImapTokenProvider:
    """Entrega access tokens XOAUTH2 válidos para un conector IMAP.

    Thread-safety: se usa desde el event loop; las llamadas bloqueantes (msal / google-auth) van a un thread.
    """

    REFRESH_MARGIN_S = 300.0  # renovar 5 minutos antes del vencimiento
    DEFAULT_TTL_S = 3600.0

    def __init__(self, cfg: ImapConnectorConfig, state: StateStore) -> None:
        if cfg.oauth2 is None:
            raise ImapOAuthError(f"el conector '{cfg.name}' no tiene oauth2 configurado")
        self.cfg = cfg
        self.oauth = cfg.oauth2
        self.state = state
        self.name = cfg.name
        self._lock = asyncio.Lock()
        self._token: str | None = None
        self._renew_at = 0.0  # time.monotonic() a partir del cual hay que renovar
        self._ms_app: Any = None
        self.refreshes = 0  # cantidad de renovaciones hechas (diagnóstico)

    def invalidate(self) -> None:
        """Descarta el access token cacheado (ej: el servidor rechazó el login)."""
        self._token = None
        self._renew_at = 0.0

    def _valid(self) -> bool:
        return self._token is not None and time.monotonic() < self._renew_at

    async def get(self, *, force: bool = False) -> str:
        if not force and self._valid():
            return self._token  # type: ignore[return-value]
        async with self._lock:
            if not force and self._valid():
                return self._token  # type: ignore[return-value]
            key = refresh_token_key(self.name)
            rt = await self.state.get_secret(key)
            if not rt:
                raise ImapOAuthReauthRequired(
                    f"el conector IMAP '{self.name}' todavía no está autorizado: {_reauth_hint(self.name)}"
                )
            if self.oauth.provider == "microsoft":
                token, ttl, new_rt = await asyncio.to_thread(self._refresh_microsoft, rt)
            else:
                token, ttl, new_rt = await asyncio.to_thread(self._refresh_google, rt)
            if new_rt and new_rt != rt:
                await self.state.set_secret(key, new_rt)
                log.info("oauth[%s]: refresh token rotado y guardado", self.name)
            ttl = max(0.0, float(ttl))
            self._token = token
            # renovar antes de que venza: 5 min antes, o a mitad de vida si el token dura poco
            self._renew_at = time.monotonic() + ttl - min(self.REFRESH_MARGIN_S, ttl / 2)
            self.refreshes += 1
            return token

    # -- Microsoft

    def _microsoft_app(self) -> Any:
        if self._ms_app is None:
            import msal

            self._ms_app = msal.PublicClientApplication(
                self.oauth.client_id, authority=_authority(self.oauth.tenant), timeout=HTTP_TIMEOUT_S
            )
        return self._ms_app

    def _refresh_microsoft(self, rt: str) -> tuple[str, float, str | None]:
        app = self._microsoft_app()
        result = app.acquire_token_by_refresh_token(rt, scopes=[MS_IMAP_SCOPE])
        if not isinstance(result, dict) or "access_token" not in result:
            result = result if isinstance(result, dict) else {}
            error = str(result.get("error") or "unknown_error")
            desc = _short(result.get("error_description"))
            if error in _REAUTH_ERRORS:
                raise ImapOAuthReauthRequired(
                    f"Microsoft rechazó el refresh token del conector '{self.name}' ({error}): "
                    f"{_reauth_hint(self.name)}. Detalle: {desc}"
                )
            raise ImapOAuthError(f"no se pudo renovar el token de Microsoft ({error}): {desc}")
        ttl = _as_float(result.get("expires_in"), self.DEFAULT_TTL_S)
        return str(result["access_token"]), ttl, result.get("refresh_token")

    # -- Google

    def _refresh_google(self, rt: str) -> tuple[str, float, str | None]:
        from google.auth import exceptions as gexc
        from google.oauth2 import credentials as gcreds

        secret = self.oauth.client_secret.get_secret_value() if self.oauth.client_secret else None
        creds = gcreds.Credentials(
            token=None,
            refresh_token=rt,
            token_uri=GOOGLE_TOKEN_URI,
            client_id=self.oauth.client_id,
            client_secret=secret,
            scopes=[GOOGLE_IMAP_SCOPE],
        )
        try:
            creds.refresh(_google_request())
        except gexc.RefreshError as exc:
            detail = _short(exc.args[0] if exc.args else exc)
            if any(e in detail for e in _REAUTH_ERRORS):
                raise ImapOAuthReauthRequired(
                    f"Google rechazó el refresh token del conector '{self.name}': {_reauth_hint(self.name)}. "
                    f"Detalle: {detail}"
                ) from None
            raise ImapOAuthError(f"no se pudo renovar el token de Google: {detail}") from None
        if not creds.token:
            raise ImapOAuthError("Google no devolvió un access token")
        ttl = self.DEFAULT_TTL_S
        expiry = getattr(creds, "expiry", None)
        if isinstance(expiry, datetime):
            exp = expiry if expiry.tzinfo else expiry.replace(tzinfo=UTC)
            ttl = (exp - datetime.now(UTC)).total_seconds()
        return str(creds.token), ttl, getattr(creds, "refresh_token", None)


def _as_float(value: object, default: float) -> float:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _google_request() -> Any:
    """Transporte de google-auth con timeout corto (el default de la librería es 120 s)."""
    from google.auth.transport.requests import Request

    class _TimeoutRequest(Request):
        def __call__(self, url, method="GET", body=None, headers=None, timeout=None, **kwargs):  # type: ignore[override]
            return super().__call__(
                url, method=method, body=body, headers=headers, timeout=timeout or HTTP_TIMEOUT_S, **kwargs
            )

    return _TimeoutRequest()


# --------------------------------------------------------------------------- interactivo (CLI)

Printer = Callable[[str], None]
Prompt = Callable[[str], str]


async def interactive_login(
    cfg: ImapConnectorConfig,
    state: StateStore,
    *,
    printer: Printer = print,
    prompt: Prompt = input,
    google_mode: Literal["auto", "local_server", "console"] = "auto",
    open_browser: bool = True,
    timeout_s: int = 300,
) -> None:
    """Autoriza a Centinela a leer el buzón IMAP vía OAuth y guarda el refresh token (cifrado).

    Lo llama `centinela auth <conector>` (proceso interactivo de consola). Lanza `ImapOAuthError` con un
    mensaje en español si algo falla. Ctrl+C corta la espera sin dejar threads colgados.
    """
    if cfg.oauth2 is None:
        raise ImapOAuthError(
            f"el conector '{cfg.name}' no tiene la sección oauth2 configurada (usa contraseña de aplicación)"
        )
    if cfg.oauth2.provider == "microsoft":
        rt, account = await _microsoft_login(cfg, printer)
    else:
        rt, account = await _google_login(cfg, printer, prompt, google_mode, open_browser, timeout_s)
    if account and account.strip().lower() != cfg.username.strip().lower():
        printer(
            f"Atención: iniciaste sesión como {account}, pero el conector está configurado para "
            f"{cfg.username}. Si no tenés permisos sobre ese buzón, el servidor va a rechazar el acceso."
        )
    await state.set_secret(refresh_token_key(cfg.name), rt)
    printer(
        f"Listo: Centinela quedó autorizado para leer {cfg.username}. "
        "El permiso se guardó cifrado; podés revocarlo cuando quieras desde tu cuenta."
    )
    log.info("oauth[%s]: autorización interactiva completada (%s)", cfg.name, cfg.oauth2.provider)


# -- Microsoft: device code flow


async def _microsoft_login(cfg: ImapConnectorConfig, printer: Printer) -> tuple[str, str | None]:
    app, flow = await asyncio.to_thread(_microsoft_start_device_flow, cfg)
    minutes = max(1, int(_as_float(flow.get("expires_in"), 900)) // 60)
    uri = flow.get("verification_uri") or flow.get("verification_url") or "https://microsoft.com/devicelogin"
    printer(
        "\n".join(
            [
                f"Para que Centinela pueda leer el buzón {cfg.username} (Microsoft / Outlook):",
                f"  1. Abrí {uri} en cualquier navegador (puede ser el del celular).",
                f"  2. Ingresá este código: {flow['user_code']}",
                f"  3. Iniciá sesión con la cuenta {cfg.username} y aceptá los permisos.",
                f"El código vence en {minutes} minutos. Esta ventana sigue sola cuando termines.",
            ]
        )
    )
    try:
        # bloquea haciendo polling hasta que el usuario termine (o venza el código)
        result = await asyncio.to_thread(app.acquire_token_by_device_flow, flow)
    except BaseException:
        flow["expires_at"] = 0  # msal: corta el loop de polling del thread (Ctrl+C / cancelación)
        raise
    return _microsoft_parse_result(result)


def _microsoft_start_device_flow(cfg: ImapConnectorConfig) -> tuple[Any, dict]:
    import msal

    assert cfg.oauth2 is not None
    app = msal.PublicClientApplication(
        cfg.oauth2.client_id, authority=_authority(cfg.oauth2.tenant), timeout=HTTP_TIMEOUT_S
    )
    flow = app.initiate_device_flow(scopes=[MS_IMAP_SCOPE])
    if not isinstance(flow, dict) or "user_code" not in flow:
        flow = flow if isinstance(flow, dict) else {}
        raise ImapOAuthError(
            "Microsoft no pudo iniciar el inicio de sesión: "
            f"{_short(flow.get('error_description') or flow.get('error') or 'respuesta inesperada')}"
        )
    return app, flow


def _microsoft_parse_result(result: object) -> tuple[str, str | None]:
    if not isinstance(result, dict) or "access_token" not in result:
        result = result if isinstance(result, dict) else {}
        error = str(result.get("error") or "unknown_error")
        msgs = {
            "authorization_declined": "rechazaste los permisos en la pantalla de Microsoft",
            "expired_token": "el código venció antes de completar el inicio de sesión; volvé a intentar",
            "bad_verification_code": "el código no es válido; volvé a intentar",
        }
        raise ImapOAuthError(
            f"no se completó la autorización con Microsoft: {msgs.get(error, error)}. "
            f"{_short(result.get('error_description'))}".strip()
        )
    rt = result.get("refresh_token")
    if not rt:
        raise ImapOAuthError(
            "Microsoft no entregó un refresh token (permiso offline_access). Revisá que la app registrada "
            "tenga habilitados los 'public client flows' y el permiso IMAP.AccessAsUser.All."
        )
    claims = result.get("id_token_claims")
    account = (claims.get("preferred_username") or claims.get("email")) if isinstance(claims, dict) else None
    return str(rt), (str(account) if account else None)


# -- Google: installed app flow


def _google_client_config(cfg: ImapConnectorConfig) -> dict[str, Any]:
    assert cfg.oauth2 is not None
    secret = cfg.oauth2.client_secret.get_secret_value() if cfg.oauth2.client_secret else None
    if not secret:
        raise ImapOAuthError(
            "para Google hace falta client_secret en oauth2 (cliente OAuth de tipo 'App de escritorio' "
            "creado en Google Cloud Console)"
        )
    return {
        "installed": {
            "client_id": cfg.oauth2.client_id,
            "client_secret": secret,
            "auth_uri": GOOGLE_AUTH_URI,
            "token_uri": GOOGLE_TOKEN_URI,
            "redirect_uris": ["http://localhost"],
        }
    }


def _browser_available() -> bool:
    try:
        webbrowser.get()
    except webbrowser.Error:
        return False
    return True


async def _google_login(
    cfg: ImapConnectorConfig,
    printer: Printer,
    prompt: Prompt,
    mode: str,
    open_browser: bool,
    timeout_s: int,
) -> tuple[str, str | None]:
    from google_auth_oauthlib.flow import InstalledAppFlow

    flow = InstalledAppFlow.from_client_config(_google_client_config(cfg), scopes=[GOOGLE_IMAP_SCOPE])
    auth_kwargs = {"prompt": "consent", "access_type": "offline", "login_hint": cfg.username}
    if mode == "auto":
        mode = "local_server" if open_browser and _browser_available() else "console"

    creds = None
    if mode == "local_server":
        try:
            creds = await asyncio.to_thread(
                flow.run_local_server,
                host="localhost",
                port=0,
                open_browser=open_browser,
                authorization_prompt_message=(
                    f"Para que Centinela pueda leer {cfg.username}, abrí esta dirección en el navegador "
                    "(si no se abrió sola) e iniciá sesión con esa cuenta:\n{url}"
                ),
                success_message="Listo: Centinela quedó autorizado. Ya podés cerrar esta pestaña.",
                timeout_seconds=timeout_s,  # el thread termina solo aunque el usuario abandone
                **auth_kwargs,
            )
        except OSError as exc:
            # no se pudo levantar el servidor local (ej: contenedor sin red de host): modo consola
            log.info("oauth[%s]: servidor local no disponible (%s); se usa modo consola", cfg.name, exc)
            mode = "console"
    if mode == "console":
        expected_state = _google_console_instructions(flow, cfg, printer, auth_kwargs)
        # a propósito en el thread principal: es un comando interactivo y así Ctrl+C corta al instante
        pasted = (prompt("Dirección (o código): ") or "").strip()[:_MAX_PASTE]
        creds = await asyncio.to_thread(_google_console_finish, flow, pasted, expected_state)

    rt = getattr(creds, "refresh_token", None)
    if not rt:
        raise ImapOAuthError(
            "Google no entregó un refresh token. Quitá el acceso de la app en "
            "https://myaccount.google.com/permissions y volvé a intentar."
        )
    return str(rt), None


def _google_console_instructions(
    flow: Any, cfg: ImapConnectorConfig, printer: Printer, auth_kwargs: dict
) -> str:
    """Modo para servidores sin navegador: el usuario autoriza en su PC y pega la URL a la que volvió.

    La redirección a http://localhost:<puerto> no va a cargar (no hay nada escuchando): es lo esperado.
    El código viaja protegido con PKCE, así que aunque otro proceso lo viera, no podría canjearlo.
    Devuelve el `state` esperado.
    """
    port = 49152 + secrets.randbelow(16000)
    flow.redirect_uri = f"http://localhost:{port}/"
    auth_url, expected_state = flow.authorization_url(**auth_kwargs)
    printer(
        "\n".join(
            [
                f"Para que Centinela pueda leer el buzón {cfg.username} (Google):",
                "  1. Abrí esta dirección en el navegador de tu computadora:",
                f"     {auth_url}",
                f"  2. Iniciá sesión con {cfg.username} y aceptá los permisos.",
                "  3. El navegador va a terminar en una página que NO carga (dirección http://localhost...).",
                "     Es normal: copiá la dirección completa de la barra del navegador y pegala acá.",
            ]
        )
    )
    return str(expected_state)


def _google_console_finish(flow: Any, pasted: str, expected_state: str) -> Any:
    code, returned_state, error = _parse_pasted_redirect(pasted)
    if error:
        raise ImapOAuthError(f"Google no autorizó el acceso: {_short(error)}")
    if not code:
        raise ImapOAuthError("no se encontró el código de autorización en lo que pegaste")
    if returned_state is not None and returned_state != expected_state:
        raise ImapOAuthError(
            "la dirección pegada no corresponde a este intento de autorización (state distinto); volvé a empezar"
        )
    flow.fetch_token(code=code)
    return flow.credentials


def _parse_pasted_redirect(pasted: str) -> tuple[str | None, str | None, str | None]:
    """Devuelve (code, state, error) de una URL de redirección pegada, o del código suelto."""
    if not pasted:
        return None, None, None
    if "://" in pasted or pasted.startswith(("localhost", "/?", "?")):
        try:
            query = urlsplit(pasted if "://" in pasted else "http://" + pasted.lstrip("/")).query
            params = parse_qs(query, keep_blank_values=False, max_num_fields=20)
        except ValueError:  # URL malformada o con demasiados parámetros
            return None, None, None
        code = (params.get("code") or [None])[0]
        state = (params.get("state") or [None])[0]
        error = (params.get("error") or [None])[0]
        return code, state, error
    if re.fullmatch(r"[A-Za-z0-9/_\-.~%]{10,2048}", pasted):
        return pasted, None, None
    return None, None, None
