from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime, timedelta

import pytest

import centinela.connectors.oauth_imap as oauth_mod
from centinela.connectors.oauth_imap import (
    GOOGLE_IMAP_SCOPE,
    MS_IMAP_SCOPE,
    ImapOAuthError,
    ImapOAuthReauthRequired,
    ImapTokenProvider,
    _parse_pasted_redirect,
    interactive_login,
    refresh_token_key,
)
from centinela.core.config import ImapConnectorConfig
from centinela.core.state import MemoryStateStore

NAME = "outlook"
KEY = refresh_token_key(NAME)


def cfg_ms(**oauth) -> ImapConnectorConfig:
    o = {"provider": "microsoft", "client_id": "cid-1", "tenant": "consumers"}
    o.update(oauth)
    return ImapConnectorConfig.model_validate(
        {
            "type": "imap",
            "name": NAME,
            "host": "outlook.office365.com",
            "username": "duenio@outlook.com",
            "oauth2": o,
        }
    )


def cfg_google(**oauth) -> ImapConnectorConfig:
    o = {"provider": "google", "client_id": "gid.apps.googleusercontent.com", "client_secret": "gsecret"}
    o.update(oauth)
    return ImapConnectorConfig.model_validate(
        {"type": "imap", "name": NAME, "host": "imap.gmail.com", "username": "duenio@gmail.com", "oauth2": o}
    )


class Out:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def __call__(self, text: str) -> None:
        self.lines.append(text)

    @property
    def text(self) -> str:
        return "\n".join(self.lines)


class FakeMsal:
    """Reemplazo de msal.PublicClientApplication configurable por test."""

    instances: list[FakeMsal] = []
    flow: dict = {}
    device_result: dict = {}
    refresh_results: list[dict] = []
    block = False
    aborted = False

    def __init__(self, client_id, authority=None, timeout=None, **kwargs):
        self.client_id, self.authority, self.timeout = client_id, authority, timeout
        self.flow_scopes = None
        self.refresh_calls: list[tuple[str, list[str]]] = []
        FakeMsal.instances.append(self)

    def initiate_device_flow(self, scopes=None, **kwargs):
        self.flow_scopes = list(scopes or [])
        return dict(FakeMsal.flow)

    def acquire_token_by_device_flow(self, flow, **kwargs):
        assert flow.get("device_code") == "dev-code"
        if FakeMsal.block:
            # como msal: hace polling hasta que el usuario termine o expires_at venza
            deadline = time.monotonic() + 5
            while flow.get("expires_at", 1) != 0 and time.monotonic() < deadline:
                time.sleep(0.01)
            FakeMsal.aborted = flow.get("expires_at") == 0
            return {"error": "expired_token"}
        return dict(FakeMsal.device_result)

    def acquire_token_by_refresh_token(self, refresh_token, scopes, **kwargs):
        self.refresh_calls.append((refresh_token, list(scopes)))
        return FakeMsal.refresh_results.pop(0)


@pytest.fixture
def fake_msal(monkeypatch):
    import msal

    FakeMsal.instances = []
    FakeMsal.flow = {
        "user_code": "ABCD-1234",
        "device_code": "dev-code",
        "verification_uri": "https://microsoft.com/devicelogin",
        "expires_in": 900,
        "message": "To sign in, use a web browser...",
    }
    FakeMsal.device_result = {
        "access_token": "AT",
        "refresh_token": "RT-NUEVO",
        "id_token_claims": {"preferred_username": "duenio@outlook.com"},
    }
    FakeMsal.refresh_results = []
    FakeMsal.block = False
    FakeMsal.aborted = False
    monkeypatch.setattr(msal, "PublicClientApplication", FakeMsal)
    return FakeMsal


# --------------------------------------------------------------------------- token provider


async def test_provider_caches_token_and_persists_rotation(fake_msal):
    state = MemoryStateStore()
    await state.set_secret(KEY, "RT-1")
    fake_msal.refresh_results = [
        {"access_token": "AT-1", "refresh_token": "RT-2", "expires_in": 3600},
        {"access_token": "AT-2", "refresh_token": "RT-3", "expires_in": 3600},
    ]
    tp = ImapTokenProvider(cfg_ms(), state)
    assert await tp.get() == "AT-1"
    assert await tp.get() == "AT-1"  # cacheado: no vuelve a pedir
    assert tp.refreshes == 1
    assert await state.get_secret(KEY) == "RT-2"
    tp.invalidate()
    assert await tp.get() == "AT-2"
    app = fake_msal.instances[0]
    assert len(fake_msal.instances) == 1  # la app msal se reutiliza
    assert app.refresh_calls == [("RT-1", [MS_IMAP_SCOPE]), ("RT-2", [MS_IMAP_SCOPE])]
    assert "offline_access" not in app.refresh_calls[0][1]  # msal lo agrega solo (y falla si se pasa)
    assert app.authority == "https://login.microsoftonline.com/consumers"
    assert await state.get_secret(KEY) == "RT-3"


async def test_provider_short_lived_token_refreshes_at_half_life(fake_msal):
    state = MemoryStateStore()
    await state.set_secret(KEY, "RT-1")
    fake_msal.refresh_results = [
        {"access_token": "AT-1", "expires_in": 0},
        {"access_token": "AT-2", "expires_in": 3600},
    ]
    tp = ImapTokenProvider(cfg_ms(), state)
    assert await tp.get() == "AT-1"
    assert await tp.get() == "AT-2"


async def test_provider_force_refresh(fake_msal):
    state = MemoryStateStore()
    await state.set_secret(KEY, "RT-1")
    fake_msal.refresh_results = [{"access_token": "AT-1"}, {"access_token": "AT-2"}]
    tp = ImapTokenProvider(cfg_ms(), state)
    assert await tp.get() == "AT-1"
    assert await tp.get(force=True) == "AT-2"


async def test_provider_missing_refresh_token():
    tp = ImapTokenProvider(cfg_ms(), MemoryStateStore())
    with pytest.raises(ImapOAuthReauthRequired, match="centinela auth outlook"):
        await tp.get()


@pytest.mark.parametrize("error", ["invalid_grant", "interaction_required", "invalid_client"])
async def test_provider_microsoft_reauth_errors(fake_msal, error):
    state = MemoryStateStore()
    await state.set_secret(KEY, "RT-1")
    fake_msal.refresh_results = [{"error": error, "error_description": "AADSTS: detalle\nTrace ID: x"}]
    tp = ImapTokenProvider(cfg_ms(), state)
    with pytest.raises(ImapOAuthReauthRequired) as ei:
        await tp.get()
    assert "Trace ID" not in str(ei.value)  # solo la primera línea del detalle
    assert await state.get_secret(KEY) == "RT-1"  # no se borra: el usuario re-autoriza


async def test_provider_microsoft_transient_error_is_not_reauth(fake_msal):
    state = MemoryStateStore()
    await state.set_secret(KEY, "RT-1")
    fake_msal.refresh_results = [{"error": "temporarily_unavailable", "error_description": "try later"}]
    tp = ImapTokenProvider(cfg_ms(), state)
    with pytest.raises(ImapOAuthError) as ei:
        await tp.get()
    assert not isinstance(ei.value, ImapOAuthReauthRequired)


def test_provider_rejects_hostile_tenant():
    with pytest.raises(ImapOAuthError):
        oauth_mod._authority("evil.com/../../x?")
    assert oauth_mod._authority("contoso.onmicrosoft.com").endswith("/contoso.onmicrosoft.com")


def test_provider_requires_oauth_config():
    cfg = ImapConnectorConfig.model_validate(
        {"type": "imap", "name": "x", "host": "h", "username": "u", "password": "p"}
    )
    with pytest.raises(ImapOAuthError):
        ImapTokenProvider(cfg, MemoryStateStore())


async def test_provider_google_refresh_and_errors(monkeypatch):
    from google.auth import exceptions as gexc
    from google.oauth2 import credentials as gcreds

    behavior = {"mode": "ok"}

    class FakeCreds:
        def __init__(
            self,
            token=None,
            refresh_token=None,
            token_uri=None,
            client_id=None,
            client_secret=None,
            scopes=None,
        ):
            self.token, self.refresh_token, self.expiry = token, refresh_token, None
            self.scopes = scopes

        def refresh(self, request):
            assert callable(request)
            if behavior["mode"] == "revoked":
                raise gexc.RefreshError(
                    "invalid_grant: Token has been expired or revoked.", {"error": "invalid_grant"}
                )
            if behavior["mode"] == "down":
                raise gexc.RefreshError("server_error: backend error", {})
            self.token = "G-AT"
            self.refresh_token = "G-RT-2" if behavior["mode"] == "rotate" else self.refresh_token
            self.expiry = datetime.now(UTC).replace(tzinfo=None) + timedelta(minutes=30)

    monkeypatch.setattr(gcreds, "Credentials", FakeCreds)
    state = MemoryStateStore()
    await state.set_secret(KEY, "G-RT-1")
    tp = ImapTokenProvider(cfg_google(), state)
    assert await tp.get() == "G-AT"
    assert await state.get_secret(KEY) == "G-RT-1"

    behavior["mode"] = "rotate"
    assert await tp.get(force=True) == "G-AT"
    assert await state.get_secret(KEY) == "G-RT-2"

    behavior["mode"] = "revoked"
    with pytest.raises(ImapOAuthReauthRequired):
        await tp.get(force=True)
    behavior["mode"] = "down"
    with pytest.raises(ImapOAuthError) as ei:
        await tp.get(force=True)
    assert not isinstance(ei.value, ImapOAuthReauthRequired)


def test_google_request_has_short_timeout(monkeypatch):
    from google.auth.transport import requests as greq

    seen = {}

    def fake_call(self, url, method="GET", body=None, headers=None, timeout=None, **kwargs):
        seen["timeout"] = timeout
        return "resp"

    monkeypatch.setattr(greq.Request, "__call__", fake_call)
    req = oauth_mod._google_request()
    assert req("https://oauth2.googleapis.com/token", method="POST") == "resp"
    assert seen["timeout"] == oauth_mod.HTTP_TIMEOUT_S


# --------------------------------------------------------------------------- interactivo: Microsoft


async def test_interactive_microsoft_device_flow_stores_refresh_token(fake_msal):
    state = MemoryStateStore()
    out = Out()
    await interactive_login(cfg_ms(tenant="organizations"), state, printer=out)
    assert await state.get_secret(KEY) == "RT-NUEVO"
    app = fake_msal.instances[0]
    assert app.flow_scopes == [MS_IMAP_SCOPE]
    assert app.authority.endswith("/organizations")
    assert "ABCD-1234" in out.text and "https://microsoft.com/devicelogin" in out.text
    assert "Ingresá este código" in out.text and "15 minutos" in out.text
    assert "Listo" in out.text
    assert "RT-NUEVO" not in out.text  # el token nunca se muestra


async def test_interactive_microsoft_cancel_stops_polling_thread(fake_msal):
    fake_msal.block = True
    state = MemoryStateStore()
    out = Out()
    task = asyncio.create_task(interactive_login(cfg_ms(), state, printer=out))
    deadline = time.monotonic() + 5
    while not out.lines:
        assert time.monotonic() < deadline
        await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    while not fake_msal.aborted:  # el thread de polling terminó por expires_at=0, no por timeout
        assert time.monotonic() < deadline
        await asyncio.sleep(0.01)
    assert await state.get_secret(KEY) is None


async def test_interactive_microsoft_warns_on_account_mismatch(fake_msal):
    fake_msal.device_result["id_token_claims"] = {"preferred_username": "otra@outlook.com"}
    state = MemoryStateStore()
    out = Out()
    await interactive_login(cfg_ms(), state, printer=out)
    assert "otra@outlook.com" in out.text and "Atención" in out.text
    assert await state.get_secret(KEY) == "RT-NUEVO"


async def test_interactive_microsoft_flow_cannot_start(fake_msal):
    fake_msal.flow = {
        "error": "invalid_client",
        "error_description": "AADSTS7000218: public client flows disabled",
    }
    state = MemoryStateStore()
    with pytest.raises(ImapOAuthError, match="AADSTS7000218"):
        await interactive_login(cfg_ms(), state, printer=Out())
    assert await state.get_secret(KEY) is None


@pytest.mark.parametrize(
    ("result", "match"),
    [
        ({"error": "authorization_declined"}, "rechazaste"),
        ({"error": "expired_token"}, "venció"),
        ({"access_token": "AT"}, "refresh token"),
    ],
)
async def test_interactive_microsoft_failures(fake_msal, result, match):
    fake_msal.device_result = result
    state = MemoryStateStore()
    with pytest.raises(ImapOAuthError, match=match):
        await interactive_login(cfg_ms(), state, printer=Out())
    assert await state.get_secret(KEY) is None


async def test_interactive_requires_oauth_section():
    cfg = ImapConnectorConfig.model_validate(
        {"type": "imap", "name": NAME, "host": "h", "username": "u", "password": "p"}
    )
    with pytest.raises(ImapOAuthError, match="oauth2"):
        await interactive_login(cfg, MemoryStateStore(), printer=Out())


# --------------------------------------------------------------------------- interactivo: Google


class FakeFlow:
    instances: list[FakeFlow] = []
    local_server_error: Exception | None = None
    creds_refresh_token: str | None = "G-RT"

    def __init__(self, client_config, scopes):
        self.client_config, self.scopes = client_config, scopes
        self.redirect_uri = None
        self.run_kwargs = None
        self.auth_kwargs = None
        self.fetched = None
        FakeFlow.instances.append(self)

    @classmethod
    def from_client_config(cls, client_config, scopes, **kwargs):
        return cls(client_config, scopes)

    def run_local_server(self, **kwargs):
        self.run_kwargs = kwargs
        if FakeFlow.local_server_error:
            raise FakeFlow.local_server_error
        return type("C", (), {"refresh_token": FakeFlow.creds_refresh_token})()

    def authorization_url(self, **kwargs):
        self.auth_kwargs = kwargs
        return "https://accounts.google.com/o/oauth2/auth?client_id=gid&state=STATE-1", "STATE-1"

    def fetch_token(self, **kwargs):
        self.fetched = kwargs
        return {"access_token": "x"}

    @property
    def credentials(self):
        return type("C", (), {"refresh_token": FakeFlow.creds_refresh_token})()


@pytest.fixture
def fake_flow(monkeypatch):
    from google_auth_oauthlib import flow as gflow

    FakeFlow.instances = []
    FakeFlow.local_server_error = None
    FakeFlow.creds_refresh_token = "G-RT"
    monkeypatch.setattr(gflow, "InstalledAppFlow", FakeFlow)
    return FakeFlow


async def test_interactive_google_local_server(fake_flow):
    state = MemoryStateStore()
    out = Out()
    await interactive_login(cfg_google(), state, printer=out, google_mode="local_server", open_browser=False)
    assert await state.get_secret(KEY) == "G-RT"
    f = fake_flow.instances[0]
    assert f.scopes == [GOOGLE_IMAP_SCOPE]
    assert f.client_config["installed"]["client_secret"] == "gsecret"
    kw = f.run_kwargs
    assert kw["port"] == 0 and kw["host"] == "localhost"
    assert kw["prompt"] == "consent" and kw["access_type"] == "offline"
    assert kw["login_hint"] == "duenio@gmail.com"
    assert kw["timeout_seconds"] > 0
    assert "{url}" in kw["authorization_prompt_message"]


async def test_interactive_google_local_server_falls_back_to_console(fake_flow):
    fake_flow.local_server_error = OSError("address in use")
    state = MemoryStateStore()
    out = Out()
    pasted = "http://localhost:51234/?state=STATE-1&code=4/0AbcDEF&scope=https://mail.google.com/"
    await interactive_login(
        cfg_google(),
        state,
        printer=out,
        prompt=lambda _: pasted,
        google_mode="local_server",
        open_browser=False,
    )
    assert fake_flow.instances[0].fetched == {"code": "4/0AbcDEF"}
    assert await state.get_secret(KEY) == "G-RT"


async def test_interactive_google_console_auto_without_browser(fake_flow, monkeypatch):
    monkeypatch.setattr(oauth_mod, "_browser_available", lambda: False)
    state = MemoryStateStore()
    out = Out()
    pasted = (
        "http://localhost:50000/?state=STATE-1&code=4%2F0Xyz123456&scope=https%3A%2F%2Fmail.google.com%2F"
    )
    await interactive_login(cfg_google(), state, printer=out, prompt=lambda _: pasted)
    f = fake_flow.instances[0]
    assert f.run_kwargs is None  # no intentó servidor local
    assert f.redirect_uri.startswith("http://localhost:")
    assert f.auth_kwargs["prompt"] == "consent"
    assert f.fetched == {"code": "4/0Xyz123456"}
    assert "NO carga" in out.text and "https://accounts.google.com" in out.text
    assert await state.get_secret(KEY) == "G-RT"


@pytest.mark.parametrize(
    ("pasted", "match"),
    [
        ("http://localhost:50000/?state=OTRO&code=4/0abcdefghij", "state"),
        ("http://localhost:50000/?error=access_denied&state=STATE-1", "access_denied"),
        ("", "código"),
        ("<script>alert(1)</script>", "código"),
    ],
)
async def test_interactive_google_console_rejects_bad_input(fake_flow, monkeypatch, pasted, match):
    monkeypatch.setattr(oauth_mod, "_browser_available", lambda: False)
    state = MemoryStateStore()
    with pytest.raises(ImapOAuthError, match=match):
        await interactive_login(cfg_google(), state, printer=Out(), prompt=lambda _: pasted)
    assert await state.get_secret(KEY) is None
    assert fake_flow.instances[0].fetched is None


async def test_interactive_google_without_refresh_token(fake_flow):
    fake_flow.creds_refresh_token = None
    with pytest.raises(ImapOAuthError, match="refresh token"):
        await interactive_login(
            cfg_google(), MemoryStateStore(), printer=Out(), google_mode="local_server", open_browser=False
        )


async def test_interactive_google_requires_client_secret(fake_flow):
    # el config lo rechaza al validar (check-config lo detecta antes de arrancar)
    with pytest.raises(ValueError, match="client_secret"):
        cfg_google(client_secret=None)
    # y si igual llega sin secreto (config armada a mano), el login falla con mensaje claro
    cfg = cfg_google().model_copy(deep=True)
    cfg.oauth2.client_secret = None
    with pytest.raises(ImapOAuthError, match="client_secret"):
        await interactive_login(cfg, MemoryStateStore(), printer=Out(), google_mode="console")


def test_parse_pasted_redirect_variants():
    assert _parse_pasted_redirect("http://localhost:1/?code=abc&state=s") == ("abc", "s", None)
    assert _parse_pasted_redirect("localhost:1/?code=abc&state=s") == ("abc", "s", None)
    assert _parse_pasted_redirect("4/0AbcdefGhijk") == ("4/0AbcdefGhijk", None, None)
    assert _parse_pasted_redirect("corto") == (None, None, None)
    assert _parse_pasted_redirect("http://localhost/?" + "&".join(f"a{i}=1" for i in range(100)))[0] is None
