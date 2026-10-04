from __future__ import annotations

import base64
import json
import webbrowser
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr

from centinela.connectors import oauth_cloud
from centinela.connectors.gmail import (
    GMAIL_API,
    PUBSUB_API,
    SCOPE_MODIFY,
    SCOPE_PUBSUB,
    SCOPE_READONLY,
    GmailAuthError,
    GmailConnector,
    oauth_mailboxes_key,
    refresh_token_key,
)
from centinela.connectors.graph import GRAPH_BASE, GraphAuthError
from centinela.core.config import GmailConnectorConfig, GraphConnectorConfig
from centinela.core.state import MemoryStateStore

# ----------------------------------------------------------------------------- Gmail login


class FakeCreds:
    def __init__(self, token="ya29.tok", refresh_token="1//refresh", granted=(SCOPE_READONLY,)):
        self.token = token
        self.refresh_token = refresh_token
        self.granted_scopes = list(granted)


class FakeFlow:
    """Imita InstalledAppFlow sin red ni navegador."""

    created: list[FakeFlow] = []
    local_server_error: Exception | None = None
    creds = FakeCreds()

    def __init__(self, scopes):
        self.scopes = scopes
        self.redirect_uri = None
        self.fetched_code = None
        self.local_kwargs = None
        self.credentials = None
        FakeFlow.created.append(self)

    @classmethod
    def from_client_secrets_file(cls, path, scopes):
        return cls(scopes)

    def run_local_server(self, **kwargs):
        self.local_kwargs = kwargs
        if FakeFlow.local_server_error is not None:
            raise FakeFlow.local_server_error
        return FakeFlow.creds

    def authorization_url(self, **kwargs):
        assert kwargs["access_type"] == "offline" and kwargs["prompt"] == "consent"
        return "https://accounts.google.com/o/oauth2/auth?x=1", "STATE123"

    def fetch_token(self, code):
        self.fetched_code = code
        self.credentials = FakeFlow.creds


@pytest.fixture
def fake_flow(monkeypatch):
    import google_auth_oauthlib.flow as flow_mod

    FakeFlow.created = []
    FakeFlow.local_server_error = None
    FakeFlow.creds = FakeCreds()
    monkeypatch.setattr(flow_mod, "InstalledAppFlow", FakeFlow)
    monkeypatch.setattr(oauth_cloud, "running_in_container", lambda: False)
    return FakeFlow


@pytest.fixture
def client_file(tmp_path) -> Path:
    p = tmp_path / "client.json"
    p.write_text(json.dumps({"installed": {"client_id": "cid", "client_secret": "csec"}}), encoding="utf-8")
    return p


def gmail_cfg(client_file, **over) -> GmailConnectorConfig:
    data = {
        "type": "gmail",
        "name": "personal",
        "auth": "oauth_user",
        "oauth_client_file": client_file,
        "tag": False,
    }
    data.update(over)
    return GmailConnectorConfig(**data)


async def test_login_local_server_stores_refresh_token(fake_flow, client_file, router):
    profile = router.get(f"{GMAIL_API}/users/me/profile").respond(
        200, json={"emailAddress": "Yo@Gmail.com", "historyId": "1"}
    )
    state = MemoryStateStore()
    out: list[str] = []
    email = await oauth_cloud.gmail_user_login(gmail_cfg(client_file), state, print_fn=out.append)
    assert email == "yo@gmail.com"
    assert fake_flow.created[0].scopes == [SCOPE_READONLY]
    assert fake_flow.created[0].local_kwargs["port"] == 0  # puerto libre elegido por el SO
    assert profile.calls.last.request.headers["Authorization"] == "Bearer ya29.tok"
    assert await state.get_secret(refresh_token_key("personal", "yo@gmail.com")) == "1//refresh"
    assert json.loads(await state.get(oauth_mailboxes_key("personal"))) == ["yo@gmail.com"]
    assert await state.get(refresh_token_key("personal", "yo@gmail.com")) is None  # solo como secreto
    assert any("Listo" in line for line in out)
    assert not any("1//refresh" in line for line in out)  # el token nunca se imprime

    # login de un segundo buzón: el índice se acumula sin duplicados
    router.get(f"{GMAIL_API}/users/me/profile").respond(200, json={"emailAddress": "otro@gmail.com"})
    await oauth_cloud.gmail_user_login(gmail_cfg(client_file), state, print_fn=out.append)
    assert json.loads(await state.get(oauth_mailboxes_key("personal"))) == ["yo@gmail.com", "otro@gmail.com"]


async def test_login_scopes_with_tag_and_pubsub(fake_flow, client_file, router):
    fake_flow.creds = FakeCreds(granted=(SCOPE_MODIFY, SCOPE_PUBSUB))
    router.get(f"{GMAIL_API}/users/me/profile").respond(200, json={"emailAddress": "yo@gmail.com"})
    cfg = gmail_cfg(
        client_file,
        tag=True,
        pubsub_topic="projects/p-123/topics/t-1",
        pubsub_subscription="projects/p-123/subscriptions/s-1",
    )
    await oauth_cloud.gmail_user_login(cfg, MemoryStateStore(), print_fn=lambda s: None)
    assert fake_flow.created[0].scopes == [SCOPE_MODIFY, SCOPE_PUBSUB]


async def test_login_console_fallback_without_browser(fake_flow, client_file, router):
    fake_flow.local_server_error = webbrowser.Error("could not locate runnable browser")
    router.get(f"{GMAIL_API}/users/me/profile").respond(200, json={"emailAddress": "yo@gmail.com"})
    printed: list[str] = []
    answer = "http://localhost:53682/?state=STATE123&code=4/0Abc-def&scope=x"
    email = await oauth_cloud.gmail_user_login(
        gmail_cfg(client_file), MemoryStateStore(), input_fn=lambda prompt: answer, print_fn=printed.append
    )
    assert email == "yo@gmail.com"
    console_flow = fake_flow.created[-1]
    assert console_flow.redirect_uri == oauth_cloud.CONSOLE_REDIRECT_URI
    assert console_flow.fetched_code == "4/0Abc-def"
    assert any("https://accounts.google.com/o/oauth2/auth" in p for p in printed)


async def test_login_console_rejects_state_mismatch_and_errors(fake_flow, client_file, router):
    cfg = gmail_cfg(client_file)
    with pytest.raises(GmailAuthError, match="state"):
        await oauth_cloud.gmail_user_login(
            cfg,
            MemoryStateStore(),
            console=True,
            input_fn=lambda p: "http://localhost:53682/?state=OTRO&code=abc",
            print_fn=lambda s: None,
        )
    with pytest.raises(GmailAuthError, match="access_denied"):
        await oauth_cloud.gmail_user_login(
            cfg,
            MemoryStateStore(),
            console=True,
            input_fn=lambda p: "http://localhost:53682/?error=access_denied",
            print_fn=lambda s: None,
        )
    with pytest.raises(GmailAuthError):
        await oauth_cloud.gmail_user_login(
            cfg, MemoryStateStore(), console=True, input_fn=lambda p: "", print_fn=lambda s: None
        )
    with pytest.raises(GmailAuthError):
        await oauth_cloud.gmail_user_login(
            cfg, MemoryStateStore(), console=True, input_fn=lambda p: "x" * 10000, print_fn=lambda s: None
        )


async def test_login_console_accepts_bare_code(fake_flow, client_file, router):
    router.get(f"{GMAIL_API}/users/me/profile").respond(200, json={"emailAddress": "yo@gmail.com"})
    await oauth_cloud.gmail_user_login(
        gmail_cfg(client_file),
        MemoryStateStore(),
        console=True,
        input_fn=lambda p: "  4/0codigo  ",
        print_fn=lambda s: None,
    )
    assert fake_flow.created[-1].fetched_code == "4/0codigo"


async def test_login_without_refresh_token_fails(fake_flow, client_file, router):
    fake_flow.creds = FakeCreds(refresh_token=None)
    state = MemoryStateStore()
    with pytest.raises(GmailAuthError, match="myaccount.google.com/permissions"):
        await oauth_cloud.gmail_user_login(gmail_cfg(client_file), state, print_fn=lambda s: None)
    assert state._s == {}


async def test_login_warns_when_other_account_authorized(fake_flow, client_file, router):
    router.get(f"{GMAIL_API}/users/me/profile").respond(200, json={"emailAddress": "equivocado@gmail.com"})
    printed: list[str] = []
    await oauth_cloud.gmail_user_login(
        gmail_cfg(client_file, mailboxes=["correcto@gmail.com"]), MemoryStateStore(), print_fn=printed.append
    )
    assert any("ATENCIÓN" in p and "correcto@gmail.com" in p for p in printed)


async def test_login_config_errors(client_file, tmp_path):
    with pytest.raises(GmailAuthError, match="oauth_user"):
        await oauth_cloud.gmail_user_login(
            GmailConnectorConfig(
                type="gmail", name="w", service_account_file=Path("sa.json"), mailboxes=["a@b.com"]
            ),
            MemoryStateStore(),
        )
    with pytest.raises(GmailAuthError, match="no existe"):
        await oauth_cloud.gmail_user_login(gmail_cfg(tmp_path / "nada.json"), MemoryStateStore())


# ----------------------------------------------------------------------------- Graph check


def fake_jwt(roles: list[str]) -> str:
    def b64(d: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")

    return f"{b64({'alg': 'RS256'})}.{b64({'roles': roles, 'tid': 't'})}.firma"


def graph_cfg(**over) -> GraphConnectorConfig:
    data = {
        "type": "graph",
        "name": "m365",
        "tenant_id": "tid",
        "client_id": "cid",
        "client_secret": SecretStr("s"),
        "mailboxes": ["a@empresa.com", "b@empresa.com"],
        "folders": ["inbox", "junkemail"],
    }
    data.update(over)
    return GraphConnectorConfig(**data)


async def test_graph_check_reports_access_per_mailbox(router):
    token = fake_jwt(["Mail.ReadWrite", "Mail.Send"])

    async def provider(force: bool = False) -> str:
        return token

    ua = f"{GRAPH_BASE}/v1.0/users/a@empresa.com/mailFolders"
    ub = f"{GRAPH_BASE}/v1.0/users/b@empresa.com/mailFolders"
    router.get(f"{ua}/inbox").respond(200, json={"displayName": "Bandeja de entrada", "totalItemCount": 42})
    router.get(f"{ua}/junkemail").respond(200, json={"displayName": "Correo no deseado", "totalItemCount": 3})
    router.get(f"{ub}/inbox").respond(
        403, json={"error": {"code": "ErrorAccessDenied", "message": "Access is denied."}}
    )
    router.get(f"{ub}/junkemail").respond(404, json={"error": {"code": "MailboxNotEnabledForRESTAPI"}})
    diag = await oauth_cloud.graph_check(graph_cfg(), token_provider=provider)
    text = str(diag)
    assert diag.ok is False
    assert "[OK] a@empresa.com: carpeta 'Bandeja de entrada' accesible (42 mensajes)." in text
    assert "RBAC for Applications" in text  # 403 explicado
    assert "Exchange Online" in text  # 404 MailboxNotEnabledForRESTAPI explicado
    assert "Mail.Send" in text and "[AVISO]" in text  # permiso de más
    assert token not in text  # nunca se imprime el token
    assert list(diag)[0].startswith("[OK] Token")


async def test_graph_check_missing_readwrite_when_tagging(router):
    async def provider(force: bool = False) -> str:
        return fake_jwt(["Mail.Read"])

    router.get(url__startswith=f"{GRAPH_BASE}/v1.0/users/").respond(200, json={"displayName": "Inbox"})
    diag = await oauth_cloud.graph_check(
        graph_cfg(mailboxes=["a@empresa.com"], folders=["inbox"]), token_provider=provider
    )
    assert diag.ok is False and "Mail.ReadWrite" in str(diag)
    diag2 = await oauth_cloud.graph_check(
        graph_cfg(mailboxes=["a@empresa.com"], folders=["inbox"], tag=False), token_provider=provider
    )
    assert diag2.ok is True


async def test_graph_check_token_failure():
    async def provider(force: bool = False) -> str:
        raise GraphAuthError("invalid_client: AADSTS7000215: Invalid client secret provided.")

    diag = await oauth_cloud.graph_check(graph_cfg(), token_provider=provider)
    assert diag.ok is False and "AADSTS7000215" in str(diag)


async def test_graph_check_without_credentials():
    diag = await oauth_cloud.graph_check(graph_cfg(client_secret=None))
    assert diag.ok is False and "client_secret" in str(diag)


async def test_graph_check_opaque_token_still_checks_access(router):
    async def provider(force: bool = False) -> str:
        return "no-es-un-jwt"

    router.get(url__startswith=f"{GRAPH_BASE}/v1.0/users/").respond(200, json={"displayName": "Inbox"})
    diag = await oauth_cloud.graph_check(
        graph_cfg(mailboxes=["a@empresa.com"], folders=["inbox"]), token_provider=provider
    )
    assert diag.ok is True


# ----------------------------------------------------------------------------- Gmail check


async def test_gmail_check(settings, router, tmp_path):
    sa = tmp_path / "sa.json"
    sa.write_text("{}", encoding="utf-8")
    cfg = GmailConnectorConfig(
        type="gmail",
        name="gw",
        service_account_file=sa,
        mailboxes=["a@empresa.com", "b@empresa.com"],
        pubsub_topic="projects/p-123/topics/t-1",
        pubsub_subscription="projects/p-123/subscriptions/s-1",
    )
    conn = GmailConnector(cfg, settings, MemoryStateStore())

    async def fake_token(key: str, force: bool = False) -> str:
        if key == "b@empresa.com":
            raise GmailAuthError("Google rechazó la delegación para el buzón b@empresa.com")
        return "tok"

    conn._access_token = fake_token
    router.get(f"{GMAIL_API}/users/a@empresa.com/profile").respond(
        200, json={"historyId": "1", "messagesTotal": 10}
    )
    router.get(f"{PUBSUB_API}/projects/p-123/subscriptions/s-1").respond(
        200, json={"topic": "projects/p-123/topics/otro"}
    )
    diag = await oauth_cloud.gmail_check(cfg, MemoryStateStore(), settings=settings, connector=conn)
    text = str(diag)
    assert "[OK] a@empresa.com: acceso OK (10 mensajes)." in text
    assert "[ERROR] b@empresa.com" in text and "delegación" in text
    assert "tópico" in text  # suscripción asociada a otro tópico
    assert diag.ok is False
    await conn.close()


async def test_gmail_check_missing_files(settings, tmp_path):
    cfg = GmailConnectorConfig(
        type="gmail", name="gw", service_account_file=tmp_path / "no.json", mailboxes=["a@b.com"]
    )
    diag = await oauth_cloud.gmail_check(cfg, MemoryStateStore(), settings=settings)
    assert diag.ok is False and "No existe" in str(diag)


def test_code_from_answer_variants():
    assert oauth_cloud._code_from_answer("localhost:53682/?state=S&code=abc", "S") == "abc"
    assert oauth_cloud._code_from_answer("abc", "S") == "abc"
    with pytest.raises(GmailAuthError):
        oauth_cloud._code_from_answer("http://localhost:53682/?state=S", "S")


def test_diagnostics_is_a_list_of_lines():
    d = oauth_cloud.Diagnostics()
    d.good("a")
    d.warn("b")
    assert d.ok and list(d) == ["[OK] a", "[AVISO] b"]
    d.fail("c")
    assert not d.ok and str(d).splitlines()[-1] == "[ERROR] c"


async def test_gmail_check_pubsub_forbidden(settings, router, tmp_path):
    sa = tmp_path / "sa.json"
    sa.write_text("{}", encoding="utf-8")
    cfg = GmailConnectorConfig(
        type="gmail",
        name="gw",
        service_account_file=sa,
        mailboxes=["a@empresa.com"],
        pubsub_topic="projects/p-123/topics/t-1",
        pubsub_subscription="projects/p-123/subscriptions/s-1",
    )
    conn = GmailConnector(cfg, settings, MemoryStateStore())

    async def fake_token(key: str, force: bool = False) -> str:
        return "tok"

    conn._access_token = fake_token
    router.get(f"{GMAIL_API}/users/a@empresa.com/profile").respond(200, json={"historyId": "1"})
    router.get(f"{PUBSUB_API}/projects/p-123/subscriptions/s-1").mock(return_value=httpx.Response(403))
    diag = await oauth_cloud.gmail_check(cfg, MemoryStateStore(), settings=settings, connector=conn)
    assert "Pub/Sub Subscriber" in str(diag) and not diag.ok
    await conn.close()
