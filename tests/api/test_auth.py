"""Login, sesión, rate limiting, CSRF del login, proxies y redirecciones seguras."""

from __future__ import annotations

import time
from types import SimpleNamespace

import pytest
from argon2 import PasswordHasher
from pydantic import SecretStr

from centinela.api.app import DashboardConfigError, create_app
from centinela.api.auth import (
    LOGIN_COOKIE,
    SESSION_COOKIE,
    LoginRateLimiter,
    ProxyTrust,
    SessionManager,
    safe_next,
)
from centinela.core.config import DashboardConfig
from tests.api.conftest import PASSWORD, SECRET_KEY, do_login, form_token, make_client
from tests.api.fakes import FakeResultStore, FakeRuntime, LegacyRuntime


def set_cookie_headers(resp) -> list[str]:
    return resp.headers.get_list("set-cookie")


def session_cookie_header(resp) -> str:
    found = [h for h in set_cookie_headers(resp) if h.startswith(f"{SESSION_COOKIE}=")]
    assert found, f"no se emitió cookie de sesión: {set_cookie_headers(resp)}"
    return found[0]


# --------------------------------------------------------------------------- arranque


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"admin_password_hash": None}, "falta dashboard.admin_password_hash"),
        ({"secret_key": None}, "falta dashboard.secret_key"),
        ({"admin_password_hash": SecretStr("mi-clave-en-claro")}, "no es un hash argon2 válido"),
        ({"admin_password_hash": SecretStr("$argon2id$basura")}, "no es un hash argon2 válido"),
        ({"secret_key": SecretStr("corta")}, "demasiado corta"),
        ({"admin_user": "  "}, "admin_user está vacío"),
    ],
)
def test_create_app_refuses_without_secrets(dash_settings, store, changes, expected):
    for key, value in changes.items():
        setattr(dash_settings.dashboard, key, value)
    with pytest.raises(DashboardConfigError) as exc:
        create_app(FakeRuntime(dash_settings, store))
    message = str(exc.value)
    assert expected in message
    assert "centinela hash-password" in message and "centinela gen-key" in message
    # el mensaje nunca incluye el secreto
    assert "mi-clave-en-claro" not in message


def test_create_app_from_env_style_blank_values(store):
    from centinela.core.config import Settings

    s = Settings.model_validate({"dashboard": {"admin_password_hash": "", "secret_key": ""}})
    with pytest.raises(DashboardConfigError):
        create_app(FakeRuntime(s, store))


async def test_disabled_dashboard_only_serves_health(store):
    from centinela.core.config import Settings

    s = Settings.model_validate({"dashboard": {"enabled": False}})
    app = create_app(FakeRuntime(s, store))  # sin secretos: no falla porque está deshabilitado
    async with make_client(app) as c:
        assert (await c.get("/healthz")).json() == {"status": "ok"}
        assert (await c.get("/metrics")).status_code == 200
        assert (await c.get("/")).status_code == 404
        assert (await c.get("/login")).status_code == 404
        assert (await c.get("/api/v1/results")).status_code == 404


async def test_runtime_with_store_attribute_is_accepted(dash_settings):
    app = create_app(LegacyRuntime(dash_settings, FakeResultStore()))
    async with make_client(app) as c:
        app.state.centinela.login_min_response_s = 0
        assert (await do_login(c)).status_code == 303
        assert (await c.get("/messages")).status_code == 200


def test_runtime_without_store_is_rejected(dash_settings):
    with pytest.raises(TypeError):
        create_app(SimpleNamespace(settings=dash_settings))


# --------------------------------------------------------------------------- login


async def test_login_page_spanish_and_sets_form_cookie(client):
    resp = await client.get("/login")
    assert resp.status_code == 200
    assert "Iniciar sesión" in resp.text and "Usuario" in resp.text and "Contraseña" in resp.text
    assert 'autocomplete="current-password"' in resp.text
    cookie = [h for h in set_cookie_headers(resp) if h.startswith(f"{LOGIN_COOKIE}=")][0].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and "path=/login" in cookie
    assert "Salir" not in resp.text  # sin sesión no hay navegación


async def test_login_success_sets_hardened_session_cookie(client):
    resp = await do_login(client)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/"
    cookie = session_cookie_header(resp).lower()
    assert "httponly" in cookie
    assert "samesite=strict" in cookie
    assert "max-age=28800" in cookie  # session_hours = 8
    assert "path=/" in cookie
    assert "secure" not in cookie  # http plano: el navegador no la mandaría
    page = await client.get("/")
    assert page.status_code == 200
    assert "Salir" in page.text and "admin" in page.text


async def test_login_over_https_marks_cookie_secure(app):
    async with make_client(app, https=True) as c:
        resp = await do_login(c)
        assert resp.status_code == 303
        assert "secure" in session_cookie_header(resp).lower()
        assert resp.headers.get("strict-transport-security", "").startswith("max-age=")


async def test_forwarded_proto_only_from_trusted_proxy(dash_settings, store):
    # proxy NO confiable: se ignora X-Forwarded-Proto
    app = create_app(FakeRuntime(dash_settings, store))
    app.state.centinela.login_min_response_s = 0
    async with make_client(app) as c:
        resp = await do_login(c, headers={"X-Forwarded-Proto": "https"})
        assert "secure" not in session_cookie_header(resp).lower()
    # proxy confiable (la conexión de prueba viene de 127.0.0.1)
    dash_settings.dashboard.trusted_proxies = ["127.0.0.0/8"]
    app = create_app(FakeRuntime(dash_settings, store))
    app.state.centinela.login_min_response_s = 0
    async with make_client(app) as c:
        proxied = {"X-Forwarded-Proto": "https"}
        page = await c.get("/login", headers=proxied)
        login_cookie = [h for h in set_cookie_headers(page) if h.startswith(f"{LOGIN_COOKIE}=")][0]
        assert "secure" in login_cookie.lower()
        # el cliente de prueba habla http con el "proxy": la cookie Secure se reenvía a mano
        c.cookies.set(LOGIN_COOKIE, login_cookie.split(";", 1)[0].split("=", 1)[1])
        resp = await c.post(
            "/login",
            data={"username": "admin", "password": PASSWORD, "csrf_token": form_token(page.text)},
            headers=proxied,
        )
        assert resp.status_code == 303
        assert "secure" in session_cookie_header(resp).lower()
        assert resp.headers.get("strict-transport-security", "").startswith("max-age=")


@pytest.mark.parametrize(
    ("username", "password"),
    [("admin", "incorrecta"), ("otro", PASSWORD), ("", ""), ("ADMIN", PASSWORD), ("admin", PASSWORD + "x")],
)
async def test_login_failure_is_generic(client, username, password):
    resp = await do_login(client, username=username, password=password)
    assert resp.status_code == 401
    assert "Usuario o contraseña incorrectos." in resp.text
    assert not [h for h in set_cookie_headers(resp) if h.startswith(f"{SESSION_COOKIE}=")]
    assert (await client.get("/")).status_code == 303


async def test_login_rejects_huge_password_without_crash(client):
    resp = await do_login(client, password="x" * 5000)
    assert resp.status_code == 401


async def test_login_requires_form_token(client):
    await client.get("/login")
    resp = await client.post("/login", data={"username": "admin", "password": PASSWORD})
    assert resp.status_code == 400
    assert "El formulario venció" in resp.text
    resp = await client.post(
        "/login", data={"username": "admin", "password": PASSWORD, "csrf_token": "x" * 43}
    )
    assert resp.status_code == 400
    assert (await client.get("/")).status_code == 303


async def test_login_token_from_other_client_is_rejected(app):
    async with make_client(app) as a, make_client(app) as b:
        token_a = form_token((await a.get("/login")).text)
        await b.get("/login")
        resp = await b.post("/login", data={"username": "admin", "password": PASSWORD, "csrf_token": token_a})
        assert resp.status_code == 400


async def test_login_rate_limit_per_ip_and_user(client, app):
    for _ in range(5):
        assert (await do_login(client, password="mala")).status_code == 401
    resp = await do_login(client)  # contraseña CORRECTA, pero bloqueado
    assert resp.status_code == 429
    assert "Demasiados intentos fallidos" in resp.text
    assert int(resp.headers["retry-after"]) > 0
    assert not [h for h in set_cookie_headers(resp) if h.startswith(f"{SESSION_COOKIE}=")]


async def test_login_rate_limit_is_per_client_ip(dash_settings, store):
    dash_settings.dashboard.trusted_proxies = ["127.0.0.1"]
    app = create_app(FakeRuntime(dash_settings, store))
    app.state.centinela.login_min_response_s = 0
    async with make_client(app) as c:
        attacker = {"X-Forwarded-For": "203.0.113.9"}
        for _ in range(5):
            assert (await do_login(c, password="mala", headers=attacker)).status_code == 401
        assert (await do_login(c, headers=attacker)).status_code == 429
        # el admin legítimo desde otra IP no queda bloqueado por el atacante
        resp = await do_login(c, headers={"X-Forwarded-For": "198.51.100.7"})
        assert resp.status_code == 303


async def test_login_rate_limit_per_ip_across_usernames(app, client):
    app.state.centinela.limiter = LoginRateLimiter(max_attempts=5, max_attempts_per_ip=6)
    for i in range(6):
        assert (await do_login(client, username=f"user{i}", password="x")).status_code == 401
    assert (await do_login(client, username="nuevo", password="x")).status_code == 429


async def test_login_success_resets_counter(client):
    for _ in range(4):
        await do_login(client, password="mala")
    assert (await do_login(client)).status_code == 303
    client.cookies.clear()
    for _ in range(4):
        assert (await do_login(client, password="mala")).status_code == 401


async def test_login_responses_have_constant_minimum_duration(app, client):
    app.state.centinela.login_min_response_s = 0.25
    app.state.centinela.limiter = LoginRateLimiter(max_attempts=1)
    timings = {}
    for label, password in (("fallo", "mala"), ("bloqueado", PASSWORD)):
        page = await client.get("/login")
        start = time.perf_counter()
        resp = await client.post(
            "/login", data={"username": "admin", "password": password, "csrf_token": form_token(page.text)}
        )
        timings[label] = (time.perf_counter() - start, resp.status_code)
    assert timings["fallo"][1] == 401 and timings["bloqueado"][1] == 429
    assert timings["fallo"][0] >= 0.24 and timings["bloqueado"][0] >= 0.24


async def test_login_next_redirect_is_local_only(client):
    resp = await do_login(client, next_path="/messages?nivel=malicious")
    assert resp.headers["location"] == "/messages?nivel=malicious"


@pytest.mark.parametrize(
    "evil",
    [
        "//evil.com",
        "https://evil.com/x",
        "/\\evil.com",
        "\\\\evil.com",
        "javascript:alert(1)",
        "/login",
        "/%0d%0a",
    ],
)
async def test_login_next_open_redirect_blocked(app, evil):
    async with make_client(app) as c:
        resp = await do_login(c, next_path=evil)
        assert resp.status_code == 303
        location = resp.headers["location"]
        assert location in ("/", "/%0d%0a")
        assert "evil" not in location


async def test_login_page_redirects_when_already_logged_in(auth_client):
    resp = await auth_client.get("/login", params={"next": "/campaigns"})
    assert resp.status_code == 303
    assert resp.headers["location"] == "/campaigns"


# --------------------------------------------------------------------------- sesión requerida


@pytest.mark.parametrize("path", ["/", "/messages", "/campaigns", "/status", "/logout", "/messages/abc"])
async def test_pages_redirect_to_login_without_session(client, path):
    resp = await client.get(path)
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/login")


async def test_redirect_keeps_target(client):
    resp = await client.get("/messages", params={"nivel": "malicious"})
    assert resp.headers["location"] == "/login?next=%2Fmessages%3Fnivel%3Dmalicious"
    page = await client.get(resp.headers["location"])
    assert 'name="next" value="/messages?nivel=malicious"' in page.text


async def test_post_without_session_redirects_to_parent_page(client):
    resp = await client.post("/messages/123/false-positive", data={"value": "1"})
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login?next=%2Fmessages%2F123"


async def test_tampered_or_foreign_cookie_is_rejected(client, dash_settings):
    client.cookies.set(SESSION_COOKIE, "eyJ1IjoiYWRtaW4ifQ.bad.signature")
    assert (await client.get("/")).status_code == 303
    other = SessionManager(
        "otra-clave-totalmente-distinta-0123456789abcdef",
        username="admin",
        password_hash=dash_settings.dashboard.admin_password_hash.get_secret_value(),
        max_age_s=3600,
    )
    value, _ = other.issue()
    client.cookies.set(SESSION_COOKIE, value)
    assert (await client.get("/")).status_code == 303
    client.cookies.set(SESSION_COOKIE, "x" * 10_000)
    assert (await client.get("/")).status_code == 303


async def test_logout_revokes_session(auth_client, csrf):
    old_cookie = auth_client.cookies.get(SESSION_COOKIE)
    resp = await auth_client.post("/logout", data={"csrf_token": csrf})
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login?salida=1"
    assert any(
        h.startswith(f"{SESSION_COOKIE}=") and "max-age=0" in h.lower() for h in set_cookie_headers(resp)
    )
    page = await auth_client.get("/login?salida=1")
    assert "Cerraste sesión." in page.text
    auth_client.cookies.set(SESSION_COOKIE, old_cookie)  # reusar la cookie robada/vieja
    assert (await auth_client.get("/")).status_code == 303


async def test_logout_requires_csrf(auth_client):
    resp = await auth_client.post("/logout", data={})
    assert resp.status_code == 403
    assert (await auth_client.get("/")).status_code == 200


async def test_logout_without_session(client):
    resp = await client.post("/logout")
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"


# --------------------------------------------------------------------------- unidades


class FakeClock:
    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def test_rate_limiter_window_and_bounds():
    clock = FakeClock()
    rl = LoginRateLimiter(max_attempts=3, window_s=60, max_attempts_per_ip=10, max_keys=5, clock=clock)
    for _ in range(3):
        assert rl.retry_after("1.1.1.1", "admin") == 0
        rl.register_failure("1.1.1.1", "admin")
    assert rl.retry_after("1.1.1.1", "ADMIN ") > 0  # normaliza el usuario
    assert rl.retry_after("1.1.1.1", "otro") == 0
    assert rl.retry_after("2.2.2.2", "admin") == 0
    clock.now += 61
    assert rl.retry_after("1.1.1.1", "admin") == 0
    for i in range(50):  # memoria acotada
        rl.register_failure(f"10.0.0.{i}", "x")
    assert len(rl._by_user) <= 5 and len(rl._by_ip) <= 5


def test_session_manager_expiry_password_change_and_revocation(password_hash):
    clock = FakeClock(1_700_000_000)
    sm = SessionManager(
        SECRET_KEY, username="admin", password_hash=password_hash, max_age_s=3600, clock=clock
    )
    value, session = sm.issue()
    loaded = sm.load(value)
    assert loaded == session
    assert loaded.check_csrf(session.csrf) and not loaded.check_csrf("otro") and not loaded.check_csrf(None)
    clock.now += 3601
    assert sm.load(value) is None  # vencida (verificado con nuestro reloj, no solo el de itsdangerous)
    clock.now -= 3601
    new_hash = PasswordHasher(time_cost=1, memory_cost=1024, parallelism=1).hash("otra-clave")
    sm2 = SessionManager(SECRET_KEY, username="admin", password_hash=new_hash, max_age_s=3600, clock=clock)
    assert sm2.load(value) is None  # cambio de contraseña invalida sesiones
    sm3 = SessionManager(
        SECRET_KEY, username="otro", password_hash=password_hash, max_age_s=3600, clock=clock
    )
    assert sm3.load(value) is None  # cambio de usuario también
    sm.revoke(session)
    assert sm.load(value) is None
    assert sm.load(None) is None and sm.load("") is None and sm.load("basura") is None


def test_login_token_roundtrip(password_hash):
    sm = SessionManager(SECRET_KEY, username="admin", password_hash=password_hash, max_age_s=3600)
    cookie, token = sm.new_login_token()
    assert sm.check_login_token(cookie, token)
    assert not sm.check_login_token(cookie, token + "x")
    assert not sm.check_login_token(None, token)
    assert not sm.check_login_token(cookie, "")
    assert not sm.check_login_token("x" * 5000, token)


def _req(host: str, headers: dict[str, str] | None = None, scheme: str = "http"):
    from starlette.requests import Request

    raw = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    return Request(
        {
            "type": "http",
            "method": "GET",
            "scheme": scheme,
            "path": "/",
            "query_string": b"",
            "headers": [(b"host", b"centinela.local"), *raw],
            "client": (host, 1234),
            "server": ("centinela.local", 80),
        }
    )


def test_proxy_trust_client_ip_and_scheme():
    trust = ProxyTrust(["10.0.0.0/8", "invalido", "::1"])
    # cliente directo: se ignoran los headers
    assert trust.client_ip(_req("203.0.113.5", {"X-Forwarded-For": "1.2.3.4"})) == "203.0.113.5"
    assert not trust.is_secure(_req("203.0.113.5", {"X-Forwarded-Proto": "https"}))
    # vía proxy confiable: primer salto no confiable desde la derecha (no el que inventa el cliente)
    req = _req("10.0.0.2", {"X-Forwarded-For": "6.6.6.6, 198.51.100.4, 10.0.0.9"})
    assert trust.client_ip(req) == "198.51.100.4"
    assert trust.is_secure(_req("10.0.0.2", {"X-Forwarded-Proto": "https"}))
    assert not trust.is_secure(_req("10.0.0.2", {"X-Forwarded-Proto": "http"}))
    assert trust.client_ip(_req("10.0.0.2", {"X-Forwarded-For": "basura, 10.0.0.3"})) == "10.0.0.2"
    assert trust.client_ip(_req("10.0.0.2", {})) == "10.0.0.2"
    assert trust.is_secure(_req("1.1.1.1", scheme="https"))
    assert ProxyTrust(["*"]).trusts("8.8.8.8")
    assert not ProxyTrust([]).trusts("127.0.0.1")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("/messages?nivel=malicious", "/messages?nivel=malicious"),
        ("/messages/abc", "/messages/abc"),
        (None, "/"),
        ("", "/"),
        ("//evil.com", "/"),
        ("/\\evil.com", "/"),
        ("https://evil.com", "/"),
        ("evil.com", "/"),
        ("/login?next=/x", "/"),
        ("/logout", "/"),
        ("/ok\r\nSet-Cookie: x=1", "/"),
        ("/" + "a" * 3000, "/"),
    ],
)
def test_safe_next(value, expected):
    assert safe_next(value) == expected


def test_dashboard_config_validation_messages():
    from centinela.api.auth import validate_dashboard_config

    cfg = DashboardConfig()
    with pytest.raises(DashboardConfigError) as exc:
        validate_dashboard_config(cfg)
    assert "falta dashboard.admin_password_hash" in str(exc.value)
    assert "falta dashboard.secret_key" in str(exc.value)
