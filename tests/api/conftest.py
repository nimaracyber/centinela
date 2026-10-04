from __future__ import annotations

import re
from collections.abc import AsyncIterator, Callable

import httpx
import pytest
from argon2 import PasswordHasher

from centinela.api.app import create_app
from centinela.core.config import Settings
from centinela.core.models import ExtractedUrl, FindingCategory, Severity, VerdictLevel
from tests.api.fakes import FakeResultStore, FakeRuntime, make_artifact, make_finding, make_result

PASSWORD = "Una-Clave-De-Prueba-123"
SECRET_KEY = "k" * 24 + "-clave-de-sesion-para-tests-0123456789"
XSS_SUBJECT = '<script>alert("xss")</script> Factura vencida'
XSS_DISPLAY = '"><img src=x onerror=alert(1)>'
XSS_FILENAME = '"><svg onload=alert(2)>.exe'
RLO_FILENAME = "factura‮fdp.exe"
EVIL_URL = "https://evil.example.com/login?next=<b>x</b>"

_CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')
_META_RE = re.compile(r'<meta name="csrf-token" content="([^"]+)">')


@pytest.fixture(scope="session")
def password_hash() -> str:
    # parámetros mínimos: los tests no necesitan que argon2 sea caro
    return PasswordHasher(time_cost=1, memory_cost=1024, parallelism=1).hash(PASSWORD)


@pytest.fixture
def dash_settings(tmp_path, password_hash) -> Settings:
    s = Settings.model_validate(
        {
            "general": {
                "company_name": "Ferretería El Tornillo",
                "timezone": "UTC",
                "data_dir": str(tmp_path),
            },
            "dashboard": {
                "enabled": True,
                "admin_user": "admin",
                "admin_password_hash": password_hash,
                "secret_key": SECRET_KEY,
                "session_hours": 8,
            },
        }
    )
    return s


@pytest.fixture
def store() -> FakeResultStore:
    return FakeResultStore()


@pytest.fixture
def runtime(dash_settings, store) -> FakeRuntime:
    return FakeRuntime(dash_settings, store)


@pytest.fixture
def app(runtime):
    application = create_app(runtime)
    application.state.centinela.login_min_response_s = 0.0
    return application


def make_client(application, *, https: bool = False) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application),
        base_url="https://testserver" if https else "http://testserver",
        follow_redirects=False,
    )


@pytest.fixture
async def client(app) -> AsyncIterator[httpx.AsyncClient]:
    async with make_client(app) as c:
        yield c


def form_token(html: str) -> str:
    m = _CSRF_RE.search(html)
    assert m, "no hay token CSRF en el formulario"
    return m.group(1)


def meta_token(html: str) -> str:
    m = _META_RE.search(html)
    assert m, "no hay meta csrf-token en la página"
    return m.group(1)


async def do_login(
    client: httpx.AsyncClient,
    *,
    username: str = "admin",
    password: str = PASSWORD,
    next_path: str | None = None,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    page = await client.get("/login", headers=headers)
    assert page.status_code == 200
    data = {"username": username, "password": password, "csrf_token": form_token(page.text)}
    if next_path is not None:
        data["next"] = next_path
    return await client.post("/login", data=data, headers=headers)


@pytest.fixture
async def auth_client(app) -> AsyncIterator[httpx.AsyncClient]:
    async with make_client(app) as c:
        resp = await do_login(c)
        assert resp.status_code == 303, resp.text
        yield c


@pytest.fixture
async def csrf(auth_client) -> str:
    page = await auth_client.get("/logout")
    return meta_token(page.text)


@pytest.fixture
def malicious_result(store):
    arts = [
        make_artifact("factura.zip", id="att0", detected_type="zip"),
        make_artifact(RLO_FILENAME, id="att0/a", detected_type="pe", depth=1, parent_id="att0"),
        make_artifact(
            XSS_FILENAME, id="att0/a/b", detected_type="pe", depth=2, parent_id="att0/a", encrypted=True
        ),
    ]
    findings = [
        make_finding(
            "yara.AsyncRAT",
            title="Firma de AsyncRAT",
            severity=Severity.CRITICAL,
            score=97,
            category=FindingCategory.MALWARE,
            artifact_id="att0/a",
            family="AsyncRAT",
            description="Se encontró un troyano de acceso remoto.",
            evidence={"strings": ["<script>evil()</script>", "AsyncClient"], "offset": 4096},
        ),
        make_finding("pe.double_extension", title="Doble extensión", severity=Severity.HIGH, score=70),
        make_finding(
            "headers.spf_fail",
            title="SPF falló",
            severity=Severity.MEDIUM,
            score=30,
            category=FindingCategory.SPOOFING,
        ),
        make_finding("info.context", title="Contexto", severity=Severity.INFO, score=0),
    ]
    result = make_result(
        level=VerdictLevel.MALICIOUS,
        subject=XSS_SUBJECT,
        from_display=XSS_DISPLAY,
        from_addr="facturas@proveedor-falso.example",
        artifacts=arts,
        findings=findings,
        urls=[ExtractedUrl(url=EVIL_URL, source="body_html", display_text="Banco <i>Nación</i>")],
        families=["AsyncRAT"],
        summary="Adjunto con malware AsyncRAT <b>peligroso</b>.",
        errors=["clamav[att0]: timeout <b>"],
        actions=["tag:imap-ventas:keyword:$Centinela_Malicious", "alert:telegram:ok", "alert:email:dedup"],
    )
    store.add(result)
    return result


@pytest.fixture
def populated(store, malicious_result) -> Callable[[], None]:
    """Un poco de todo: limpios, sospechoso, error y el malicioso con payloads XSS."""
    store.add(
        make_result(subject="Pedido 1234", level=VerdictLevel.CLEAN),
        make_result(subject="Presupuesto", level=VerdictLevel.CLEAN, mailbox="compras@empresa.com"),
        make_result(
            subject="Actualizá tu cuenta",
            level=VerdictLevel.SUSPICIOUS,
            from_addr="soporte@banco-falso.example",
            findings=[
                make_finding(
                    "url.lookalike",
                    title="Link parecido a un banco",
                    category=FindingCategory.PHISHING,
                    severity=Severity.MEDIUM,
                    score=40,
                )
            ],
        ),
        make_result(subject="No se pudo analizar", level=VerdictLevel.ERROR, errors=["parse: mime roto"]),
    )
    return lambda: None
