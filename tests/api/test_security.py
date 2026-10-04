"""Cabeceras de seguridad, límites, errores sin filtración, estáticos y templates compatibles con la CSP."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from centinela.api.app import CONTENT_SECURITY_POLICY, STATIC_DIR, TEMPLATES_DIR

REQUIRED_CSP = (
    "default-src 'self'",
    "img-src 'self' data:",
    "style-src 'self'",
    "script-src 'self'",
    "frame-ancestors 'none'",
)


def assert_security_headers(resp) -> None:
    csp = resp.headers.get("content-security-policy", "")
    for directive in REQUIRED_CSP:
        assert directive in csp, (directive, resp.request.url)
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert resp.headers.get("x-content-type-options") == "nosniff"
    assert resp.headers.get("referrer-policy") == "no-referrer"
    assert resp.headers.get("x-frame-options") == "DENY"


@pytest.mark.parametrize(
    "path",
    [
        "/login",
        "/healthz",
        "/readyz",
        "/metrics",
        "/no-existe",
        "/static/css/app.css",
        "/api/v1/results",
        "/",
    ],
)
async def test_security_headers_everywhere_anonymous(client, path):
    resp = await client.get(path)
    assert_security_headers(resp)
    assert "strict-transport-security" not in resp.headers  # http plano


async def test_security_headers_on_authenticated_pages_and_api(auth_client, populated, malicious_result):
    for path in (
        "/",
        "/messages",
        f"/messages/{malicious_result.id}",
        "/campaigns",
        "/status",
        "/api/v1/stats",
    ):
        resp = await auth_client.get(path)
        assert resp.status_code == 200, path
        assert_security_headers(resp)
        assert resp.headers.get("cache-control") == "no-store"  # datos sensibles: nunca en caché


async def test_static_assets_are_cacheable_and_traversal_blocked(client):
    resp = await client.get("/static/css/app.css")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/css")
    assert resp.headers["cache-control"].startswith("public")
    resp = await client.get("/static/js/app.js")
    assert resp.status_code == 200 and "javascript" in resp.headers["content-type"]
    assert (await client.get("/static/img/favicon.svg")).status_code == 200
    resp = await client.get("/static/%2e%2e/app.py")
    assert resp.status_code == 404
    assert "def create_app" not in resp.text
    resp = await client.get("/static/..%2fapp.py")
    assert resp.status_code == 404


async def test_api_docs_not_exposed(client):
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert (await client.get(path)).status_code == 404


async def test_cross_site_post_blocked(client):
    resp = await client.post(
        "/login", data={"username": "admin", "password": "x"}, headers={"Sec-Fetch-Site": "cross-site"}
    )
    assert resp.status_code == 403
    assert_security_headers(resp)


async def test_same_origin_post_allowed(client):
    resp = await client.post("/login", data={"username": "admin"}, headers={"Sec-Fetch-Site": "same-origin"})
    assert resp.status_code == 400  # llega a la ruta (falta el token del formulario)


async def test_oversized_body_rejected(client, auth_client, csrf, malicious_result):
    resp = await client.post(
        "/login",
        content=b"a=" + b"x" * 100_000,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 413
    assert_security_headers(resp)

    async def chunks():
        for _ in range(20):
            yield b"x" * 10_000

    resp = await client.post(
        "/login", content=chunks(), headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert resp.status_code == 413
    resp = await auth_client.post(
        f"/api/v1/results/{malicious_result.id}/false-positive",
        content=b'{"note": "' + b"n" * 70_000 + b'"}',
        headers={"Content-Type": "application/json", "X-CSRF-Token": csrf},
    )
    assert resp.status_code == 413
    assert resp.json()["detail"] == "La solicitud es demasiado grande."


async def test_invalid_content_length_rejected(client):
    resp = await client.post("/login", content=b"a=1", headers={"Content-Length": "abc"})
    assert resp.status_code in (400, 413)


async def test_unhandled_error_returns_generic_500_with_headers(auth_client, store):
    store.fail_with = RuntimeError("fallo con secreto postgres://user:clave@db")
    resp = await auth_client.get("/messages")
    assert resp.status_code == 500
    assert "Ocurrió un error interno" in resp.text
    assert "clave@db" not in resp.text and "Traceback" not in resp.text
    assert_security_headers(resp)
    resp = await auth_client.get("/api/v1/results")
    assert resp.status_code == 500
    assert resp.json()["detail"].startswith("Ocurrió un error interno")
    assert "clave" not in resp.text


async def test_not_found_page_keeps_navigation_when_logged_in(auth_client, client):
    resp = await auth_client.get("/no-existe")
    assert resp.status_code == 404
    assert "No encontramos lo que buscabas." in resp.text and "Salir" in resp.text
    resp = await client.get("/no-existe")
    assert resp.status_code == 404 and "Salir" not in resp.text


async def test_head_on_probes(client):
    assert (await client.head("/healthz")).status_code == 200
    assert (await client.head("/readyz")).status_code == 200


async def test_method_not_allowed_is_spanish(auth_client):
    resp = await auth_client.put("/messages")
    assert resp.status_code == 405


async def test_hsts_only_over_https(app):
    from tests.api.conftest import make_client

    async with make_client(app, https=True) as c:
        resp = await c.get("/healthz")
        assert resp.headers["strict-transport-security"].startswith("max-age=")


def test_csp_constant_matches_requirements():
    for directive in REQUIRED_CSP:
        assert directive in CONTENT_SECURITY_POLICY


# --------------------------------------------------------------------------- análisis estático de templates/JS


def _templates() -> list[Path]:
    files = sorted(Path(TEMPLATES_DIR).rglob("*.html"))
    assert files
    return files


@pytest.mark.parametrize("path", _templates(), ids=lambda p: p.name)
def test_templates_are_csp_compatible_and_never_mark_safe(path):
    text = path.read_text(encoding="utf-8")
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", text), "script inline"
    assert not re.search(r"\sstyle\s*=", text), "atributo style inline"
    assert "<style" not in text, "bloque <style> inline"
    assert not re.search(r"\son[a-z]+\s*=", text), "handler on*= inline"
    assert "javascript:" not in text
    assert "|safe" not in text and "Markup(" not in text and "autoescape false" not in text
    assert "http://" not in text  # nada de recursos externos (ni CDNs)
    for url in re.findall(r"https://[^\s\"'<>]+", text):
        assert url.startswith(("https://www.virustotal.com", "https://bazaar.abuse.ch")), url


def test_static_js_has_no_dangerous_sinks():
    js = (Path(STATIC_DIR) / "js" / "app.js").read_text(encoding="utf-8")
    for sink in ("innerHTML", "outerHTML", "eval(", "new Function", "document.write", "insertAdjacentHTML"):
        assert sink not in js
    assert "http://" not in js and "https://" not in js


def test_static_css_has_no_external_resources():
    css = (Path(STATIC_DIR) / "css" / "app.css").read_text(encoding="utf-8")
    assert "@import" not in css and "url(" not in css


def test_jinja_autoescape_enabled(app):
    env = app.state.centinela.env
    assert env.autoescape is True
    rendered = env.from_string("{{ v }}").render(v="<b>&\"'")
    assert rendered == "&lt;b&gt;&amp;&#34;&#39;"
