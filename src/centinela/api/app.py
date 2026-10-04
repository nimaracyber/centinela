"""Dashboard web + API REST + health/metrics de Centinela (FastAPI).

    from centinela.api.app import create_app
    app = create_app(runtime)      # runtime: .settings, .storage (ResultStore), async .health()

Rutas:
- Dashboard (requiere login): `/` resumen, `/messages`, `/messages/{id}`, `/campaigns`, `/status`,
  `/login`, `/logout`.
- API JSON (requiere login): `/api/v1/...` (ver `centinela.api.rest`).
- Sin login: `GET /healthz` (liveness: `{"status": "ok"}`), `GET /readyz` (solo booleanos, 503 si la base
  o Redis no responden) y `GET /metrics` (Prometheus).

IMPORTANTE (despliegue): `/metrics` y `/readyz` NO piden login para que Prometheus y el orquestador
puedan consultarlos. No expongas el puerto del dashboard directo a internet: publicalo detrás de un proxy
inverso con HTTPS (y listalo en `dashboard.trusted_proxies`), y bloqueá `/metrics` desde afuera o accedé
por VPN. Las métricas no incluyen datos de mails, pero sí nombres de conectores y volúmenes de tráfico.

Seguridad: el dashboard muestra metadatos sensibles de los mails. Por eso `create_app` se niega a
arrancar si el dashboard está habilitado sin hash de contraseña o sin clave de sesión, todas las
respuestas llevan cabeceras de seguridad (CSP estricta sin inline, sin frames, sin referrer, no-store),
los formularios POST llevan token CSRF, el login tiene rate limiting y los templates escapan todo.
"""

from __future__ import annotations

import asyncio
import html
import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, tzinfo
from pathlib import Path
from typing import Any, Protocol, runtime_checkable
from urllib.parse import quote

import jinja2
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from starlette.datastructures import Headers, MutableHeaders
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from centinela import __version__, metrics
from centinela.api import rest, views
from centinela.api.auth import (
    DashboardConfigError,
    LoginRateLimiter,
    LoginRequired,
    PasswordVerifier,
    ProxyTrust,
    SessionManager,
    session_from_request,
    session_max_age_s,
    validate_dashboard_config,
)
from centinela.core.config import Settings
from centinela.storage.protocol import ResultStore

log = logging.getLogger(__name__)

PACKAGE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = PACKAGE_DIR / "templates"
STATIC_DIR = PACKAGE_DIR / "static"

MAX_BODY_BYTES = 64 * 1024  # formularios y JSON del dashboard son chicos; nada legítimo pesa más
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

CONTENT_SECURITY_POLICY = (
    "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'"
)
SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("Content-Security-Policy", CONTENT_SECURITY_POLICY),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("X-Frame-Options", "DENY"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    (
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()",
    ),
    ("X-Robots-Tag", "noindex, nofollow"),
)

HTTP_ERROR_TEXTS = {
    400: "La solicitud no es válida.",
    401: "Tenés que iniciar sesión.",
    403: "No tenés permiso para hacer esto.",
    404: "No encontramos lo que buscabas.",
    405: "Esa acción no está permitida en esta dirección.",
    413: "La solicitud es demasiado grande.",
    429: "Demasiados pedidos seguidos. Esperá un momento.",
    500: "Ocurrió un error interno. Ya quedó registrado; probá de nuevo en un rato.",
}


@runtime_checkable
class DashboardRuntime(Protocol):
    """Lo que el dashboard necesita del runtime (ver `centinela.runtime.Runtime`).

    `storage` es el `ResultStore`; por compatibilidad también se acepta un atributo `store`."""

    settings: Settings
    storage: ResultStore

    async def health(self) -> dict[str, Any]: ...


def _load_timezone(name: str | None) -> tzinfo:
    if not name or name.upper() == "UTC":
        return UTC
    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo(name)
    except Exception:  # noqa: BLE001 - falta tzdata, nombre inválido...
        log.warning("zona horaria %r no disponible (¿falta tzdata?); el dashboard muestra horas en UTC", name)
        return UTC


def _resolve_store(runtime: Any) -> ResultStore:
    store = getattr(runtime, "storage", None)
    if store is None:
        store = getattr(runtime, "store", None)
    if store is None:
        raise TypeError("el runtime no expone `storage` (ResultStore): no se puede armar el dashboard")
    return store


@dataclass
class DashboardContext:
    """Estado compartido por las rutas (en `app.state.centinela`)."""

    runtime: Any
    settings: Settings
    store: ResultStore
    tz: tzinfo
    proxies: ProxyTrust
    env: jinja2.Environment | None = None
    sessions: SessionManager | None = None
    verifier: PasswordVerifier | None = None
    limiter: LoginRateLimiter = field(default_factory=LoginRateLimiter)
    login_min_response_s: float = 0.5  # duración mínima de toda respuesta a POST /login
    health_timeout_s: float = 5.0
    health_cache_s: float = 5.0  # /readyz no requiere login: que no se pueda martillar la base
    version: str = __version__
    _health_cache: tuple[float, dict[str, Any]] | None = field(default=None, repr=False)
    _health_lock: asyncio.Lock | None = field(default=None, repr=False)

    def static_url(self, path: str) -> str:
        return f"/static/{path.lstrip('/')}?v={quote(self.version)}"

    async def health(self) -> dict[str, Any]:
        """`runtime.health()` con timeout y una caché corta compartida (coalesce de pedidos simultáneos)."""
        cached = self._health_cache
        if cached is not None and time.monotonic() - cached[0] < self.health_cache_s:
            return cached[1]
        if self._health_lock is None:
            self._health_lock = asyncio.Lock()
        async with self._health_lock:
            cached = self._health_cache
            if cached is not None and time.monotonic() - cached[0] < self.health_cache_s:
                return cached[1]
            data = await asyncio.wait_for(self.runtime.health(), timeout=self.health_timeout_s)
            if not isinstance(data, dict):
                raise TypeError("runtime.health() no devolvió un dict")
            self._health_cache = (time.monotonic(), data)
            return data

    def render(
        self,
        request: Request,
        template: str,
        context: dict[str, Any],
        *,
        status_code: int = 200,
        headers: dict[str, str] | None = None,
    ) -> HTMLResponse:
        if self.env is None:  # dashboard deshabilitado: no hay templates
            return HTMLResponse(
                _plain_error_page(status_code, "Dashboard deshabilitado."), status_code=status_code
            )
        session = getattr(request.state, "session", None)
        base: dict[str, Any] = {
            "user": session.user if session is not None else None,
            "csrf_token": session.csrf if session is not None else "",
            "company_name": self.settings.general.company_name,
            "version": self.version,
            "request_path": request.url.path,
            "nav": "",
        }
        base.update(context)
        body = self.env.get_template(template).render(base)
        return HTMLResponse(body, status_code=status_code, headers=headers)


# --------------------------------------------------------------------------- respuestas de error


def _is_api(path: str) -> bool:
    return path.startswith("/api/")


def _plain_error_page(status_code: int, message: str) -> str:
    """Página de error mínima sin depender de templates (middlewares, errores tempranos)."""
    msg = html.escape(message)
    return (
        '<!doctype html><html lang="es"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>Error {int(status_code)} · Centinela</title>"
        f'<link rel="stylesheet" href="/static/css/app.css?v={quote(__version__)}"></head>'
        f'<body><main class="container narrow"><div class="card error-card"><h1>Error {int(status_code)}</h1>'
        f'<p>{msg}</p><p><a href="/">Volver al inicio</a></p></div></main></body></html>'
    )


def _simple_error(path: str, status_code: int, message: str) -> Response:
    if _is_api(path):
        return JSONResponse({"detail": message}, status_code=status_code)
    return HTMLResponse(_plain_error_page(status_code, message), status_code=status_code)


def _error_response(
    request: Request, status_code: int, detail: Any, headers: dict[str, str] | None = None
) -> Response:
    message = detail if isinstance(detail, str) and detail else HTTP_ERROR_TEXTS.get(status_code, "Error.")
    if _is_api(request.url.path):
        return JSONResponse({"detail": message}, status_code=status_code, headers=headers)
    ctx: DashboardContext | None = getattr(request.app.state, "centinela", None)
    if ctx is None or ctx.env is None:
        return HTMLResponse(_plain_error_page(status_code, message), status_code=status_code, headers=headers)
    if getattr(request.state, "session", None) is None:
        session = session_from_request(request)  # ruta inexistente: mostrar igual la navegación si hay sesión
        if session is not None:
            request.state.session = session
    try:
        return ctx.render(
            request,
            "error.html",
            {
                "status_code": status_code,
                "message": message,
                "title": HTTP_ERROR_TEXTS.get(status_code, "Error"),
            },
            status_code=status_code,
            headers=headers,
        )
    except Exception:  # noqa: BLE001 - nunca fallar al mostrar un error
        log.exception("no se pudo renderizar la página de error")
        return HTMLResponse(_plain_error_page(status_code, message), status_code=status_code, headers=headers)


# --------------------------------------------------------------------------- middlewares ASGI


class BodyLimitMiddleware:
    """Corta cuerpos de más de `max_bytes` (413) en métodos con cuerpo. Lee y re-entrega el cuerpo,
    así ninguna ruta puede ser forzada a procesar megas de formulario/JSON."""

    def __init__(self, app: ASGIApp, max_bytes: int = MAX_BODY_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method", "GET") in SAFE_METHODS:
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        declared = Headers(scope=scope).get("content-length")
        if declared is not None:
            try:
                size = int(declared)
            except ValueError:
                await _simple_error(path, 400, "Content-Length inválido.")(scope, receive, send)
                return
            if size > self.max_bytes:
                await _simple_error(path, 413, HTTP_ERROR_TEXTS[413])(scope, receive, send)
                return
        chunks: list[bytes] = []
        total = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            total += len(chunk)
            if total > self.max_bytes:
                await _simple_error(path, 413, HTTP_ERROR_TEXTS[413])(scope, receive, send)
                return
            chunks.append(chunk)
            if not message.get("more_body", False):
                break
        body = b"".join(chunks)
        delivered = False

        async def replay() -> Message:
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


class SecurityHeadersMiddleware:
    """Cabeceras de seguridad en TODA respuesta (incluidos errores), bloqueo de POST cross-site
    (Sec-Fetch-Site) y red de contención para excepciones no controladas (500 sin detalles)."""

    def __init__(self, app: ASGIApp, proxies: ProxyTrust) -> None:
        self.app = app
        self.proxies = proxies

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path: str = scope.get("path", "")
        method: str = scope.get("method", "GET")
        secure = self.proxies.is_secure(Request(scope))
        started = False

        async def send_wrapper(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                headers = MutableHeaders(scope=message)
                for name, value in SECURITY_HEADERS:
                    headers[name] = value
                if path.startswith("/static/"):
                    headers["Cache-Control"] = "public, max-age=3600"
                else:
                    headers["Cache-Control"] = "no-store"
                    headers["Pragma"] = "no-cache"
                if secure:
                    headers["Strict-Transport-Security"] = "max-age=31536000"
            await send(message)

        if (
            method not in SAFE_METHODS
            and Headers(scope=scope).get("sec-fetch-site", "").lower() == "cross-site"
        ):
            log.warning("POST cross-site bloqueado: %s %r", method, path[:200])
            await _simple_error(path, 403, "Pedido desde otro sitio bloqueado.")(scope, receive, send_wrapper)
            return
        try:
            await self.app(scope, receive, send_wrapper)
        except Exception:
            log.exception("error no controlado en %s %r", method, path[:200])
            if started:
                raise
            await _simple_error(path, 500, HTTP_ERROR_TEXTS[500])(scope, receive, send_wrapper)


# --------------------------------------------------------------------------- endpoints sin login


async def healthz() -> JSONResponse:
    """Liveness: el proceso responde. No toca la base (no debe reiniciar el contenedor por un corte de DB)."""
    return JSONResponse({"status": "ok"})


async def readyz(request: Request) -> JSONResponse:
    """Readiness: solo booleanos (sin mensajes de error ni nombres internos)."""
    ctx: DashboardContext = request.app.state.centinela
    try:
        health = await ctx.health()
    except Exception as exc:  # noqa: BLE001
        log.warning("readyz: runtime.health() falló (%s)", type(exc).__name__)
        return JSONResponse({"ready": False, "db": False, "redis": False, "degraded": True}, status_code=503)

    def _ok(key: str) -> bool:
        part = health.get(key)
        return bool(part.get("ok")) if isinstance(part, dict) else False

    ready = bool(health.get("ok"))
    body = {"ready": ready, "db": _ok("db"), "redis": _ok("redis"), "degraded": bool(health.get("degraded"))}
    return JSONResponse(body, status_code=200 if ready else 503)


async def metrics_endpoint() -> Response:
    """Métricas Prometheus. NO exponer a internet (ver docstring del módulo)."""
    return Response(generate_latest(metrics.REGISTRY), media_type=CONTENT_TYPE_LATEST)


# --------------------------------------------------------------------------- app


def create_app(runtime: DashboardRuntime) -> FastAPI:
    """Arma la app. Lanza `DashboardConfigError` si el dashboard está habilitado sin secretos."""
    settings: Settings = runtime.settings
    dash = settings.dashboard
    store = _resolve_store(runtime)
    if dash.enabled:
        validate_dashboard_config(dash)

    proxies = ProxyTrust(dash.trusted_proxies)
    app = FastAPI(
        title="Centinela",
        version=__version__,
        docs_url=None,  # la API no se documenta públicamente (y Swagger necesitaría CDNs)
        redoc_url=None,
        openapi_url=None,
        swagger_ui_oauth2_redirect_url=None,
    )
    ctx = DashboardContext(
        runtime=runtime,
        settings=settings,
        store=store,
        tz=_load_timezone(settings.general.timezone),
        proxies=proxies,
    )
    app.state.centinela = ctx

    app.add_api_route("/healthz", healthz, methods=["GET", "HEAD"], include_in_schema=False)
    app.add_api_route("/readyz", readyz, methods=["GET", "HEAD"], include_in_schema=False)
    app.add_api_route("/metrics", metrics_endpoint, methods=["GET"], include_in_schema=False)

    if dash.enabled:
        assert dash.admin_password_hash is not None and dash.secret_key is not None  # validado arriba
        password_hash = dash.admin_password_hash.get_secret_value().strip()
        ctx.sessions = SessionManager(
            dash.secret_key.get_secret_value(),
            username=dash.admin_user,
            password_hash=password_hash,
            max_age_s=session_max_age_s(dash),
        )
        ctx.verifier = PasswordVerifier(dash.admin_user, password_hash)
        ctx.env = views.build_environment(TEMPLATES_DIR, tz=ctx.tz, static_url=ctx.static_url)
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
        app.include_router(views.router, include_in_schema=False)
        app.include_router(rest.router, include_in_schema=False)
        log.info(
            "dashboard habilitado (usuario %s, sesión de %d h)",
            dash.admin_user,
            ctx.sessions.max_age_s // 3600,
        )
    else:
        log.info("dashboard deshabilitado: solo /healthz, /readyz y /metrics")

    @app.exception_handler(LoginRequired)
    async def _login_required(request: Request, exc: LoginRequired) -> Response:
        target = "/login" if exc.next_path in ("", "/") else f"/login?next={quote(exc.next_path, safe='')}"
        return RedirectResponse(target, status_code=303)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException) -> Response:
        return _error_response(request, exc.status_code, exc.detail, getattr(exc, "headers", None))

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError) -> Response:
        if _is_api(request.url.path):
            errors = [
                {"loc": [str(p) for p in err.get("loc", ())][:5], "msg": str(err.get("msg", ""))[:200]}
                for err in exc.errors()[:20]
            ]  # sin "input": no se refleja lo que mandó el cliente
            return JSONResponse({"detail": "Parámetros inválidos.", "errors": errors}, status_code=422)
        return _error_response(request, 400, "Los parámetros de la dirección no son válidos.")

    # el último agregado queda más afuera: SecurityHeaders envuelve también los 413 del límite de cuerpo
    app.add_middleware(BodyLimitMiddleware, max_bytes=MAX_BODY_BYTES)
    app.add_middleware(SecurityHeadersMiddleware, proxies=proxies)
    return app


__all__ = [
    "CONTENT_SECURITY_POLICY",
    "DashboardConfigError",
    "DashboardContext",
    "DashboardRuntime",
    "create_app",
]
