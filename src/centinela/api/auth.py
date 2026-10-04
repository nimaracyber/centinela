"""Autenticación del dashboard: login con argon2, sesión firmada en cookie, CSRF, rate limiting y proxies.

Diseño (un único usuario administrador, sin base de usuarios):

- Login: `dashboard.admin_user` + verificación argon2 de `dashboard.admin_password_hash`
  (generado con `centinela hash-password`). Siempre se verifica el hash, aunque el usuario no coincida,
  y todas las respuestas del POST de login duran un mínimo fijo: no se filtra por tiempos si el
  usuario existe ni si se llegó al límite de intentos.
- Sesión: cookie firmada con `dashboard.secret_key` (itsdangerous, HMAC-SHA256), HttpOnly,
  SameSite=Strict, `Secure` cuando la conexión es HTTPS (directa o informada por un proxy listado en
  `dashboard.trusted_proxies`). Vence a las `dashboard.session_hours` horas (vencimiento absoluto,
  verificado también del lado del servidor). Incluye una huella del hash de la contraseña: si se cambia
  la contraseña, todas las sesiones anteriores dejan de valer. Logout revoca la sesión en memoria.
- CSRF: token aleatorio atado a la sesión, obligatorio en todo formulario POST (campo `csrf_token`) y en
  la API (header `X-CSRF-Token`). El formulario de login (todavía sin sesión) usa un token propio en una
  cookie firmada de corta vida (doble envío).
- Rate limiting de login en memoria: 5 intentos fallidos cada 5 minutos por IP+usuario y 20 por IP.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import logging
import secrets
import time
from collections import OrderedDict, deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from argon2 import PasswordHasher, extract_parameters
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import Depends, HTTPException, Request
from itsdangerous import BadData, URLSafeTimedSerializer

if TYPE_CHECKING:
    from starlette.responses import Response

    from centinela.core.config import DashboardConfig

log = logging.getLogger(__name__)

SESSION_COOKIE = "centinela_session"
LOGIN_COOKIE = "centinela_login"
CSRF_FIELD = "csrf_token"
CSRF_HEADER = "X-CSRF-Token"

MIN_SECRET_KEY_CHARS = 32
MAX_SESSION_HOURS = 24 * 30
LOGIN_TOKEN_MAX_AGE_S = 2 * 3600
MAX_USERNAME_CHARS = 200
MAX_PASSWORD_CHARS = 1024
MAX_COOKIE_CHARS = 4096
MAX_TOKEN_CHARS = 256
MAX_REVOKED_SESSIONS = 10_000

CLI_HINT = (
    "Generá el hash de la contraseña con `centinela hash-password` y la clave de sesión con "
    "`centinela gen-key`, y cargalos en config.yaml / .env (dashboard.admin_password_hash y "
    "dashboard.secret_key). Si no vas a usar el dashboard, poné `dashboard.enabled: false`."
)


class DashboardConfigError(RuntimeError):
    """La configuración no permite arrancar el dashboard de forma segura (falta un secreto, etc.)."""


# --------------------------------------------------------------------------- validación de config


def is_argon2_hash(value: str) -> bool:
    """True si `value` es un hash argon2 en formato PHC que argon2-cffi puede verificar."""
    if not value.startswith("$argon2"):
        return False
    try:
        extract_parameters(value)
    except (InvalidHashError, ValueError):
        return False
    return True


def validate_dashboard_config(cfg: DashboardConfig) -> None:
    """Lanza `DashboardConfigError` (en español, con los comandos de la CLI) si falta algún secreto."""
    problems: list[str] = []
    if not (cfg.admin_user or "").strip():
        problems.append("dashboard.admin_user está vacío")
    pw_hash = cfg.admin_password_hash.get_secret_value().strip() if cfg.admin_password_hash else ""
    if not pw_hash:
        problems.append("falta dashboard.admin_password_hash")
    elif not is_argon2_hash(pw_hash):
        problems.append(
            "dashboard.admin_password_hash no es un hash argon2 válido (¿se cargó la contraseña en claro?)"
        )
    key = cfg.secret_key.get_secret_value() if cfg.secret_key else ""
    if not key.strip():
        problems.append("falta dashboard.secret_key")
    elif len(key) < MIN_SECRET_KEY_CHARS:
        problems.append(f"dashboard.secret_key es demasiado corta (mínimo {MIN_SECRET_KEY_CHARS} caracteres)")
    if problems:
        raise DashboardConfigError(
            "No se puede iniciar el dashboard de forma segura: " + "; ".join(problems) + ". " + CLI_HINT
        )


def session_max_age_s(cfg: DashboardConfig) -> int:
    hours = max(1, min(int(cfg.session_hours or 1), MAX_SESSION_HOURS))
    return hours * 3600


# --------------------------------------------------------------------------- contraseña


class PasswordVerifier:
    """Verifica usuario + contraseña contra el hash argon2 configurado.

    argon2 es caro a propósito (CPU y memoria): se corre en un thread y con concurrencia acotada, así
    una ráfaga de intentos de login no puede tumbar el proceso.
    """

    def __init__(self, username: str, password_hash: str, *, max_concurrency: int = 2) -> None:
        self._username = username.encode("utf-8", "replace")
        self._hash = password_hash.strip()
        self._hasher = PasswordHasher()
        self._sem = asyncio.Semaphore(max(1, max_concurrency))

    def _verify_password(self, password: str) -> bool:
        try:
            return bool(self._hasher.verify(self._hash, password))
        except (VerificationError, InvalidHashError):
            return False
        except Exception:  # noqa: BLE001 - p.ej. surrogates sueltos en la contraseña
            log.debug("error verificando la contraseña", exc_info=True)
            return False

    async def check(self, username: str, password: str) -> bool:
        too_long = len(password) > MAX_PASSWORD_CHARS
        user_ok = hmac.compare_digest(username.encode("utf-8", "replace"), self._username)
        async with self._sem:
            # se verifica SIEMPRE (aunque el usuario no coincida) para que el tiempo no delate nada
            pw_ok = await asyncio.to_thread(self._verify_password, password[:MAX_PASSWORD_CHARS])
        return user_ok and pw_ok and not too_long


# --------------------------------------------------------------------------- rate limiting


class LoginRateLimiter:
    """Limita intentos de login FALLIDOS en una ventana deslizante, en memoria.

    - por (IP, usuario): `max_attempts` en `window_s` (por defecto 5 en 5 minutos);
    - por IP (cualquier usuario): `max_attempts_per_ip` (frena el "password spraying").
    Un atacante desde otra IP no puede bloquear al administrador legítimo. La memoria está acotada
    (`max_keys` por tabla, se descartan las claves más viejas).
    """

    def __init__(
        self,
        max_attempts: int = 5,
        window_s: float = 300.0,
        *,
        max_attempts_per_ip: int = 20,
        max_keys: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.max_attempts = max(1, int(max_attempts))
        self.max_attempts_per_ip = max(self.max_attempts, int(max_attempts_per_ip))
        self.window_s = float(window_s)
        self.max_keys = max(1, int(max_keys))
        self._clock = clock
        self._by_user: OrderedDict[tuple[str, str], deque[float]] = OrderedDict()
        self._by_ip: OrderedDict[str, deque[float]] = OrderedDict()

    @staticmethod
    def _norm_user(user: str) -> str:
        return (user or "").strip().casefold()[:MAX_USERNAME_CHARS]

    def _tables(self, ip: str, user: str) -> list[tuple[OrderedDict[Any, deque[float]], Any, int]]:
        return [
            (self._by_user, (ip, self._norm_user(user)), self.max_attempts),
            (self._by_ip, ip, self.max_attempts_per_ip),
        ]

    def retry_after(self, ip: str, user: str) -> float:
        """Segundos hasta poder reintentar; 0 si el intento está permitido."""
        now = self._clock()
        wait = 0.0
        for table, key, limit in self._tables(ip, user):
            dq = table.get(key)
            if dq is None:
                continue
            while dq and now - dq[0] >= self.window_s:
                dq.popleft()
            if not dq:
                del table[key]
                continue
            if len(dq) >= limit:
                wait = max(wait, self.window_s - (now - dq[-limit]))
        return max(0.0, wait)

    def register_failure(self, ip: str, user: str) -> None:
        now = self._clock()
        for table, key, limit in self._tables(ip, user):
            dq = table.get(key)
            if dq is None:
                dq = deque(maxlen=limit)
                table[key] = dq
            else:
                table.move_to_end(key)
            dq.append(now)
            while len(table) > self.max_keys:
                table.popitem(last=False)

    def reset(self, ip: str, user: str) -> None:
        """Login exitoso: limpia el contador de esa IP+usuario (el de la IP sigue su ventana)."""
        self._by_user.pop((ip, self._norm_user(user)), None)


# --------------------------------------------------------------------------- sesión


@dataclass(frozen=True, slots=True)
class Session:
    user: str
    csrf: str
    sid: str
    issued_at: int

    def check_csrf(self, token: str | None) -> bool:
        """Comparación en tiempo constante del token CSRF recibido contra el de la sesión."""
        if not token or len(token) > MAX_TOKEN_CHARS:
            return False
        return hmac.compare_digest(token.encode("utf-8", "replace"), self.csrf.encode("utf-8"))


class SessionManager:
    """Emite y valida la cookie de sesión y el token anti-CSRF del formulario de login."""

    def __init__(
        self,
        secret_key: str,
        *,
        username: str,
        password_hash: str,
        max_age_s: int,
        clock: Callable[[], float] = time.time,
    ) -> None:
        signer_kwargs = {"digest_method": hashlib.sha256}
        self._serializer = URLSafeTimedSerializer(
            secret_key, salt="centinela.session.v1", signer_kwargs=signer_kwargs
        )
        self._login_serializer = URLSafeTimedSerializer(
            secret_key, salt="centinela.login-form.v1", signer_kwargs=signer_kwargs
        )
        self._username = username
        # huella del hash: cambiar la contraseña invalida todas las sesiones emitidas antes
        self._pw_fingerprint = hashlib.sha256(
            b"centinela-session:" + password_hash.strip().encode()
        ).hexdigest()[:32]
        self.max_age_s = int(max_age_s)
        self._clock = clock
        self._revoked: dict[str, float] = {}

    # -- sesión
    def issue(self) -> tuple[str, Session]:
        session = Session(
            user=self._username,
            csrf=secrets.token_urlsafe(32),
            sid=secrets.token_urlsafe(16),
            issued_at=int(self._clock()),
        )
        value = self._serializer.dumps(
            {
                "u": session.user,
                "c": session.csrf,
                "s": session.sid,
                "t": session.issued_at,
                "p": self._pw_fingerprint,
            }
        )
        return value, session

    def load(self, value: str | None) -> Session | None:
        if not value or len(value) > MAX_COOKIE_CHARS:
            return None
        try:
            data = self._serializer.loads(value, max_age=self.max_age_s + 60)
        except BadData:
            return None
        except Exception:  # noqa: BLE001 - payload inesperado: sesión inválida, nunca un 500
            return None
        if not isinstance(data, dict):
            return None
        user, csrf, sid, issued, fingerprint = (data.get(k) for k in ("u", "c", "s", "t", "p"))
        if not (
            isinstance(user, str)
            and isinstance(csrf, str)
            and isinstance(sid, str)
            and isinstance(issued, int)
            and isinstance(fingerprint, str)
        ):
            return None
        if not hmac.compare_digest(
            user.encode("utf-8", "replace"), self._username.encode("utf-8", "replace")
        ):
            return None
        if not hmac.compare_digest(fingerprint.encode(), self._pw_fingerprint.encode()):
            return None
        now = self._clock()
        if issued > now + 300 or now - issued > self.max_age_s:
            return None
        self._prune_revoked(now)
        if sid in self._revoked:
            return None
        return Session(user=user, csrf=csrf, sid=sid, issued_at=issued)

    def revoke(self, session: Session) -> None:
        now = self._clock()
        self._prune_revoked(now)
        while len(self._revoked) >= MAX_REVOKED_SESSIONS:
            self._revoked.pop(next(iter(self._revoked)))
        self._revoked[session.sid] = session.issued_at + self.max_age_s

    def _prune_revoked(self, now: float) -> None:
        if not self._revoked:
            return
        expired = [sid for sid, until in self._revoked.items() if until < now]
        for sid in expired:
            del self._revoked[sid]

    # -- token del formulario de login (antes de tener sesión)
    def new_login_token(self) -> tuple[str, str]:
        """(valor de la cookie firmada, token para el campo oculto del formulario)."""
        token = secrets.token_urlsafe(32)
        return self._login_serializer.dumps(token), token

    def check_login_token(self, cookie_value: str | None, form_token: str | None) -> bool:
        if not cookie_value or not form_token:
            return False
        if len(cookie_value) > MAX_COOKIE_CHARS or len(form_token) > MAX_TOKEN_CHARS:
            return False
        try:
            token = self._login_serializer.loads(cookie_value, max_age=LOGIN_TOKEN_MAX_AGE_S)
        except BadData:
            return False
        except Exception:  # noqa: BLE001
            return False
        if not isinstance(token, str):
            return False
        return hmac.compare_digest(token.encode(), form_token.encode("utf-8", "replace"))


# --------------------------------------------------------------------------- proxies e IP del cliente


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return None


class ProxyTrust:
    """Decide si creer en X-Forwarded-For / X-Forwarded-Proto según `dashboard.trusted_proxies`.

    Acepta IPs y redes CIDR ("10.0.0.0/8") y "*" (confiar en cualquiera: solo si el puerto del dashboard
    no es alcanzable más que por el proxy).
    """

    MAX_HOPS = 20

    def __init__(self, entries: Iterable[str] = ()) -> None:
        self.trust_all = False
        self.networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for raw in entries:
            entry = str(raw).strip()
            if not entry:
                continue
            if entry == "*":
                self.trust_all = True
                continue
            try:
                self.networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                log.warning("dashboard.trusted_proxies: entrada inválida %r (se ignora)", entry[:100])

    def trusts(self, host: str | None) -> bool:
        if not host:
            return False
        if self.trust_all:
            return True
        ip = _parse_ip(host)
        if ip is None:
            return False
        return any(ip.version == net.version and ip in net for net in self.networks)

    @staticmethod
    def _peer(request: Request) -> str:
        client = request.client
        return client.host if client and client.host else ""

    def client_ip(self, request: Request) -> str:
        """IP real del cliente: el primer salto no confiable de X-Forwarded-For (de derecha a izquierda),
        solo si quien nos habla es un proxy confiable. Si no, la IP de la conexión."""
        peer = self._peer(request)
        if self.trusts(peer):
            header = request.headers.get("x-forwarded-for", "")[:2000]
            hops = [h.strip() for h in header.split(",") if h.strip()][-self.MAX_HOPS :]
            for hop in reversed(hops):
                ip = _parse_ip(hop)
                if ip is None:
                    break  # cadena malformada: no se puede confiar en lo que sigue
                if not self.trusts(str(ip)):
                    return str(ip)
            else:
                if hops:
                    first = _parse_ip(hops[0])
                    if first is not None:
                        return str(first)
        return peer or "desconocida"

    def is_secure(self, request: Request) -> bool:
        """HTTPS directo, o informado por un proxy confiable con X-Forwarded-Proto: https."""
        if request.url.scheme in ("https", "wss"):
            return True
        if self.trusts(self._peer(request)):
            proto = request.headers.get("x-forwarded-proto", "")[:100].split(",")[0].strip().lower()
            return proto == "https"
        return False


# --------------------------------------------------------------------------- redirecciones seguras


def safe_next(value: str | None, default: str = "/") -> str:
    """Solo rutas locales ("/messages?x=1"): bloquea open redirects ("//evil.com", "https://...", "/\\evil")."""
    if not value or len(value) > 2000:
        return default
    if not value.startswith("/") or value.startswith("//") or "\\" in value:
        return default
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        return default
    parts = urlsplit(value)
    if parts.scheme or parts.netloc:
        return default
    if parts.path in ("/login", "/logout"):
        return default
    return value


# --------------------------------------------------------------------------- dependencias FastAPI


class LoginRequired(Exception):  # noqa: N818 - es un flujo de control, no un error
    """Página protegida sin sesión válida: la app redirige a /login?next=..."""

    def __init__(self, next_path: str) -> None:
        super().__init__("login requerido")
        self.next_path = next_path


def _sessions(request: Request) -> SessionManager | None:
    ctx = getattr(request.app.state, "centinela", None)
    return getattr(ctx, "sessions", None)


def session_from_request(request: Request) -> Session | None:
    sessions = _sessions(request)
    if sessions is None:
        return None
    return sessions.load(request.cookies.get(SESSION_COOKIE))


async def require_session(request: Request) -> Session:
    """Para páginas HTML: sin sesión => redirección a /login (conservando a dónde iba)."""
    session = session_from_request(request)
    if session is None:
        if request.method in ("GET", "HEAD"):
            target = request.url.path + (f"?{request.url.query}" if request.url.query else "")
        else:  # un POST no se puede repetir con un redirect: volver a la página "padre"
            target = request.url.path.rsplit("/", 1)[0] or "/"
        raise LoginRequired(safe_next(target))
    request.state.session = session
    return session


async def require_api_session(request: Request) -> Session:
    """Para la API JSON: sin sesión => 401."""
    session = session_from_request(request)
    if session is None:
        raise HTTPException(status_code=401, detail="No autenticado: iniciá sesión en el dashboard.")
    request.state.session = session
    return session


async def require_api_csrf(request: Request, session: Session = Depends(require_api_session)) -> Session:  # noqa: B008
    """POST de la API: además de la sesión, exige el header X-CSRF-Token de esa sesión."""
    if not session.check_csrf(request.headers.get(CSRF_HEADER)):
        raise HTTPException(status_code=403, detail="Token CSRF inválido o ausente (header X-CSRF-Token).")
    return session


# --------------------------------------------------------------------------- cookies


def set_session_cookie(response: Response, value: str, *, secure: bool, max_age: int) -> None:
    response.set_cookie(
        SESSION_COOKIE, value, max_age=max_age, path="/", secure=secure, httponly=True, samesite="strict"
    )


def clear_session_cookie(response: Response, *, secure: bool) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/", secure=secure, httponly=True, samesite="strict")


def set_login_cookie(response: Response, value: str, *, secure: bool) -> None:
    response.set_cookie(
        LOGIN_COOKIE,
        value,
        max_age=LOGIN_TOKEN_MAX_AGE_S,
        path="/login",
        secure=secure,
        httponly=True,
        samesite="strict",
    )


def clear_login_cookie(response: Response, *, secure: bool) -> None:
    response.delete_cookie(LOGIN_COOKIE, path="/login", secure=secure, httponly=True, samesite="strict")


async def pad_response_time(started: float, minimum_s: float) -> None:
    """Completa hasta `minimum_s` segundos desde `started` (time.perf_counter): respuestas de login de
    duración constante, sea éxito, fallo o límite de intentos."""
    remaining = minimum_s - (time.perf_counter() - started)
    if remaining > 0:
        await asyncio.sleep(remaining)


__all__ = [
    "CLI_HINT",
    "CSRF_FIELD",
    "CSRF_HEADER",
    "LOGIN_COOKIE",
    "SESSION_COOKIE",
    "DashboardConfigError",
    "LoginRateLimiter",
    "LoginRequired",
    "PasswordVerifier",
    "ProxyTrust",
    "Session",
    "SessionManager",
    "clear_login_cookie",
    "clear_session_cookie",
    "is_argon2_hash",
    "pad_response_time",
    "require_api_csrf",
    "require_api_session",
    "require_session",
    "safe_next",
    "session_from_request",
    "session_max_age_s",
    "set_login_cookie",
    "set_session_cookie",
    "validate_dashboard_config",
]
