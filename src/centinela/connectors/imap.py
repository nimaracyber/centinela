"""Conector IMAP genérico (Yahoo, iCloud, Zoho, cPanel/Plesk, Dovecot propio, Outlook.com, Gmail por IMAP...).

Diseño:

- Una tarea asyncio por carpeta, cada una con su propia conexión `IMAPClient` (librería sincrónica). Todas
  las llamadas de una conexión corren en un executor de UN thread propio de esa carpeta: equivale a
  `asyncio.to_thread`, pero las esperas largas de IDLE no ocupan el pool por defecto (que usa el
  pipeline para parsear) y la conexión siempre se usa desde el mismo thread.
- Pasivo: la carpeta se abre en modo SOLO LECTURA (EXAMINE) y el mail se baja con `BODY.PEEK[]`, que no
  marca el mensaje como leído. Para etiquetar (`apply_verdict`) se abre otra conexión corta, en modo
  lectura-escritura, que solo agrega un keyword IMAP o un label de Gmail. Nunca borra ni mueve nada.
  `apply_verdict` devuelve la descripción de lo hecho, None si no corresponde (carpeta renumerada, mail
  borrado, servidor sin keywords) y LANZA ante fallas reales (red, login, STORE rechazado): el
  dispatcher las registra como error de etiquetado.
- Tamaño: si `RFC822.SIZE` supera `limits.max_message_bytes` NO se omite (sería una evasión trivial): se
  baja solo `BODY.PEEK[HEADER]` y se emite truncado (`truncated=True`, `original_size`). El cuerpo se baja
  con un rango parcial (`<0.límite+1>`), así un servidor que miente el tamaño tampoco agota la memoria.
- Cursor por carpeta en el state store: `<carpeta>:uidvalidity` y `<carpeta>:last_uid`. Se guarda
  DESPUÉS de que `emit` retorna (al-menos-una-vez). La primera vez arranca en UIDNEXT-1 (no analiza el
  histórico) salvo `backfill_hours`. Si cambia UIDVALIDITY, el cursor se reinicia en UIDNEXT-1.
- Tiempo real con IMAP IDLE (renovado cada 10 min, por debajo de los 29 de RFC 2177); si el servidor no lo
  soporta, polling con NOOP cada `poll_interval_s`.
- Reconexión infinita con backoff exponencial (1 s .. 300 s) ante cualquier error. Nunca tira abajo el
  proceso. Gauge `centinela_connector_up` = 1 solo si todas las carpetas están conectadas.
- TLS siempre con verificación de certificado (`ssl.create_default_context`). Con `security: starttls`,
  si el servidor no ofrece STARTTLS no se envían credenciales.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import logging
import socket
import ssl
import time
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, ClassVar, TypeVar

from imapclient import IMAPClient, SocketTimeout
from imapclient.exceptions import CapabilityError, IMAPClientAbortError, IMAPClientError, LoginError

from centinela.connectors._backoff import Backoff, sleep_or_stop
from centinela.connectors._headers import header_cap, header_section, oversize_raw
from centinela.connectors.base import Connector
from centinela.connectors.oauth_imap import ImapOAuthError, ImapOAuthReauthRequired, ImapTokenProvider
from centinela.core.models import MessageRef, RawMessage, VerdictLevel
from centinela.metrics import CONNECTOR_UP

if TYPE_CHECKING:
    from centinela.connectors.base import EmitFn
    from centinela.core.config import ImapConnectorConfig, Settings, TagConfig
    from centinela.core.models import AnalysisResult
    from centinela.core.state import StateStore

log = logging.getLogger(__name__)

# imaplib (vía imapclient) loguea TODO el protocolo en DEBUG, incluidos encabezados de mails. Lo bajamos a
# WARNING salvo que alguien lo haya configurado explícitamente.
_imaplib_log = logging.getLogger("imapclient.imaplib")
if _imaplib_log.level == logging.NOTSET:
    _imaplib_log.setLevel(logging.WARNING)

__all__ = [
    "KEYWORD_MALICIOUS",
    "KEYWORD_SUSPICIOUS",
    "ImapConnector",
    "make_remote_id",
    "parse_remote_id",
]

KEYWORD_MALICIOUS = "$Centinela_Malicious"
KEYWORD_SUSPICIOUS = "$Centinela_Suspicious"

T = TypeVar("T")


class ImapSecurityError(RuntimeError):
    """El servidor no permite una conexión segura; no se envían credenciales."""


class ImapProtocolError(RuntimeError):
    """Respuesta del servidor que no se puede usar (falta UIDVALIDITY, FETCH sin cuerpo, BYE...)."""


# --------------------------------------------------------------------------- helpers puros


def make_remote_id(folder: str, uidvalidity: int, uid: int) -> str:
    return f"{folder}:{uidvalidity}:{uid}"


def parse_remote_id(remote_id: str) -> tuple[str, int, int]:
    """Inversa de `make_remote_id`. La carpeta puede contener ':' (se parte desde la derecha)."""
    folder, validity, uid = remote_id.rsplit(":", 2)
    if not folder:
        raise ValueError("carpeta vacía")
    v, u = int(validity), int(uid)
    if v < 0 or u <= 0:
        raise ValueError("uid/uidvalidity fuera de rango")
    return folder, v, u


def _int(value: object) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)  # type: ignore[call-overload]
    except (TypeError, ValueError):
        return None


def _now() -> datetime:
    return datetime.now(UTC)


def _to_utc(value: object) -> datetime:
    if isinstance(value, datetime):
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    return _now()


def _describe(exc: BaseException, limit: int = 300) -> str:
    """Descripción corta de una excepción para logs/health (sin saltos de línea)."""
    text = " ".join(str(exc).split())
    return f"{type(exc).__name__}: {text}"[:limit] if text else type(exc).__name__


def _chunks(seq: Sequence[T], size: int) -> Iterable[Sequence[T]]:
    for i in range(0, len(seq), size):
        yield seq[i : i + size]


def _response_kind(resp: object) -> bytes | None:
    """Tipo de una respuesta IDLE/NOOP ya parseada por imapclient: (n, b'EXISTS'), (b'BYE', b'...')..."""
    if not isinstance(resp, tuple) or not resp:
        return None
    for item in resp[:2]:
        if isinstance(item, bytes) and item.isalpha():
            return item.upper()
    return None


def _has_new_mail(responses: Iterable[object]) -> bool:
    return any(_response_kind(r) in (b"EXISTS", b"RECENT") for r in responses or ())


def _has_bye(responses: Iterable[object]) -> bool:
    return any(_response_kind(r) == b"BYE" for r in responses or ())


def _body_from(fetch_item: dict) -> bytes | None:
    for key, value in fetch_item.items():
        if isinstance(key, bytes) and key.upper().startswith(b"BODY["):
            if value is None:
                return None
            if isinstance(value, str):
                return value.encode("utf-8", "surrogateescape")
            return bytes(value)
    return None


def _allows_keyword(permanentflags: object, keyword: str) -> bool:
    """PERMANENTFLAGS con `\\*` permite keywords nuevas; si ya lista la keyword, también se puede usar."""
    if permanentflags is None:
        return True  # RFC 3501: sin PERMANENTFLAGS se asume que todos los flags son permanentes
    flags = {
        f.decode("utf-8", "replace").lower() if isinstance(f, bytes) else str(f).lower()
        for f in permanentflags
    }
    return "\\*" in flags or keyword.lower() in flags


def _enable_keepalive(client: Any) -> None:
    """TCP keepalive (best-effort) para detectar conexiones muertas detrás de NAT durante IDLE."""
    try:
        sock = client.socket()
        if sock is None:
            return
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if hasattr(socket, "TCP_KEEPIDLE"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 30)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 4)
        elif hasattr(socket, "SIO_KEEPALIVE_VALS"):
            sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 60_000, 30_000))
    except (OSError, AttributeError, TypeError, ValueError):
        log.debug("no se pudo activar TCP keepalive", exc_info=True)


def _drain_pending_exists(client: Any) -> bool:
    """Saca de imaplib los avisos EXISTS/RECENT acumulados fuera de IDLE. True si había alguno.

    Usa un atributo interno de imapclient (`_imap.untagged_responses`); si cambia, degrada a "no hay".
    """
    try:
        pending = client._imap.untagged_responses
    except AttributeError:
        return False
    if not isinstance(pending, dict):
        return False
    found = False
    for key in ("EXISTS", "RECENT", b"EXISTS", b"RECENT"):
        if pending.pop(key, None):
            found = True
    return found


def _close_client_sync(client: Any, in_idle: bool) -> None:
    if client is None:
        return
    if in_idle:
        with contextlib.suppress(Exception):
            client.idle_done()
    try:
        client.logout()
    except Exception:  # noqa: BLE001 - la conexión puede estar muerta: cerrar el socket alcanza
        with contextlib.suppress(Exception):
            client.shutdown()


# --------------------------------------------------------------------------- estado por carpeta


@dataclass
class _FolderStatus:
    folder: str
    connected: bool = False
    mode: str | None = None  # "idle" | "poll"
    last_connect: datetime | None = None
    last_error: str | None = None
    last_error_at: datetime | None = None
    uidvalidity: int | None = None
    last_uid: int | None = None
    emitted: int = 0
    skipped: int = 0  # mensajes "veneno" que fallaron siempre al bajarse
    truncated: int = 0  # superaban max_message_bytes: se analizaron solo los headers

    def as_dict(self) -> dict[str, Any]:
        return {
            "connected": self.connected,
            "mode": self.mode,
            "last_connect": self.last_connect.isoformat() if self.last_connect else None,
            "last_error": self.last_error,
            "last_error_at": self.last_error_at.isoformat() if self.last_error_at else None,
            "uidvalidity": self.uidvalidity,
            "last_uid": self.last_uid,
            "messages_emitted": self.emitted,
            "messages_skipped": self.skipped,
            "truncated_too_large": self.truncated,
        }


class _Session:
    """Una conexión IMAP + el executor de un thread donde corren todas sus llamadas."""

    def __init__(self, label: str) -> None:
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix=label)
        self.client: Any = None
        self.in_idle = False

    async def call(self, fn: Callable[..., T], /, *args: Any, **kwargs: Any) -> T:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self.executor, functools.partial(fn, *args, **kwargs))


# --------------------------------------------------------------------------- conector


class ImapConnector(Connector):
    type: ClassVar[str] = "imap"

    # Tiempos/límites (atributos de clase para poder ajustarlos en tests)
    IDLE_RENEW_S: ClassVar[float] = 10 * 60  # RFC 2177: re-emitir IDLE antes de 29 min
    IDLE_CHECK_S: ClassVar[float] = 1.0  # cada cuánto se revisa `stop` mientras se espera en IDLE
    BACKOFF_BASE_S: ClassVar[float] = 1.0
    BACKOFF_CAP_S: ClassVar[float] = 300.0
    AUTH_RETRY_MIN_S: ClassVar[float] = 60.0  # espera mínima tras un login rechazado
    CONNECT_TIMEOUT_S: ClassVar[float] = 30.0
    READ_TIMEOUT_S: ClassVar[float] = 120.0
    CLOSE_TIMEOUT_S: ClassVar[float] = 5.0
    # por intento; 2 intentos + la pausa entran en el timeout de etiquetado del dispatcher (60 s)
    VERDICT_TIMEOUT_S: ClassVar[float] = 25.0
    VERDICT_RETRY_DELAY_S: ClassVar[float] = 2.0
    FETCH_BATCH: ClassVar[int] = 50  # UIDs por FETCH RFC822.SIZE
    MAX_UID_ATTEMPTS: ClassVar[int] = 5  # un mensaje que falla siempre al bajarse se omite tras N intentos
    MAX_BACKFILL_MESSAGES: ClassVar[int] = 5000

    config: ImapConnectorConfig

    def __init__(self, config: ImapConnectorConfig, settings: Settings, state: StateStore) -> None:
        super().__init__(config, settings, state)
        folders: list[str] = []
        for f in config.folders:
            if f and f not in folders:
                folders.append(f)
        self.folders = folders
        self._status: dict[str, _FolderStatus] = {f: _FolderStatus(f) for f in folders}
        self._tokens: ImapTokenProvider | None = None
        # una sola conexión extra para etiquetar: los servers limitan conexiones simultáneas por cuenta
        self._verdict_sem = asyncio.Semaphore(1)
        self._uid_failures: dict[tuple[str, int, int], int] = {}
        self._last_tag: str | None = None
        self._last_tag_error: str | None = None
        self._last_tag_error_at: datetime | None = None

    # ------------------------------------------------------------------ autenticación / conexión

    def _token_provider(self) -> ImapTokenProvider | None:
        if self.config.oauth2 is None:
            return None
        if self._tokens is None:
            self._tokens = ImapTokenProvider(self.config, self.state)
        return self._tokens

    async def _access_token(self) -> str | None:
        tp = self._token_provider()
        return await tp.get() if tp else None

    def _open_client_sync(self, access_token: str | None) -> Any:
        """Conecta, negocia TLS (verificando certificado) y hace login. Corre en un thread."""
        cfg = self.config
        ctx = ssl.create_default_context()
        timeout = SocketTimeout(connect=self.CONNECT_TIMEOUT_S, read=self.READ_TIMEOUT_S)
        use_ssl = cfg.security == "ssl"
        client = IMAPClient(
            cfg.host,
            port=cfg.port,
            use_uid=True,
            ssl=use_ssl,
            ssl_context=ctx if use_ssl else None,
            timeout=timeout,
        )
        try:
            if not use_ssl:
                try:
                    client.starttls(ctx)
                except CapabilityError as exc:
                    raise ImapSecurityError(
                        f"el servidor {cfg.host}:{cfg.port} no ofrece STARTTLS; no se envían credenciales sin cifrar"
                    ) from exc
            client.normalise_times = False  # INTERNALDATE con zona horaria
            _enable_keepalive(client)
            try:
                if access_token:
                    client.oauth2_login(cfg.username, access_token)
                elif cfg.password is not None:
                    client.login(cfg.username, cfg.password.get_secret_value())
                else:  # el validador de config lo impide, pero por las dudas
                    raise ImapOAuthError("conector IMAP sin password ni oauth2")
            except UnicodeError:
                # imaplib codifica en ASCII y el mensaje de UnicodeEncodeError incluye un carácter del secreto
                raise LoginError(
                    "el usuario o la contraseña tienen caracteres no ASCII que IMAP LOGIN no admite"
                ) from None
        except BaseException:
            _close_client_sync(client, False)
            raise
        return client

    async def _connect(self, session: _Session) -> None:
        token = await self._access_token()
        try:
            session.client = await session.call(self._open_client_sync, token)
        except LoginError:
            if self._tokens is not None:
                self._tokens.invalidate()  # el access token pudo haber sido revocado: renovar en el próximo intento
            raise

    async def _close_session(self, session: _Session) -> None:
        client, in_idle = session.client, session.in_idle
        session.client, session.in_idle = None, False
        try:
            if client is not None:
                try:
                    await asyncio.wait_for(
                        session.call(_close_client_sync, client, in_idle), timeout=self.CLOSE_TIMEOUT_S
                    )
                except Exception:  # noqa: BLE001 - incluye TimeoutError
                    # el thread sigue bloqueado (ej: lectura lenta): cortar el socket desde afuera
                    with contextlib.suppress(Exception):
                        await asyncio.to_thread(client.shutdown)
        finally:
            session.executor.shutdown(wait=False, cancel_futures=True)

    # ------------------------------------------------------------------ estado / métricas

    def _update_gauge(self) -> None:
        up = bool(self._status) and all(s.connected for s in self._status.values())
        CONNECTOR_UP.labels(connector=self.name).set(1 if up else 0)

    def _set_connected(self, folder: str, connected: bool, mode: str | None = None) -> None:
        st = self._status[folder]
        st.connected = connected
        if connected:
            st.last_connect = _now()
            st.mode = mode
        self._update_gauge()

    def _record_error(self, folder: str, exc: BaseException) -> str:
        st = self._status[folder]
        if isinstance(exc, LoginError):
            hint = (
                "el servidor rechazó el token OAuth"
                if self.config.oauth2
                else "usuario o contraseña incorrectos (Gmail, Yahoo e iCloud exigen una contraseña de aplicación)"
            )
            msg = f"login rechazado: {hint}. {_describe(exc, 200)}"
        elif isinstance(exc, ImapOAuthError):
            msg = str(exc)[:400]
        elif isinstance(exc, ssl.SSLCertVerificationError):
            msg = f"certificado TLS inválido para {self.config.host}: {_describe(exc, 200)}"
        else:
            msg = _describe(exc)
        st.last_error = msg
        st.last_error_at = _now()
        return msg

    # ------------------------------------------------------------------ run

    async def run(self, emit: EmitFn, stop: asyncio.Event) -> None:
        if not self.folders:
            log.error("imap[%s]: no hay carpetas configuradas; el conector no hace nada", self.name)
            await stop.wait()
            return
        self._update_gauge()
        tasks = [
            asyncio.create_task(self._run_folder(folder, emit, stop), name=f"imap:{self.name}:{folder}")
            for folder in self.folders
        ]
        try:
            await asyncio.gather(*tasks)
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            for st in self._status.values():
                st.connected = False
            CONNECTOR_UP.labels(connector=self.name).set(0)

    async def _run_folder(self, folder: str, emit: EmitFn, stop: asyncio.Event) -> None:
        backoff = Backoff(self.BACKOFF_BASE_S, self.BACKOFF_CAP_S)
        label = f"imap-{self.name}-{self.folders.index(folder)}"
        while not stop.is_set():
            delay: float | None = None
            session = _Session(label)
            try:
                await self._session_cycle(session, folder, emit, stop, backoff)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - reconectar siempre, nunca tirar el proceso
                msg = self._record_error(folder, exc)
                delay = backoff.next()
                if isinstance(exc, LoginError | ImapOAuthReauthRequired):
                    # credenciales rechazadas: no martillar el servidor (fail2ban / bloqueo de cuenta)
                    delay = max(delay, self.AUTH_RETRY_MIN_S)
                level = (
                    logging.ERROR
                    if isinstance(exc, LoginError | ImapOAuthError | ImapSecurityError)
                    else logging.WARNING
                )
                log.log(
                    level,
                    "imap[%s/%s]: %s; reintento en %.0f s",
                    self.name,
                    folder,
                    msg,
                    delay,
                    exc_info=not isinstance(
                        exc,
                        OSError | IMAPClientError | ImapOAuthError | ImapSecurityError | ImapProtocolError,
                    ),
                )
            finally:
                await self._close_session(session)
                self._set_connected(folder, False)
            if delay is not None and await sleep_or_stop(stop, delay):
                break

    async def _session_cycle(
        self, session: _Session, folder: str, emit: EmitFn, stop: asyncio.Event, backoff: Backoff
    ) -> None:
        await self._connect(session)
        client = session.client
        info = await session.call(client.select_folder, folder, readonly=True)
        uidvalidity = _int(info.get(b"UIDVALIDITY"))
        if uidvalidity is None:
            raise ImapProtocolError(f"el servidor no informó UIDVALIDITY para la carpeta {folder!r}")
        use_idle = bool(self.config.idle) and bool(await session.call(client.has_capability, "IDLE"))
        mode = "idle" if use_idle else "poll"
        self._set_connected(folder, True, mode)
        log.info("imap[%s/%s]: conectado a %s (%s)", self.name, folder, self.config.host, mode)

        await self._sync_cursor(session, folder, info, uidvalidity)
        await self._fetch_new(session, folder, uidvalidity, emit, stop)
        backoff.reset()  # recién acá: un mensaje "veneno" que rompe cada sesión no debe reconectar en loop

        if use_idle:
            await self._idle_loop(session, folder, uidvalidity, emit, stop)
        else:
            await self._poll_loop(session, folder, uidvalidity, emit, stop)

    async def _idle_loop(
        self, session: _Session, folder: str, uidvalidity: int, emit: EmitFn, stop: asyncio.Event
    ) -> None:
        client = session.client
        while not stop.is_set():
            # Si llegó un "* n EXISTS" mientras corría el SEARCH/FETCH anterior, imaplib lo guardó aparte y
            # IDLE no lo volvería a avisar: revisar antes de entrar en IDLE (acotado, para no girar en loop).
            for _ in range(3):
                if stop.is_set() or not await session.call(_drain_pending_exists, client):
                    break
                await self._fetch_new(session, folder, uidvalidity, emit, stop)
            if stop.is_set():
                return
            await session.call(client.idle)
            session.in_idle = True
            started = time.monotonic()
            reason = "stop"
            while not stop.is_set():
                responses = await session.call(client.idle_check, timeout=self.IDLE_CHECK_S)
                if _has_bye(responses):
                    raise ImapProtocolError("el servidor cerró la conexión (BYE)")
                if _has_new_mail(responses):
                    reason = "new"
                    break
                if time.monotonic() - started >= self.IDLE_RENEW_S:
                    reason = "renew"
                    break
            await session.call(client.idle_done)
            session.in_idle = False
            if reason == "stop" or stop.is_set():
                return
            # tras un aviso de mail nuevo y también en cada renovación (por si se perdió un aviso)
            await self._fetch_new(session, folder, uidvalidity, emit, stop)

    async def _poll_loop(
        self, session: _Session, folder: str, uidvalidity: int, emit: EmitFn, stop: asyncio.Event
    ) -> None:
        client = session.client
        interval = max(1.0, float(self.config.poll_interval_s))
        while not stop.is_set():
            if await sleep_or_stop(stop, interval):
                return
            resp = await session.call(client.noop)
            untagged = resp[1] if isinstance(resp, tuple) and len(resp) > 1 else ()
            if _has_bye(untagged):
                raise ImapProtocolError("el servidor cerró la conexión (BYE)")
            await self._fetch_new(session, folder, uidvalidity, emit, stop)

    # ------------------------------------------------------------------ cursor

    @staticmethod
    def _keys(folder: str) -> tuple[str, str]:
        return f"{folder}:uidvalidity", f"{folder}:last_uid"

    async def _sync_cursor(self, session: _Session, folder: str, info: dict, uidvalidity: int) -> int:
        st = self._status[folder]
        k_validity, k_last = self._keys(folder)
        stored_validity = _int(await self.get_cursor(k_validity))
        stored_last = _int(await self.get_cursor(k_last))
        uidnext_select = _int(info.get(b"UIDNEXT"))

        if (
            stored_validity == uidvalidity
            and stored_last is not None
            and stored_last >= 0
            and (uidnext_select is None or stored_last < uidnext_select)
        ):
            last = stored_last
        else:
            uidnext = await self._uidnext(session, folder, uidnext_select)
            if stored_validity is None:
                if self.config.backfill_hours > 0:
                    last = await self._backfill_start(session, folder, uidnext)
                    log.info(
                        "imap[%s/%s]: primer arranque con backfill de %s h: se analiza desde UID %s",
                        self.name,
                        folder,
                        self.config.backfill_hours,
                        last + 1,
                    )
                else:
                    last = uidnext - 1
                    log.info(
                        "imap[%s/%s]: primer arranque: se analizan solo los mails que lleguen desde ahora",
                        self.name,
                        folder,
                    )
            elif stored_validity != uidvalidity:
                last = uidnext - 1
                log.warning(
                    "imap[%s/%s]: cambió UIDVALIDITY (%s -> %s): el servidor renumeró la carpeta; "
                    "se reinicia el cursor y se analizan solo los mails nuevos",
                    self.name,
                    folder,
                    stored_validity,
                    uidvalidity,
                )
            else:
                last = uidnext - 1
                log.warning(
                    "imap[%s/%s]: cursor guardado inválido (last_uid=%s, UIDNEXT=%s); se reinicia",
                    self.name,
                    folder,
                    stored_last,
                    uidnext,
                )
            last = max(0, last)
            await self.set_cursor(k_last, str(last))
            await self.set_cursor(k_validity, str(uidvalidity))
        st.uidvalidity = uidvalidity
        st.last_uid = last
        return last

    async def _uidnext(self, session: _Session, folder: str, from_select: int | None) -> int:
        if from_select:
            return from_select
        client = session.client
        try:
            status = await session.call(client.folder_status, folder, ["UIDNEXT"])
            value = _int((status or {}).get(b"UIDNEXT"))
            if value:
                return value
        except IMAPClientAbortError:
            raise
        except IMAPClientError:
            log.debug("STATUS UIDNEXT no disponible", exc_info=True)
        try:
            uids = await session.call(client.search, ["UID", "*"])
        except IMAPClientAbortError:
            raise
        except IMAPClientError:
            uids = []
        return (max(uids) + 1) if uids else 1

    async def _backfill_start(self, session: _Session, folder: str, uidnext: int) -> int:
        """Cursor inicial para analizar los mails de las últimas `backfill_hours` horas."""
        client = session.client
        cutoff = _now() - timedelta(hours=self.config.backfill_hours)
        # SINCE trabaja por fecha (sin hora) y en la zona del servidor: pedir un día de más y filtrar exacto
        since = (cutoff - timedelta(days=1)).date()
        uids = sorted({u for u in await session.call(client.search, ["SINCE", since]) if isinstance(u, int)})
        if len(uids) > self.MAX_BACKFILL_MESSAGES:
            log.warning(
                "imap[%s/%s]: backfill limitado a los últimos %s mensajes",
                self.name,
                folder,
                self.MAX_BACKFILL_MESSAGES,
            )
            uids = uids[-self.MAX_BACKFILL_MESSAGES :]
        kept: list[int] = []
        for chunk in _chunks(uids, 500):
            dates = await session.call(client.fetch, list(chunk), ["INTERNALDATE"])
            for uid in chunk:
                item = dates.get(uid)
                if item is None:
                    continue
                when = item.get(b"INTERNALDATE")
                if not isinstance(when, datetime) or _to_utc(when) >= cutoff:
                    kept.append(uid)
        return (min(kept) - 1) if kept else uidnext - 1

    async def _advance(self, folder: str, uidvalidity: int, uid: int) -> None:
        await self.set_cursor(self._keys(folder)[1], str(uid))
        self._status[folder].last_uid = uid
        self._uid_failures.pop((folder, uidvalidity, uid), None)

    # ------------------------------------------------------------------ descarga

    async def _fetch_new(
        self, session: _Session, folder: str, uidvalidity: int, emit: EmitFn, stop: asyncio.Event
    ) -> None:
        client = session.client
        last = self._status[folder].last_uid or 0
        await session.call(_drain_pending_exists, client)  # este SEARCH ya cubre los avisos previos
        # "N:*" incluye siempre el último mensaje aunque su UID sea < N (RFC 3501): filtrar
        found = await session.call(client.search, ["UID", f"{last + 1}:*"])
        new = sorted({u for u in found if isinstance(u, int) and u > last})
        for chunk in _chunks(new, self.FETCH_BATCH):
            if stop.is_set():
                return
            sizes = await session.call(client.fetch, list(chunk), ["RFC822.SIZE"])
            for uid in chunk:
                if stop.is_set():
                    return
                await self._process_uid(session, folder, uidvalidity, uid, sizes.get(uid), emit)

    async def _process_uid(
        self, session: _Session, folder: str, uidvalidity: int, uid: int, size_item: dict | None, emit: EmitFn
    ) -> None:
        st = self._status[folder]
        limit = int(self.settings.limits.max_message_bytes)
        if size_item is None:
            log.debug("imap[%s/%s]: UID %s ya no existe (expunged); se saltea", self.name, folder, uid)
            await self._advance(folder, uidvalidity, uid)
            return
        size = _int(size_item.get(b"RFC822.SIZE"))
        oversize = size is not None and size > limit
        hcap = header_cap(limit)
        # BODY.PEEK no marca \Seen; el rango parcial acota la memoria aunque el server mienta el tamaño.
        # Un mail demasiado grande NO se omite (evasión trivial): se bajan solo sus headers.
        section = f"BODY.PEEK[HEADER]<0.{hcap}>" if oversize else f"BODY.PEEK[]<0.{limit + 1}>"

        key = (folder, uidvalidity, uid)
        try:
            resp = await session.call(session.client.fetch, [uid], [section, "INTERNALDATE"])
            item = resp.get(uid)
            body = _body_from(item) if item is not None else None
            if item is not None and body is None:
                raise ImapProtocolError(f"el servidor no devolvió el contenido del UID {uid}")
        except Exception as exc:
            attempts = self._uid_failures.get(key, 0) + 1
            self._uid_failures[key] = attempts
            if attempts >= self.MAX_UID_ATTEMPTS:
                st.skipped += 1
                log.error(
                    "imap[%s/%s]: no se pudo descargar el UID %s tras %s intentos (%s); se omite",
                    self.name,
                    folder,
                    uid,
                    attempts,
                    _describe(exc),
                )
                await self._advance(folder, uidvalidity, uid)
                return
            raise
        if item is None:
            log.debug("imap[%s/%s]: UID %s desapareció antes de bajarlo", self.name, folder, uid)
            await self._advance(folder, uidvalidity, uid)
            return
        assert body is not None
        ref = MessageRef(
            connector=self.name,
            mailbox=self.config.username,
            remote_id=make_remote_id(folder, uidvalidity, uid),
            folder=folder,
        )
        received_at = _to_utc(item.get(b"INTERNALDATE"))
        if oversize or len(body) > limit:
            # mentiroso (RFC822.SIZE chico, cuerpo enorme): ya tenemos los primeros límite+1 bytes
            real = size if oversize else max(size or 0, len(body))
            raw = oversize_raw(
                ref, header_section(body, hcap), original_size=real, limit=limit, received_at=received_at
            )
            log.warning(
                "imap[%s/%s]: el mensaje UID %s pesa %s bytes y supera el límite de %s; "
                "se analizan solo los encabezados",
                self.name,
                folder,
                uid,
                real if oversize else f"más de {limit}",
                limit,
            )
        else:
            raw = RawMessage(ref=ref, raw=body, received_at=received_at)
        await emit(raw)  # si falla, NO se avanza el cursor: se reintenta (al-menos-una-vez)
        await self._advance(folder, uidvalidity, uid)
        st.emitted += 1
        if raw.truncated:
            st.truncated += 1

    # ------------------------------------------------------------------ etiquetado

    async def apply_verdict(self, ref: MessageRef, result: AnalysisResult, tag: TagConfig) -> str | None:
        """Agrega el keyword/label. Devuelve lo hecho, None si no corresponde, y LANZA ante fallas reales.

        Fallas transitorias (red, timeout, conexión cortada) se reintentan una vez; un login rechazado se
        reintenta solo con OAuth (token renovado). La última excepción se propaga: el dispatcher la
        cuenta como error de etiquetado. El detalle queda también en `healthcheck()["last_tag_error"]`.
        """
        if not (self.config.tag and tag.enabled and self.config.tag_mode == "keyword"):
            return None
        level = result.verdict.level
        if level not in (VerdictLevel.SUSPICIOUS, VerdictLevel.MALICIOUS):
            return None
        if level.rank < VerdictLevel(tag.min_level).rank:
            return None
        if ref.connector != self.name:
            return None
        try:
            folder_from_id, uidvalidity, uid = parse_remote_id(ref.remote_id)
        except ValueError:
            log.warning("imap[%s]: remote_id inválido %r; no se etiqueta", self.name, ref.remote_id[:200])
            return None
        folder = ref.folder or folder_from_id
        malicious = level == VerdictLevel.MALICIOUS
        keyword = KEYWORD_MALICIOUS if malicious else KEYWORD_SUSPICIOUS
        label = tag.label_malicious if malicious else tag.label_suspicious

        async with self._verdict_sem:
            attempt = 0
            while True:
                attempt += 1
                try:
                    token = await self._access_token()
                    done = await asyncio.wait_for(
                        asyncio.to_thread(self._tag_sync, token, folder, uidvalidity, uid, keyword, label),
                        timeout=self.VERDICT_TIMEOUT_S,
                    )
                except LoginError as exc:
                    if self._tokens is not None:
                        self._tokens.invalidate()
                    self._tag_failed(ref, exc)
                    if attempt >= 2 or self._tokens is None:
                        raise  # password rechazado: reintentar no sirve (y puede bloquear la cuenta)
                except (OSError, IMAPClientAbortError, TimeoutError) as exc:
                    self._tag_failed(ref, exc)
                    if attempt >= 2:
                        raise
                    await asyncio.sleep(self.VERDICT_RETRY_DELAY_S)
                except Exception as exc:
                    self._tag_failed(ref, exc)  # STORE rechazado, OAuth sin autorizar...: no se reintenta
                    raise
                else:
                    if done:
                        self._last_tag = done
                    return done

    def _tag_failed(self, ref: MessageRef, exc: BaseException) -> None:
        self._last_tag_error = _describe(exc)
        self._last_tag_error_at = _now()
        log.warning(
            "imap[%s]: no se pudo etiquetar %s: %s", self.name, ref.remote_id[:200], self._last_tag_error
        )

    def _tag_sync(
        self, access_token: str | None, folder: str, uidvalidity: int, uid: int, keyword: str, label: str
    ) -> str | None:
        client = self._open_client_sync(access_token)
        try:
            info = client.select_folder(folder, readonly=False)
            current = _int(info.get(b"UIDVALIDITY"))
            if current != uidvalidity:
                log.warning(
                    "imap[%s/%s]: UIDVALIDITY cambió (%s -> %s); el mensaje ya no se puede ubicar, no se etiqueta",
                    self.name,
                    folder,
                    uidvalidity,
                    current,
                )
                return None
            if uid not in set(client.search(["UID", str(uid)])):
                log.info(
                    "imap[%s/%s]: el UID %s ya no está en la carpeta; no se etiqueta", self.name, folder, uid
                )
                return None
            if client.has_capability("X-GM-EXT-1"):
                try:
                    client.add_gmail_labels([uid], [label], silent=True)
                except IMAPClientAbortError:
                    raise
                except IMAPClientError:
                    # el label puede no existir todavía: crearlo (en Gmail los labels son carpetas) y reintentar
                    with contextlib.suppress(IMAPClientError):
                        client.create_folder(label)
                    client.add_gmail_labels([uid], [label], silent=True)
                return f"imap:gmlabel:{label}"
            if _allows_keyword(info.get(b"PERMANENTFLAGS"), keyword):
                client.add_flags([uid], [keyword], silent=True)
                return f"imap:keyword:{keyword}"
            log.info(
                "imap[%s/%s]: el servidor no admite keywords personalizadas (PERMANENTFLAGS sin \\*); "
                "solo se envían alertas",
                self.name,
                folder,
            )
            return None
        finally:
            _close_client_sync(client, False)

    # ------------------------------------------------------------------ salud / diagnóstico

    async def healthcheck(self) -> dict[str, Any]:
        statuses = list(self._status.values())
        connects = [s.last_connect for s in statuses if s.last_connect]
        errors = sorted(
            (s for s in statuses if s.last_error and s.last_error_at), key=lambda s: s.last_error_at
        )
        return {
            "ok": bool(statuses) and all(s.connected for s in statuses),
            "type": self.type,
            "host": self.config.host,
            "mailbox": self.config.username,
            "auth": "oauth2:" + self.config.oauth2.provider if self.config.oauth2 else "password",
            "last_connect": max(connects).isoformat() if connects else None,
            "last_error": errors[-1].last_error if errors else None,
            "folders": {s.folder: s.as_dict() for s in statuses},
            "last_tag": self._last_tag,
            "last_tag_error": self._last_tag_error,
            "last_tag_error_at": self._last_tag_error_at.isoformat() if self._last_tag_error_at else None,
        }

    async def check_connection(self) -> dict[str, Any]:
        """Prueba de conexión (para `centinela check-config` / después de `centinela auth`). No modifica nada."""
        try:
            token = await self._access_token()
            return await asyncio.wait_for(
                asyncio.to_thread(self._check_sync, token), timeout=self.VERDICT_TIMEOUT_S
            )
        except Exception as exc:  # noqa: BLE001
            msg = (
                str(exc)[:400]
                if isinstance(exc, ImapOAuthError | ImapOAuthReauthRequired)
                else _describe(exc)
            )
            return {"ok": False, "error": msg}

    def _check_sync(self, token: str | None) -> dict[str, Any]:
        client = self._open_client_sync(token)
        try:
            caps = {
                c.decode("ascii", "replace") if isinstance(c, bytes) else str(c)
                for c in client.capabilities()
            }
            folders: dict[str, Any] = {}
            for folder in self.folders:
                try:
                    st = client.folder_status(folder, ["MESSAGES", "UIDNEXT", "UIDVALIDITY"])
                    folders[folder] = {k.decode() if isinstance(k, bytes) else k: v for k, v in st.items()}
                except IMAPClientAbortError:
                    raise
                except IMAPClientError as exc:
                    folders[folder] = {"error": _describe(exc)}
            return {
                "ok": all("error" not in v for v in folders.values()),
                "idle": "IDLE" in caps,
                "gmail_ext": "X-GM-EXT-1" in caps,
                "folders": folders,
            }
        finally:
            _close_client_sync(client, False)

    async def close(self) -> None:
        for st in self._status.values():
            st.connected = False
        CONNECTOR_UP.labels(connector=self.name).set(0)
