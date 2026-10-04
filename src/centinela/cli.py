"""Línea de comandos de Centinela.

    centinela run [--role all|ingest|worker|api]   # servicio
    centinela scan mail.eml [--json] [--offline]   # analizar un .eml suelto (sin base ni cola)
    centinela check-config                         # validar config.yaml
    centinela auth <conector>                      # login OAuth (Gmail personal, Outlook.com IMAP) o diagnóstico (Graph)
    centinela hash-password                        # hash argon2 para el dashboard
    centinela gen-key                              # claves para ENCRYPTION_KEY y DASHBOARD_SECRET_KEY
    centinela test-alert                           # manda una alerta de prueba a todos los canales
    centinela rules check                          # compila las reglas YARA y reporta errores

Códigos de salida: 0 bien; 1 falló algo en tiempo de ejecución (un componente se cayó, una alerta de prueba
no salió, reglas YARA con errores, diagnóstico con problemas); 4 configuración inválida o incompleta.
`scan` usa además 0 limpio, 1 sospechoso, 2 malicioso, 3 error de análisis.

Todo lo que se imprime de un mail (asunto, remitente, nombres de adjuntos) pasa por `_safe`: un nombre de
archivo hostil con secuencias de escape ANSI o caracteres bidi no puede manipular la terminal.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
import secrets
import signal
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any

import typer

from centinela import __version__

if TYPE_CHECKING:
    from centinela.core.config import Settings
    from centinela.core.models import AnalysisResult, RawMessage

app = typer.Typer(
    name="centinela",
    help="Centinela: análisis pasivo de correo para PyMEs (RATs, stealers, phishing).",
    no_args_is_help=True,
    add_completion=False,
)
rules_app = typer.Typer(help="Reglas YARA.", no_args_is_help=True)
app.add_typer(rules_app, name="rules")

ConfigOpt = Annotated[
    Path | None,
    typer.Option("--config", "-c", help="Ruta a config.yaml (default: $CENTINELA_CONFIG o ./config.yaml)"),
]

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_CONFIG = 4
EXIT_BY_LEVEL = {"clean": 0, "suspicious": 1, "malicious": 2, "error": 3}
ROLES = ("all", "ingest", "worker", "api")

HEADER_PEEK_BYTES = 1024 * 1024  # mail demasiado grande: se leen como máximo 1 MB para sacar los headers
SHUTDOWN_WAIT_S = 30.0

# C0/C1 (incluye ESC de las secuencias ANSI), DEL y marcas bidi/invisibles. \t y \n se conservan aparte.
_UNSAFE_RE = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f​-‏‪-‮⁠-⁤⁦-⁩﻿]")


def _safe(value: Any, limit: int = 500) -> str:
    """Texto apto para imprimir en la terminal: caracteres de control/bidi visibles como [U+XXXX]."""
    text = "" if value is None else str(value)
    if len(text) > limit:
        text = text[:limit] + "…"
    return _UNSAFE_RE.sub(lambda m: f"[U+{ord(m.group()):04X}]", text.replace("\n", " ").replace("\t", " "))


def _error(message: str) -> None:
    typer.secho(message, fg=typer.colors.RED, err=True)


def _settings(config: Path | None) -> Settings:
    from centinela.core.config import load_settings

    try:
        return load_settings(config)
    except Exception as exc:  # noqa: BLE001 - mensaje claro para el usuario
        _error(f"Configuración inválida: {exc}")
        raise typer.Exit(EXIT_CONFIG) from exc


def _cli_logging(settings: Settings) -> None:
    """Logs de los comandos sueltos: texto plano, solo avisos y errores, con redacción de secretos."""
    from centinela.logging_setup import setup_logging

    setup_logging(settings, level="WARNING", json_format=False)


def _install_signal_handlers(stop: asyncio.Event) -> None:
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError):  # Windows
            signal.signal(sig, lambda *_: loop.call_soon_threadsafe(stop.set))


@app.command()
def version() -> None:
    """Muestra la versión."""
    typer.echo(f"centinela {__version__}")


# --------------------------------------------------------------------------- run


def _dashboard_problem(settings: Settings) -> str | None:
    """Mensaje (en español, con los comandos a usar) si el dashboard no puede arrancar de forma segura."""
    from centinela.api.auth import DashboardConfigError, validate_dashboard_config

    try:
        validate_dashboard_config(settings.dashboard)
    except DashboardConfigError as exc:
        return str(exc)
    return None


@app.command()
def run(
    config: ConfigOpt = None,
    role: Annotated[str, typer.Option(help="all | ingest | worker | api")] = "all",
    workers: Annotated[
        int, typer.Option(min=1, max=64, help="Mensajes analizados en paralelo por proceso worker")
    ] = 4,
) -> None:
    """Arranca el servicio."""
    if role not in ROLES:
        raise typer.BadParameter("role debe ser all, ingest, worker o api", param_hint="--role")
    settings = _settings(config)
    code = asyncio.run(_run(settings, role, workers))
    if code:
        raise typer.Exit(code)


async def _run(settings: Settings, role: str, workers: int, *, stop: asyncio.Event | None = None) -> int:
    """Corre el rol pedido hasta que llegue SIGINT/SIGTERM (o hasta `stop`, en tests). Devuelve el código
    de salida: 0 apagado normal, 1 si un componente se cayó, 4 si falta configuración del dashboard."""
    from centinela.runtime import Runtime

    serve_api = role in {"all", "api"} and settings.dashboard.enabled
    if serve_api:
        # antes de tocar la base o compilar reglas: sin secretos del dashboard no se arranca
        problem = _dashboard_problem(settings)
        if problem:
            _error(problem)
            return EXIT_CONFIG
    if role == "api" and not serve_api:
        typer.secho("Nada para correr: el dashboard está deshabilitado y role=api.", fg=typer.colors.YELLOW)
        return EXIT_CONFIG

    try:
        runtime = await Runtime.create(settings, role=role)
    except Exception as exc:  # noqa: BLE001 - base inaccesible, esquema más nuevo, Redis caído...
        from centinela.logging_setup import redact

        _error(
            f"No se pudo iniciar Centinela: {_safe(redact(f'{type(exc).__name__}: {exc}', limit=600), 700)}"
        )
        return EXIT_FAILED
    tasks: list[asyncio.Task[Any]] = []
    try:
        api_app = None
        if serve_api:
            from centinela.api.app import DashboardConfigError, create_app

            try:
                api_app = create_app(runtime)  # ANTES de lanzar tareas: si falla, no queda nada a medias
            except DashboardConfigError as exc:
                _error(str(exc))
                return EXIT_CONFIG
        if stop is None:
            stop = asyncio.Event()
            _install_signal_handlers(stop)
        if role == "all":
            tasks.append(asyncio.create_task(runtime.run_all(stop, concurrency=workers), name="runtime"))
        elif role == "ingest":
            tasks.append(asyncio.create_task(runtime.run_ingest(stop), name="ingest"))
        elif role == "worker":
            tasks.append(asyncio.create_task(runtime.run_worker(stop, concurrency=workers), name="worker"))
            tasks.append(asyncio.create_task(runtime.run_retention(stop), name="retention"))
        if api_app is not None:
            tasks.append(asyncio.create_task(_serve_api(api_app, settings, stop), name="api"))
        return await _wait_tasks(stop, tasks)
    finally:
        if stop is not None:
            stop.set()
        if tasks:
            _done, pending = await asyncio.wait(tasks, timeout=SHUTDOWN_WAIT_S)
            for t in pending:
                t.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
        await runtime.close()


async def _wait_tasks(stop: asyncio.Event, tasks: list[asyncio.Task[Any]]) -> int:
    """Espera la señal de parada; si antes se cae (o termina) un componente, apaga todo con código 1."""
    stopper = asyncio.create_task(stop.wait(), name="stop")
    try:
        done, _pending = await asyncio.wait({stopper, *tasks}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        stopper.cancel()
    crashed = [t for t in done if t is not stopper]
    if not crashed or stop.is_set():
        return EXIT_OK
    for t in crashed:
        exc = None if t.cancelled() else t.exception()
        detail = f"{type(exc).__name__}: {_safe(exc, 300)}" if exc else "terminó sin que se lo pidieran"
        _error(f"{t.get_name()} se detuvo: {detail}")
    return EXIT_FAILED


def _uvicorn_server(app_: Any, settings: Settings) -> Any:
    import uvicorn

    class _Server(uvicorn.Server):
        """Las señales las maneja la CLI (evento `stop`): uvicorn no debe capturarlas."""

        @contextlib.contextmanager
        def capture_signals(self):  # type: ignore[override]  # uvicorn >= 0.29
            yield

        def install_signal_handlers(self) -> None:  # uvicorn < 0.29
            return None

    dash = settings.dashboard
    return _Server(
        uvicorn.Config(
            app_,
            host=dash.host,
            port=dash.port,
            log_config=None,  # los logs de uvicorn van al logger raíz (con redacción de secretos)
            proxy_headers=bool(dash.trusted_proxies),
            forwarded_allow_ips=",".join(dash.trusted_proxies) or None,
            server_header=False,
        )
    )


async def _serve_api(app_: Any, settings: Settings, stop: asyncio.Event) -> None:
    server = _uvicorn_server(app_, settings)
    where = f"{settings.dashboard.host}:{settings.dashboard.port}"

    async def _guarded() -> None:
        # uvicorn hace sys.exit() si no puede escuchar (puerto ocupado, permisos...). Un SystemExit que
        # escapa de una tarea atraviesa el event loop entero: se convierte en error acá adentro.
        try:
            await server.serve()
        except SystemExit:
            raise RuntimeError(
                f"no se pudo iniciar el dashboard en {where} (¿el puerto está ocupado?)"
            ) from None

    serve = asyncio.create_task(_guarded(), name="uvicorn")
    stopper = asyncio.create_task(stop.wait())
    try:
        await asyncio.wait({serve, stopper}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        stopper.cancel()
    server.should_exit = True
    await serve
    if not stop.is_set():
        raise RuntimeError("el servidor del dashboard terminó inesperadamente")


# --------------------------------------------------------------------------- scan


def _headers_only(data: bytes) -> bytes:
    """Solo la sección de headers de un mail (hasta la primera línea en blanco)."""
    ends = [(i, len(sep)) for sep in (b"\r\n\r\n", b"\n\n") if (i := data.find(sep)) != -1]
    if ends:
        idx, sep_len = min(ends)
        return data[: idx + sep_len]
    head = data[:65536]
    cut = head.rfind(b"\n")
    return (head[: cut + 1] if cut != -1 else head) + b"\r\n"


def _read_eml(path: Path, max_bytes: int) -> tuple[bytes, bool, int]:
    """(bytes, truncado, tamaño original). Un mail más grande que `max_bytes` NO se descarta: se analizan
    solo sus headers (igual que hacen los conectores) y el pipeline lo marca como no analizado completo."""
    size = path.stat().st_size
    with path.open("rb") as fh:
        if size <= max_bytes:
            data = fh.read(max_bytes + 1)
            if len(data) <= max_bytes:
                return data, False, len(data)
            fh.seek(0)  # creció mientras se leía: tratarlo como grande
        head = fh.read(min(HEADER_PEEK_BYTES, max(max_bytes, 1)))
    return _headers_only(head), True, max(size, len(head))


@app.command()
def scan(
    eml: Annotated[Path, typer.Argument(exists=True, dir_okay=False, readable=True, help="Archivo .eml")],
    config: ConfigOpt = None,
    as_json: Annotated[bool, typer.Option("--json", help="Salida JSON")] = False,
    offline: Annotated[
        bool,
        typer.Option("--offline", help="Sin consultas de reputación ni ClamAV: nada sale de esta PC"),
    ] = False,
) -> None:
    """Analiza un .eml suelto e imprime el veredicto. Código de salida: 0 limpio, 1 sospechoso, 2 malicioso, 3 error."""
    settings = _settings(config)
    _cli_logging(settings)
    if offline:
        settings.privacy.hash_lookups = False
        settings.privacy.url_lookups = False
        settings.analyzers.reputation.enabled = False
        settings.analyzers.clamav.enabled = False  # clamd corre en otra máquina/contenedor
    result = asyncio.run(_scan(settings, eml))
    if as_json:
        typer.echo(result.model_dump_json(indent=2))
    else:
        _print_report(result)
    raise typer.Exit(EXIT_BY_LEVEL.get(result.verdict.level.value, 3))


def _raw_from_file(settings: Settings, eml: Path) -> RawMessage:
    from centinela.core.models import MessageRef, RawMessage

    data, truncated, size = _read_eml(eml, int(settings.limits.max_message_bytes))
    return RawMessage(
        ref=MessageRef(connector="cli", mailbox="local", remote_id=eml.name),
        raw=data,
        truncated=truncated,
        original_size=size if truncated else None,
    )


async def _scan(settings: Settings, eml: Path) -> AnalysisResult:
    import httpx

    from centinela.analyzers import build_analyzers
    from centinela.core.cache import MemoryCache
    from centinela.core.pipeline import Pipeline

    raw = await asyncio.to_thread(_raw_from_file, settings, eml)
    async with httpx.AsyncClient(timeout=15, follow_redirects=False) as http:
        pipeline = Pipeline(settings, build_analyzers(settings), http, MemoryCache())
        try:
            return await pipeline.analyze(raw)
        finally:
            await pipeline.close()


def _print_report(result: AnalysisResult) -> None:
    colors = {"clean": typer.colors.GREEN, "suspicious": typer.colors.YELLOW, "malicious": typer.colors.RED}
    level = result.verdict.level.value
    names = {"clean": "LIMPIO", "suspicious": "SOSPECHOSO", "malicious": "MALICIOSO", "error": "ERROR"}
    typer.secho(
        f"\n{names.get(level, 'ERROR')}  (score {result.verdict.score}/100)", fg=colors.get(level), bold=True
    )
    typer.echo(_safe(result.verdict.summary, 1000))
    if result.truncated:
        typer.secho(
            "ATENCIÓN: mail demasiado grande: solo se analizaron los encabezados (los adjuntos NO se revisaron).",
            fg=typer.colors.YELLOW,
        )
    typer.echo(
        f"\nAsunto: {_safe(result.subject)}\nDe: {_safe(result.from_display or '')} <{_safe(result.from_addr or '?')}>"
    )
    if result.verdict.malware_families:
        typer.echo("Familias: " + ", ".join(_safe(f, 100) for f in result.verdict.malware_families))
    if result.artifacts:
        typer.echo("\nArchivos:")
        for a in result.artifacts:
            pad = "  " * (min(a.depth, 8) + 1)
            flags = []
            if a.encrypted:
                flags.append("cifrado: no se pudo abrir")
            elif a.password_protected:
                flags.append("con contraseña")
            if a.listing_only:
                flags.append("solo listado: no se analizó")
            extra = f"  ({'; '.join(flags)})" if flags else ""
            sha = f"  sha256={a.sha256}" if a.sha256 else ""
            typer.echo(
                f"{pad}- {_safe(a.filename or a.id, 200)}  [{_safe(a.detected_type, 40)}, {a.size} bytes]{sha}{extra}"
            )
    if result.findings:
        typer.echo("\nHallazgos:")
        for f in result.findings:
            target = f" ({_safe(f.artifact_id, 200)})" if f.artifact_id else ""
            typer.echo(
                f"  [{f.severity.name:<8}] {f.score:>3}  {_safe(f.title, 300)}{target}   <{_safe(f.rule, 200)}>"
            )
    if result.errors:
        typer.secho("\nErrores de análisis:", fg=typer.colors.YELLOW)
        for e in result.errors:
            typer.echo(f"  - {_safe(e, 500)}")
    typer.echo(f"\nDuración: {result.duration_ms} ms")


# --------------------------------------------------------------------------- check-config


@app.command("check-config")
def check_config(config: ConfigOpt = None) -> None:
    """Valida config.yaml y muestra un resumen (sin secretos)."""
    s = _settings(config)
    _cli_logging(s)
    from centinela.analyzers import build_analyzers

    typer.secho("Configuración válida.", fg=typer.colors.GREEN)
    typer.echo(
        f"Empresa: {s.general.company_name}  dominios: {', '.join(s.general.company_domains) or '(ninguno)'}"
    )
    if s.general.trusted_domains:
        typer.echo(f"Dominios de confianza: {', '.join(s.general.trusted_domains)}")
    typer.echo(f"Base de datos: {_db_label(s.database_url)}")
    typer.echo(f"Cola: {'Redis' if s.redis_url else 'en memoria (todo-en-uno)'}")
    typer.echo("Conectores:" if s.connectors else "Conectores: (ninguno)")
    for c in s.connectors:
        typer.echo(
            f"  - {c.name} ({c.type}){'' if c.enabled else ' [deshabilitado]'}{' [solo alertas]' if not c.tag else ''}"
        )
    typer.echo("Analizadores: " + (", ".join(a.name for a in build_analyzers(s)) or "(ninguno)"))
    typer.echo(
        "Alertas: " + (", ".join(f"{c.name} ({c.type})" for c in s.actions.alerts.channels) or "(ninguna)")
    )
    typer.echo(
        f"Dashboard: {'habilitado en ' + s.dashboard.host + ':' + str(s.dashboard.port) if s.dashboard.enabled else 'deshabilitado'}"
    )
    problems: list[str] = []
    if s.dashboard.enabled:
        problem = _dashboard_problem(s)
        if problem:
            problems.append(problem)
    if not s.encryption_key and any(
        getattr(c, "oauth2", None) or getattr(c, "auth", None) == "oauth_user" for c in s.connectors
    ):
        problems.append("falta encryption_key: se necesita para guardar tokens OAuth cifrados (usar gen-key)")
    if not s.general.company_domains:
        problems.append("general.company_domains vacío: no se detectará suplantación del dominio propio")
    if not s.connectors:
        problems.append("no hay conectores: Centinela no va a recibir ningún mail")
    for p in problems:
        typer.secho(f"Atención: {p}", fg=typer.colors.YELLOW)


def _db_label(url: str) -> str:
    """URL de base sin credenciales."""
    try:
        from sqlalchemy.engine import make_url

        return make_url(url).render_as_string(hide_password=True)
    except Exception:  # noqa: BLE001 - URL rara: mostrar solo lo que sigue a la arroba
        return url.rsplit("@", 1)[-1]


# --------------------------------------------------------------------------- auth


@app.command()
def auth(
    connector: Annotated[str, typer.Argument(help="Nombre del conector en config.yaml")],
    config: ConfigOpt = None,
) -> None:
    """Login OAuth interactivo (Gmail personal, IMAP con OAuth) o diagnóstico de permisos (Microsoft Graph)."""
    settings = _settings(config)
    try:
        cfg = settings.connector(connector)
    except KeyError:
        _error(f"No existe el conector '{_safe(connector, 100)}' en la configuración.")
        raise typer.Exit(EXIT_CONFIG) from None
    _cli_logging(settings)
    code = asyncio.run(_auth(settings, cfg))
    if code:
        raise typer.Exit(code)


async def _auth(settings: Settings, cfg: Any) -> int:
    if cfg.type == "graph":
        from centinela.connectors.oauth_cloud import graph_check

        typer.echo(f"Probando el acceso de la app a Microsoft 365 para el conector '{cfg.name}'...")
        diag = await graph_check(cfg)
        for line in diag:
            color = typer.colors.RED if line.startswith("[ERROR]") else None
            typer.secho(_safe(line, 1000), fg=color)
        if diag.ok:
            typer.secho("Listo: la configuración de Microsoft Graph funciona.", fg=typer.colors.GREEN)
            return EXIT_OK
        _error("Hay problemas de configuración o permisos (ver arriba).")
        return EXIT_FAILED
    if cfg.type == "imap" and not cfg.oauth2:
        typer.echo("Este conector IMAP usa contraseña de aplicación: no necesita 'auth'.")
        return EXIT_OK
    if cfg.type == "gmail" and cfg.auth != "oauth_user":
        typer.echo("Este conector Gmail usa cuenta de servicio: no necesita 'auth'.")
        return EXIT_OK
    if cfg.type not in {"imap", "gmail"}:
        typer.echo(f"Los conectores '{cfg.type}' no requieren login.")
        return EXIT_OK

    from centinela.storage.db import SqlResultStore
    from centinela.storage.state import DbStateStore

    store = SqlResultStore(settings)
    try:
        state = DbStateStore(store, settings)
        if not state.can_store_secrets:  # antes del login: que no autorice para después no poder guardar
            _error(state.key_problem or "No se pueden guardar credenciales cifradas (falta encryption_key).")
            return EXIT_CONFIG
        await store.init()
        if cfg.type == "imap":
            from centinela.connectors.oauth_imap import ImapOAuthError, interactive_login

            try:
                await interactive_login(cfg, state, printer=typer.echo, prompt=input)
            except ImapOAuthError as exc:
                _error(f"No se pudo autorizar: {_safe(exc, 500)}")
                return EXIT_FAILED
        else:
            from centinela.connectors import _http
            from centinela.connectors.gmail import GmailAuthError
            from centinela.connectors.oauth_cloud import gmail_user_login

            try:
                await gmail_user_login(cfg, state, print_fn=typer.echo, input_fn=input)
            except (GmailAuthError, _http.HttpError) as exc:
                _error(f"No se pudo autorizar: {_safe(exc, 500)}")
                return EXIT_FAILED
        typer.secho("Listo: credenciales guardadas (cifradas).", fg=typer.colors.GREEN)
        return EXIT_OK
    finally:
        await store.close()


# --------------------------------------------------------------------------- claves


@app.command("hash-password")
def hash_password() -> None:
    """Genera el hash argon2 para dashboard.admin_password_hash."""
    from argon2 import PasswordHasher

    pw = typer.prompt("Contraseña del dashboard", hide_input=True, confirmation_prompt=True)
    if len(pw) < 12:
        _error("Usá al menos 12 caracteres.")
        raise typer.Exit(EXIT_CONFIG)
    typer.echo(PasswordHasher().hash(pw))


@app.command("gen-key")
def gen_key() -> None:
    """Genera claves aleatorias para el archivo .env."""
    from cryptography.fernet import Fernet

    typer.echo(f"CENTINELA_ENCRYPTION_KEY={Fernet.generate_key().decode()}")
    typer.echo(f"CENTINELA_DASHBOARD_SECRET_KEY={secrets.token_urlsafe(48)}")


# --------------------------------------------------------------------------- test-alert


@app.command("test-alert")
def test_alert(config: ConfigOpt = None) -> None:
    """Envía una alerta de prueba (mail ficticio) a todos los canales configurados."""
    settings = _settings(config)
    _cli_logging(settings)
    code = asyncio.run(_test_alert(settings))
    if code:
        raise typer.Exit(code)


def _test_result(settings: Settings) -> AnalysisResult:
    from centinela.core.models import (
        AnalysisResult,
        ArtifactSummary,
        Finding,
        FindingCategory,
        MessageRef,
        Severity,
        Verdict,
        VerdictLevel,
        utcnow,
    )

    domain = (settings.general.company_domains or ["empresa.com"])[0]
    return AnalysisResult(
        ref=MessageRef(connector="prueba", mailbox=f"ventas@{domain}", remote_id="test"),
        subject="[PRUEBA] Factura pendiente de pago",
        from_addr="facturacion@proveedor-falso.example",
        from_display="Facturación",
        received_at=utcnow(),
        artifacts=[
            ArtifactSummary(
                id="att0", filename="factura.pdf.exe", detected_type="pe", size=123456, sha256="0" * 64
            )
        ],
        findings=[
            Finding(
                analyzer="prueba",
                rule="test.alert",
                title="Esto es una alerta de prueba",
                description="Si recibiste este mensaje, el canal de alertas funciona.",
                category=FindingCategory.MALWARE,
                severity=Severity.CRITICAL,
                score=99,
                artifact_id="att0",
                malware_family="Prueba",
            )
        ],
        verdict=Verdict(
            level=VerdictLevel.MALICIOUS,
            score=99,
            summary="ALERTA DE PRUEBA: no hay ningún mail real involucrado.",
            malware_families=["Prueba"],
        ),
    )


async def _test_alert(settings: Settings) -> int:
    import httpx

    from centinela.actions.alerts import AlertDeliveryError, build_channels, describe_exception
    from centinela.logging_setup import redact

    result = _test_result(settings)
    async with httpx.AsyncClient(timeout=15) as http:
        channels = build_channels(settings, http)
        if not channels:
            typer.secho(
                "No hay canales de alerta configurados (o ninguno es válido: ver los avisos).",
                fg=typer.colors.YELLOW,
            )
            return EXIT_CONFIG if settings.actions.alerts.channels else EXIT_OK
        failed = 0
        for ch in channels:
            try:
                await asyncio.wait_for(ch.send(result), timeout=60)
                typer.secho(f"  OK     {ch.name}", fg=typer.colors.GREEN)
            except Exception as exc:  # noqa: BLE001
                failed += 1
                # los AlertDeliveryError no llevan secretos; el resto se describe y redacta igual
                text = str(exc) if isinstance(exc, AlertDeliveryError) else describe_exception(exc)
                typer.secho(
                    f"  FALLÓ  {ch.name}: {redact(text or type(exc).__name__, limit=500)}",
                    fg=typer.colors.RED,
                )
            finally:
                with contextlib.suppress(Exception):
                    await ch.close()
    return EXIT_FAILED if failed else EXIT_OK


# --------------------------------------------------------------------------- rules


@rules_app.command("check")
def rules_check(config: ConfigOpt = None) -> None:
    """Compila las reglas YARA configuradas y reporta cuántas cargaron (código 1 si alguna tiene errores)."""
    settings = _settings(config)
    _cli_logging(settings)
    from centinela.analyzers.yara_scan import YaraAnalyzer

    if not YaraAnalyzer.available():
        _error("yara-x no está instalado: no se pueden compilar las reglas.")
        raise typer.Exit(EXIT_CONFIG)
    analyzer = YaraAnalyzer(settings)
    asyncio.run(analyzer.setup())
    info = {
        "motor": getattr(analyzer, "engine_name", None),
        "carpetas": [str(d) for d in settings.analyzers.yara.rules_dirs],
        "reglas": int(getattr(analyzer, "rule_count", 0) or 0),
        "archivos_cargados": list(getattr(analyzer, "loaded_files", []) or []),
        "archivos_con_errores": dict(getattr(analyzer, "skipped_files", {}) or {}),
    }
    typer.echo(json.dumps(info, indent=2, ensure_ascii=False, default=str))
    if info["archivos_con_errores"]:
        _error(
            f"{len(info['archivos_con_errores'])} archivo(s) de reglas con errores: se saltean (ver arriba)."
        )
        raise typer.Exit(EXIT_FAILED)
    if not info["reglas"]:
        _error("No se cargó ninguna regla YARA (¿la carpeta rules_dirs existe y tiene archivos .yar/.yara?).")
        raise typer.Exit(EXIT_FAILED)
    typer.secho(
        f"Listo: {info['reglas']} reglas compiladas de {len(info['archivos_cargados'])} archivo(s).",
        fg=typer.colors.GREEN,
    )


def main() -> None:  # pragma: no cover
    try:
        app()
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":  # pragma: no cover
    main()
