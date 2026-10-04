"""CLI (`centinela ...`) contra los módulos reales: config, claves, scan offline, reglas YARA, auth, alertas
de prueba y `run`. Sin red real: Graph y webhooks con respx, el dashboard en 127.0.0.1 con puerto efímero."""

from __future__ import annotations

import asyncio
import base64
import json
import socket
from pathlib import Path

import httpx
import respx
from argon2 import PasswordHasher
from cryptography.fernet import Fernet
from typer.testing import CliRunner

from centinela import cli
from centinela.core.config import load_settings
from centinela.runtime import Runtime
from tests.helpers import build_eml

runner = CliRunner()

TELEGRAM_TOKEN = "123456789:AAH-sup3rSecretTokenValue_xyz0123456"
WEBHOOK_URL = "https://hooks.example.com/centinela/s3cr3t-path-abcdef123456"
GRAPH_SECRET = "graph-client-secret-NO-MOSTRAR-42"


def invoke(*args: str, input: str | None = None):
    return runner.invoke(cli.app, list(args), input=input)


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def fake_jwt(roles: list[str]) -> str:
    def b64(obj: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    return f"{b64({'alg': 'none'})}.{b64({'roles': roles})}.firma"


# --------------------------------------------------------------------------- básicos


def test_version_and_help():
    result = invoke("version")
    assert result.exit_code == 0 and result.output.startswith("centinela ")
    result = invoke("--help")
    assert result.exit_code == 0
    for command in ("run", "scan", "check-config", "auth", "hash-password", "gen-key", "test-alert", "rules"):
        assert command in result.output


def test_gen_key_produces_valid_keys(write_config):
    result = invoke("gen-key")
    assert result.exit_code == 0
    lines = dict(line.split("=", 1) for line in result.output.strip().splitlines())
    Fernet(lines["CENTINELA_ENCRYPTION_KEY"].encode())  # clave Fernet válida
    assert len(lines["CENTINELA_DASHBOARD_SECRET_KEY"]) >= 48
    # y sirven tal cual para el config (encryption_key + dashboard)
    cfg = write_config({"encryption_key": lines["CENTINELA_ENCRYPTION_KEY"]})
    assert load_settings(cfg).encryption_key is not None


def test_hash_password_prompts_and_verifies():
    pw = "Una-Clave-Larga-De-Prueba-1"
    result = invoke("hash-password", input=f"{pw}\n{pw}\n")
    assert result.exit_code == 0
    hashed = result.output.strip().splitlines()[-1]
    assert hashed.startswith("$argon2") and PasswordHasher().verify(hashed, pw)
    assert pw not in result.output
    short = invoke("hash-password", input="corta\ncorta\n")
    assert short.exit_code == cli.EXIT_CONFIG and "12 caracteres" in short.output


# --------------------------------------------------------------------------- check-config


def test_check_config_summary_without_secrets(write_config):
    cfg = write_config(
        {
            "database_url": "postgresql://centinela:SuperSecretaDB@db:5432/centinela",
            "actions": {
                "alerts": {
                    "channels": [
                        {"type": "telegram", "name": "tg", "bot_token": TELEGRAM_TOKEN, "chat_id": "-100123"},
                        {"type": "webhook", "name": "hook", "url": WEBHOOK_URL},
                    ]
                }
            },
            "connectors": [
                {
                    "type": "graph",
                    "name": "m365",
                    "tenant_id": "t",
                    "client_id": "c",
                    "client_secret": GRAPH_SECRET,
                    "mailboxes": ["ventas@empresa.com"],
                }
            ],
        }
    )
    result = invoke("check-config", "-c", str(cfg))
    assert result.exit_code == 0, result.output
    out = result.output
    assert "Configuración válida." in out
    assert "m365 (graph)" in out and "tg (telegram)" in out and "hook (webhook)" in out
    assert "Dashboard: deshabilitado" in out
    for secret in ("SuperSecretaDB", TELEGRAM_TOKEN, "s3cr3t-path", GRAPH_SECRET):
        assert secret not in out
    assert "db:5432/centinela" in out


def test_check_config_warns_about_dashboard_and_oauth_without_key(write_config):
    cfg = write_config(
        {
            "dashboard": {"enabled": True},
            "connectors": [
                {
                    "type": "imap",
                    "name": "outlook",
                    "host": "outlook.office365.com",
                    "username": "ventas@outlook.com",
                    "oauth2": {"provider": "microsoft", "client_id": "abc"},
                }
            ],
        }
    )
    result = invoke("check-config", "-c", str(cfg))
    assert result.exit_code == 0
    assert "falta dashboard.admin_password_hash" in result.output
    assert "centinela hash-password" in result.output
    assert "falta encryption_key" in result.output


def test_invalid_config_exits_4(tmp_path):
    bad = tmp_path / "malo.yaml"
    bad.write_text("scoring:\n  suspicious_threshold: 90\n  malicious_threshold: 10\n", encoding="utf-8")
    result = invoke("check-config", "-c", str(bad))
    assert result.exit_code == cli.EXIT_CONFIG
    assert "Configuración inválida" in result.output


# --------------------------------------------------------------------------- scan


def _scan_config(write_config, **limits):
    over = {"analyzers": {"yara": {"enabled": False}}}
    if limits:
        over["limits"] = limits
    return write_config(over)


def test_scan_clean_offline(write_config, tmp_path):
    eml = tmp_path / "limpio.eml"
    eml.write_bytes(build_eml(subject="Reunión del lunes", text="Nos vemos el lunes a las 10."))
    result = invoke("scan", str(eml), "--offline", "-c", str(_scan_config(write_config)))
    assert result.exit_code == 0, result.output
    assert "LIMPIO" in result.output and "Reunión del lunes" in result.output


def test_scan_suspicious_attachment_with_real_rules_and_hostile_names(write_config, tmp_path):
    exe = b"MZ" + b"\x00" * 300  # "ejecutable" inerte
    eml = tmp_path / "factura.eml"
    eml.write_bytes(
        build_eml(
            subject="Factura \x1b[2J vencida",
            text="Adjunto la factura pendiente de pago, abrir urgente.",
            attachments=[("factura‮.pdf.exe", exe, "application/octet-stream")],
        )
    )
    cfg = write_config()  # YARA habilitado: compila las reglas reales del repo
    result = invoke("scan", str(eml), "--offline", "-c", str(cfg))
    assert result.exit_code in (1, 2), result.output  # sospechoso o malicioso
    out = result.output
    assert "Hallazgos:" in out and "filetype." in out
    # nada de secuencias de escape ni marcas bidi crudas en la terminal
    assert "\x1b" not in out and "‮" not in out
    assert "[U+001B]" in out and "[U+202E]" in out


def test_scan_json_and_oversized_message_is_analyzed_headers_only(write_config, tmp_path):
    eml = tmp_path / "grande.eml"
    eml.write_bytes(
        build_eml(
            subject="Archivo enorme",
            attachments=[("grande.bin", b"A" * 20_000, "application/octet-stream")],
        )
    )
    cfg = _scan_config(write_config, max_message_bytes=4096)
    result = invoke("scan", str(eml), "--offline", "--json", "-c", str(cfg))
    assert result.exit_code == 1, result.output  # nunca "limpio": el hallazgo de política lo marca
    data = json.loads(result.stdout)
    assert data["truncated"] is True and data["subject"] == "Archivo enorme"
    assert "policy.message_too_large" in {f["rule"] for f in data["findings"]}
    assert data["artifacts"] == []  # no se abrió ningún adjunto
    text = invoke("scan", str(eml), "--offline", "-c", str(cfg))
    assert "solo se analizaron los encabezados" in text.output


def test_scan_offline_disables_network_analyzers(write_config, tmp_path, monkeypatch):
    seen = {}

    def fake_build(settings):
        seen["privacy"] = (settings.privacy.hash_lookups, settings.privacy.url_lookups)
        seen["engines"] = (settings.analyzers.reputation.enabled, settings.analyzers.clamav.enabled)
        return []

    monkeypatch.setattr("centinela.analyzers.build_analyzers", fake_build)
    eml = tmp_path / "x.eml"
    eml.write_bytes(build_eml())
    assert invoke("scan", str(eml), "--offline", "-c", str(write_config())).exit_code == 0
    assert seen == {"privacy": (False, False), "engines": (False, False)}


def test_read_eml_and_headers_only(tmp_path):
    small = tmp_path / "a.eml"
    content = b"Subject: hola\r\n\r\ncuerpo"
    small.write_bytes(content)
    assert cli._read_eml(small, 1000) == (content, False, len(content))
    assert cli._read_eml(small, len(content)) == (content, False, len(content))  # justo en el límite
    assert cli._read_eml(small, len(content) - 1) == (b"Subject: hola\r\n\r\n", True, len(content))
    big = tmp_path / "b.eml"
    big.write_bytes(b"Subject: x\nFrom: a@b.com\n\n" + b"Z" * 5000)
    data, truncated, size = cli._read_eml(big, 100)
    assert truncated and size == big.stat().st_size and data == b"Subject: x\nFrom: a@b.com\n\n"
    assert cli._headers_only(b"A: 1\r\n\r\nB\n\nC") == b"A: 1\r\n\r\n"
    assert cli._headers_only(b"A: 1\n\nB\r\n\r\nC") == b"A: 1\n\n"
    no_end = cli._headers_only(b"A: 1\nB: 2\n" + b"x" * 100_000)
    assert len(no_end) <= 65536 + 2 and no_end.endswith(b"\r\n")


def test_safe_neutralizes_terminal_controls():
    assert cli._safe("a\x1b[31mb‮c\x00d\te\nf") == "a[U+001B][31mb[U+202E]c[U+0000]d e f"
    assert cli._safe("x" * 1000, 10) == "x" * 10 + "…"
    assert cli._safe(None) == ""


# --------------------------------------------------------------------------- rules check


def test_rules_check_with_repo_rules(write_config):
    result = invoke("rules", "check", "-c", str(write_config()))
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout[: result.stdout.rindex("}") + 1])
    assert data["motor"] and data["reglas"] > 0 and data["archivos_cargados"]
    assert data["archivos_con_errores"] == {}
    assert "reglas compiladas" in result.output


def test_rules_check_reports_broken_files(write_config, tmp_path):
    rules = tmp_path / "reglas"
    rules.mkdir()
    (rules / "buena.yar").write_text(
        'rule Prueba_Inerte { strings: $a = "centinela-prueba-inerte" condition: $a }', encoding="utf-8"
    )
    (rules / "rota.yar").write_text("rule Rota { condition: $no_existe }", encoding="utf-8")
    cfg = write_config({"analyzers": {"yara": {"rules_dirs": [rules.as_posix()]}}})
    result = invoke("rules", "check", "-c", str(cfg))
    assert result.exit_code == cli.EXIT_FAILED
    data = json.loads(result.stdout[: result.stdout.rindex("}") + 1])
    assert data["reglas"] == 1 and data["archivos_cargados"] == ["buena.yar"]
    assert list(data["archivos_con_errores"]) == ["rota.yar"]
    assert "con errores" in result.output


def test_rules_check_without_rules_fails(write_config, tmp_path):
    empty = tmp_path / "vacia"
    empty.mkdir()
    cfg = write_config({"analyzers": {"yara": {"rules_dirs": [empty.as_posix()]}}})
    result = invoke("rules", "check", "-c", str(cfg))
    assert result.exit_code == cli.EXIT_FAILED and "No se cargó ninguna regla" in result.output


# --------------------------------------------------------------------------- auth


def _graph_config(write_config, **extra):
    connector = {
        "type": "graph",
        "name": "m365",
        "tenant_id": "00000000-0000-0000-0000-000000000001",
        "client_id": "11111111-1111-1111-1111-111111111111",
        "client_secret": GRAPH_SECRET,
        "mailboxes": ["ventas@empresa.com"],
        "folders": ["inbox"],
        **extra,
    }
    return write_config({"connectors": [connector]})


class FakeGraphTokens:
    roles = ["Mail.ReadWrite", "MailboxSettings.ReadWrite"]
    calls = 0

    def __init__(self, cfg) -> None:
        self.cfg = cfg

    async def __call__(self, force: bool = False) -> str:
        FakeGraphTokens.calls += 1
        return fake_jwt(self.roles)


def test_auth_graph_runs_diagnostics_with_mocked_tokens(write_config, monkeypatch):
    monkeypatch.setattr("centinela.connectors.oauth_cloud.GraphTokenProvider", FakeGraphTokens)
    with respx.mock(assert_all_called=True) as mock:
        route = mock.get(
            url__startswith="https://graph.microsoft.com/v1.0/users/ventas@empresa.com/mailFolders/inbox"
        )
        route.mock(
            return_value=httpx.Response(200, json={"displayName": "Bandeja de entrada", "totalItemCount": 12})
        )
        result = invoke("auth", "m365", "-c", str(_graph_config(write_config)))
    assert result.exit_code == 0, result.output
    out = result.output
    assert "[OK] Token de aplicación obtenido" in out
    assert "carpeta 'Bandeja de entrada' accesible (12 mensajes)" in out
    assert "Listo: la configuración de Microsoft Graph funciona." in out
    assert GRAPH_SECRET not in out


def test_auth_graph_reports_missing_permissions(write_config, monkeypatch):
    class ReadOnly(FakeGraphTokens):
        roles = ["Mail.Read"]

    monkeypatch.setattr("centinela.connectors.oauth_cloud.GraphTokenProvider", ReadOnly)
    with respx.mock() as mock:
        mock.get(url__startswith="https://graph.microsoft.com/").mock(
            return_value=httpx.Response(403, json={"error": {"code": "ErrorAccessDenied", "message": "x"}})
        )
        result = invoke("auth", "m365", "-c", str(_graph_config(write_config)))
    assert result.exit_code == cli.EXIT_FAILED
    assert "[ERROR]" in result.output and "Mail.ReadWrite" in result.output
    assert "acceso denegado (403" in result.output


def test_auth_unknown_connector_and_not_needed(write_config, tmp_path):
    cfg = write_config(
        {
            "connectors": [
                {
                    "type": "imap",
                    "name": "yahoo",
                    "host": "imap.mail.yahoo.com",
                    "username": "a@yahoo.com",
                    "password": "x",
                },
                {"type": "directory", "name": "carpeta", "path": tmp_path.as_posix()},
            ]
        }
    )
    result = invoke("auth", "no-existe", "-c", str(cfg))
    assert result.exit_code == cli.EXIT_CONFIG and "No existe el conector" in result.output
    assert "contraseña de aplicación" in invoke("auth", "yahoo", "-c", str(cfg)).output
    assert "no requieren login" in invoke("auth", "carpeta", "-c", str(cfg)).output


def _imap_oauth_config(write_config, *, key: str | None):
    over = {
        "connectors": [
            {
                "type": "imap",
                "name": "outlook",
                "host": "outlook.office365.com",
                "username": "ventas@outlook.com",
                "oauth2": {"provider": "microsoft", "client_id": "abc"},
            }
        ]
    }
    if key:
        over["encryption_key"] = key
    return write_config(over)


def test_auth_imap_oauth_requires_encryption_key_before_login(write_config, monkeypatch):
    called = []

    async def fake_login(cfg, state, **kw):  # no debería llegar a pedir el login
        called.append(cfg.name)

    monkeypatch.setattr("centinela.connectors.oauth_imap.interactive_login", fake_login)
    result = invoke("auth", "outlook", "-c", str(_imap_oauth_config(write_config, key=None)))
    assert result.exit_code == cli.EXIT_CONFIG
    assert "No hay clave de cifrado configurada" in result.output and "gen-key" in result.output
    assert called == []


def test_auth_imap_oauth_stores_token_encrypted(write_config, monkeypatch, tmp_path):
    key = Fernet.generate_key().decode()
    seen = {}

    async def fake_login(cfg, state, *, printer, prompt, **kw):
        seen["can_store"] = state.can_store_secrets
        await state.set_secret(f"connector:{cfg.name}:imap_refresh_token", "refresh-token-de-prueba")
        printer("Listo: Centinela quedó autorizado.")

    monkeypatch.setattr("centinela.connectors.oauth_imap.interactive_login", fake_login)
    cfg = _imap_oauth_config(write_config, key=key)
    result = invoke("auth", "outlook", "-c", str(cfg))
    assert result.exit_code == 0, result.output
    assert seen == {"can_store": True}
    assert "credenciales guardadas (cifradas)" in result.output
    # quedó cifrado en la base (nunca en claro), incluido el WAL de SQLite si quedó alguno
    db_files = list(tmp_path.glob("centinela.db*"))
    assert db_files
    assert all(b"refresh-token-de-prueba" not in f.read_bytes() for f in db_files)


def test_auth_imap_oauth_error_is_reported(write_config, monkeypatch):
    from centinela.connectors.oauth_imap import ImapOAuthError

    async def failing(cfg, state, **kw):
        raise ImapOAuthError("el código venció; volvé a intentar")

    monkeypatch.setattr("centinela.connectors.oauth_imap.interactive_login", failing)
    cfg = _imap_oauth_config(write_config, key=Fernet.generate_key().decode())
    result = invoke("auth", "outlook", "-c", str(cfg))
    assert result.exit_code == cli.EXIT_FAILED and "el código venció" in result.output


def test_auth_gmail_user_login(write_config, monkeypatch, tmp_path):
    from centinela.connectors.gmail import GmailAuthError

    client_file = tmp_path / "client.json"
    client_file.write_text("{}", encoding="utf-8")
    cfg = write_config(
        {
            "encryption_key": Fernet.generate_key().decode(),
            "connectors": [
                {
                    "type": "gmail",
                    "name": "gmail-personal",
                    "auth": "oauth_user",
                    "oauth_client_file": client_file.as_posix(),
                }
            ],
        }
    )
    calls = []

    async def fake_gmail_login(cfg, state, *, print_fn, input_fn, **kw):
        calls.append(cfg.name)
        print_fn("Listo: dueño@gmail.com quedó autorizado")
        return "dueño@gmail.com"

    monkeypatch.setattr("centinela.connectors.oauth_cloud.gmail_user_login", fake_gmail_login)
    result = invoke("auth", "gmail-personal", "-c", str(cfg))
    assert result.exit_code == 0 and calls == ["gmail-personal"]
    assert "quedó autorizado" in result.output

    async def failing(cfg, state, **kw):
        raise GmailAuthError("Google no devolvió un refresh token.")

    monkeypatch.setattr("centinela.connectors.oauth_cloud.gmail_user_login", failing)
    result = invoke("auth", "gmail-personal", "-c", str(cfg))
    assert result.exit_code == cli.EXIT_FAILED and "refresh token" in result.output


# --------------------------------------------------------------------------- test-alert


def test_test_alert_ok_and_failure_without_leaking_webhook(write_config):
    cfg = write_config(
        {"actions": {"alerts": {"channels": [{"type": "webhook", "name": "hook", "url": WEBHOOK_URL}]}}}
    )
    with respx.mock() as mock:
        route = mock.post(WEBHOOK_URL).mock(return_value=httpx.Response(200, json={"ok": True}))
        result = invoke("test-alert", "-c", str(cfg))
        assert result.exit_code == 0, result.output
        assert "OK" in result.output and "hook" in result.output
        body = json.loads(route.calls[0].request.content)
        assert "PRUEBA" in json.dumps(body, ensure_ascii=False)
    with respx.mock() as mock:
        mock.post(WEBHOOK_URL).mock(return_value=httpx.Response(500, text="error interno"))
        result = invoke("test-alert", "-c", str(cfg))
    assert result.exit_code == cli.EXIT_FAILED
    assert "FALLÓ" in result.output and "s3cr3t-path" not in result.output


def test_test_alert_without_channels(write_config):
    result = invoke("test-alert", "-c", str(write_config()))
    assert result.exit_code == 0 and "No hay canales de alerta configurados" in result.output


# --------------------------------------------------------------------------- run


# los tests de `run` no necesitan analizadores pesados ni ClamAV (que intentaría resolver el host "clamav")
FAST_ANALYZERS = {"yara": {"enabled": False}, "clamav": {"enabled": False}, "reputation": {"enabled": False}}


def _dash_overrides(port: int) -> dict:
    pw_hash = PasswordHasher(time_cost=1, memory_cost=1024, parallelism=1).hash("Una-Clave-De-Prueba-123")
    return {
        "dashboard": {
            "enabled": True,
            "host": "127.0.0.1",
            "port": port,
            "admin_password_hash": pw_hash,
            "secret_key": "k" * 40,
        },
        "analyzers": FAST_ANALYZERS,
    }


def test_run_without_dashboard_secrets_fails_fast(write_config, tmp_path):
    cfg = write_config({"dashboard": {"enabled": True}})
    result = invoke("run", "-c", str(cfg))
    assert result.exit_code == cli.EXIT_CONFIG
    assert "No se puede iniciar el dashboard de forma segura" in result.output
    assert "centinela hash-password" in result.output
    assert not (tmp_path / "centinela.db").exists()  # falló antes de tocar la base


def test_run_rejects_unknown_role(write_config):
    result = invoke("run", "--role", "todo", "-c", str(write_config()))
    assert result.exit_code == 2 and "role" in result.output


async def test_run_api_role_serves_dashboard_until_stop(write_config):
    port = free_port()
    settings = load_settings(write_config(_dash_overrides(port)))
    stop = asyncio.Event()
    task = asyncio.create_task(cli._run(settings, "api", 1, stop=stop))
    resp = None
    async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}") as client:
        for _ in range(300):
            try:
                resp = await client.get("/healthz")
                break
            except httpx.TransportError:
                assert not task.done(), "el proceso terminó antes de servir el dashboard"
                await asyncio.sleep(0.05)
        assert resp is not None and resp.status_code == 200 and resp.json() == {"status": "ok"}
        login = await client.get("/login")
        assert login.status_code == 200 and "Ferretería El Tornillo" in login.text
        assert "server" not in {k.lower() for k in login.headers}  # server_header=False
    stop.set()
    assert await asyncio.wait_for(task, 30) == cli.EXIT_OK


async def test_run_builds_app_before_background_tasks(write_config, monkeypatch, capsys):
    from centinela.api.auth import DashboardConfigError

    settings = load_settings(write_config(_dash_overrides(free_port())))
    started = []

    async def fake_run_all(self, stop, concurrency=4):
        started.append("run_all")

    def broken_create_app(runtime):
        raise DashboardConfigError("No se puede iniciar el dashboard de forma segura: falta algo.")

    monkeypatch.setattr(Runtime, "run_all", fake_run_all)
    monkeypatch.setattr("centinela.api.app.create_app", broken_create_app)
    monkeypatch.setattr(cli, "_dashboard_problem", lambda s: None)
    closed = []
    real_close = Runtime.close

    async def tracking_close(self):
        closed.append(True)
        await real_close(self)

    monkeypatch.setattr(Runtime, "close", tracking_close)
    code = await asyncio.wait_for(cli._run(settings, "all", 1, stop=asyncio.Event()), 30)
    assert code == cli.EXIT_CONFIG
    assert started == []  # no arrancó ingest/worker
    assert closed == [True]
    assert "falta algo" in capsys.readouterr().err


async def test_run_reports_port_in_use(write_config, capsys):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as blocker:
        blocker.bind(("127.0.0.1", 0))
        blocker.listen()
        port = blocker.getsockname()[1]
        settings = load_settings(write_config(_dash_overrides(port)))
        code = await asyncio.wait_for(cli._run(settings, "api", 1, stop=asyncio.Event()), 30)
    assert code == cli.EXIT_FAILED
    err = capsys.readouterr().err
    assert "no se pudo iniciar el dashboard" in err and str(port) in err


async def test_run_crashed_component_exits_1(write_config, monkeypatch, capsys):
    async def broken_ingest(self, stop):
        raise RuntimeError("conector roto")

    monkeypatch.setattr(Runtime, "run_ingest", broken_ingest)
    settings = load_settings(write_config({"analyzers": FAST_ANALYZERS}))
    code = await asyncio.wait_for(cli._run(settings, "ingest", 1, stop=asyncio.Event()), 30)
    assert code == cli.EXIT_FAILED
    assert "ingest se detuvo: RuntimeError: conector roto" in capsys.readouterr().err


async def test_run_all_without_dashboard_stops_cleanly(write_config, monkeypatch):
    seen = {}
    real = Runtime.run_all

    async def spy(self, stop, concurrency=4):
        seen["concurrency"] = concurrency
        await real(self, stop, concurrency)

    monkeypatch.setattr(Runtime, "run_all", spy)
    settings = load_settings(write_config({"analyzers": FAST_ANALYZERS}))
    stop = asyncio.Event()
    task = asyncio.create_task(cli._run(settings, "all", 3, stop=stop))
    await asyncio.sleep(0.3)
    assert not task.done()
    stop.set()
    assert await asyncio.wait_for(task, 30) == cli.EXIT_OK
    assert seen == {"concurrency": 3}  # --workers también aplica al modo todo-en-uno


async def test_run_startup_failure_is_reported_without_secrets(write_config, monkeypatch, capsys):
    async def failing_create(cls, settings, **kw):
        raise OSError("no se pudo conectar a postgresql://centinela:SuperSecretaDB@db:5432/c")

    monkeypatch.setattr(Runtime, "create", classmethod(failing_create))
    settings = load_settings(write_config({"analyzers": FAST_ANALYZERS}))
    assert await cli._run(settings, "worker", 1, stop=asyncio.Event()) == cli.EXIT_FAILED
    err = capsys.readouterr().err
    assert "No se pudo iniciar Centinela: OSError" in err and "SuperSecretaDB" not in err


async def test_run_api_role_with_dashboard_disabled(write_config):
    settings = load_settings(write_config())
    assert await cli._run(settings, "api", 1, stop=asyncio.Event()) == cli.EXIT_CONFIG


def test_scan_missing_file_is_usage_error(tmp_path):
    result = invoke("scan", str(Path(tmp_path) / "no-existe.eml"))
    assert result.exit_code == 2
