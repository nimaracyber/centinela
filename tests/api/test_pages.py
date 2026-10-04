"""Páginas HTML del dashboard con datos falsos: textos en español, filtros, detalle, escape de XSS."""

from __future__ import annotations

import re
from datetime import timedelta

from centinela.core.models import FindingCategory, Severity, VerdictLevel, utcnow
from tests.api.conftest import RLO_FILENAME, XSS_DISPLAY, XSS_FILENAME, XSS_SUBJECT, form_token
from tests.api.fakes import make_artifact, make_finding, make_result, sha

INLINE_SCRIPT_RE = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>", re.IGNORECASE)


def assert_csp_safe(html: str) -> None:
    """Nada que la CSP bloquearía: ni <script> inline, ni style=, ni handlers on*=."""
    assert not INLINE_SCRIPT_RE.search(html)
    assert ' style="' not in html
    assert not re.search(r"<[^>]+\son[a-z]+=", html, re.IGNORECASE)


# --------------------------------------------------------------------------- resumen


async def test_overview_renders_spanish_kpis_chart_and_tops(auth_client, populated):
    resp = await auth_client.get("/")
    assert resp.status_code == 200
    html = resp.text
    for text in ("Resumen", "Últimas 24 horas", "Últimos 7 días", "Analizados", "Sospechosos", "Maliciosos"):
        assert text in html
    assert 'data-kpi="24h.total">5<' in html
    assert 'data-kpi="24h.malicious">1<' in html
    assert 'class="chart-svg"' in html and "seg seg-malicious" in html
    assert "Ver los datos en una tabla" in html
    assert "AsyncRAT" in html  # top familias
    assert "facturas@proveedor-falso.example" in html  # top remitentes peligrosos
    assert "yara.AsyncRAT" in html  # top reglas
    assert 'data-autorefresh="stats"' in html
    # últimos maliciosos/sospechosos: no incluye limpios
    assert "Pedido 1234" not in html
    assert "Actualizá tu cuenta" in html
    assert XSS_SUBJECT not in html
    assert "&lt;script&gt;alert(" in html
    assert_csp_safe(html)


async def test_overview_empty_state(auth_client):
    resp = await auth_client.get("/")
    assert resp.status_code == 200
    assert "Todavía no hay mensajes analizados en este período." in resp.text
    assert "No hay mails sospechosos ni maliciosos" in resp.text


async def test_overview_hides_false_positives_from_recent(auth_client, store, malicious_result):
    store.fp[malicious_result.id] = {"value": True, "user": "admin", "note": ""}
    resp = await auth_client.get("/")
    assert "Factura vencida" not in resp.text


# --------------------------------------------------------------------------- listado


async def test_messages_list_and_level_filter(auth_client, populated):
    resp = await auth_client.get("/messages")
    assert resp.status_code == 200
    html = resp.text
    assert "Mensajes" in html and "Incluir falsos positivos" in html
    assert "5 mensajes" in html
    assert "Pedido 1234" in html and "Actualizá tu cuenta" in html
    assert XSS_SUBJECT not in html and XSS_DISPLAY not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html
    assert_csp_safe(html)

    resp = await auth_client.get("/messages", params={"nivel": "malicious"})
    assert "1 mensaje" in resp.text
    assert "Pedido 1234" not in resp.text
    assert "Factura vencida" in resp.text

    resp = await auth_client.get("/messages", params={"nivel": "amenazas"})
    assert "2 mensajes" in resp.text


async def test_messages_search_mailbox_and_connector_filters(auth_client, store, populated):
    resp = await auth_client.get("/messages", params={"q": "presupuesto"})
    assert "1 mensaje" in resp.text and "Presupuesto" in resp.text
    resp = await auth_client.get("/messages", params={"buzon": "COMPRAS@empresa.com"})
    assert "1 mensaje" in resp.text
    resp = await auth_client.get("/messages", params={"conector": "otro"})
    assert "Ningún mensaje coincide con estos filtros." in resp.text
    flt = store.calls[-1][1]
    assert flt.connector == "otro"


async def test_messages_false_positives_hidden_by_default(auth_client, store, malicious_result, populated):
    store.fp[malicious_result.id] = {"value": True, "user": "admin", "note": ""}
    resp = await auth_client.get("/messages")
    assert "4 mensajes" in resp.text
    assert "Factura vencida" not in resp.text
    resp = await auth_client.get("/messages", params={"fp": "1"})
    assert "5 mensajes" in resp.text
    assert "Falso positivo" in resp.text


async def test_messages_date_range_uses_configured_timezone(auth_client, store, populated):
    today = utcnow().date()
    resp = await auth_client.get("/messages", params={"desde": today.isoformat(), "hasta": today.isoformat()})
    assert resp.status_code == 200
    flt = store.calls[-1][1]
    assert flt.since.isoformat().startswith(today.isoformat() + "T00:00:00")
    assert flt.until.isoformat().startswith(today.isoformat() + "T23:59:59.999999")
    future = (today + timedelta(days=3)).isoformat()
    resp = await auth_client.get("/messages", params={"desde": future})
    assert "Ningún mensaje coincide" in resp.text


async def test_messages_pagination(auth_client, store):
    base = utcnow()
    store.add(
        *[
            make_result(subject=f"Mail número {i:03d}", received_at=base - timedelta(minutes=i))
            for i in range(120)
        ]
    )
    resp = await auth_client.get("/messages")
    assert "Página 1 de 3" in resp.text
    assert "Mail número 000" in resp.text and "Mail número 050" not in resp.text
    assert 'href="/messages?pagina=2"' in resp.text
    resp = await auth_client.get("/messages", params={"pagina": "3"})
    assert "Mail número 119" in resp.text and "Mail número 099" not in resp.text
    assert "Página 3 de 3" in resp.text
    assert 'href="/messages?pagina=2"' in resp.text
    resp = await auth_client.get("/messages", params={"pagina": "99"})
    assert "Volver a la primera página" in resp.text


async def test_messages_hostile_params_do_not_break(auth_client, populated):
    params = {
        "nivel": "<script>",
        "desde": "no-es-fecha",
        "hasta": "2026-13-45",
        "pagina": "abc",
        "q": "x" * 5000,
        "conector": "\x00\x01<b>",
        "fp": "<svg>",
    }
    resp = await auth_client.get("/messages", params=params)
    assert resp.status_code == 200
    assert "La fecha «desde» no es válida" in resp.text
    assert "La fecha «hasta» no es válida" in resp.text
    assert "<b>" not in resp.text
    assert "&lt;b&gt;" in resp.text  # conector inexistente: se muestra escapado en el select
    resp = await auth_client.get("/messages", params={"pagina": "-5"})
    assert resp.status_code == 200
    resp = await auth_client.get("/messages", params={"desde": "2026-10-05", "hasta": "2026-10-01"})
    assert "posterior a «hasta»" in resp.text


async def test_messages_family_filter_chip(auth_client, populated):
    resp = await auth_client.get("/messages", params={"familia": "AsyncRAT", "fp": "1"})
    assert "1 mensaje" in resp.text
    assert "Quitar el filtro de familia" in resp.text


# --------------------------------------------------------------------------- detalle


async def test_detail_renders_everything_escaped(auth_client, malicious_result):
    resp = await auth_client.get(f"/messages/{malicious_result.id}")
    assert resp.status_code == 200
    html = resp.text
    # veredicto + qué hacer
    assert "verdict verdict-malicious" in html
    assert "Malicioso" in html and "score 95/100" in html
    assert "Qué hacer" in html
    assert "desconectá esa computadora de la red" in html
    assert "cambiá las contraseñas" in html  # malware => robo de credenciales
    # hallazgos agrupados por severidad, con evidencia escapada y colapsable
    assert html.index("Crítico") < html.index("Alto") < html.index("Medio") < html.index("Informativo")
    assert "Firma de AsyncRAT" in html and "yara.AsyncRAT" in html
    assert "Ver evidencia técnica" in html and "<details" in html
    assert "<script>evil()" not in html and "&lt;script&gt;evil()" in html
    # árbol de artifacts con indentación por profundidad
    assert 'class="art depth-0"' in html and 'class="art depth-1"' in html and 'class="art depth-2"' in html
    files_section = html.split('id="archivos-title"', 1)[1]
    assert files_section.index("factura.zip") < files_section.index("[U+202E]")  # padre antes que hijo
    assert RLO_FILENAME not in html  # el truco RLO queda a la vista
    assert "factura[U+202E]fdp.exe" in html
    assert XSS_FILENAME not in html and "&lt;svg onload=alert(2)&gt;" in html
    assert "Cifrado: no se pudo abrir" in html
    # hashes: copiar + links externos seguros
    sha_child = malicious_result.artifacts[1].sha256
    assert f'data-copy="{sha_child}"' in html
    assert f'href="https://www.virustotal.com/gui/file/{sha_child}"' in html
    assert f'href="https://bazaar.abuse.ch/browse.php?search=sha256%3A{sha_child}"' in html
    for link in re.findall(r"<a [^>]*virustotal[^>]*>", html):
        assert 'target="_blank"' in link and 'rel="noopener noreferrer"' in link
    # URLs desactivadas, nunca clicables
    assert "hxxps://evil[.]example[.]com/login" in html
    assert 'href="https://evil.example.com' not in html and "evil.example.com/login" not in html
    assert "&lt;b&gt;x&lt;/b&gt;" in html
    assert "Banco &lt;i&gt;Nación&lt;/i&gt;" in html
    # errores y acciones en español
    assert "clamav[att0]: timeout &lt;b&gt;" in html
    assert "Alerta enviada por «telegram»" in html
    assert "omitida: ya se avisó de esta misma campaña" in html
    assert "Mail etiquetado en el buzón" in html
    # nada de XSS crudo
    assert XSS_SUBJECT not in html and XSS_DISPLAY not in html
    assert "<b>peligroso</b>" not in html
    # formulario de falso positivo con CSRF
    assert f'action="/messages/{malicious_result.id}/false-positive"' in html
    assert "Marcar como falso positivo" in html
    assert_csp_safe(html)


async def test_detail_recommendations_by_level(auth_client, store):
    clean = make_result(level=VerdictLevel.CLEAN)
    error = make_result(level=VerdictLevel.ERROR, errors=["pipeline: timeout"])
    phishing = make_result(
        level=VerdictLevel.SUSPICIOUS,
        findings=[
            make_finding(
                "url.lookalike", category=FindingCategory.PHISHING, severity=Severity.MEDIUM, score=40
            ),
            make_finding(
                "headers.dmarc_fail", category=FindingCategory.SPOOFING, severity=Severity.MEDIUM, score=30
            ),
        ],
    )
    store.add(clean, error, phishing)
    html = (await auth_client.get(f"/messages/{clean.id}")).text
    assert "No se encontraron amenazas" in html and "verdict-clean" in html
    assert "Este mail no tenía archivos adjuntos." in html
    html = (await auth_client.get(f"/messages/{error.id}")).text
    assert "NO debe considerarse seguro" in html and "Error de análisis" in html
    html = (await auth_client.get(f"/messages/{phishing.id}")).text
    assert "no los ingreses" in html
    assert "cambios de CBU" in html


async def test_detail_not_found_and_invalid_id(auth_client):
    resp = await auth_client.get("/messages/00000000-0000-0000-0000-000000000000")
    assert resp.status_code == 404
    assert "No encontramos ese mensaje" in resp.text
    resp = await auth_client.get("/messages/no-es-un-uuid")
    assert resp.status_code == 404
    resp = await auth_client.get("/messages/" + "a" * 500)
    assert resp.status_code == 404


async def test_detail_truncates_huge_results(auth_client, store):
    big = make_result(
        level=VerdictLevel.SUSPICIOUS,
        artifacts=[make_artifact(f"f{i}.txt", id=f"att{i}") for i in range(600)],
        # texto largo con espacios (un bloque base64 ya lo recorta core/defang antes de llegar acá)
        findings=[make_finding(f"rule.n{i}", evidence={"blob": "texto " * 4000}) for i in range(520)],
    )
    store.add(big)
    resp = await auth_client.get(f"/messages/{big.id}")
    assert resp.status_code == 200
    assert "Hay 20 hallazgos más que no se muestran." in resp.text
    assert "Hay 100 archivos más que no se muestran." in resp.text
    assert "(recortado)" in resp.text


# --------------------------------------------------------------------------- falso positivo


async def test_false_positive_toggle_with_csrf(auth_client, store, malicious_result, csrf):
    url = f"/messages/{malicious_result.id}/false-positive"
    resp = await auth_client.post(
        url, data={"csrf_token": csrf, "value": "1", "note": "Confirmado\x00 por teléfono"}
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == f"/messages/{malicious_result.id}?fp=marcado"
    assert store.fp[malicious_result.id] == {
        "value": True,
        "user": "admin",
        "note": "Confirmado  por teléfono",
    }
    calls_before = len(store.calls)
    page = await auth_client.get(resp.headers["location"])
    assert "Listo: el mail quedó marcado como falso positivo." in page.text
    assert "Marcado como falso positivo" in page.text
    assert "Deshacer: quitar la marca" in page.text
    # quién, cuándo y la nota salen del resultado (get_result), sin consultas extra de listado
    fp_card = page.text.split('class="card fp-card"', 1)[1].split("</section>", 1)[0]
    assert "Marcado por" in fp_card and "<dd>admin</dd>" in fp_card
    assert "Confirmado  por teléfono" in fp_card
    assert utcnow().strftime("%d/%m/%Y") in fp_card
    assert [c[0] for c in store.calls[calls_before:]] == ["get_result"]
    token = form_token(fp_card)
    resp = await auth_client.post(url, data={"csrf_token": token, "value": "0"})
    assert resp.status_code == 303
    assert store.fp[malicious_result.id]["value"] is False
    page = await auth_client.get(resp.headers["location"])
    assert "se quitó la marca" in page.text
    assert "admin quitó la marca el" in page.text  # queda el historial de quién la quitó
    assert "Marcar como falso positivo" in page.text


async def test_false_positive_note_is_escaped_on_detail(auth_client, store, malicious_result, csrf):
    url = f"/messages/{malicious_result.id}/false-positive"
    note = '<script>alert("nota")</script> ok‮'
    resp = await auth_client.post(url, data={"csrf_token": csrf, "value": "1", "note": note})
    assert resp.status_code == 303
    html = (await auth_client.get(f"/messages/{malicious_result.id}")).text
    assert '<script>alert("nota")' not in html
    assert "&lt;script&gt;alert(" in html and "ok[U+202E]" in html
    assert_csp_safe(html)


async def test_detail_truncated_banner(auth_client, store):
    big = make_result(
        level=VerdictLevel.SUSPICIOUS,
        truncated=True,
        findings=[
            make_finding(
                "policy.message_too_large",
                title="Mail demasiado grande: no se pudo analizar completo",
                category=FindingCategory.POLICY,
                severity=Severity.MEDIUM,
                score=35,
            )
        ],
    )
    normal = make_result(level=VerdictLevel.SUSPICIOUS)
    store.add(big, normal)
    html = (await auth_client.get(f"/messages/{big.id}")).text
    assert "Mail demasiado grande: solo se analizaron los encabezados." in html
    assert 'data-truncated="1"' in html and 'role="alert"' in html
    assert "los adjuntos NO se analizaron" in html  # también en "Qué hacer"
    assert_csp_safe(html)
    html = (await auth_client.get(f"/messages/{normal.id}")).text
    assert "solo se analizaron los encabezados" not in html
    # un mail truncado que quedó "limpio" no se presenta como seguro sin más
    clean_big = make_result(level=VerdictLevel.CLEAN, truncated=True)
    store.add(clean_big)
    html = (await auth_client.get(f"/messages/{clean_big.id}")).text
    assert "el resto del mail no se pudo revisar" in html
    assert "No se encontraron amenazas en este mail." not in html


async def test_detail_marks_password_protected_and_listing_only_artifacts(auth_client, store):
    arts = [
        make_artifact("pago.zip", id="att0", detected_type="zip", password_protected=True),
        make_artifact(
            "pago.exe",
            id="att0/pago.exe",
            parent_id="att0",
            depth=1,
            password_protected=True,
            listing_only=True,
            note="cifrado: no se pudo extraer",
        ),
        make_artifact("bloqueado.7z", id="att1", detected_type="7z", encrypted=True, password_protected=True),
        make_artifact("normal.pdf", id="att2", detected_type="pdf"),
    ]
    r = make_result(level=VerdictLevel.SUSPICIOUS, artifacts=arts)
    store.add(r)
    html = (await auth_client.get(f"/messages/{r.id}")).text
    files = html.split('id="archivos-title"', 1)[1].split("</section>", 1)[0]
    items = files.split('<li class="art')[1:]
    assert len(items) == 4
    zip_li, exe_li, sevenz_li, pdf_li = items
    assert "Con contraseña" in zip_li and "Solo listado" not in zip_li
    assert "Solo listado: no se analizó" in exe_li and "SHA-256" not in exe_li  # sin hashes
    assert "Cifrado: no se pudo abrir" in sevenz_li and "Con contraseña" not in sevenz_li
    assert "Con contraseña" not in pdf_li and "Solo listado" not in pdf_li and "SHA-256" in pdf_li
    assert "1 archivo solo se pudo listar" in files
    assert_csp_safe(html)


async def test_false_positive_requires_valid_csrf(auth_client, store, malicious_result, app):
    url = f"/messages/{malicious_result.id}/false-positive"
    resp = await auth_client.post(url, data={"value": "1"})
    assert resp.status_code == 403
    assert "CSRF" in resp.text
    resp = await auth_client.post(url, data={"csrf_token": "x" * 43, "value": "1"})
    assert resp.status_code == 403
    # token válido pero de OTRA sesión
    _cookie, other = app.state.centinela.sessions.issue()
    resp = await auth_client.post(url, data={"csrf_token": other.csrf, "value": "1"})
    assert resp.status_code == 403
    assert store.fp[malicious_result.id]["value"] is False
    assert not [c for c in store.calls if c[0] == "set_false_positive"]


async def test_false_positive_unknown_id(auth_client, csrf):
    resp = await auth_client.post(
        "/messages/11111111-1111-1111-1111-111111111111/false-positive",
        data={"csrf_token": csrf, "value": "1"},
    )
    assert resp.status_code == 404


async def test_false_positive_note_is_bounded(auth_client, store, malicious_result, csrf):
    url = f"/messages/{malicious_result.id}/false-positive"
    resp = await auth_client.post(url, data={"csrf_token": csrf, "value": "1", "note": "n" * 3000})
    assert resp.status_code == 303
    assert len(store.fp[malicious_result.id]["note"]) == 500


# --------------------------------------------------------------------------- campañas y estado


async def test_campaigns_page(auth_client, store):
    shared = make_artifact("orden_de_compra.iso", detected_type="iso", seed="campaña-1")
    for mailbox in ("ventas@empresa.com", "compras@empresa.com", "admin@empresa.com"):
        store.add(
            make_result(
                level=VerdictLevel.MALICIOUS, mailbox=mailbox, artifacts=[shared], families=["Remcos"]
            )
        )
    store.add(make_result(level=VerdictLevel.CLEAN, artifacts=[make_artifact("logo.png", seed="logo")]))
    resp = await auth_client.get("/campaigns")
    assert resp.status_code == 200
    html = resp.text
    assert "Campañas" in html and "orden_de_compra.iso" in html and "Remcos" in html
    assert "compras@empresa.com" in html and "admin@empresa.com" in html
    assert f'href="/messages?q={sha("campaña-1")}&amp;fp=1"' in html
    assert "logo.png" not in html
    assert_csp_safe(html)
    resp = await auth_client.get("/campaigns", params={"dias": "9999"})
    assert resp.status_code == 200
    assert store.calls[-1][0] == "campaigns"


async def test_campaigns_empty(auth_client):
    resp = await auth_client.get("/campaigns", params={"dias": "7"})
    assert "No se detectaron campañas" in resp.text


async def test_status_page_renders_health_without_secrets(auth_client, runtime):
    runtime.health_result["connectors"]["gmail-ws"] = {
        "ok": False,
        "password": "hunter2",
        "refresh_token": "1//0gSECRET",
        "last_error": "LOGIN failed for imaps://ventas:SuperSecreta@mail.example.com token=abc123def",
        "folders": {"INBOX": {"ok": False, "error": "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.zzz"}},
    }
    runtime.health_result["degraded"] = ["connector:gmail-ws"]
    runtime.health_result["status"] = "degraded"
    resp = await auth_client.get("/status")
    assert resp.status_code == 200
    html = resp.text
    assert "Estado del sistema" in html and "Funciona con problemas" in html
    assert "Base de datos" in html and "Antivirus ClamAV" in html and "Cola de análisis" in html
    assert "imap-ventas" in html and "gmail-ws" in html and "Con fallas" in html
    assert "No se usa: cola en memoria" in html
    for secret in ("hunter2", "1//0gSECRET", "SuperSecreta", "abc123def", "eyJhbGciOiJIUzI1NiJ9"):
        assert secret not in html
    assert "imaps://***@mail.example.com" in html
    assert "/metrics" in html
    assert_csp_safe(html)


async def test_status_page_when_health_fails(auth_client, runtime):
    runtime.health_exc = RuntimeError("postgres://user:pw@db explotó")
    resp = await auth_client.get("/status")
    assert resp.status_code == 200
    assert "No se pudo obtener el estado del sistema (RuntimeError)." in resp.text
    assert "explotó" not in resp.text


async def test_status_page_timeout(auth_client, app, runtime):
    import asyncio

    async def slow():
        await asyncio.sleep(5)
        return {}

    runtime.health = slow
    app.state.centinela.health_timeout_s = 0.05
    resp = await auth_client.get("/status")
    assert "no respondió a tiempo" in resp.text


async def test_logout_confirmation_page(auth_client):
    resp = await auth_client.get("/logout")
    assert resp.status_code == 200
    assert "Sí, cerrar sesión" in resp.text
