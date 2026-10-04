from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from html.parser import HTMLParser

import pytest

from centinela.actions.alerts.format import (
    TELEGRAM_MAX_CHARS,
    TEXT_MAX_CHARS,
    build_alert,
    cef_escape_extension,
    cef_escape_header,
    clean_text,
    defang_email,
    defang_text,
    defang_url,
    escape_discord,
    format_local_datetime,
    utf16_len,
)
from centinela.core.models import ArtifactSummary, Finding, FindingCategory, Severity, VerdictLevel
from tests.alerts.conftest import BODY_SECRET, PHISH_URL, SHA_EXE, bec_result, make_result, stealer_result


def all_renderings(alert) -> list[str]:
    return [
        alert.to_text(),
        alert.to_telegram_html(),
        alert.to_markdown("slack"),
        alert.to_markdown("discord"),
        alert.to_html_email(),
        alert.to_cef(),
        alert.to_recipient_text(),
        alert.to_recipient_html(),
        alert.email_subject(),
        json.dumps(alert.machine, ensure_ascii=False),
    ]


def hostile_result():
    """Todo lo que controla el atacante, envenenado."""
    findings = [
        Finding(
            analyzer=f"a{i}",
            rule=f"rule.{i}|x=y\\z",
            title=f"<script>alert({i})</script> hallazgo {'X' * 400} http://evil{i}.com/p",
            description="D" * 5000 + "\n<b>nope</b>",
            category=FindingCategory.MALWARE,
            severity=Severity.HIGH,
            score=60,
            artifact_id=f"att{i}",
            malware_family=f"Fam{i}",
            evidence={"url": [f"https://evil{i}.example.com/{'q' * 300}"]},
        )
        for i in range(40)
    ]
    artifacts = [
        ArtifactSummary(
            id=f"att{i}",
            filename=f"fact‮ura{i}<img src=x>.exe" + "N" * 300,
            detected_type="pe",
            sha256=f"{i:064x}",
        )
        for i in range(40)
    ]
    return make_result(
        subject="<b>URGENTE</b> <!channel> @everyone [clic](https://evil.com) \x00\x1b[31m" + "S" * 5000,
        from_display="Banco <seguridad@banco.com>\r\nBcc: victima@empresa.com",
        from_addr="x@evil.com",
        summary="Resumen " + "R" * 10_000,
        to=[f"user{i}@empresa.com" for i in range(300)],
        artifacts=artifacts,
        findings=findings,
        families=[f"Fam{i}" for i in range(40)],
    )


# --------------------------------------------------------------------------- contenido


def test_malicious_alert_core_fields(alert_settings, malicious):
    a = build_alert(malicious, alert_settings)
    assert a.level == "malicious"
    assert a.emoji == "🔴"
    assert a.title == "Mail malicioso detectado en ventas@empresa.com"
    assert a.summary.startswith("El adjunto factura.pdf.exe es un programa que roba contraseñas")
    assert a.dashboard_url == f"https://centinela.empresa.com/messages/{malicious.id}"
    assert a.rule == "yara.AgentTesla"
    assert a.families == ("AgentTesla",)
    # el INFO no cuenta como hallazgo relevante
    assert a.total_findings == 3
    assert [f.rule for f in a.findings] == [
        "yara.AgentTesla",
        "file.double_extension",
        "url.lookalike_domain",
    ]
    # adjunto peligroso: el .exe dentro del zip (no el zip, que no tiene hallazgos propios)
    assert len(a.attachments) == 1
    att = a.attachments[0]
    assert att.display_name == "factura.zip › factura.pdf.exe"
    assert att.sha256 == SHA_EXE
    assert att.type_label == "programa de Windows"
    assert att.families == ("AgentTesla",)


def test_text_has_spanish_summary_facts_and_recommendations(alert_settings, malicious):
    text = build_alert(malicious, alert_settings).to_text()
    assert text.startswith("🔴 Mail malicioso detectado en ventas@empresa.com")
    assert "QUÉ HACER" in text
    assert "No abras los adjuntos" in text
    assert "desconectá esa PC de la red" in text
    # stealer => cambiar contraseñas desde OTRO dispositivo y cerrar sesiones
    assert "desde OTRO dispositivo" in text and "cerrá las sesiones" in text
    assert "De: AFIP Cobranzas <cobranzas@pagos-afip[.]com>" in text
    assert "Para: ventas@empresa.com, juan@empresa.com, cliente@externo.com" in text
    assert "Asunto: Factura vencida N° 4471" in text
    assert "Fecha: 03/10/2026 14:32 (UTC-03:00)" in text
    assert f"SHA-256: {SHA_EXE}" in text
    assert "FAMILIA DE MALWARE: AgentTesla" in text
    assert "[Crítica] Firma de AgentTesla" in text
    assert f"https://centinela.empresa.com/messages/{malicious.id}" in text
    assert len(text) <= TEXT_MAX_CHARS


def test_no_body_or_evidence_content_and_urls_defanged_everywhere(alert_settings, malicious):
    a = build_alert(malicious, alert_settings)
    assert a.urls == ("hxxps://pagos-afip[.]com/login[.]php?token=XYZ",)
    for out in all_renderings(a):
        assert BODY_SECRET not in out
        assert PHISH_URL not in out
        assert "://pagos-afip.com" not in out
    # en los textos para humanos tampoco aparece el dominio "clickeable" (ni en el remitente)
    for out in (a.to_text(), a.to_telegram_html(), a.to_markdown("slack"), a.to_html_email()):
        assert "pagos-afip.com" not in out
        assert "pagos-afip[.]com" in out


def test_machine_payload_has_no_evidence_and_is_json(alert_settings, malicious):
    a = build_alert(malicious, alert_settings)
    raw = json.dumps(a.machine, ensure_ascii=False)
    assert "evidence" not in raw
    assert BODY_SECRET not in raw
    m = a.machine
    assert m["schema"] == "centinela.alert/v1"
    assert m["level"] == "malicious" and m["score"] == 97
    assert m["message"]["from"] == "cobranzas@pagos-afip.com"
    assert m["message"]["received_at"] == "2026-10-03T17:32:00Z"
    assert {f["rule"] for f in m["findings"]} >= {"yara.AgentTesla", "headers.info"}
    assert m["dangerous_attachments"][0]["sha256"] == SHA_EXE
    assert all("data" not in art for art in m["artifacts"])
    assert m["urls_defanged"] == ["hxxps://pagos-afip[.]com/login[.]php?token=XYZ"]


def test_suspicious_bec_recommendations(alert_settings, suspicious_bec):
    a = build_alert(suspicious_bec, alert_settings)
    assert a.emoji == "🟠"
    assert a.title == "Mail sospechoso detectado en ventas@empresa.com"
    recs = " ".join(a.recommendations)
    assert "verificá llamando por teléfono a un número que ya tengas" in recs
    # sin adjuntos ni malware: nada de desconectar la PC ni de stealers
    assert "desconect" not in recs
    assert "OTRO dispositivo" not in recs
    assert "Si ingresaste tu usuario y contraseña" not in recs
    assert a.attachments == ()


def test_macro_recommendation():
    finding = Finding(
        analyzer="office",
        rule="office.vba.autoexec",
        title="Documento con macro que se ejecuta sola",
        category=FindingCategory.SUSPICIOUS_FILE,
        severity=Severity.HIGH,
        score=70,
        artifact_id="att0",
    )
    r = make_result(
        level=VerdictLevel.SUSPICIOUS,
        score=60,
        artifacts=[
            ArtifactSummary(id="att0", filename="pedido.docm", detected_type="ooxml", sha256="c" * 64)
        ],
        findings=[finding],
    )
    from centinela.core.config import Settings

    recs = " ".join(build_alert(r, Settings()).recommendations)
    assert "Habilitar contenido" in recs
    assert "No abras los adjuntos de este mail." in recs


def test_rat_and_ransomware_family_advice():
    from centinela.core.config import Settings

    r = make_result(
        families=["AsyncRAT"],
        findings=[],
        artifacts=[ArtifactSummary(id="att0", filename="x.exe", detected_type="pe")],
    )
    recs = " ".join(build_alert(r, Settings()).recommendations)
    assert "controlar la PC a distancia" in recs
    r2 = make_result(
        families=["LockBit"], artifacts=[ArtifactSummary(id="att0", filename="x.exe", detected_type="pe")]
    )
    assert "no pagues" in " ".join(build_alert(r2, Settings()).recommendations)


def test_clean_and_error_levels(settings):
    clean = build_alert(make_result(level=VerdictLevel.CLEAN, score=0, summary=""), settings)
    assert clean.emoji == "🟢"
    assert clean.recommendations == ()
    assert clean.findings == ()
    assert clean.summary == "Centinela no encontró amenazas en este mail."
    assert clean.dashboard_url is None
    err = build_alert(
        make_result(level=VerdictLevel.ERROR, score=0, summary="No se pudo leer el mensaje."), settings
    )
    assert err.title.startswith("No se pudo analizar")
    assert "no pudo revisar" in err.recommendations[0]
    assert err.email_subject().startswith("[Centinela] ⚠️ No se pudo analizar un mail:")


def test_email_subject_format(alert_settings, malicious):
    a = build_alert(malicious, alert_settings)
    assert a.email_subject() == "[Centinela] 🔴 Mail malicioso: Factura vencida N° 4471"
    long = build_alert(stealer_result(subject="Z" * 500), alert_settings)
    subj = long.email_subject()
    assert subj.startswith("[Centinela] 🔴 Mail malicioso: ZZZ") and subj.endswith("…")
    assert len(subj) < 120
    sus = build_alert(bec_result(), alert_settings)
    assert sus.email_subject() == "[Centinela] 🟠 Mail sospechoso: Nuevos datos bancarios"


def test_top_five_findings_and_counts(alert_settings):
    findings = [
        Finding(
            analyzer="x",
            rule=f"r.{i}",
            title=f"Hallazgo {i}",
            category=FindingCategory.SUSPICIOUS_FILE,
            severity=Severity.LOW if i < 6 else Severity.CRITICAL,
            score=10 + i,
        )
        for i in range(8)
    ]
    a = build_alert(make_result(findings=findings), alert_settings)
    assert len(a.findings) == 5
    assert a.total_findings == 8
    assert [f.rule for f in a.findings][:2] == ["r.7", "r.6"]  # críticos primero
    assert "QUÉ ENCONTRAMOS (5 DE 8)" in a.to_text()


def test_dashboard_url_validation(settings, malicious):
    settings.actions.alerts.dashboard_base_url = "javascript:alert(1)"
    assert build_alert(malicious, settings).dashboard_url is None
    settings.actions.alerts.dashboard_base_url = 'https://x.com/"><script>'
    assert build_alert(malicious, settings).dashboard_url is None
    settings.actions.alerts.dashboard_base_url = "http://10.0.0.5:8080/centinela"
    assert (
        build_alert(malicious, settings).dashboard_url
        == f"http://10.0.0.5:8080/centinela/messages/{malicious.id}"
    )


# --------------------------------------------------------------------------- input hostil


class _TagCollector(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack: list[str] = []
        self.tags: set[str] = set()
        self.balanced = True
        self.hrefs: list[str] = []

    def handle_starttag(self, tag, attrs):
        self.tags.add(tag)
        self.stack.append(tag)
        self.hrefs += [v for k, v in attrs if k == "href"]

    def handle_endtag(self, tag):
        if not self.stack or self.stack.pop() != tag:
            self.balanced = False


def test_telegram_html_escaping_and_allowed_tags(alert_settings):
    a = build_alert(hostile_result(), alert_settings)
    html = a.to_telegram_html()
    assert "<script>" not in html and "<img" not in html and "<!channel>" not in html
    assert "&lt;b&gt;URGENTE&lt;/b&gt;" in html
    p = _TagCollector()
    p.feed(html)
    assert p.tags <= {"b", "i", "code", "a"}
    assert p.balanced and not p.stack
    assert p.hrefs == [f"https://centinela.empresa.com/messages/{a.result_id}"]
    # sólo las 4 entidades con nombre que acepta Telegram
    assert set(re.findall(r"&([a-z]+);", html)) <= {"lt", "gt", "amp", "quot"}


def test_telegram_truncation_keeps_link_and_limit(alert_settings):
    a = build_alert(hostile_result(), alert_settings)
    html = a.to_telegram_html()
    assert utf16_len(html) <= TELEGRAM_MAX_CHARS
    assert a.dashboard_url in html
    p = _TagCollector()
    p.feed(html)
    assert p.balanced and not p.stack
    # un límite chico fuerza el recorte por líneas: sigue siendo HTML válido
    small = a.to_telegram_html(max_len=600)
    assert utf16_len(small) <= 600
    p2 = _TagCollector()
    p2.feed(small)
    assert p2.balanced and not p2.stack
    assert "…" in small


def test_text_truncation_hostile(alert_settings):
    a = build_alert(hostile_result(), alert_settings)
    text = a.to_text()
    assert len(text) <= TEXT_MAX_CHARS
    assert a.dashboard_url in text
    assert "\x00" not in text and "\x1b" not in text
    # el truco RLO queda visible, y la inyección de headers (CRLF) no rompe líneas
    assert "[U+202E]" in a.attachments[0].display_name
    assert "\r" not in text
    assert "Bcc: victima" not in text.split("\n")[0]
    assert all(not line.startswith("Bcc:") for line in text.split("\n"))
    # no hay links clickeables del atacante
    assert "https://evil" not in text and "http://evil" not in text
    assert "evil.com" not in text


def test_markdown_slack_and_discord_escaping(alert_settings):
    a = build_alert(hostile_result(), alert_settings)
    slack = a.to_markdown("slack")
    assert "<!channel>" not in slack and "&lt;!channel&gt;" in slack
    assert f"<{a.dashboard_url}|" in slack
    assert len(slack) <= 3000
    assert "<script>" not in slack
    discord = a.to_markdown("discord", max_len=4000)
    assert "\\@everyone" in discord
    assert "[clic](" not in discord  # el link markdown del atacante quedó roto
    assert len(discord) <= 4000
    assert f"]({a.dashboard_url})" in discord


def test_html_email_is_escaped_and_simple(alert_settings):
    a = build_alert(hostile_result(), alert_settings)
    html = a.to_html_email()
    assert html.startswith("<!DOCTYPE html>")
    assert "<script" not in html.lower()
    assert "<img" not in html.lower()
    assert "&lt;img src=x&gt;" in html
    assert "style=" in html and "<style" not in html  # CSS inline (Outlook)
    assert f'href="{a.dashboard_url}"' in html
    good = build_alert(stealer_result(), alert_settings).to_html_email()
    assert "Qué hacer" in good and SHA_EXE in good and "#B91C1C" in good


def test_recipient_variant_is_soft_and_non_technical(alert_settings, malicious):
    a = build_alert(malicious, alert_settings)
    txt = a.to_recipient_text()
    assert txt.startswith("🔴 Cuidado con un mail que recibiste")
    assert "Ferretería El Tornillo" in txt
    assert "SHA-256" not in txt and SHA_EXE not in txt
    assert "yara" not in txt.lower()
    assert "avisá enseguida a soporte" in txt
    assert "Cuidado con este mail" in a.recipient_email_subject()


def test_artifact_parent_cycle_and_unknown_ids(alert_settings):
    arts = [
        ArtifactSummary(id="a", filename="uno.zip", parent_id="b"),
        ArtifactSummary(id="b", filename="dos.zip", parent_id="a"),
    ]
    f1 = Finding(
        analyzer="x",
        rule="x.y",
        title="t",
        category=FindingCategory.MALWARE,
        severity=Severity.HIGH,
        score=70,
        artifact_id="a",
    )
    f2 = Finding(
        analyzer="x",
        rule="x.z",
        title="t2",
        category=FindingCategory.MALWARE,
        severity=Severity.HIGH,
        score=70,
        artifact_id="fantasma",
    )
    a = build_alert(make_result(artifacts=arts, findings=[f1, f2]), alert_settings)
    assert a.attachments[0].display_name == "dos.zip › uno.zip"
    assert a.attachments[1].display_name == "fantasma"
    assert a.attachments[1].sha256 == ""
    assert "(sin hash)" in a.to_text()


def test_surrogates_and_controls_never_break_json(alert_settings):
    r = make_result(subject="hola \ud800 mundo ​‍", from_display="\udcff")
    a = build_alert(r, alert_settings)
    json.dumps(a.machine, ensure_ascii=False).encode("utf-8")  # no lanza
    assert a.subject == "hola mundo"


def test_machine_caps(alert_settings):
    a = build_alert(hostile_result(), alert_settings)
    raw = json.dumps(a.machine, ensure_ascii=False)
    assert len(a.machine["findings"]) <= 100
    assert len(a.machine["message"]["to"]) == 50
    assert len(raw) < 300_000


# --------------------------------------------------------------------------- CEF


def test_cef_structure_and_severity(alert_settings, malicious):
    a = build_alert(malicious, alert_settings)
    cef = a.to_cef()
    parts = cef.split("|", 7)
    assert parts[:7] == [
        "CEF:0",
        "Centinela",
        "Centinela",
        parts[3],
        "yara.AgentTesla",
        "Mail malicioso detectado en ventas@empresa.com",
        "10",
    ]
    ext = parts[7]
    assert "\n" not in cef
    assert "act=alert" in ext and "cat=malicious" in ext
    assert f"fileHash={SHA_EXE}" in ext
    assert "cs2Label=malwareFamilies cs2=AgentTesla" in ext
    assert "request=hxxps://pagos-afip[.]com/login[.]php?token\\=XYZ" in ext
    sus = build_alert(bec_result(score=40), alert_settings)
    assert sus.to_cef().split("|")[6] == "5"


def test_cef_escaping_of_hostile_values(alert_settings):
    f = Finding(
        analyzer="x",
        rule="weird|rule\\id",
        title="t",
        category=FindingCategory.MALWARE,
        severity=Severity.CRITICAL,
        score=99,
    )
    r = make_result(subject="a=b\\c|d", findings=[f], message_id=None)
    cef = build_alert(r, alert_settings).to_cef()
    header, _, _ = cef.rpartition("|")
    assert "weird\\|rule\\\\id" in header
    assert "cs1=a\\=b\\\\c|d" in cef  # en extensiones el pipe no se escapa
    assert "cs3Label" not in cef  # sin Message-ID no va el label vacío


def test_cef_escape_functions():
    assert cef_escape_header("a|b\\c") == "a\\|b\\\\c"
    assert cef_escape_header("x\ny") == "x y"
    assert cef_escape_extension("k=v\\w\nz\r") == "k\\=v\\\\w\\nz"
    assert cef_escape_extension("line1\r\nline2") == "line1\\nline2"


# --------------------------------------------------------------------------- utilidades


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://example.com/a.php", "hxxps://example[.]com/a[.]php"),
        ("http://192.168.0.1/x", "hxxp://192[.]168[.]0[.]1/x"),
        ("HTTPS://Evil.COM", "hxxps://Evil[.]COM"),
        ("ftp://files.example.org", "fxp://files[.]example[.]org"),
        ("https://a.com/?next=https://b.com", "hxxps://a[.]com/?next=hxxps://b[.]com"),
    ],
)
def test_defang_url(url, expected):
    assert defang_url(url, None) == expected


def test_defang_text_domains_but_not_filenames():
    assert defang_text("visitá evil.com ya") == "visitá evil[.]com ya"
    assert defang_text("www.algo.zip") == "www[.]algo[.]zip"
    assert defang_text("abrí factura.pdf.exe y factura.zip") == "abrí factura.pdf.exe y factura.zip"
    assert defang_text("versión 1.2.3 y IP 10.0.0.1") == "versión 1.2.3 y IP 10.0.0.1"
    assert defang_text("login.microsoftonline.com.evil.ru/x") == "login[.]microsoftonline[.]com[.]evil[.]ru/x"
    assert defang_text("ya defangueado hxxps://a[.]com") == "ya defangueado hxxps://a[.]com"
    assert defang_text("") == ""


def test_defang_email():
    assert defang_email("juan@proveedor.com.ar") == "juan@proveedor[.]com[.]ar"
    assert defang_email(None) == ""


def test_clean_text():
    assert clean_text("a‮b", 50) == "a[U+202E]b"
    assert clean_text("a​b\x00c\x7f", 50) == "abc"
    assert clean_text("uno\r\ndos\tes", 50) == "uno dos es"
    assert clean_text("uno\n\n\n\ndos", 50, multiline=True) == "uno\n\ndos"
    assert clean_text("x" * 100, 10) == "x" * 9 + "…"
    assert clean_text(None, 10) == ""


def test_regex_performance_on_pathological_input():
    import time

    evil = ("a." * 5000) + "1"
    t0 = time.perf_counter()
    defang_text(clean_text(evil, 2000))
    defang_text("http://" + "a" * 10000)
    assert time.perf_counter() - t0 < 2.0


def test_escape_discord():
    assert escape_discord("**x** [a](b) @everyone") == "\\*\\*x\\*\\* \\[a\\](b) \\@everyone"
    assert escape_discord("- item") == "\\- item"


def test_format_local_datetime():
    dt = datetime(2026, 10, 3, 17, 32, tzinfo=UTC)
    assert format_local_datetime(dt, "America/Argentina/Buenos_Aires") == "03/10/2026 14:32 (UTC-03:00)"
    assert format_local_datetime(dt, "America/Mexico_City") == "03/10/2026 11:32 (UTC-06:00)"
    assert format_local_datetime(dt, "No/Existe") == "03/10/2026 17:32 (UTC)"
    assert format_local_datetime(dt.replace(tzinfo=None), "UTC") == "03/10/2026 17:32 (UTC)"
    assert format_local_datetime(None, "UTC") == "(sin fecha)"
