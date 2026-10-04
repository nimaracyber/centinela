"""Escenarios completos con los 4 analizadores de este grupo (headers, urls, content, filetype).

El score se combina igual que docs/ARCHITECTURE.md (noisy-OR, deduplicando por (rule, artifact_id, dedupe_key)
como el pipeline) para verificar que mails legítimos típicos de una PyME quedan por debajo del umbral de "sospechoso"
(30) y que campañas reales de malware/phishing/BEC lo superan con holgura.
"""

from __future__ import annotations

from centinela.analyzers.content import ContentAnalyzer
from centinela.analyzers.filetype import FileTypeAnalyzer
from centinela.analyzers.headers import HeaderAnalyzer
from centinela.analyzers.urls import UrlAnalyzer
from centinela.core.models import Artifact, ExtractedUrl, ParsedMessage
from centinela.parsing.archives import NOTE_ENCRYPTED, NOTE_NOT_EXTRACTED
from tests.helpers import make_artifact, make_ref

SUSPICIOUS = 30
MALICIOUS = 70


async def analyze_all(make_ctx, m: ParsedMessage):
    ctx = make_ctx(m)
    s = ctx.settings
    findings = []
    for a in (HeaderAnalyzer(s), UrlAnalyzer(s), ContentAnalyzer(s)):
        findings += await a.analyze(ctx)
    ft = FileTypeAnalyzer(s)
    for art in m.artifacts:
        if ft.accepts(art):
            findings += await ft.analyze(ctx, art)
    seen, uniq = set(), []
    for f in findings:
        if (f.rule, f.artifact_id, f.dedupe_key) not in seen:
            seen.add((f.rule, f.artifact_id, f.dedupe_key))
            uniq.append(f)
    prod = 1.0
    for f in uniq:
        prod *= 1 - f.score / 100
    return round((1 - prod) * 100), uniq


def url(u: str, display: str | None = None) -> ExtractedUrl:
    return ExtractedUrl(url=u, source="body_html", display_text=display)


PASS = (
    "Authentication-Results",
    "mx.google.com; dkim=pass header.d=proveedor.com; spf=pass smtp.mailfrom=proveedor.com; dmarc=pass header.from=proveedor.com",
)


# --------------------------------------------------------------------------- legítimos


async def test_legit_supplier_invoice_with_pdf(make_ctx):
    m = ParsedMessage(
        ref=make_ref(),
        subject="Factura electrónica B 0003-00012345",
        from_addr="facturacion@proveedor.com",
        from_display="Facturación Proveedor S.A.",
        return_path="bounce@proveedor.com",
        headers=[PASS],
        body_text="Estimado cliente: adjuntamos la factura del mes. Puede ver su cuenta en www.proveedor.com. Saludos.",
        urls=[url("https://www.proveedor.com", "www.proveedor.com"), url("https://www.afip.gob.ar/", "Consulta AFIP"),
              url("mailto:cobranzas@proveedor.com", "cobranzas@proveedor.com")],
        artifacts=[make_artifact(b"%PDF-1.7\n", "Factura B 0003-00012345.pdf", "pdf", declared_content_type="application/pdf")],
    )  # fmt: skip
    score, findings = await analyze_all(make_ctx, m)
    assert score < SUSPICIOUS, [(f.rule, f.score) for f in findings]


async def test_legit_newsletter_via_esp(make_ctx):
    m = ParsedMessage(
        ref=make_ref(),
        subject="Novedades de octubre en Proveedor",
        from_addr="novedades@proveedor.com",
        from_display="Proveedor",
        return_path="bounce-mc.us1_123@mail123.mcsv.net",
        headers=[PASS],
        body_html="<p>Conocé los nuevos productos.</p><a href='x'>Ver en el navegador</a>",
        urls=[
            url("https://proveedor.us1.list-manage.com/track/click?u=1&id=2&e=3", "Ver productos"),
            url("https://proveedor.us1.list-manage.com/track/click?u=1&id=4&e=3", "www.proveedor.com"),
            url("https://www.facebook.com/proveedor", "Facebook"),
            url("https://www.instagram.com/proveedor", "Instagram"),
            url("https://wa.me/5491112345678", "WhatsApp"),
            url("https://proveedor.us1.list-manage.com/unsubscribe?u=1", "Desuscribirse"),
        ],
    )
    score, findings = await analyze_all(make_ctx, m)
    assert score < SUSPICIOUS, [(f.rule, f.score) for f in findings]


async def test_legit_internal_mail(make_ctx):
    m = ParsedMessage(
        ref=make_ref(),
        subject="Reunión del martes",
        from_addr="juan@empresa.com",
        from_display="Juan Pérez",
        headers=[
            (
                "Authentication-Results",
                "mx.google.com; dkim=pass header.d=empresa.com; spf=pass smtp.mailfrom=empresa.com; dmarc=pass header.from=empresa.com",
            )
        ],
        body_text="Te paso la presentación para el martes. Saludos.",
        urls=[
            url(
                "https://empresa.sharepoint.com/sites/ventas/Shared%20Documents/presentacion.pptx",
                "presentación",
            )
        ],
        artifacts=[make_artifact(b"PK\x03\x04", "presentacion.pptx", "ooxml")],
    )
    score, findings = await analyze_all(make_ctx, m)
    assert score == 0, [(f.rule, f.score) for f in findings]


# --------------------------------------------------------------------------- maliciosos


async def test_malspam_zip_with_double_extension_and_password(make_ctx):
    z = make_artifact(b"PK\x03\x04", "comprobante.zip", "zip", id="att0")
    exe = make_artifact(
        b"MZ", "comprobante.pdf.exe", "pe", id="att0/comprobante.pdf.exe", depth=1, parent_id="att0"
    )
    m = ParsedMessage(
        ref=make_ref(),
        subject="Comprobante de transferencia",
        from_addr="avisos@mercadopag0.com",
        from_display="Mercado Pago",
        headers=[
            (
                "Authentication-Results",
                "mx.google.com; spf=softfail smtp.mailfrom=mercadopag0.com; dkim=none; dmarc=none",
            )
        ],
        body_text="Adjuntamos el comprobante. La contraseña del archivo es 1234",
        artifacts=[z, exe],
    )
    score, findings = await analyze_all(make_ctx, m)
    rules = {f.rule for f in findings}
    assert score >= 90
    assert {"headers.lookalike_brand", "headers.display_name_brand", "content.password_protected_lure",
            "filetype.archive_only_executable", "filetype.double_extension"} <= rules  # fmt: skip


async def test_credential_phishing_m365(make_ctx):
    m = ParsedMessage(
        ref=make_ref(),
        subject="Su contraseña expira hoy",
        from_addr="no-reply@secure-mail.example",
        from_display="Microsoft 365",
        headers=[("Authentication-Results", "mx; spf=fail smtp.mailfrom=secure-mail.example; dmarc=none")],
        body_html="<p>Su contraseña de Office 365 expira hoy. Verifique su cuenta dentro de las 24 horas.</p>",
        urls=[
            url(
                "https://login-microsoftonline.web.app/?e=ventas@empresa.com",
                "https://login.microsoftonline.com",
            )
        ],
    )
    score, findings = await analyze_all(make_ctx, m)
    rules = {f.rule for f in findings}
    assert score >= MALICIOUS
    assert {
        "url.deceptive_link",
        "url.lookalike_brand",
        "content.credential_lure",
        "headers.display_name_brand",
    } <= rules


async def test_bec_ceo_fraud_bank_change(make_ctx):
    m = ParsedMessage(
        ref=make_ref(),
        subject="Pago a proveedor",
        from_addr="gerencia@empresa.com",
        from_display="Gerencia",
        reply_to=["gerencia.empresa@gmail.com"],
        headers=[
            (
                "Authentication-Results",
                "spf=fail (sender IP is 198.51.100.9) smtp.mailfrom=evil.example; dkim=none;dmarc=fail action=none header.from=empresa.com",
            )
        ],
        body_text="Estoy en una reunión. Necesito que hagas una transferencia hoy al nuevo CBU del proveedor.",
    )
    score, findings = await analyze_all(make_ctx, m)
    rules = {f.rule for f in findings}
    assert score >= MALICIOUS
    assert {"headers.own_domain_spoof", "headers.reply_to_mismatch", "content.bec_bank_change"} <= rules


async def test_iso_lnk_delivery(make_ctx):
    iso = make_artifact(b"\x00" * 64, "Pedido_2024.iso", "iso", id="att0")
    lnk = make_artifact(
        b"L\x00\x00\x00", "Pedido.pdf.lnk", "lnk", id="att0/Pedido.pdf.lnk", depth=1, parent_id="att0"
    )
    m = ParsedMessage(ref=make_ref(), subject="Orden de compra", from_addr="compras@cliente-nuevo.example",
                      headers=[PASS], body_text="Adjunto orden de compra.", artifacts=[iso, lnk])  # fmt: skip
    score, findings = await analyze_all(make_ctx, m)
    assert score >= MALICIOUS, [(f.rule, f.score) for f in findings]


async def test_encrypted_zip_whose_exe_could_only_be_listed(make_ctx):
    # el zip tiene contraseña que no está en el mail: el .exe de adentro solo se pudo LISTAR (sin contenido)
    z = make_artifact(b"PK\x03\x04", "Factura_0923.zip", "zip", id="att0")
    z.password_protected = z.encrypted = True
    z.extraction_note = f"{NOTE_ENCRYPTED}: 1 archivo(s) no se pudieron abrir"
    exe = Artifact(
        id="att0/Factura_0923.exe", filename="Factura_0923.exe", size=900_000, depth=1, parent_id="att0",
        listing_only=True, extraction_note=f"{NOTE_NOT_EXTRACTED}: {NOTE_ENCRYPTED}: no se encontró la contraseña",
    )  # fmt: skip
    m = ParsedMessage(ref=make_ref(), subject="Factura vencida", from_addr="cobranzas@proveedor-nuevo.example",
                      headers=[PASS], body_text="Adjuntamos la factura. El archivo está protegido con contraseña.",
                      artifacts=[z, exe])  # fmt: skip
    score, findings = await analyze_all(make_ctx, m)
    rules = {f.rule for f in findings}
    assert score >= MALICIOUS, [(f.rule, f.score) for f in findings]
    assert {"filetype.encrypted_archive", "filetype.archive_only_executable", "filetype.executable_in_archive",
            "content.password_protected_lure"} <= rules  # fmt: skip


async def test_newsletter_from_trusted_esp_is_clean_only_when_trusted(make_ctx, settings):
    m = ParsedMessage(
        ref=make_ref(),
        subject="Novedades de octubre",
        from_addr="novedades@proveedor.com",
        from_display="Proveedor",
        return_path="rebote-123@envios-esp.net",
        headers=[
            (
                "Authentication-Results",
                "mx.google.com; spf=softfail smtp.mailfrom=envios-esp.net; dkim=fail "
                "header.d=proveedor.com; dmarc=none",
            )
        ],  # fmt: skip
        body_html="<p>Conocé los nuevos productos.</p>",
        urls=[
            url("https://click.envios-esp.net/c/abc", "www.proveedor.com"),
            url("https://lnk.envios-esp.net/" + "x" * 10, "Ver productos"),
        ],
    )
    before, findings = await analyze_all(make_ctx, m)
    assert before >= SUSPICIOUS, [(f.rule, f.score) for f in findings]
    settings.general.trusted_domains = ["envios-esp.net", "proveedor.com"]
    after, findings = await analyze_all(make_ctx, m)
    assert after < SUSPICIOUS, [(f.rule, f.score) for f in findings]
