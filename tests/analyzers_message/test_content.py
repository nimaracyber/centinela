"""Tests de ContentAnalyzer: señuelos en ES/PT/EN, BEC y 'adjunto cifrado + contraseña en el texto'."""

from __future__ import annotations

import time

import pytest

from centinela.analyzers.content import ContentAnalyzer, _password_hint, html_to_text, normalize_text
from centinela.core.models import ExtractedUrl, FindingCategory, ParsedMessage, Severity
from tests.helpers import make_artifact, make_ref


def msg(subject: str = "", text: str = "", html: str = "", artifacts=None, urls=None) -> ParsedMessage:
    return ParsedMessage(
        ref=make_ref(),
        subject=subject,
        body_text=text,
        body_html=html,
        artifacts=artifacts or [],
        urls=[ExtractedUrl(url=x, source="body_html") for x in (urls or [])],
    )


async def run(make_ctx, m: ParsedMessage):
    return await ContentAnalyzer(make_ctx().settings).analyze(make_ctx(m))


def by_rule(findings):
    return {f.rule: f for f in findings}


def zip_att(name: str = "factura.zip", encrypted: bool = False):
    a = make_artifact(b"PK\x03\x04" + b"\x00" * 20, name, "zip")
    a.encrypted = encrypted
    return a


def pdf_att(name: str = "factura.pdf"):
    return make_artifact(b"%PDF-1.7\n%inert\n", name, "pdf")


# --------------------------------------------------------------------------- contraseña de adjunto


@pytest.mark.parametrize(
    ("text", "artifacts"),
    [
        ("Le envío la factura. La contraseña del archivo es 1234", [zip_att()]),
        ("CONTRASEÑA DEL ARCHIVO: 4321", [zip_att()]),
        ("Adjunto comprobante. Clave: Fc2024", [zip_att("comprobante.7z", encrypted=True)]),
        ("El archivo está protegido con contraseña, se la paso por WhatsApp", [zip_att(encrypted=True)]),
        ("Password: invoice2024", [zip_att("invoice.rar")]),
        ("Senha do arquivo: 9876", [zip_att("nota_fiscal.zip")]),
        ("pass 2024abc", [zip_att()]),
    ],
)
async def test_password_protected_lure(make_ctx, text, artifacts):
    r = by_rule(await run(make_ctx, msg("Factura", text, artifacts=artifacts)))
    f = r["content.password_protected_lure"]
    assert f.score == 65 and f.severity == Severity.HIGH
    assert f.category == FindingCategory.SUSPICIOUS_FILE


async def test_password_masked_in_evidence(make_ctx):
    r = by_rule(await run(make_ctx, msg("", "La contraseña del archivo es 1234", artifacts=[zip_att()])))
    hint = r["content.password_protected_lure"].evidence["password_hint"]
    assert hint == "1***"  # nunca la contraseña completa


async def test_password_with_plain_pdf_is_low(make_ctx):
    r = by_rule(
        await run(
            make_ctx,
            msg("Recibo de sueldo", "La clave para abrir el documento es 20304050", artifacts=[pdf_att()]),
        )
    )
    assert r["content.password_hint"].score == 15
    assert "content.password_protected_lure" not in r


async def test_password_protected_nested_archive_is_lure(make_ctx):
    # .eml adjunto (no es comprimido) que trae adentro un zip con contraseña, abierto con la clave del texto
    eml = make_artifact(b"From: x@y\r\n\r\nhola", "reenviado.eml", "eml", id="att0")
    inner = make_artifact(
        b"PK\x03\x04", "factura.zip", "zip", id="att0/factura.zip", depth=1, parent_id="att0"
    )
    inner.password_protected = True  # se pudo abrir: igual es la técnica de evasión
    r = by_rule(
        await run(make_ctx, msg("Factura", "La contraseña del archivo es 1234", artifacts=[eml, inner]))
    )
    f = r["content.password_protected_lure"]
    assert f.score == 65 and f.severity == Severity.HIGH
    assert f.evidence["password_protected"] == ["factura.zip"]
    assert f.evidence["encrypted"] is False
    assert "content.password_hint" not in r


async def test_password_protected_document_opened_stays_low(make_ctx):
    # un PDF/Office abierto con la clave lo evalúan sus analizadores: acá solo la pista débil
    pdf = pdf_att("recibo.pdf")
    pdf.password_protected = True
    r = by_rule(
        await run(make_ctx, msg("Recibo", "La clave para abrir el documento es 20304050", artifacts=[pdf]))
    )
    assert r["content.password_hint"].score == 15
    assert "content.password_protected_lure" not in r


async def test_encrypted_document_that_could_not_be_opened_is_lure(make_ctx):
    pdf = pdf_att("factura.pdf")
    pdf.encrypted = pdf.password_protected = True
    r = by_rule(await run(make_ctx, msg("Factura", "Clave: Fc2024", artifacts=[pdf])))
    assert r["content.password_protected_lure"].evidence["password_protected"] == ["factura.pdf"]


async def test_password_without_attachment_ignored(make_ctx):
    r = by_rule(await run(make_ctx, msg("Alta de usuario", "Tu contraseña temporal es Xy12345")))
    assert "content.password_hint" not in r and "content.password_protected_lure" not in r


@pytest.mark.parametrize(
    "text",
    [
        "Ingresá con tu clave fiscal en la web de AFIP",
        "Tu contraseña expira en 5 días",
        "La contraseña es incorrecta",
        "Código de verificación de envío",
        "Nunca compartas tu clave con nadie",
    ],
)
def test_password_hint_negative(text):
    masked, _present = _password_hint(normalize_text(text))
    assert masked is None


# --------------------------------------------------------------------------- BEC


@pytest.mark.parametrize(
    "text",
    [
        "Le informamos nuestro nuevo CBU para futuras transferencias: 0000003100000000000000",
        "Por favor tomar nota del cambio de cuenta bancaria a partir de este mes.",
        "Nuestros datos bancarios fueron actualizados, abonar al nuevo alias PAGOS.PROVEEDOR",
        "Les pasamos el CVU nuevo para el pago de la factura",
        "Please note our new bank account details for the next payment.",
        "Updated payment instructions attached.",
        "Informamos a nova conta bancária para pagamento.",
        "Cambiamos nuestros datos bancarios",
    ],
)
async def test_bec_bank_change(make_ctx, text):
    r = by_rule(await run(make_ctx, msg("Pago", text)))
    f = r["content.bec_bank_change"]
    assert f.score >= 45 and f.severity == Severity.MEDIUM


@pytest.mark.parametrize(
    "text",
    [
        "Le enviamos el nuevo resumen de cuenta corriente.",
        "Adjunto la factura, el CBU es el mismo de siempre.",
        "Abriste tu nueva caja de ahorro",
        "Tu cuenta fue actualizada con éxito",
    ],
)
async def test_bec_bank_change_negative(make_ctx, text):
    assert "content.bec_bank_change" not in by_rule(await run(make_ctx, msg("", text)))


async def test_bec_ceo_fraud_combo(make_ctx):
    text = (
        "Estoy en una reunión y no puedo hablar. Necesito un favor: comprá tarjetas de regalo de Google Play."
    )
    f = by_rule(await run(make_ctx, msg("Urgente", text)))["content.bec_lure"]
    assert f.score >= 40 and f.severity == Severity.MEDIUM


async def test_bec_single_phrase_is_low(make_ctx):
    f = by_rule(await run(make_ctx, msg("Consulta", "Hola, ¿estás disponible para una llamada el martes?")))[
        "content.bec_lure"
    ]
    assert f.score == 10 and f.severity == Severity.LOW


# --------------------------------------------------------------------------- credenciales / facturas / urgencia


@pytest.mark.parametrize(
    "text",
    [
        "Su buzón está lleno. Verifique su cuenta para seguir recibiendo correos.",
        "Su contraseña de Office 365 expira hoy",
        "Tiene 5 mensajes retenidos, ingrese sus credenciales para liberarlos",
        "Your mailbox is full. Verify your account.",
        "Sua caixa de correio cheia: atualize seus dados",
        "Detectamos actividad inusual: confirme su identidad",
    ],
)
async def test_credential_lure(make_ctx, text):
    f = by_rule(await run(make_ctx, msg("Aviso", text)))["content.credential_lure"]
    assert 15 <= f.score <= 40


async def test_credential_lure_combined_scores_higher(make_ctx):
    base = by_rule(await run(make_ctx, msg("Aviso", "Su buzón está lleno")))["content.credential_lure"].score
    combo = by_rule(
        await run(
            make_ctx,
            msg(
                "Aviso",
                "Su buzón está lleno. Verifique dentro de las 24 horas",
                urls=["https://x.example/login"],
            ),
        )
    )["content.credential_lure"]
    assert combo.score > base
    assert combo.severity == Severity.MEDIUM


@pytest.mark.parametrize(
    ("subject", "artifacts", "score"),
    [
        ("Factura N° 0001-00001234", [], 10),
        ("Factura N° 0001-00001234", [pdf_att()], 15),
        ("Factura N° 0001-00001234", [zip_att()], 30),
        ("Comprovante de pagamento", [make_artifact(b"MZ", "comprovante.exe", "pe")], 30),
        ("Invoice #4411", [make_artifact(b"<html>", "invoice.html", "html")], 30),
        ("Carta documento - intimación de pago", [], 10),
    ],
)
async def test_invoice_lure(make_ctx, subject, artifacts, score):
    f = by_rule(await run(make_ctx, msg(subject, "Adjunto el documento.", artifacts=artifacts)))[
        "content.invoice_lure"
    ]
    assert f.score == score
    assert f.evidence["in_subject"] is True


async def test_urgency_alone_is_weak(make_ctx):
    out = await run(make_ctx, msg("URGENTE", "Necesito esto hoy mismo"))
    assert [(f.rule, f.score) for f in out] == [("content.urgency", 5)]


async def test_zero_width_obfuscation_is_removed(make_ctx):
    r = by_rule(await run(make_ctx, msg("Fac​tu­ra pendiente", "")))
    assert "content.invoice_lure" in r


async def test_word_boundaries(make_ctx):
    # "manufactura" no es "factura"; "arcade" no es "arca"
    out = await run(make_ctx, msg("Manufactura textil", "Visitá nuestro arcade de juegos"))
    assert out == []


async def test_html_only_body_and_script_ignored(make_ctx):
    html = "<html><head><title>factura</title></head><body><p>Su <b>buzón</b> est&aacute; lleno</p><script>var factura=1</script></body></html>"
    r = by_rule(await run(make_ctx, msg("", "", html=html)))
    assert "content.credential_lure" in r
    assert "content.invoice_lure" not in r  # "factura" solo estaba en <title>/<script>


# --------------------------------------------------------------------------- falsos positivos


@pytest.mark.parametrize(
    ("subject", "text"),
    [
        ("Novedades de octubre", "Conocé los nuevos productos de nuestra tienda. ¡Te esperamos!"),
        ("Reunión", "Nos vemos en la reunión del martes a las 10."),
        (
            "Consulta",
            "Gracias por su consulta.\n--\nEste mensaje es confidencial y está dirigido únicamente a su destinatario.",
        ),
        ("Hola", "Te paso el link de la presentación que vimos ayer."),
        ("Weekly update", "Here is the summary of this week's work."),
    ],
)
async def test_benign_mails_no_findings(make_ctx, subject, text):
    assert await run(make_ctx, msg(subject, text)) == []


async def test_legit_invoice_with_pdf_is_low(make_ctx):
    out = await run(
        make_ctx,
        msg(
            "Factura electrónica B 0003-00012345",
            "Estimado cliente, adjuntamos la factura del mes. Saludos.",
            artifacts=[pdf_att()],
        ),
    )
    assert out and all(f.score <= 15 for f in out)


# --------------------------------------------------------------------------- input hostil


def test_html_to_text_hostile():
    t0 = time.perf_counter()
    assert html_to_text("<div>" * 200_000 + "hola").endswith("hola")
    html_to_text("<script>" + "a" * 3_000_000)  # script sin cerrar, más grande que el límite
    html_to_text("<<<<>>>><!--" * 50_000)
    html_to_text("&#xFFFFFFFF;&#0;&bogus;" * 10_000)
    assert time.perf_counter() - t0 < 10


async def test_huge_body_is_bounded(make_ctx):
    t0 = time.perf_counter()
    text = ("palabra " * 200_000) + " factura "
    out = await run(make_ctx, msg("x", text, html="<p>" + "y " * 500_000 + "</p>"))
    assert isinstance(out, list)
    assert time.perf_counter() - t0 < 10


async def test_regex_no_catastrophic_backtracking(make_ctx):
    # muchas palabras clave seguidas de rellenos sin valor final: debe terminar rápido
    evil = ("contraseña del archivo de la " * 5000) + ("nuevo de la " * 5000) + ("cbu " * 5000)
    t0 = time.perf_counter()
    await run(make_ctx, msg("x", evil, artifacts=[zip_att()]))
    assert time.perf_counter() - t0 < 5
