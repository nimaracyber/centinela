"""Tests de HeaderAnalyzer: SPF/DKIM/DMARC, suplantación del nombre visible, Reply-To, lookalikes."""

from __future__ import annotations

import time

import pytest

from centinela.analyzers.headers import (
    HeaderAnalyzer,
    authserv_id_trusted,
    collect_auth,
    normalize_authserv_ids,
    parse_authentication_results,
    parse_received_spf,
    strip_comments,
)
from centinela.core.models import FindingCategory, ParsedMessage, Severity
from tests.helpers import make_ref

GMAIL_PASS = (
    "mx.google.com; dkim=pass header.i=@proveedor.com header.s=s1 header.b=AbCd; "
    "spf=pass (google.com: domain of ventas@proveedor.com designates 203.0.113.5 as permitted sender) "
    "smtp.mailfrom=ventas@proveedor.com; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=proveedor.com"
)
GMAIL_DMARC_FAIL = (
    "mx.google.com; dkim=none; spf=fail (google.com: domain of x@proveedor.com does not designate 198.51.100.9 "
    "as permitted sender) smtp.mailfrom=x@proveedor.com; dmarc=fail (p=REJECT sp=REJECT dis=REJECT) "
    "header.from=proveedor.com"
)
MS_OWN_SPOOF = (
    "spf=fail (sender IP is 198.51.100.9) smtp.mailfrom=evil.example; dkim=none (message not signed) "
    "header.d=none;dmarc=fail action=none header.from=empresa.com;compauth=fail reason=000"
)


def msg(**kw) -> ParsedMessage:
    kw.setdefault("from_addr", "ventas@proveedor.com")
    return ParsedMessage(ref=make_ref(), **kw)


async def run(make_ctx, m: ParsedMessage):
    return await HeaderAnalyzer(make_ctx().settings).analyze(make_ctx(m))


def rules(findings) -> dict[str, object]:
    return {f.rule: f for f in findings}


# --------------------------------------------------------------------------- parseo


def test_strip_comments_nested_and_quoted():
    assert strip_comments("a (b (c) d) e").split() == ["a", "e"]
    assert strip_comments('x="(no comment)" y').split() == ['x="(no', 'comment)"', "y"]
    assert strip_comments(r"a (esc \) still) b").split() == ["a", "b"]
    assert strip_comments("((((((").strip() == ""  # comentario sin cerrar: no explota


def test_parse_gmail_format():
    r = parse_authentication_results(GMAIL_PASS)
    assert r.authserv_id == "mx.google.com"
    assert (r.spf, r.dkim, r.dmarc) == ("pass", "pass", "pass")
    assert r.header_from == "proveedor.com"
    assert r.dkim_domains == ["proveedor.com"]


def test_parse_microsoft_format_without_authserv_id():
    r = parse_authentication_results(MS_OWN_SPOOF)
    assert r.authserv_id is None
    assert (r.spf, r.dkim, r.dmarc, r.compauth) == ("fail", "none", "fail", "fail")
    assert r.dmarc_policy == "none"
    assert r.header_from == "empresa.com"


def test_parse_semicolons_inside_comments_and_policy():
    r = parse_authentication_results(
        "mx.google.com; spf=pass (domain of a@b.com; designates (nested; comment) 1.2.3.4) smtp.mailfrom=b.com; "
        "dmarc=fail (p=QUARANTINE sp=NONE) header.from=b.com"
    )
    assert r.spf == "pass"
    assert r.dmarc == "fail"
    assert r.dmarc_policy == "quarantine"


def test_parse_dkim_any_pass_wins():
    r = parse_authentication_results("mx; dkim=fail header.d=a.com; dkim=pass header.d=b.com")
    assert r.dkim == "pass"
    assert r.dkim_domains == ["a.com", "b.com"]


def test_parse_arc_instance():
    r = parse_authentication_results(
        "i=2; mx.google.com; dmarc=fail header.from=x.com", source="arc-authentication-results"
    )
    assert r.instance == 2 and r.authserv_id == "mx.google.com" and r.dmarc == "fail"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("Pass (protection.outlook.com: domain of x designates 1.2.3.4 as permitted sender)", "pass"),
        (
            "SoftFail (protection.outlook.com: domain of transitioning x discourages use of 1.2.3.4)",
            "softfail",
        ),
        ("fail (google.com: domain of x does not designate 1.2.3.4) client-ip=1.2.3.4;", "fail"),
        ("garbage words here", None),
        ("", None),
    ],
)
def test_parse_received_spf(value, expected):
    assert parse_received_spf(value) == expected


def test_collect_uses_only_topmost_authentication_results():
    # el de abajo (falsificado por el atacante antes de enviar) dice pass; el de arriba (el proveedor) dice fail
    m = msg(
        headers=[
            ("Authentication-Results", GMAIL_DMARC_FAIL),
            ("Received", "x"),
            ("Authentication-Results", GMAIL_PASS),
        ]
    )
    assert collect_auth(m).dmarc == "fail"
    m2 = msg(
        headers=[
            ("Authentication-Results", GMAIL_PASS),
            ("Received", "x"),
            ("Authentication-Results", GMAIL_DMARC_FAIL),
        ]
    )
    assert collect_auth(m2).dmarc == "pass"


def test_collect_merges_adjacent_same_authserv():
    m = msg(
        headers=[
            ("Authentication-Results", "mx.example.net; spf=pass smtp.mailfrom=proveedor.com"),
            ("Authentication-Results", "mx.example.net; dmarc=fail header.from=proveedor.com"),
        ]
    )
    a = collect_auth(m)
    assert (a.spf, a.dmarc) == ("pass", "fail")


def test_collect_arc_fallback_highest_instance_and_received_spf():
    m = msg(
        headers=[
            ("ARC-Authentication-Results", "i=1; mx.relay.net; dmarc=pass header.from=proveedor.com"),
            ("ARC-Authentication-Results", "i=2; mx.google.com; dmarc=fail header.from=proveedor.com"),
            ("Received-SPF", "softfail (google.com: ...) client-ip=1.2.3.4"),
        ]
    )
    a = collect_auth(m)
    assert a.source == "arc-authentication-results"
    assert a.dmarc == "fail"
    assert a.spf == "softfail" and a.spf_source == "received-spf"


# --------------------------------------------------------------------------- autenticación


async def test_legit_mail_dmarc_pass_no_findings(make_ctx):
    out = await run(
        make_ctx, msg(from_display="Juan Pérez", headers=[("Authentication-Results", GMAIL_PASS)])
    )
    assert out == []


async def test_dmarc_fail_medium_40(make_ctx):
    r = rules(await run(make_ctx, msg(headers=[("Authentication-Results", GMAIL_DMARC_FAIL)])))
    f = r["headers.dmarc_fail"]
    assert f.score == 40 and f.severity == Severity.MEDIUM and f.category == FindingCategory.SPOOFING
    assert "headers.spf_fail" not in r  # ya contemplado dentro de DMARC
    assert f.evidence["dmarc"] == "fail"


async def test_dmarc_fail_policy_none_is_30(make_ctx):
    hdr = "mx.google.com; spf=fail smtp.mailfrom=proveedor.com; dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=proveedor.com"
    r = rules(await run(make_ctx, msg(headers=[("Authentication-Results", hdr)])))
    assert r["headers.dmarc_fail"].score == 30


async def test_own_domain_spoof_microsoft(make_ctx):
    m = msg(
        from_addr="ceo@empresa.com", from_display="CEO", headers=[("Authentication-Results", MS_OWN_SPOOF)]
    )
    r = rules(await run(make_ctx, m))
    f = r["headers.own_domain_spoof"]
    assert f.score == 70 and f.severity == Severity.HIGH
    assert "headers.dmarc_fail" not in r


async def test_own_domain_spoof_without_dmarc_record(make_ctx):
    hdr = "mx.empresa.com; spf=softfail smtp.mailfrom=empresa.com; dkim=none; dmarc=none header.from=empresa.com"
    r = rules(
        await run(make_ctx, msg(from_addr="pagos@empresa.com", headers=[("Authentication-Results", hdr)]))
    )
    assert "headers.own_domain_spoof" in r


async def test_own_domain_internal_pass_ok(make_ctx):
    hdr = "mx.google.com; dkim=pass header.d=empresa.com; spf=pass smtp.mailfrom=empresa.com; dmarc=pass header.from=empresa.com"
    out = await run(
        make_ctx,
        msg(from_addr="juan@empresa.com", from_display="Juan", headers=[("Authentication-Results", hdr)]),
    )
    assert out == []


async def test_own_domain_o365_internal_no_spf_ok(make_ctx):
    # correo interno de M365: sin SPF, dkim=none, dmarc=none -> NO es suplantación
    hdr = "dkim=none (message not signed) header.d=none;dmarc=none action=none header.from=empresa.com;"
    r = rules(
        await run(make_ctx, msg(from_addr="juan@empresa.com", headers=[("Authentication-Results", hdr)]))
    )
    assert "headers.own_domain_spoof" not in r


@pytest.mark.parametrize(
    ("headers", "rule", "score"),
    [
        (
            [
                (
                    "Received-SPF",
                    "Fail (protection.outlook.com: domain of proveedor.com does not designate ...)",
                )
            ],
            "headers.spf_fail",
            30,
        ),
        (
            [("Authentication-Results", "mx; spf=softfail smtp.mailfrom=proveedor.com; dmarc=none")],
            "headers.spf_softfail",
            10,
        ),
        (
            [("Authentication-Results", "mx; spf=hardfail smtp.mailfrom=proveedor.com")],
            "headers.spf_fail",
            30,
        ),
        (
            [("Authentication-Results", "mx; dkim=fail header.d=proveedor.com; dmarc=none")],
            "headers.dkim_fail",
            15,
        ),
        (
            [
                (
                    "Authentication-Results",
                    "spf=pass smtp.mailfrom=proveedor.com;dmarc=none;compauth=fail reason=001",
                )
            ],
            "headers.compauth_fail",
            15,
        ),
        ([], "headers.no_auth_results", 0),
        ([("Authentication-Results", "mx.google.com; none")], "headers.no_auth_results", 0),
    ],
)
async def test_auth_table(make_ctx, headers, rule, score):
    r = rules(await run(make_ctx, msg(headers=headers)))
    assert rule in r, list(r)
    assert r[rule].score == score


async def test_spf_fail_with_dmarc_pass_is_ignored(make_ctx):
    # reenvío automático: SPF falla pero DKIM alineado hace pasar DMARC
    hdr = "mx.google.com; dkim=pass header.d=proveedor.com; spf=fail smtp.mailfrom=fwd.example; dmarc=pass header.from=proveedor.com"
    out = await run(make_ctx, msg(headers=[("Authentication-Results", hdr)]))
    assert out == []


# --------------------------------------------------------------------------- nombre visible


@pytest.mark.parametrize(
    ("display", "from_addr", "rule", "score"),
    [
        ("ceo@empresa.com", "evil@gmail.com", "headers.display_name_spoof", 65),
        ("Soporte empresa.com", "x@evil.example", "headers.display_name_spoof", 65),
        ("pagos@bancogalicia.com.ar", "x@random.ru", "headers.display_name_spoof", 65),
        ("ventas@otrodominio.com.ar", "x@random.ru", "headers.display_name_spoof", 65),  # mostrado como email
        ("Info www.otrodominio.com.ar", "x@random.ru", "headers.display_name_spoof", 45),
        ("Banco Galicia", "x@random.ru", "headers.display_name_brand", 45),
        ("Banco Galicia", "bancogalicia.alertas@gmail.com", "headers.display_name_brand", 60),
        ("Microsoft Outlook", "security@outlook.com", "headers.display_name_brand", 60),
        ("Mercado Pago", "no-reply@mp-notificaciones.xyz", "headers.display_name_brand", 45),
        ("AFIP", "notificaciones@afip-ar.net", "headers.display_name_brand", 45),
    ],
)
async def test_display_name_positive(make_ctx, display, from_addr, rule, score):
    r = rules(
        await run(
            make_ctx,
            msg(
                from_display=display,
                from_addr=from_addr,
                headers=[("Authentication-Results", "mx; dmarc=pass")],
            ),
        )
    )
    assert rule in r, list(r)
    assert r[rule].score == score


@pytest.mark.parametrize(
    ("display", "from_addr"),
    [
        ("Juan Pérez", "juan@proveedor.com"),
        ("Juan Santander", "juan.santander@gmail.com"),  # apellido, no el banco
        ("Mercado Pago", "info@mercadopago.com.ar"),
        ("Mercado Libre", "novedades@e.mercadolibre.com.ar"),
        ("Banco Galicia", "avisos@bancogalicia.com.ar"),
        ("AFIP", "notificaciones@afip.gob.ar"),
        ("DocuSign NA3 System", "dse_na3@docusign.net"),
        ("juan@proveedor.com (vía Google Drive)", "drive-shares-dm-noreply@google.com"),
        ("Andreani via DocuSign", "dse@docusign.net"),
        ("ventas@proveedor.com", "ventas@proveedor.com"),
        ("Proveedor S.A. - proveedor.com", "facturacion@mail.proveedor.com"),
        ("J.R.R. Tolkien", "jrr@proveedor.com"),
        ("Envío factura.zip", "ventas@proveedor.com"),  # "factura.zip" no es un dominio en un nombre
    ],
)
async def test_display_name_negative(make_ctx, display, from_addr):
    r = rules(
        await run(
            make_ctx,
            msg(
                from_display=display,
                from_addr=from_addr,
                headers=[("Authentication-Results", "mx; dmarc=pass")],
            ),
        )
    )
    assert not {
        "headers.display_name_spoof",
        "headers.display_name_brand",
        "headers.display_name_company",
    } & set(r), r


async def test_display_name_company(make_ctx, settings):
    settings.general.company_name = "Empresa Ejemplo S.A."
    m = msg(
        from_display="Empresa Ejemplo - Gerencia",
        from_addr="gerencia.empresa@gmail.com",
        headers=[("Authentication-Results", "mx; dmarc=pass")],
    )
    r = rules(await run(make_ctx, m))
    assert r["headers.display_name_company"].score == 60
    # el mismo nombre desde el dominio propio no es sospechoso
    m2 = msg(
        from_display="Empresa Ejemplo - Gerencia",
        from_addr="gerencia@empresa.com",
        headers=[("Authentication-Results", "mx; dmarc=pass")],
    )
    assert "headers.display_name_company" not in rules(await run(make_ctx, m2))


async def test_display_name_company_default_name_not_used(make_ctx):
    # "Mi Empresa" (default) no se usa; la etiqueta del dominio propio ("empresa") sí
    m = msg(
        from_display="Mi Banco Amigo",
        from_addr="x@gmail.com",
        headers=[("Authentication-Results", "mx; dmarc=pass")],
    )
    assert "headers.display_name_company" not in rules(await run(make_ctx, m))


# --------------------------------------------------------------------------- Reply-To / Return-Path


@pytest.mark.parametrize(
    ("from_addr", "reply_to", "expected"),
    [
        ("ventas@proveedor.com", ["proveedor.pagos@gmail.com"], 35),
        ("ceo@empresa.com", ["ceo.empresa@gmail.com"], 45),  # "interno" que pide respuesta a casilla gratuita
        ("ventas@proveedor.com", ["pagos@empresa-pagos.com"], 35),  # Reply-To parecido al dominio propio
        ("ventas@proveedor.com", ["ventas@proveedor.com"], None),
        ("ventas@proveedor.com", ["soporte@mesadeayuda-proveedor.com"], None),  # corporativo, no gratuito
        ("ventas@proveedor.com", ["juan@mail.proveedor.com"], None),
        ("calendar-notification@google.com", ["organizador@gmail.com"], None),  # plataforma
        ("ventas@proveedor.com", [], None),
    ],
)
async def test_reply_to(make_ctx, from_addr, reply_to, expected):
    r = rules(
        await run(
            make_ctx,
            msg(
                from_addr=from_addr, reply_to=reply_to, headers=[("Authentication-Results", "mx; dmarc=pass")]
            ),
        )
    )
    if expected is None:
        assert "headers.reply_to_mismatch" not in r
    else:
        assert r["headers.reply_to_mismatch"].score == expected


@pytest.mark.parametrize(
    ("return_path", "auth", "expected"),
    [
        ("bounce@random-sender.net", "mx; spf=pass smtp.mailfrom=random-sender.net; dmarc=none", True),
        ("bounce@random-sender.net", "mx; dmarc=pass header.from=proveedor.com", False),
        ("0101abc@amazonses.com", "mx; dmarc=none", False),
        ("bounces+123@sendgrid.net", "mx; dmarc=none", False),
        ("ventas@proveedor.com", "mx; dmarc=none", False),
        ("<>", "mx; dmarc=none", False),
    ],
)
async def test_return_path(make_ctx, return_path, auth, expected):
    r = rules(await run(make_ctx, msg(return_path=return_path, headers=[("Authentication-Results", auth)])))
    assert ("headers.return_path_mismatch" in r) is expected
    if expected:
        assert r["headers.return_path_mismatch"].severity == Severity.LOW


# --------------------------------------------------------------------------- lookalikes


@pytest.mark.parametrize(
    ("from_addr", "rule"),
    [
        ("pagos@ernpresa.com", "headers.lookalike_domain"),
        ("pagos@empresa.com.ar", "headers.lookalike_domain"),
        ("pagos@empresa-pagos.com", "headers.lookalike_domain"),
        ("ceo@empressa.com", "headers.lookalike_domain"),
        ("ceo@xn--mpresa-2of.com", "headers.lookalike_domain"),  # е cirílica
        ("avisos@mercadopag0.com", "headers.lookalike_brand"),
        ("notificaciones@afip-tramites.com", "headers.lookalike_brand"),
    ],
)
async def test_lookalike_from(make_ctx, from_addr, rule):
    r = rules(
        await run(make_ctx, msg(from_addr=from_addr, headers=[("Authentication-Results", "mx; dmarc=pass")]))
    )
    f = r[rule]
    assert f.severity == Severity.HIGH
    assert f.score == (70 if rule == "headers.lookalike_domain" else 65)
    assert f.evidence["matches"][0]["header"] == "From"


async def test_lookalike_return_path_company_only(make_ctx):
    m = msg(return_path="b@ernpresa.com", headers=[("Authentication-Results", "mx; dmarc=pass")])
    r = rules(await run(make_ctx, m))
    assert r["headers.lookalike_domain"].evidence["matches"][0]["header"] == "Return-Path"


@pytest.mark.parametrize(
    "from_addr", ["juan@empresa.com", "a@proveedor.com", "x@mercadopago.com.ar", "y@gmail.com"]
)
async def test_lookalike_negative(make_ctx, from_addr):
    r = rules(
        await run(make_ctx, msg(from_addr=from_addr, headers=[("Authentication-Results", "mx; dmarc=pass")]))
    )
    assert "headers.lookalike_domain" not in r and "headers.lookalike_brand" not in r


async def test_no_company_domains_configured(make_ctx, settings):
    settings.general.company_domains = []
    m = msg(from_addr="pagos@ernpresa.com", headers=[("Authentication-Results", MS_OWN_SPOOF)])
    r = rules(await run(make_ctx, m))
    assert "headers.lookalike_domain" not in r and "headers.own_domain_spoof" not in r
    assert "headers.dmarc_fail" in r


# --------------------------------------------------------------------------- trusted_authserv_ids

FORGED_PASS = "mx.google.com; spf=pass smtp.mailfrom=proveedor.com; dkim=pass header.d=proveedor.com; dmarc=pass header.from=proveedor.com"  # fmt: skip


@pytest.mark.parametrize(
    ("authserv", "patterns", "expected"),
    [
        ("mx.google.com", ("mx.google.com",), True),
        ("MX.Google.com.", ("mx.google.com",), True),
        ("abc123.prod.outlook.com", ("*.prod.outlook.com",), True),
        ("a.b.prod.outlook.com", ("*.prod.outlook.com",), True),
        ("prod.outlook.com", ("*.prod.outlook.com",), False),  # "*." = solo subdominios
        ("evilprod.outlook.com", ("*.prod.outlook.com",), False),
        ("mx.google.com.evil.example", ("mx.google.com",), False),
        (None, ("mx.google.com",), False),
        ("mx.google.com", (), False),
    ],
)
def test_authserv_id_trusted(authserv, patterns, expected):
    assert authserv_id_trusted(authserv, patterns) is expected


def test_normalize_authserv_ids():
    assert normalize_authserv_ids([" MX.Google.com. ", "*", "", "*.prod.outlook.com", "mx.google.com"]) == (
        "mx.google.com",
        "*.prod.outlook.com",
    )


async def test_trusted_authserv_skips_untrusted_results_above(make_ctx, settings):
    settings.general.trusted_authserv_ids = ["mx.google.com"]
    # un relay interno no confiable agregó un "pass" arriba; el de Google (confiable) dice fail
    m = msg(
        headers=[
            ("Authentication-Results", "relay.oficina.local; dmarc=pass header.from=proveedor.com"),
            ("Received", "x"),
            ("Authentication-Results", GMAIL_DMARC_FAIL),
        ]
    )
    r = rules(await run(make_ctx, m))
    assert r["headers.dmarc_fail"].evidence["authserv_id"] == "mx.google.com"
    assert collect_auth(m).dmarc == "pass"  # sin la lista: se usa el de más arriba


async def test_trusted_authserv_wildcard(make_ctx, settings):
    settings.general.trusted_authserv_ids = ["*.prod.outlook.com"]
    hdr = "dm6pr01mb1234.namprd01.prod.outlook.com; spf=fail smtp.mailfrom=proveedor.com; dmarc=fail header.from=proveedor.com"
    r = rules(await run(make_ctx, msg(headers=[("Authentication-Results", hdr)])))
    assert "headers.dmarc_fail" in r


async def test_trusted_authserv_none_match_is_info(make_ctx, settings):
    settings.general.trusted_authserv_ids = ["mx.empresa.com"]
    m = msg(
        headers=[
            (
                "Authentication-Results",
                FORGED_PASS,
            ),  # lo escribió quien mandó el mail (o un proveedor no listado)
            ("Authentication-Results", MS_OWN_SPOOF),  # Microsoft: sin authserv-id
            ("Received-SPF", "fail (google.com: domain of x does not designate 1.2.3.4)"),
        ]
    )
    out = await run(make_ctx, m)
    r = rules(out)
    f = r["headers.no_trusted_auth_results"]
    assert (f.severity, f.score, f.category) == (Severity.INFO, 0, FindingCategory.SPOOFING)
    assert f.title == "No hay resultados de autenticación confiables"
    assert f.evidence["authserv_ids_found"] == ["mx.google.com", "(sin authserv-id)"]
    assert f.evidence["trusted_authserv_ids"] == ["mx.empresa.com"]
    # ni el "pass" falso ni el Received-SPF se usan
    assert not {"headers.dmarc_fail", "headers.spf_fail", "headers.no_auth_results"} & set(r)


async def test_trusted_authserv_without_any_auth_header(make_ctx, settings):
    settings.general.trusted_authserv_ids = ["mx.google.com"]
    r = rules(await run(make_ctx, msg(headers=[("Received", "x")])))
    assert set(r) == {"headers.no_auth_results"}


async def test_trusted_authserv_arc_fallback_for_microsoft(make_ctx, settings):
    settings.general.trusted_authserv_ids = ["mx.microsoft.com"]
    m = msg(
        from_addr="ceo@empresa.com",
        headers=[
            ("ARC-Authentication-Results", "i=2; mx.evil.example; dmarc=pass header.from=empresa.com"),
            (
                "ARC-Authentication-Results",
                "i=1; mx.microsoft.com 1; spf=fail smtp.mailfrom=evil.example; dmarc=fail action=none "
                "header.from=empresa.com; dkim=none",
            ),
            ("Authentication-Results", MS_OWN_SPOOF.replace("dmarc=fail", "dmarc=pass")),  # sin authserv-id
        ],
    )
    r = rules(await run(make_ctx, m))
    f = r["headers.own_domain_spoof"]
    assert f.evidence["source"] == "arc-authentication-results"
    assert f.evidence["authserv_id"] == "mx.microsoft.com"


def test_trusted_authserv_merges_adjacent_same_id():
    m = msg(
        headers=[
            ("Authentication-Results", "mx.example.net; spf=pass smtp.mailfrom=proveedor.com"),
            ("Authentication-Results", "mx.example.net; dmarc=fail header.from=proveedor.com"),
        ]
    )
    a = collect_auth(m, ["mx.example.net"])
    assert (a.spf, a.dmarc) == ("pass", "fail")


async def test_many_untrusted_auth_headers_are_bounded(make_ctx, settings):
    settings.general.trusted_authserv_ids = ["mx.google.com"]
    hdrs = [("Authentication-Results", f"mx{i}.evil.example; " + "a=b; " * 2000) for i in range(800)]
    t0 = time.perf_counter()
    out = await run(make_ctx, msg(headers=hdrs))
    assert time.perf_counter() - t0 < 5
    assert len(rules(out)["headers.no_trusted_auth_results"].evidence["authserv_ids_found"]) == 5


# --------------------------------------------------------------------------- trusted_domains


@pytest.mark.parametrize(
    ("headers", "rule"),
    [
        ([("Authentication-Results", "mx; spf=softfail smtp.mailfrom=proveedor.com; dmarc=none")], "headers.spf_softfail"),
        ([("Authentication-Results", "mx; dkim=fail header.d=proveedor.com; dmarc=none")], "headers.dkim_fail"),
        ([("Authentication-Results", "spf=pass smtp.mailfrom=proveedor.com;dmarc=none;compauth=fail reason=001")],
         "headers.compauth_fail"),
    ],
)  # fmt: skip
async def test_trusted_domain_skips_weak_auth_signals(make_ctx, settings, headers, rule):
    assert rule in rules(await run(make_ctx, msg(headers=headers)))
    settings.general.trusted_domains = ["proveedor.com"]
    assert rule not in rules(await run(make_ctx, msg(headers=headers)))


async def test_trusted_domain_matches_subdomains_and_envelope(make_ctx, settings):
    settings.general.trusted_domains = ["@ESP-Envios.net"]
    hdr = "mx; spf=softfail smtp.mailfrom=bounces.esp-envios.net; dmarc=none"
    r = rules(
        await run(
            make_ctx, msg(from_addr="novedades@tienda.example", headers=[("Authentication-Results", hdr)])
        )
    )
    assert "headers.spf_softfail" not in r  # el sobre (smtp.mailfrom) es del ESP de confianza


async def test_trusted_domain_never_hides_strong_auth_failures(make_ctx, settings):
    settings.general.trusted_domains = ["proveedor.com"]
    r = rules(await run(make_ctx, msg(headers=[("Authentication-Results", GMAIL_DMARC_FAIL)])))
    assert r["headers.dmarc_fail"].score == 40
    r = rules(
        await run(
            make_ctx, msg(headers=[("Authentication-Results", "mx; spf=fail smtp.mailfrom=proveedor.com")])
        )
    )
    assert r["headers.spf_fail"].score == 30


async def test_trusted_domain_never_hides_own_domain_spoof(make_ctx, settings):
    settings.general.trusted_domains = ["empresa.com"]  # error de configuración: igual se detecta
    m = msg(from_addr="ceo@empresa.com", headers=[("Authentication-Results", MS_OWN_SPOOF)])
    assert rules(await run(make_ctx, m))["headers.own_domain_spoof"].score == 70


async def test_trusted_domain_return_path_and_reply_to(make_ctx, settings):
    m = msg(
        return_path="bounce@envios-proveedor.net",
        reply_to=["pagos@empresa-pagos.com"],
        headers=[("Authentication-Results", "mx; spf=pass smtp.mailfrom=envios-proveedor.net; dmarc=none")],
    )
    r = rules(await run(make_ctx, m))
    assert {"headers.return_path_mismatch", "headers.reply_to_mismatch", "headers.lookalike_domain"} <= set(r)
    settings.general.trusted_domains = ["envios-proveedor.net", "empresa-pagos.com"]
    r = rules(await run(make_ctx, m))
    assert "headers.return_path_mismatch" not in r and "headers.reply_to_mismatch" not in r
    assert "headers.lookalike_domain" in r  # imitar el dominio propio no es una señal débil


async def test_trusted_from_still_flags_reply_to_freemail(make_ctx, settings):
    settings.general.trusted_domains = ["proveedor.com"]
    m = msg(reply_to=["proveedor.pagos@gmail.com"], headers=[("Authentication-Results", "mx; dmarc=pass")])
    assert rules(await run(make_ctx, m))["headers.reply_to_mismatch"].score == 35  # BEC: no es señal débil


# --------------------------------------------------------------------------- extra_brands


async def test_extra_brand_display_name_and_lookalike(make_ctx, settings):
    settings.analyzers.extra_brands = ["Banco Regional: bancoregional.com.ar"]
    auth = [("Authentication-Results", "mx; dmarc=pass")]
    r = rules(
        await run(
            make_ctx, msg(from_display="Banco Regional", from_addr="avisos.banco@gmail.com", headers=auth)
        )
    )
    assert r["headers.display_name_brand"].score == 60
    assert r["headers.display_name_brand"].evidence["brands"] == ["Banco Regional"]
    r = rules(await run(make_ctx, msg(from_display="Banco Regional", from_addr="avisos@bancoregional-alertas.com",
                                      headers=auth)))  # fmt: skip
    assert r["headers.lookalike_brand"].evidence["matches"][0]["imitates"] == "Banco Regional"
    ok = rules(await run(make_ctx, msg(from_display="Banco Regional", from_addr="avisos@bancoregional.com.ar",
                                       headers=auth)))  # fmt: skip
    assert not {"headers.display_name_brand", "headers.lookalike_brand"} & set(ok)


# --------------------------------------------------------------------------- input hostil


@pytest.mark.parametrize(
    "headers",
    [
        [("Authentication-Results", "(" * 200_000)],
        [("Authentication-Results", "a=b; " * 50_000)],
        [("Authentication-Results", "\x00\xff�;;;;===")],
        [("Authentication-Results", "")],
        [("ARC-Authentication-Results", "i=999999999; x")],
        [("Received-SPF", ")" * 100_000)],
        [("X-Junk", "y")] * 20_000,
    ],
)
async def test_hostile_headers_do_not_crash(make_ctx, headers):
    t0 = time.perf_counter()
    m = msg(
        from_display="‮" * 10_000 + "@" * 1000,
        from_addr="a@" + "b" * 5000 + ".com",
        headers=headers,
        reply_to=["x" * 10_000],
    )
    out = await run(make_ctx, m)
    assert isinstance(out, list)
    assert time.perf_counter() - t0 < 5


async def test_missing_from(make_ctx):
    out = await run(
        make_ctx, ParsedMessage(ref=make_ref(), headers=[("Authentication-Results", GMAIL_DMARC_FAIL)])
    )
    assert {f.rule for f in out} == {"headers.dmarc_fail"}
