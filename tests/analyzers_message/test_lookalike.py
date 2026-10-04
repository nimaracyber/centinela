"""Tests del helper compartido de dominios parecidos (offline, sin red)."""

from __future__ import annotations

import time

import pytest

from centinela.analyzers._lookalike import (
    LookalikeDetector,
    brands_in_text,
    domain_info,
    edit_distance,
    email_domain,
    host_in_domains,
    is_freemail,
    is_mixed_script,
    is_well_known,
    is_whole_script_confusable,
    normalize_domains,
    parse_extra_brands,
    parse_ipv4_whatwg,
    registrable_domain,
    skeleton,
)

CYR_E = "е"  # е cirílica
APPLE_CYR = "аррӏе"  # "аррӏе" todo en cirílico


@pytest.fixture(scope="module")
def det() -> LookalikeDetector:
    return LookalikeDetector(["empresa.com"])


@pytest.mark.parametrize(
    ("host", "kind"),
    [
        ("ernpresa.com", "homoglyph"),  # rn -> m
        ("empresa.com.ar", "tld_swap"),
        ("empresa.net", "tld_swap"),
        ("empresa-pagos.com", "affix"),
        ("pagos-empresa.com", "affix"),
        ("empresapagos.com", "affix"),
        ("empressa.com", "typo"),
        ("enpresa.com", "typo"),
        (f"{CYR_E}mpresa.com", "punycode"),
        ("empresa.com.facturas.xyz", "subdomain"),
        ("EMPRESA-PAGOS.COM.", "affix"),  # mayúsculas y punto final
    ],
)
def test_company_lookalike_positive(det, host, kind):
    m = det.company_match(host)
    assert m is not None, host
    assert m.kind == kind
    assert m.target == "empresa.com"
    assert not m.is_brand


@pytest.mark.parametrize(
    "host",
    [
        "empresa.com",
        "mail.empresa.com",
        "a.b.empresa.com",
        "empresarial.com",  # palabra real, no un agregado delimitado
        "empresa.sharepoint.com",  # tenant propio de M365
        "proveedor.com",
        "gmail.com",
        "192.0.2.1",
        "",
        "localhost",
    ],
)
def test_company_lookalike_negative(det, host):
    assert det.company_match(host) is None


def test_punycode_ascii_form_detected(det):
    ascii_form = domain_info(f"{CYR_E}mpresa.com").host
    assert ascii_form.startswith("xn--")
    m = det.company_match(ascii_form)
    assert m is not None and m.kind == "punycode"


@pytest.mark.parametrize(
    ("host", "brand", "kind"),
    [
        ("micros0ft.com", "Microsoft", "homoglyph"),
        ("rnicrosoft.com", "Microsoft", "homoglyph"),
        ("microsoft-login.com", "Microsoft", "affix"),
        ("office365-login.com", "Microsoft", "affix"),
        ("mercadopag0.com", "Mercado Pago", "homoglyph"),
        ("rnercadolibre.com.ar", "Mercado Libre", "homoglyph"),
        ("afip-tramites.com", "AFIP", "affix"),
        ("afip.com.ar", "AFIP", "tld_swap"),
        ("afip.gob.ar.tramites.com", "AFIP", "subdomain"),
        (f"{APPLE_CYR}.com", "Apple", "punycode"),
        ("docusign.co", "DocuSign", "tld_swap"),
        ("docusign-secure.sharepoint.com", "DocuSign", "subdomain"),
        ("microsoft-login.web.app", "Microsoft", "subdomain"),
        ("banco-galicia-online.com", "Banco Galicia", "affix"),
        ("dhl-tracking.info", "DHL", "affix"),
        ("g00gle.com", "Google", "homoglyph"),
        ("paypa1.com", "PayPal", "homoglyph"),
        ("we-transfer.com", "WeTransfer", "typo"),
        ("login.microsoftonline.com.evil.ru", "Microsoft", "subdomain"),
    ],
)
def test_brand_lookalike_positive(det, host, brand, kind):
    m = det.brand_match(host)
    assert m is not None, host
    assert m.target == brand
    assert m.kind == kind
    assert m.is_brand


@pytest.mark.parametrize(
    "host",
    [
        "login.microsoftonline.com",
        "outlook.office365.com",
        "mercadopago.com.ar",
        "mercadolibre.com.mx",
        "mercadolivre.com.br",
        "afip.gob.ar",
        "www.arca.gob.ar",
        "apple.com",
        "applebees.com",
        "pineapple.com",
        "officedepot.com",
        "groups.google.com",
        "google.com.ar",
        "google-analytics.com",
        "galicia.es",  # región de España: "galicia" es palabra genérica
        "santanderrio.com.ar",
        "cloud.com",
        "mail.com",
        "email.com",
        "lanacion.com.ar",
        "macromedia.com",
        "paypay.ne.jp",
        "mercadolibre.custhelp.com",  # mesa de ayuda SaaS de la marca
        "startups.com",
        "groups.io",
        "bna.com.ar",
        "naranjas.com",
        "docusign.net",
        "empresa.com",
    ],
)
def test_brand_lookalike_negative(det, host):
    assert det.brand_match(host) is None, host


@pytest.mark.parametrize(
    ("host", "expected", "obfuscated"),
    [
        ("3232235777", "192.168.1.1", True),
        ("0xC0A80101", "192.168.1.1", True),
        ("0300.0250.1.1", "192.168.1.1", True),
        ("192.168.1", "192.168.0.1", True),
        ("1.2.3.4", "1.2.3.4", False),
        ("1.2.3.4.", "1.2.3.4", False),
    ],
)
def test_parse_ipv4_whatwg(host, expected, obfuscated):
    assert parse_ipv4_whatwg(host) == (expected, obfuscated)


@pytest.mark.parametrize(
    "host", ["1.2.3.256", "example.com", "1.2.3.4.5", "9" * 40, "0x", "1..2", "", "0xZZ.1.1.1", "١.٢.٣.٤"]
)
def test_parse_ipv4_whatwg_rejects(host):
    # "0x" solo es 0.0.0.0 para WHATWG; el resto no son IPv4
    res = parse_ipv4_whatwg(host)
    if host == "0x":
        assert res == ("0.0.0.0", True)
    else:
        assert res is None


def test_skeleton_maps_confusables():
    assert skeleton("rnicrosoft") == skeleton("microsoft")
    assert skeleton("vvetransfer") == skeleton("wetransfer")
    assert skeleton("paypa1") == skeleton("paypal")
    assert skeleton("g00gle") == skeleton("google")
    assert skeleton(APPLE_CYR) == "apple"
    assert skeleton("Mícrosoft") == skeleton("microsoft")  # acentos
    assert skeleton("ｍｉｃｒｏｓｏｆｔ") == skeleton("microsoft")  # fullwidth


def test_edit_distance():
    assert edit_distance("empresa", "empressa", 2) == 1
    assert edit_distance("empresa", "emrpesa", 2) == 1  # transposición
    assert edit_distance("empresa", "zzzzzzzzzz", 2) == 3  # corta en limit+1
    assert edit_distance("a" * 500, "b" * 500, 2) == 3  # entradas largas acotadas


def test_scripts():
    assert is_mixed_script("pаypal")  # a cirílica en palabra latina
    assert not is_mixed_script("paypal")
    assert not is_mixed_script("яндекс")
    assert is_whole_script_confusable(APPLE_CYR)
    assert not is_whole_script_confusable("яндекс")  # ruso legítimo: no se parece a latín
    assert not is_whole_script_confusable("apple")


def test_domain_info_and_registrable():
    info = domain_info("a.b.empresa.com.ar")
    assert info.registrable == "empresa.com.ar"
    assert info.subdomain == "a.b"
    assert registrable_domain("mail.empresa.com") == "empresa.com"
    assert registrable_domain("afip.gob.ar") == "afip.gob.ar"
    assert registrable_domain("192.0.2.1") == "192.0.2.1"
    assert domain_info("[2001:db8::1]").is_ip
    assert domain_info("www。empresa。com").registrable == "empresa.com"  # puntos ideográficos


@pytest.mark.parametrize(
    "host",
    [
        "",
        "...",
        "xn--zzzzzzzzzzzzzzzzzzzzzzzz.com",
        "a" * 5000,
        ("x" * 63 + ".") * 200 + "com",
        "\x00\x01.com",
        "[::zz]",
    ],
)
def test_domain_info_hostile(host):
    t0 = time.perf_counter()
    domain_info(host)  # no debe explotar
    LookalikeDetector(["empresa.com"]).match(host)
    assert time.perf_counter() - t0 < 1.0


def test_email_domain():
    assert email_domain("Juan@Proveedor.COM") == "proveedor.com"
    assert email_domain("<a@b.com>") == "b.com"
    assert email_domain("sin-arroba") == ""
    assert email_domain(None) == ""


def test_freemail_and_well_known():
    assert is_freemail("gmail.com")
    assert is_freemail("hotmail.com.ar")
    assert is_freemail("yahoo.com.mx")
    assert not is_freemail("empresa.com")
    assert is_well_known("www.afip.gob.ar")
    assert is_well_known("accounts.google.com")
    assert not is_well_known("x.web.app")  # hosting de usuarios
    assert not is_well_known("sites.google.com")
    assert not is_well_known("random-shop.xyz")


@pytest.mark.parametrize(
    ("text", "brands"),
    [
        ("Banco Galicia", ["Banco Galicia"]),
        ("Mercado Pago", ["Mercado Pago"]),
        ("Itaú", ["Itaú"]),
        ("Santander Alertas", ["Santander"]),
        ("ARCA Agencia de Recaudación", ["ARCA"]),
        ("UPS Delivery", ["UPS"]),
        ("Equipo de Soporte Office", ["Microsoft"]),
        ("Juan Santander", []),  # apellido
        ("Arca Continental", []),  # empresa real, sin contexto fiscal
        ("UPS", []),
        ("Pedro Gómez", []),
        ("", []),
    ],
)
def test_brands_in_text(text, brands):
    assert [b.name for b in brands_in_text(text)] == brands


def test_detector_ignores_bad_company_domains():
    d = LookalikeDetector(["", "  ", "@Empresa.com", "*.otra.com.ar", "1.2.3.4", "localhost"])
    assert d.company_regs == frozenset({"empresa.com", "otra.com.ar"})
    assert d.is_company("mail.otra.com.ar")
    assert d.same_entity("www.empresa.com", "otra.com.ar")
    assert d.same_entity("mercadopago.com.ar", "mercadolibre.com.mx")
    assert not d.same_entity("empresa.com", "gmail.com")


# --------------------------------------------------------------------------- dominios de confianza


def test_normalize_domains_and_matching():
    doms = normalize_domains(
        [
            "@Proveedor.COM",
            "*.esp-envios.net",
            "portal.socio.com.ar.",
            "com.ar",
            "co",
            "203.0.113.5",
            "localhost",
            "",
        ]
    )
    assert doms == frozenset({"proveedor.com", "esp-envios.net", "portal.socio.com.ar"})
    assert host_in_domains("proveedor.com", doms)
    assert host_in_domains("MAIL.Proveedor.com.", doms)
    assert host_in_domains("a.b.esp-envios.net", doms)
    assert host_in_domains("portal.socio.com.ar", doms)
    assert not host_in_domains("socio.com.ar", doms)  # se confió solo en el subdominio
    assert not host_in_domains("xproveedor.com", doms)
    assert not host_in_domains("proveedor.com.evil.ru", doms)
    assert not host_in_domains("", doms) and not host_in_domains("proveedor.com", frozenset())


def test_normalize_domains_idn_and_hostile():
    doms = normalize_domains(["pañalera.com.ar", "x" * 5000, None, 42])  # type: ignore[list-item]
    puny = domain_info("www.pañalera.com.ar").host
    assert puny.startswith("www.xn--")
    assert host_in_domains(puny, doms)  # forma ASCII (punycode) y Unicode son el mismo dominio
    assert host_in_domains("www.pañalera.com.ar", doms)
    assert len(doms) == 1
    assert normalize_domains(None) == frozenset()


# --------------------------------------------------------------------------- marcas extra


def test_parse_extra_brands_formats():
    brands = parse_extra_brands(
        [
            "bancoregional.com.ar",
            "Distribuidora Norte: distrinorte.com.ar, https://www.dnorte.com/inicio",
            "Coop Sur = coopsur.coop",
            "bcr.com.ar",  # etiqueta corta: solo homógrafos / agregados con anzuelo
            "Banco Sin Dominio",  # sin dominio: no se puede usar (se marcaría a sí mismo)
            "com.ar",
            "203.0.113.5",
            "",
        ]
    )
    by_name = {b.name: b for b in brands}
    assert set(by_name) == {"bancoregional.com.ar", "Distribuidora Norte", "Coop Sur", "bcr.com.ar"}
    dn = by_name["Distribuidora Norte"]
    assert dn.legit == ("distrinorte.com.ar", "dnorte.com")
    assert dn.keys == ("distrinorte", "dnorte", "distribuidoranorte")
    assert "distribuidora norte" in dn.display
    assert by_name["Coop Sur"].legit == ("coopsur.coop",)
    assert by_name["bcr.com.ar"].keys == () and by_name["bcr.com.ar"].weak_keys == ("bcr",)
    assert by_name["bancoregional.com.ar"].display == ("bancoregional",)


def test_parse_extra_brands_is_bounded():
    many = [f"marca{i}.com.ar" for i in range(500)]
    assert len(parse_extra_brands(many)) == 50
    assert parse_extra_brands(["x" * 100_000 + ".com"]) == ()
    assert parse_extra_brands(None) == ()


@pytest.mark.parametrize(
    ("host", "kind"),
    [
        ("bancoregional-pagos.com", "affix"),
        ("bancoregional.com", "tld_swap"),
        ("bancoreglonal.com.ar", "homoglyph"),
        ("bancoregional.com.ar.tramites-online.ru", "subdomain"),
        ("distribuidoranorte.com", "tld_swap"),
        ("bcr-login.com", "affix"),
    ],
)
def test_extra_brand_lookalikes(host, kind):
    d = LookalikeDetector(
        ["empresa.com"],
        extra_brands=["bancoregional.com.ar", "Distribuidora Norte: distrinorte.com.ar", "bcr.com.ar"],
    )
    m = d.brand_match(host)
    assert m is not None and m.kind == kind and m.is_brand


@pytest.mark.parametrize(
    "host",
    [
        "bancoregional.com.ar",
        "www.bancoregional.com.ar",
        "distrinorte.com.ar",
        "bcr.com",
        "mercadopago.com.ar",
    ],
)
def test_extra_brand_legit_domains_not_flagged(host):
    d = LookalikeDetector(["empresa.com"], extra_brands=["bancoregional.com.ar", "Distribuidora Norte: distrinorte.com.ar",
                                                         "bcr.com.ar"])  # fmt: skip
    assert d.brand_match(host) is None


def test_extra_brands_extend_builtin_list():
    d = LookalikeDetector(
        ["empresa.com"], extra_brands=["Distribuidora Norte: distrinorte.com.ar, dnorte.com"]
    )
    assert d.brand_match("micros0ft.com").target == "Microsoft"  # las de fábrica siguen
    assert [b.name for b in d.brands_in_text("Distribuidora Norte - Ventas")] == ["Distribuidora Norte"]
    assert d.same_entity("www.dnorte.com", "distrinorte.com.ar")
    assert brands_in_text("Distribuidora Norte") == []  # la lista de fábrica no cambia
    assert LookalikeDetector(["empresa.com"]).brand_match("distrinorte-pagos.com") is None
