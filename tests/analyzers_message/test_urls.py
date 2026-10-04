"""Tests de UrlAnalyzer. Ninguna URL se visita: el analizador es puramente léxico."""

from __future__ import annotations

import time

import httpx
import pytest
import respx

from centinela.analyzers.urls import UrlAnalyzer, analyze_urls
from centinela.core.models import ExtractedUrl, FindingCategory, ParsedMessage, Severity
from tests.helpers import make_ref

APPLE_CYR_PUNY = "xn--80ak6aa92e.com"  # "аррӏе.com" en cirílico


def u(url: str, display: str | None = None, source: str = "body_html") -> ExtractedUrl:
    return ExtractedUrl(url=url, source=source, display_text=display)


async def run(make_ctx, *urls: ExtractedUrl):
    m = ParsedMessage(ref=make_ref(), urls=list(urls))
    return await UrlAnalyzer(make_ctx().settings).analyze(make_ctx(m))


def by_rule(findings):
    return {f.rule: f for f in findings}


# --------------------------------------------------------------------------- detecciones


@pytest.mark.parametrize(
    ("url", "rule", "score"),
    [
        ("http://203.0.113.10/login", "url.ip_literal", 35),
        ("http://3232235777/x", "url.ip_literal", 50),  # 192.168.1.1 en decimal (ofuscada)
        ("http://0xC6336401/", "url.ip_literal", 50),  # hex
        ("http://0306.0063.0144.01/", "url.ip_literal", 50),  # octal
        ("http://[2606:4700::1111]/x", "url.ip_literal", 35),
        (f"https://{APPLE_CYR_PUNY}/id", "url.idn_homograph", 70),
        ("https://pаypal.com/signin", "url.idn_homograph", 70),  # 'а' cirílica mezclada
        ("https://ernpresa.com/login", "url.lookalike_domain", 70),
        ("https://empresa.com.ar.login-seguro.xyz/", "url.lookalike_domain", 65),
        ("https://mercadopag0.com/", "url.lookalike_brand", 70),
        ("https://afip-tramites.com/clave-fiscal", "url.lookalike_brand", 70),
        ("https://login.microsoftonline.com.secure-check.ru/", "url.lookalike_brand", 65),
        ("https://microsoft-login.web.app/", "url.lookalike_brand", 65),
        ("javascript:alert(document.cookie)", "url.dangerous_scheme", 75),
        ("JaVa\tScRiPt:alert(1)", "url.dangerous_scheme", 75),
        ("data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", "url.dangerous_scheme", 75),
        ("data:image/svg+xml;base64,PHN2Zz4=", "url.dangerous_scheme", 75),
        ("search-ms:query=factura&crumb=location:\\\\198.51.100.7@80\\share", "url.dangerous_scheme", 75),
        ("ms-msdt:/id PCWDiagnostic /skip force", "url.dangerous_scheme", 75),
        ("ms-officecmd:{...}", "url.dangerous_scheme", 75),
        ("ms-appinstaller:?source=https://evil.example/app.msix", "url.dangerous_scheme", 75),
        ("file://198.51.100.7/share/factura.lnk", "url.dangerous_scheme", 75),
        ("\\\\198.51.100.7\\share\\factura.pdf", "url.dangerous_scheme", 75),
        ("https://archivos-compartidos.net/factura.exe", "url.risky_download", 45),
        ("https://archivos-compartidos.net/d/Factura%20Abril.ZIP", "url.risky_download", 45),
        ("https://example.org/download.php?file=factura.js", "url.risky_download", 45),
        ("https://cdn.discordapp.com/attachments/1/2/factura.zip", "url.risky_download", 65),
        ("https://www.dropbox.com/s/abc/factura.zip?dl=1", "url.risky_download", 65),
        ("https://www.dropbox.com/s/abc/factura.zip?dl=0", "url.risky_download", 45),
        ("https://raw.githubusercontent.com/x/y/main/run.ps1", "url.risky_download", 65),
        ("https://github.com/x/y/releases/download/v1/setup.msi", "url.risky_download", 65),
        ("https://abc.trycloudflare.com/doc.hta", "url.risky_download", 65),
        ("https://ipfs.io/ipfs/bafybeigdyrzt/factura.iso", "url.risky_download", 65),
        ("https://bit.ly/3xYz", "url.shortener", 10),
        ("https://acortar.link/abc", "url.shortener", 10),
        ("https://microsoft.com@evil.example/login", "url.userinfo_trick", 70),
        ("https://www.bancogalicia.com.ar%2Flogin@evil.example/", "url.userinfo_trick", 70),
        ("https://a.b.c.d.e.f.random-host.com/", "url.long_hostname", 10),
        ("https://secure-login-account-verify-now.com/", "url.long_hostname", 10),
        ("http://servidor-raro.example:8081/x", "url.nonstandard_port", 20),
        ("https://foo-bar.workers.dev/login", "url.free_hosting", 15),
        ("https://abc123.ngrok-free.app/", "url.free_hosting", 15),
        ("www.ernpresa.com/login", "url.lookalike_domain", 70),  # sin esquema
    ],
)
async def test_url_detections(make_ctx, url, rule, score):
    r = by_rule(await run(make_ctx, u(url)))
    assert rule in r, (url, list(r))
    assert r[rule].score == score


async def test_risky_download_category_and_evidence(make_ctx):
    f = by_rule(await run(make_ctx, u("https://mega.nz/file/abc/factura.rar")))["url.risky_download"]
    assert f.category == FindingCategory.SUSPICIOUS_FILE
    assert f.severity == Severity.HIGH
    assert f.evidence["details"][0]["service"] == "MEGA"


async def test_backslash_is_slash_like_browsers(make_ctx):
    # WHATWG: "https://banco.com\@evil" va a banco.com (la "@" queda en el path) -> no es truco de usuario
    r = by_rule(await run(make_ctx, u("https://www.bancogalicia.com.ar\\@evil.example/")))
    assert "url.userinfo_trick" not in r
    assert "url.lookalike_brand" not in r


@pytest.mark.parametrize(
    ("display", "href", "score"),
    [
        ("https://www.bancogalicia.com.ar", "https://evil.example.net/x", 65),
        ("www.afip.gob.ar", "http://198.51.100.20/afip/", 65),
        ("Ingresá a www.empresa.com/portal", "https://portal-empresa.example/", 65),
        ("www.mercadopago.com.ar", "https://bit.ly/abc", 40),  # acortador: destino escondido
    ],
)
async def test_deceptive_link(make_ctx, display, href, score):
    r = by_rule(await run(make_ctx, u(href, display)))
    assert r["url.deceptive_link"].score == score
    assert r["url.deceptive_link"].evidence["details"][0]["display_domain"]


@pytest.mark.parametrize(
    ("display", "href"),
    [
        ("www.mercadolibre.com.ar", "https://www.mercadolibre.com.ar/ofertas"),
        ("mercadolibre.com.ar", "https://articulo.mercadolibre.com.mx/x"),  # misma marca, otro país
        ("Haga clic aquí", "https://www.afip.gob.ar/"),
        ("www.proveedor.com", "https://proveedor.us1.list-manage.com/track/click?u=1&id=2"),  # tracking ESP
        ("www.proveedor.com", "https://click.proveedor.com/ls/click?upn=abc"),
        ("WWW.EMPRESA.COM", "http://empresa.com/?utm_source=x"),
        ("10.5.2024", "https://www.empresa.com/agenda"),  # fecha, no IP
        ("Total $1.234,56", "https://www.empresa.com/pago"),
        ("factura.zip", "https://www.empresa.com/f/123"),  # TLD .zip sin www/esquema: es nombre de archivo
        ("soporte@empresa.com", "https://www.empresa.com/soporte"),
    ],
)
async def test_deceptive_link_negative(make_ctx, display, href):
    assert "url.deceptive_link" not in by_rule(await run(make_ctx, u(href, display)))


# --------------------------------------------------------------------------- desenvolver filtros


async def test_unwrap_safelinks(make_ctx):
    href = (
        "https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fmercadopag0.com%2Flogin"
        "&data=05%7C01%7C&sdata=abc&reserved=0"
    )
    f = by_rule(await run(make_ctx, u(href, "https://www.mercadopago.com.ar")))
    assert (
        f["url.lookalike_brand"]
        .evidence["details"][0]["unwrapped_from"]
        .endswith("safelinks.protection.outlook.com")
    )
    assert "url.deceptive_link" in f


async def test_unwrap_safelinks_legit_is_clean(make_ctx):
    href = (
        "https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fwww.bancogalicia.com.ar%2F&data=x"
    )
    assert await run(make_ctx, u(href, "https://www.bancogalicia.com.ar/")) == []


@pytest.mark.parametrize(
    ("href", "rule"),
    [
        (
            "https://urldefense.proofpoint.com/v2/url?u=https-3A__ernpresa.com_login&d=DwMF&c=x",
            "url.lookalike_domain",
        ),
        ("https://urldefense.com/v3/__https://ernpresa.com/login__;!!abc$", "url.lookalike_domain"),
        ("https://www.google.com/url?q=http://203.0.113.5/x&sa=D", "url.ip_literal"),
        ("https://linkprotect.cudasvc.com/url?a=https%3A%2F%2Fmercadopag0.com&c=E", "url.lookalike_brand"),
        ("https://l.facebook.com/l.php?u=https%3A%2F%2Fmercadopag0.com%2F&h=AT", "url.lookalike_brand"),
        ("https://www.google.com/url?q=javascript:alert(1)", "url.dangerous_scheme"),
        (
            "https://tracker.example/r?u=https%3A%2F%2Fmicros0ft.com%2F",
            "url.lookalike_brand",
        ),  # redirección abierta
    ],
)
async def test_unwrap_and_embedded(make_ctx, href, rule):
    assert rule in by_rule(await run(make_ctx, u(href)))


# --------------------------------------------------------------------------- falsos positivos


@pytest.mark.parametrize(
    "url",
    [
        "https://www.empresa.com/contacto",
        "https://intranet.empresa.com:8443/app",  # puerto en dominio propio
        "http://192.168.1.10/sistema",  # intranet
        "http://192.168.1.10:8080/",
        "http://[::1]/x",
        "mailto:ventas@empresa.com",
        "tel:+541112345678",
        "cid:image001.png@01D9",
        "#ancla",
        "/relativo/pagina",
        "https://www.linkedin.com/company/x",
        "https://www.facebook.com/empresa",
        "https://wa.me/5491112345678",
        "https://drive.google.com/file/d/abc/view?usp=sharing",
        "https://docs.google.com/document/d/x/edit",
        "https://www.afip.gob.ar/landing/default.asp",
        "https://login.microsoftonline.com/common/oauth2",
        "https://empresa.sharepoint.com/sites/ventas/Shared%20Documents/presupuesto.xlsx",
        "https://www.mercadolibre.com.ar/ofertas",
        "https://outlook.office365.com/owa/",
        "https://www.youtube.com/watch?v=abc",
        "data:image/png;base64,iVBORw0KGgo=",
        "https://aka.ms/mfasetup",
        "https://www.bancogalicia.com.ar/personas",
        "https://santanderrio.com.ar/banco/online",
    ],
)
async def test_legit_links_no_findings(make_ctx, url):
    out = await run(make_ctx, u(url))
    assert out == [], [(f.rule, f.score) for f in out]


async def test_legit_downloads_low_score(make_ctx):
    out = await run(
        make_ctx,
        u("https://www.afip.gob.ar/aplicativos/siap/descarga/siap.zip"),
        u("https://www.empresa.com/catalogo/lista-precios.zip"),
    )
    assert all(f.score <= 10 for f in out), [(f.rule, f.score) for f in out]


async def test_newsletter_mail_is_clean(make_ctx):
    out = await run(
        make_ctx,
        u("https://proveedor.us1.list-manage.com/track/click?u=1&id=2&e=3", "Ver ofertas"),
        u("https://proveedor.us1.list-manage.com/track/click?u=1&id=4&e=3", "www.proveedor.com"),
        u("https://www.facebook.com/proveedor", "Facebook"),
        u("https://www.instagram.com/proveedor", "Instagram"),
        u("https://proveedor.us1.list-manage.com/unsubscribe?u=1", "Desuscribirse"),
        u("mailto:info@proveedor.com", "info@proveedor.com"),
    )
    assert out == [], [(f.rule, f.score) for f in out]


# --------------------------------------------------------------------------- agrupación


async def test_grouping_one_finding_per_rule_with_domains(make_ctx):
    out = await run(
        make_ctx,
        u("https://mercadopag0.com/a"),
        u("https://mercadopag0.com/b"),
        u("https://micros0ft.com/x"),
    )
    lk = [f for f in out if f.rule == "url.lookalike_brand"]
    assert len(lk) == 1
    assert set(lk[0].evidence["domains"]) == {"mercadopag0.com", "micros0ft.com"}
    assert len(lk[0].evidence["urls"]) == 3
    assert "1 dominio más" in lk[0].title


async def test_grouping_caps_evidence(make_ctx):
    out = await run(make_ctx, *[u(f"http://203.0.113.{i}/x") for i in range(1, 30)])
    f = by_rule(out)["url.ip_literal"]
    assert len(f.evidence["urls"]) == 5
    assert len(f.evidence["domains"]) <= 20


async def test_artifact_source_sets_artifact_id(make_ctx):
    out = await run(
        make_ctx, u("https://mercadopag0.com/", source="artifact:att0"), u("https://mercadopag0.com/")
    )
    ids = sorted((f.artifact_id or "") for f in out if f.rule == "url.lookalike_brand")
    assert ids == ["", "att0"]


# --------------------------------------------------------------------------- trusted_domains / extra_brands


@pytest.mark.parametrize(
    ("url", "rule"),
    [
        ("https://a.b.c.d.e.f.cdn-proveedor.com/", "url.long_hostname"),
        ("http://erp.cdn-proveedor.com:8081/x", "url.nonstandard_port"),
        ("https://usuario@portal.cdn-proveedor.com/", "url.userinfo_trick"),  # variante no engañosa (LOW)
        ("https://facturas-proveedor.workers.dev/", "url.free_hosting"),
    ],
)
async def test_trusted_domain_skips_weak_signals(make_ctx, settings, url, rule):
    assert rule in by_rule(await run(make_ctx, u(url)))
    settings.general.trusted_domains = ["cdn-proveedor.com", "facturas-proveedor.workers.dev"]
    assert rule not in by_rule(await run(make_ctx, u(url)))


async def test_trusted_domain_lowers_download_like_a_known_site(make_ctx, settings):
    url = "https://descargas.cdn-proveedor.com/lista-precios.zip"
    assert by_rule(await run(make_ctx, u(url)))["url.risky_download"].score == 45
    settings.general.trusted_domains = ["cdn-proveedor.com"]
    assert by_rule(await run(make_ctx, u(url)))["url.risky_download"].score == 10


async def test_trusted_esp_tracker_is_not_a_deceptive_link(make_ctx, settings):
    link = u("https://click.envios-proveedor.net/r/abc123", "www.proveedor.com")
    assert by_rule(await run(make_ctx, link))["url.deceptive_link"].score == 65
    settings.general.trusted_domains = ["envios-proveedor.net"]
    assert "url.deceptive_link" not in by_rule(await run(make_ctx, link))


@pytest.mark.parametrize(
    ("url", "rule"),
    [
        ("https://mercadopag0.com/login", "url.lookalike_brand"),
        ("https://ernpresa.com/login", "url.lookalike_domain"),
        ("javascript:alert(1)", "url.dangerous_scheme"),
        ("https://www.mercadopago.com.ar@mercadopag0.com/", "url.userinfo_trick"),
    ],
)
async def test_trusted_domain_never_hides_strong_signals(make_ctx, settings, url, rule):
    settings.general.trusted_domains = ["mercadopag0.com", "ernpresa.com"]
    f = by_rule(await run(make_ctx, u(url)))[rule]
    assert f.severity == Severity.HIGH


async def test_bogus_trusted_entries_are_ignored(make_ctx, settings):
    settings.general.trusted_domains = ["com", "com.ar", "*.co", "203.0.113.10", "", "localhost"]
    r = by_rule(await run(make_ctx, u("https://a.b.c.d.e.f.random-host.com/"), u("http://203.0.113.10/x")))
    assert {"url.long_hostname", "url.ip_literal"} <= set(r)


async def test_extra_brands_are_protected(make_ctx, settings):
    settings.analyzers.extra_brands = [
        "Distribuidora Norte: distrinorte.com.ar, dnorte.com",
        "bancoregional.com.ar",
    ]
    r = by_rule(
        await run(make_ctx, u("https://bancoregional-login.com/"), u("https://distrinorte-facturas.com/x"))
    )
    f = r["url.lookalike_brand"]
    assert set(f.evidence["domains"]) == {"bancoregional-login.com", "distrinorte-facturas.com"}
    assert {d["imitates"] for d in f.evidence["details"]} == {"bancoregional.com.ar", "Distribuidora Norte"}
    # los dominios reales no se marcan, y dos dominios de la misma marca no son un "link engañoso"
    ok = await run(
        make_ctx,
        u("https://www.bancoregional.com.ar/personas"),
        u("https://www.distrinorte.com.ar/catalogo", "www.dnorte.com"),
    )
    assert ok == [], [(x.rule, x.score) for x in ok]


def test_sync_entrypoint_accepts_config_lists():
    out = analyze_urls(
        [u("https://bit.ly/x"), u("https://bancoregional-pagos.com/")],
        ["empresa.com"],
        trusted_domains=["bit.ly"],
        extra_brands=["bancoregional.com.ar"],
    )
    assert {f.rule for f in out} == {"url.lookalike_brand"}


# --------------------------------------------------------------------------- input hostil y sin red


@pytest.mark.parametrize(
    "url",
    [
        "http://[bad/",
        "http://:80",
        "http://%zz%zz/",
        "https://xn--zzzzzzzzzzzzz.com/",
        "http://a.com:99999/",
        "http://a.com:abc/",
        "https://" + "a." * 3000 + "com/",
        "https://example.com/?" + "&".join(f"k{i}=v" for i in range(5000)),
        "https://example.com/" + "%" * 10_000,
        "\x00\x01\x02javascript:alert(1)",
        "",
        "   ",
        "http://",
        "https://user:pass@",
        "ht!tp://weird",
        "https://" + "‮" * 100 + ".com",
    ],
    ids=lambda s: ascii(s[:40]),  # ids cortos: Windows limita el largo de PYTEST_CURRENT_TEST
)
async def test_hostile_urls_no_crash(make_ctx, url):
    out = await run(make_ctx, u(url))
    assert isinstance(out, list)


async def test_many_urls_capped_and_fast(make_ctx):
    urls = [u(f"https://host{i}.example{i % 7}.com/p?x={i}", f"www.dominio{i}.com") for i in range(3000)]
    t0 = time.perf_counter()
    out = await run(make_ctx, *urls)
    assert time.perf_counter() - t0 < 10
    dec = by_rule(out)["url.deceptive_link"]
    assert len(dec.evidence["urls"]) == 5


def test_sync_entrypoint_never_touches_network():
    with respx.mock(assert_all_called=False) as router:
        route = router.route().mock(return_value=httpx.Response(200))
        analyze_urls([u("https://mercadopag0.com/"), u("http://203.0.113.9/x.exe")], ["empresa.com"])
        assert not route.called
