"""UrlReputationAnalyzer (URLhaus) con HTTP mockeado por respx: privacidad primero."""

from __future__ import annotations

from urllib.parse import parse_qs

import httpx
import pytest
import respx
from pydantic import SecretStr

from centinela.analyzers.reputation import URLHAUS_API_URL, UrlReputationAnalyzer, reset_rate_limits
from centinela.core.models import ExtractedUrl, FindingCategory, ParsedMessage, Severity
from tests.helpers import make_ref

KEY = "urlhaus-clave-de-prueba"


@pytest.fixture(autouse=True)
def _reset_limits():
    reset_rate_limits()
    yield
    reset_rate_limits()


@pytest.fixture
def enabled(settings):
    settings.privacy.url_lookups = True
    settings.analyzers.reputation.urlhaus_api_key = SecretStr(KEY)
    return settings


@pytest.fixture
def router():
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as r:
        yield r


def _msg(*urls: str | tuple[str, str]) -> ParsedMessage:
    items = []
    for u in urls:
        url, source = u if isinstance(u, tuple) else (u, "body_html")
        items.append(ExtractedUrl(url=url, source=source))
    return ParsedMessage(ref=make_ref(), urls=items)


def _listed(threat: str = "malware_download", status: str = "online", signature: str | None = "AgentTesla"):
    return httpx.Response(
        200,
        json={
            "query_status": "ok",
            "id": "123456",
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/123456/",
            "url": "http://ignored",
            "url_status": status,
            "threat": threat,
            "tags": ["exe", "AgentTesla"],
            "date_added": "2026-09-30 10:00:00 UTC",
            "payloads": [{"filename": "x.exe", "signature": signature, "response_sha256": "ab" * 32}],
        },
    )


NO_RESULTS = httpx.Response(200, json={"query_status": "no_results"})


def _sent_urls(route) -> list[str]:
    return [parse_qs(c.request.content.decode())["url"][0] for c in route.calls]


async def test_listed_malware_url_is_high_and_request_is_correct(enabled, router, make_ctx):
    route = router.post(URLHAUS_API_URL).mock(return_value=_listed())
    an = UrlReputationAnalyzer(enabled)
    findings = await an.analyze(make_ctx(_msg("http://descargas-falsas.example/factura.exe")))
    assert len(findings) == 1
    f = findings[0]
    assert f.rule == "rep.urlhaus"
    assert f.analyzer == "url_reputation"
    assert f.category == FindingCategory.MALWARE
    assert f.severity == Severity.HIGH and f.score == 85
    assert f.malware_family == "AgentTesla"
    assert f.artifact_id is None
    assert f.evidence["urls"][0]["url"] == "http://descargas-falsas.example/factura.exe"
    assert f.evidence["urls"][0]["reference"] == "https://urlhaus.abuse.ch/url/123456/"
    req = route.calls.last.request
    assert req.headers["Auth-Key"] == KEY
    assert _sent_urls(route) == ["http://descargas-falsas.example/factura.exe"]


async def test_phishing_threat_maps_to_phishing(enabled, router, make_ctx):
    router.post(URLHAUS_API_URL).mock(return_value=_listed(threat="phishing", signature=None))
    findings = await UrlReputationAnalyzer(enabled).analyze(make_ctx(_msg("https://login-falso.example/x")))
    assert findings[0].category == FindingCategory.PHISHING and findings[0].malware_family is None


async def test_offline_or_unknown_status_scores(enabled, router, make_ctx):
    route = router.post(URLHAUS_API_URL)
    route.side_effect = [_listed(status="offline"), _listed(status="unknown")]
    an = UrlReputationAnalyzer(enabled)
    f_off = await an.analyze(make_ctx(_msg("http://a.example/1")))
    f_unk = await an.analyze(make_ctx(_msg("http://b.example/2")))
    assert f_off[0].score == 85 and f_unk[0].score == 75
    assert f_off[0].severity == f_unk[0].severity == Severity.HIGH


async def test_unlisted_urls_produce_nothing(enabled, router, make_ctx):
    router.post(URLHAUS_API_URL).mock(return_value=NO_RESULTS)
    assert await UrlReputationAnalyzer(enabled).analyze(make_ctx(_msg("https://www.example.com/"))) == []


async def test_privacy_flag_off_means_no_http(settings, router, make_ctx):
    settings.analyzers.reputation.urlhaus_api_key = SecretStr(KEY)
    assert settings.privacy.url_lookups is False  # por defecto, apagado
    assert (
        await UrlReputationAnalyzer(settings).analyze(make_ctx(_msg("http://descargas-falsas.example/a.exe")))
        == []
    )
    assert len(router.calls) == 0


async def test_without_key_or_disabled_no_http(enabled, router, make_ctx):
    enabled.analyzers.reputation.urlhaus_api_key = None
    assert (
        await UrlReputationAnalyzer(enabled).analyze(make_ctx(_msg("http://descargas-falsas.example/a")))
        == []
    )
    enabled.analyzers.reputation.urlhaus_api_key = SecretStr(KEY)
    enabled.analyzers.reputation.enabled = False
    assert UrlReputationAnalyzer.enabled(enabled) is False
    assert (
        await UrlReputationAnalyzer(enabled).analyze(make_ctx(_msg("http://descargas-falsas.example/a")))
        == []
    )
    assert len(router.calls) == 0


async def test_internal_and_non_http_urls_are_never_sent(enabled, router, make_ctx):
    route = router.post(URLHAUS_API_URL).mock(return_value=NO_RESULTS)
    msg = _msg(
        "http://192.168.1.10/intranet",
        "http://10.0.0.5:8080/x",
        "http://127.0.0.1/",
        "http://[::1]/x",
        "http://localhost/panel",
        "http://intranet/wiki",
        "https://empresa.com/portal",  # dominio propio (fixture: company_domains = ["empresa.com"])
        "https://mail.empresa.com/owa",
        "http://servidor.local/",
        "mailto:ventas@empresa.com",
        "ftp://203.0.113.30/archivo",
        "javascript:alert(1)",
        "http://",
        "http://x" + "a" * 3000 + ".example/",
        "http://203.0.113.40/ip-de-documentacion",  # no es una IP pública
        "http://100.64.0.1/cgnat",
        "http://169.254.169.254/latest/meta-data",
        "http://descargas.example/ok",
    )
    await UrlReputationAnalyzer(enabled).analyze(make_ctx(msg))
    assert _sent_urls(route) == ["http://descargas.example/ok"]


async def test_public_ip_urls_are_sent(enabled, router, make_ctx):
    route = router.post(URLHAUS_API_URL).mock(return_value=NO_RESULTS)
    await UrlReputationAnalyzer(enabled).analyze(make_ctx(_msg("http://8.8.8.8/x.exe")))
    assert _sent_urls(route) == ["http://8.8.8.8/x.exe"]


async def test_fragment_and_credentials_are_stripped(enabled, router, make_ctx):
    route = router.post(URLHAUS_API_URL).mock(return_value=NO_RESULTS)
    await UrlReputationAnalyzer(enabled).analyze(
        make_ctx(_msg("HTTPS://usuario:clave@evil.example:8443/path?q=1#token=secreto"))
    )
    assert _sent_urls(route) == ["https://evil.example:8443/path?q=1"]


async def test_dedupe_and_cap_per_message(enabled, router, make_ctx):
    route = router.post(URLHAUS_API_URL).mock(return_value=NO_RESULTS)
    urls = [f"http://sitio{i}.example/a" for i in range(30)]
    urls += ["http://sitio0.example/a", "http://sitio0.example/a#otro-fragmento"]
    await UrlReputationAnalyzer(enabled).analyze(make_ctx(_msg(*urls)))
    sent = _sent_urls(route)
    assert len(sent) == 20 and len(set(sent)) == 20
    assert sent[0] == "http://sitio0.example/a"


async def test_findings_are_grouped_by_source_artifact(enabled, router, make_ctx):
    router.post(URLHAUS_API_URL).mock(return_value=_listed())
    msg = _msg(
        ("http://cdn-malo.example0/a.exe", "body_html"),
        ("http://cdn-malo.example1/b.exe", "artifact:att0/doc.pdf"),
        ("http://cdn-malo.example2/c.exe", "artifact:att0/doc.pdf"),
    )
    findings = await UrlReputationAnalyzer(enabled).analyze(make_ctx(msg))
    by_art = {f.artifact_id: f for f in findings}
    assert set(by_art) == {None, "att0/doc.pdf"}
    assert by_art["att0/doc.pdf"].evidence["count"] == 2


async def test_timeout_becomes_info_note_and_other_urls_still_work(enabled, router, make_ctx):
    router.post(URLHAUS_API_URL, data={"url": "http://a.example/1"}).mock(side_effect=httpx.ReadTimeout("t"))
    router.post(URLHAUS_API_URL, data={"url": "http://c.example/3"}).mock(return_value=_listed())
    findings = await UrlReputationAnalyzer(enabled).analyze(
        make_ctx(_msg("http://a.example/1", "http://c.example/3"))
    )
    rules = {f.rule: f for f in findings}
    assert rules["rep.urlhaus"].severity == Severity.HIGH
    note = rules["rep.urlhaus.error"]
    assert note.severity == Severity.INFO and note.category == FindingCategory.POLICY
    assert note.evidence["errors"] == {"timeout": 1}


async def test_429_pauses_further_lookups(enabled, router, make_ctx):
    limited = router.post(URLHAUS_API_URL, data={"url": "http://b.example/2"}).mock(
        return_value=httpx.Response(429, text="slow down")
    )
    other = router.post(URLHAUS_API_URL, data={"url": "http://d.example/4"}).mock(return_value=_listed())
    an = UrlReputationAnalyzer(enabled)
    first = await an.analyze(make_ctx(_msg("http://b.example/2")))
    second = await an.analyze(make_ctx(_msg("http://d.example/4")))  # durante el cooldown
    assert [f.rule for f in first] == ["rep.urlhaus.error"]
    assert first[0].evidence["errors"] == {"rate_limited": 1}
    assert [f.rule for f in second] == ["rep.urlhaus.error"]
    assert limited.call_count == 1 and not other.called


async def test_results_are_cached(enabled, router, make_ctx):
    route = router.post(URLHAUS_API_URL).mock(return_value=_listed())
    an = UrlReputationAnalyzer(enabled)
    ctx1 = make_ctx(_msg("http://srv4.malo.example/x.exe"))
    await an.analyze(ctx1)
    ctx2 = make_ctx(_msg("http://srv4.malo.example/x.exe"))
    ctx2.cache = ctx1.cache
    findings = await an.analyze(ctx2)
    assert route.call_count == 1
    assert findings[0].rule == "rep.urlhaus"
    # la clave de caché no guarda la URL en claro
    assert not any("srv4.malo.example" in k for k in ctx1.cache._d)


async def test_bad_payload_is_handled(enabled, router, make_ctx):
    router.post(URLHAUS_API_URL).mock(return_value=httpx.Response(200, text="<html>error</html>"))
    findings = await UrlReputationAnalyzer(enabled).analyze(make_ctx(_msg("http://a.example/")))
    assert [f.rule for f in findings] == ["rep.urlhaus.error"]
