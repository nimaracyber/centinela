"""ReputationAnalyzer (MalwareBazaar + VirusTotal) con HTTP mockeado por respx (sin red real)."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from urllib.parse import parse_qs

import httpx
import pytest
import respx
from pydantic import SecretStr

from centinela.analyzers import reputation
from centinela.analyzers.reputation import (
    MB_API_URL,
    VT_BUCKET,
    VT_FILE_URL,
    ReputationAnalyzer,
    TokenBucket,
    canonical_family,
    reset_rate_limits,
    vt_bucket_for,
)
from centinela.core.cache import MemoryCache
from centinela.core.models import Artifact, FindingCategory, Severity
from tests.helpers import make_artifact

MB_KEY = "mb-clave-de-prueba-123"
VT_KEY = "vt-clave-de-prueba-456"
PE_DATA = b"MZ" + b"\x00" * 2000  # inerte


@pytest.fixture(autouse=True)
def _reset_limits():
    reset_rate_limits()
    yield
    reset_rate_limits()


@pytest.fixture
def keyed(settings):
    settings.analyzers.reputation.malwarebazaar_api_key = SecretStr(MB_KEY)
    settings.analyzers.reputation.virustotal_api_key = SecretStr(VT_KEY)
    return settings


@pytest.fixture
def router():
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as r:
        yield r


def _art(data: bytes = PE_DATA, **kw):
    kw.setdefault("filename", "factura.exe")
    kw.setdefault("detected_type", "pe")
    return make_artifact(data, kw.pop("filename"), kw.pop("detected_type"), **kw)


def _vt_url(art) -> str:
    return VT_FILE_URL.format(sha256=art.sha256)


def _mb_ok(sha: str, signature: str | None = "AgentTesla", tags=None) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "query_status": "ok",
            "data": [
                {
                    "sha256_hash": sha,
                    "signature": signature,
                    "tags": tags if tags is not None else ["exe", "AgentTesla", "geo"],
                    "first_seen": "2026-09-30 10:00:00",
                    "file_type": "exe",
                    "file_name": "cotizacion.exe",
                }
            ],
        },
    )


def _vt_report(
    malicious: int, total: int = 70, label: str | None = "trojan.remcos/remcosrat"
) -> httpx.Response:
    attrs = {
        "last_analysis_stats": {
            "malicious": malicious,
            "suspicious": 0,
            "undetected": total - malicious,
            "harmless": 0,
        }
    }
    if label:
        attrs["popular_threat_classification"] = {
            "suggested_threat_label": label,
            "popular_threat_name": [{"value": "remcos", "count": 20}],
        }
    return httpx.Response(200, json={"data": {"type": "file", "id": "x", "attributes": attrs}})


MB_NOT_FOUND = httpx.Response(200, json={"query_status": "hash_not_found"})
VT_NOT_FOUND = httpx.Response(404, json={"error": {"code": "NotFoundError", "message": "not found"}})


async def test_malwarebazaar_hit_is_critical_and_skips_virustotal(keyed, router, make_ctx):
    art = _art()
    mb = router.post(MB_API_URL).mock(return_value=_mb_ok(art.sha256))
    vt = router.get(_vt_url(art)).mock(return_value=_vt_report(50))
    an = ReputationAnalyzer(keyed)
    findings = await an.analyze(make_ctx(), art)

    assert len(findings) == 1
    f = findings[0]
    assert f.rule == "rep.malwarebazaar"
    assert f.category == FindingCategory.REPUTATION
    assert f.severity == Severity.CRITICAL and f.score == 98
    assert f.malware_family == "AgentTesla"
    assert f.artifact_id == art.id
    assert f.evidence["link"] == f"https://bazaar.abuse.ch/sample/{art.sha256}/"
    assert f.evidence["cached"] is False
    assert not vt.called  # no gastamos cuota de VT

    req = mb.calls.last.request
    assert req.headers["Auth-Key"] == MB_KEY
    assert parse_qs(req.content.decode()) == {"query": ["get_info"], "hash": [art.sha256]}
    assert PE_DATA not in req.content  # nunca se manda el archivo


async def test_family_falls_back_to_tags_when_signature_is_null(keyed, router, make_ctx):
    art = _art()
    router.post(MB_API_URL).mock(return_value=_mb_ok(art.sha256, signature=None, tags=["exe", "RemcosRAT"]))
    findings = await ReputationAnalyzer(keyed).analyze(make_ctx(), art)
    assert findings[0].malware_family == "Remcos"


async def test_unknown_everywhere_produces_nothing(keyed, router, make_ctx):
    art = _art()
    mb = router.post(MB_API_URL).mock(return_value=MB_NOT_FOUND)
    vt = router.get(_vt_url(art)).mock(return_value=VT_NOT_FOUND)
    assert await ReputationAnalyzer(keyed).analyze(make_ctx(), art) == []
    assert mb.call_count == 1 and vt.call_count == 1
    assert vt.calls.last.request.headers["x-apikey"] == VT_KEY


@pytest.mark.parametrize(
    "malicious,rule,severity,score,family",
    [
        (12, "rep.virustotal", Severity.CRITICAL, 95, "Remcos"),
        (5, "rep.virustotal", Severity.CRITICAL, 95, "Remcos"),
        (3, "rep.virustotal.low_detections", Severity.MEDIUM, 40, "Remcos"),
        (2, "rep.virustotal.low_detections", Severity.MEDIUM, 40, "Remcos"),
        (1, "rep.virustotal.clean", Severity.INFO, 0, None),
        (0, "rep.virustotal.clean", Severity.INFO, 0, None),
    ],
)
async def test_virustotal_thresholds(keyed, router, make_ctx, malicious, rule, severity, score, family):
    art = _art()
    router.post(MB_API_URL).mock(return_value=MB_NOT_FOUND)
    router.get(_vt_url(art)).mock(return_value=_vt_report(malicious))
    findings = await ReputationAnalyzer(keyed).analyze(make_ctx(), art)
    assert len(findings) == 1
    f = findings[0]
    assert (f.rule, f.severity, f.score, f.malware_family) == (rule, severity, score, family)
    assert f.category == FindingCategory.REPUTATION
    assert f.evidence["malicious"] == malicious and f.evidence["total"] == 70
    if malicious >= 5:
        assert f.evidence["label"] == "trojan.remcos/remcosrat"


async def test_virustotal_generic_label_gives_no_family(keyed, router, make_ctx):
    art = _art()
    router.post(MB_API_URL).mock(return_value=MB_NOT_FOUND)
    resp = _vt_report(30, label="trojan.zusy/razy")
    body = json.loads(resp.content)
    body["data"]["attributes"]["popular_threat_classification"]["popular_threat_name"] = [{"value": "zusy"}]
    router.get(_vt_url(art)).mock(return_value=httpx.Response(200, json=body))
    findings = await ReputationAnalyzer(keyed).analyze(make_ctx(), art)
    assert findings[0].severity == Severity.CRITICAL and findings[0].malware_family is None


async def test_virustotal_429_is_info_note_and_starts_cooldown(keyed, router, make_ctx):
    a1, a2 = _art(b"MZ" + b"1" * 2000), _art(b"MZ" + b"2" * 2000, id="att1")
    router.post(MB_API_URL).mock(return_value=MB_NOT_FOUND)
    vt1 = router.get(_vt_url(a1)).mock(
        return_value=httpx.Response(429, json={"error": {"code": "QuotaExceededError"}})
    )
    vt2 = router.get(_vt_url(a2)).mock(return_value=_vt_report(40))
    an = ReputationAnalyzer(keyed)
    f1 = await an.analyze(make_ctx(), a1)
    assert [(f.rule, f.severity, f.category) for f in f1] == [
        ("rep.virustotal.rate_limited", Severity.INFO, FindingCategory.POLICY)
    ]
    f2 = await an.analyze(make_ctx(), a2)  # durante el cooldown no se consulta
    assert [f.rule for f in f2] == ["rep.virustotal.rate_limited"]
    assert vt1.call_count == 1 and not vt2.called


async def test_token_bucket_exhausted_skips_without_blocking(keyed, router, make_ctx):
    art = _art()
    router.post(MB_API_URL).mock(return_value=MB_NOT_FOUND)
    vt = router.get(_vt_url(art)).mock(return_value=_vt_report(40))
    an = ReputationAnalyzer(keyed)
    an.vt_bucket = TokenBucket(rate_per_minute=4, capacity=0)  # sin cupo: el próximo token tarda 15 s
    an.vt_max_wait_s = 0.5
    loop = asyncio.get_running_loop()
    t0 = loop.time()
    findings = await an.analyze(make_ctx(), art)
    assert loop.time() - t0 < 2
    assert [f.rule for f in findings] == ["rep.virustotal.rate_limited"]
    assert not vt.called


async def test_rate_limit_note_is_emitted_once_per_message(keyed, router, make_ctx):
    router.post(MB_API_URL).mock(return_value=MB_NOT_FOUND)
    vt = router.get(url__startswith="https://www.virustotal.com/api/v3/files/").mock(
        return_value=VT_NOT_FOUND
    )
    an = ReputationAnalyzer(keyed)
    an.vt_bucket = TokenBucket(rate_per_minute=4, capacity=0)
    an.vt_max_wait_s = 0.0
    ctx = make_ctx()  # un solo mail con 3 adjuntos distintos
    results = [await an.analyze(ctx, _art(b"MZ" + bytes([i]) * 1500, id=f"att{i}")) for i in range(3)]
    notes = [f for group in results for f in group]
    assert [f.rule for f in notes] == ["rep.virustotal.rate_limited"]
    assert notes[0].artifact_id == "att0" and not vt.called


async def test_free_tier_allows_four_lookups_then_skips(keyed, router, make_ctx):
    router.post(MB_API_URL).mock(return_value=MB_NOT_FOUND)
    vt = router.get(url__startswith="https://www.virustotal.com/api/v3/files/").mock(
        return_value=VT_NOT_FOUND
    )
    an = ReputationAnalyzer(keyed)
    an.vt_max_wait_s = 0.0
    results = []
    for i in range(6):
        results.append(await an.analyze(make_ctx(), _art(b"MZ" + bytes([i]) * 1500, id=f"att{i}")))
    assert vt.call_count == 4
    assert results[:4] == [[]] * 4
    assert all(r[0].rule == "rep.virustotal.rate_limited" for r in results[4:])


@pytest.mark.parametrize(
    "side_effect,kind",
    [
        (httpx.ConnectTimeout("timeout"), "timeout"),
        (httpx.ReadTimeout("timeout"), "timeout"),
        (httpx.ConnectError("refused"), "network"),
    ],
)
async def test_malwarebazaar_network_errors_are_notes_and_vt_still_runs(
    keyed, router, make_ctx, side_effect, kind
):
    art = _art()
    router.post(MB_API_URL).mock(side_effect=side_effect)
    router.get(_vt_url(art)).mock(return_value=_vt_report(9))
    findings = await ReputationAnalyzer(keyed).analyze(make_ctx(), art)
    rules = {f.rule: f for f in findings}
    assert rules["rep.malwarebazaar.error"].evidence["error"] == kind
    assert rules["rep.malwarebazaar.error"].severity == Severity.INFO
    assert rules["rep.virustotal"].severity == Severity.CRITICAL


@pytest.mark.parametrize(
    "response,kind",
    [
        (httpx.Response(200, json={"query_status": "unknown_auth_key"}), "auth"),
        (httpx.Response(401, text="Unauthorized"), "auth"),
        (httpx.Response(200, text="<html>mantenimiento</html>"), "invalid"),
        (httpx.Response(200, json={"query_status": "ok", "data": []}), "invalid"),
        (httpx.Response(200, json=["no", "es", "un", "objeto"]), "invalid"),
        (httpx.Response(503, text="down"), "http"),
    ],
)
async def test_malwarebazaar_bad_responses_are_notes(keyed, router, make_ctx, caplog, response, kind):
    keyed.analyzers.reputation.virustotal_api_key = None
    art = _art()
    router.post(MB_API_URL).mock(return_value=response)
    with caplog.at_level(logging.WARNING):
        findings = await ReputationAnalyzer(keyed).analyze(make_ctx(), art)
    assert [(f.rule, f.evidence.get("error")) for f in findings] == [("rep.malwarebazaar.error", kind)]
    assert MB_KEY not in caplog.text  # nunca se loguea la API key


async def test_oversized_response_is_rejected(keyed, router, make_ctx, monkeypatch):
    monkeypatch.setattr(reputation, "_MAX_RESPONSE_BYTES", 1000)
    keyed.analyzers.reputation.virustotal_api_key = None
    router.post(MB_API_URL).mock(return_value=httpx.Response(200, content=b"{" + b" " * 5000 + b"}"))
    findings = await ReputationAnalyzer(keyed).analyze(make_ctx(), _art())
    assert findings[0].evidence["error"] == "too_large"


async def test_positive_results_are_cached(keyed, router, make_ctx):
    art = _art()
    mb = router.post(MB_API_URL).mock(return_value=_mb_ok(art.sha256))
    an = ReputationAnalyzer(keyed)
    ctx1 = make_ctx()
    first = await an.analyze(ctx1, art)
    ctx2 = make_ctx()
    ctx2.cache = ctx1.cache  # otro mail, mismo caché
    second = await an.analyze(ctx2, art)
    assert mb.call_count == 1
    assert second[0].rule == first[0].rule == "rep.malwarebazaar"
    assert second[0].malware_family == "AgentTesla"
    assert second[0].evidence["cached"] is True


async def test_negative_results_are_cached_with_shorter_ttl(keyed, router, make_ctx):
    class RecordingCache(MemoryCache):
        def __init__(self) -> None:
            super().__init__()
            self.ttls: dict[str, int] = {}

        async def set(self, key, value, ttl_s):
            self.ttls[key] = ttl_s
            await super().set(key, value, ttl_s)

    art = _art()
    mb = router.post(MB_API_URL).mock(return_value=MB_NOT_FOUND)
    vt = router.get(_vt_url(art)).mock(return_value=_vt_report(9))
    cache = RecordingCache()
    an = ReputationAnalyzer(keyed)
    for _ in range(2):
        ctx = make_ctx()
        ctx.cache = cache
        findings = await an.analyze(ctx, art)
        assert findings[0].rule == "rep.virustotal"
    assert mb.call_count == 1 and vt.call_count == 1
    assert cache.ttls[f"rep:vt:{art.sha256}"] == 24 * 3600  # positivo: cache_ttl_hours
    assert cache.ttls[f"rep:mb:{art.sha256}"] == 6 * 3600  # negativo: tope de 6 h


async def test_corrupt_cache_entry_is_ignored(keyed, router, make_ctx):
    art = _art()
    mb = router.post(MB_API_URL).mock(return_value=_mb_ok(art.sha256))
    ctx = make_ctx()
    await ctx.cache.set(f"rep:mb:{art.sha256}", "{no es json", 60)
    findings = await ReputationAnalyzer(keyed).analyze(ctx, art)
    assert findings[0].rule == "rep.malwarebazaar" and mb.call_count == 1


async def test_errors_are_not_cached(keyed, router, make_ctx):
    keyed.analyzers.reputation.virustotal_api_key = None
    art = _art()
    mb = router.post(MB_API_URL).mock(side_effect=[httpx.ConnectTimeout("t"), _mb_ok(art.sha256)])
    an = ReputationAnalyzer(keyed)
    ctx1 = make_ctx()
    assert (await an.analyze(ctx1, art))[0].rule == "rep.malwarebazaar.error"
    ctx2 = make_ctx()
    ctx2.cache = ctx1.cache
    assert (await an.analyze(ctx2, art))[0].rule == "rep.malwarebazaar"
    assert mb.call_count == 2


async def test_privacy_flag_off_means_no_http_at_all(keyed, router, make_ctx):
    keyed.privacy.hash_lookups = False
    an = ReputationAnalyzer(keyed)
    art = _art()
    assert an.accepts(art) is False
    assert await an.analyze(make_ctx(), art) == []
    assert len(router.calls) == 0


async def test_reputation_disabled(keyed, router, make_ctx):
    keyed.analyzers.reputation.enabled = False
    assert ReputationAnalyzer.enabled(keyed) is False
    assert await ReputationAnalyzer(keyed).analyze(make_ctx(), _art()) == []
    assert len(router.calls) == 0


async def test_no_api_keys_means_no_http(settings, router, make_ctx):
    an = ReputationAnalyzer(settings)
    assert an.accepts(_art()) is False
    assert await an.analyze(make_ctx(), _art()) == []
    assert len(router.calls) == 0


async def test_only_virustotal_key_skips_malwarebazaar(keyed, router, make_ctx):
    keyed.analyzers.reputation.malwarebazaar_api_key = None
    art = _art()
    mb = router.post(MB_API_URL).mock(return_value=_mb_ok(art.sha256))
    router.get(_vt_url(art)).mock(return_value=_vt_report(20))
    findings = await ReputationAnalyzer(keyed).analyze(make_ctx(), art)
    assert [f.rule for f in findings] == ["rep.virustotal"] and not mb.called


def test_accepts_skips_images_small_text_and_bad_hashes(keyed):
    an = ReputationAnalyzer(keyed)
    assert not an.accepts(make_artifact(b"\x89PNG" + b"0" * 5000, "logo.png", "image/png"))
    assert not an.accepts(make_artifact(b"hola" * 10, "nota.txt", "text"))
    assert an.accepts(make_artifact(b"hola" * 400, "largo.txt", "text"))
    assert an.accepts(make_artifact(b"PK" + b"0" * 100, "x.zip", "zip"))
    broken = make_artifact(b"x" * 2000, "x.bin")
    broken.sha256 = "no-es-un-hash"
    assert not an.accepts(broken)
    assert not an.accepts(make_artifact(b"", "vacio.exe", "pe"))


async def test_listing_only_and_empty_hashes_are_never_sent(keyed, router, make_ctx):
    an = ReputationAnalyzer(keyed)
    listed = Artifact(
        id="att0/factura.exe",
        filename="factura.exe",
        size=900_000,
        depth=1,
        parent_id="att0",
        listing_only=True,
    )
    assert not an.accepts(listed)
    # aunque viniera con un hash (contrato roto), una entrada solo listada no se consulta
    listed_with_hash = listed.model_copy(update={"sha256": "a" * 64})
    assert not an.accepts(listed_with_hash)
    # el SHA-256 de un archivo vacío nunca se manda, aunque el tamaño diga otra cosa
    empty_hash = make_artifact(b"MZ" * 1000, "x.exe", "pe").model_copy(
        update={"sha256": hashlib.sha256(b"").hexdigest()}
    )
    assert not an.accepts(empty_hash)
    for art in (listed, listed_with_hash, empty_hash):
        assert await an.analyze(make_ctx(), art) == []
    assert len(router.calls) == 0


async def test_virustotal_rate_comes_from_config(keyed, router, make_ctx):
    keyed.analyzers.reputation.virustotal_requests_per_minute = 2
    router.post(MB_API_URL).mock(return_value=MB_NOT_FOUND)
    vt = router.get(url__startswith="https://www.virustotal.com/api/v3/files/").mock(
        return_value=VT_NOT_FOUND
    )
    an = ReputationAnalyzer(keyed)
    an.vt_max_wait_s = 0.0
    assert an.vt_bucket is vt_bucket_for(2) and an.vt_bucket is not VT_BUCKET
    results = [await an.analyze(make_ctx(), _art(b"MZ" + bytes([i]) * 1500, id=f"att{i}")) for i in range(4)]
    assert vt.call_count == 2
    assert [r[0].rule for r in results[2:]] == ["rep.virustotal.rate_limited"] * 2


def test_vt_buckets_are_shared_per_rate():
    assert vt_bucket_for(4) is VT_BUCKET
    assert vt_bucket_for(500) is vt_bucket_for(500)
    assert vt_bucket_for(500).capacity == 500


async def test_virustotal_rate_zero_disables_virustotal(keyed, router, make_ctx):
    keyed.analyzers.reputation.virustotal_requests_per_minute = 0
    router.post(MB_API_URL).mock(return_value=MB_NOT_FOUND)
    vt = router.get(url__startswith="https://www.virustotal.com/api/v3/files/").mock(
        return_value=_vt_report(50)
    )
    assert await ReputationAnalyzer(keyed).analyze(make_ctx(), _art()) == []  # ni consulta ni nota
    assert not vt.called
    # solo VT, desactivado: el analizador no hace nada
    keyed.analyzers.reputation.malwarebazaar_api_key = None
    assert ReputationAnalyzer(keyed).accepts(_art()) is False


class _RecordingCache(MemoryCache):
    def __init__(self) -> None:
        super().__init__()
        self.ttls: dict[str, int] = {}

    async def set(self, key, value, ttl_s):
        self.ttls[key] = ttl_s
        await super().set(key, value, ttl_s)


@pytest.mark.parametrize(("hours", "expected"), [(1, 3600), (12, 12 * 3600), (48, 24 * 3600)])
async def test_negative_ttl_comes_from_config(keyed, router, make_ctx, hours, expected):
    keyed.analyzers.reputation.virustotal_api_key = None
    keyed.analyzers.reputation.negative_cache_ttl_hours = hours
    art = _art()
    router.post(MB_API_URL).mock(return_value=MB_NOT_FOUND)
    ctx = make_ctx()
    ctx.cache = cache = _RecordingCache()
    await ReputationAnalyzer(keyed).analyze(ctx, art)
    assert cache.ttls[f"rep:mb:{art.sha256}"] == expected  # nunca más largo que un positivo (24 h)


async def test_negative_ttl_zero_means_not_cached(keyed, router, make_ctx):
    keyed.analyzers.reputation.virustotal_api_key = None
    keyed.analyzers.reputation.negative_cache_ttl_hours = 0
    art = _art()
    mb = router.post(MB_API_URL).mock(side_effect=[MB_NOT_FOUND, _mb_ok(art.sha256)])
    cache = _RecordingCache()
    an = ReputationAnalyzer(keyed)
    for _ in range(2):
        ctx = make_ctx()
        ctx.cache = cache
        last = await an.analyze(ctx, art)
    assert mb.call_count == 2 and last[0].rule == "rep.malwarebazaar"  # la campaña nueva se detecta enseguida
    assert list(cache.ttls.values()) == [24 * 3600]  # solo se guardó el positivo


async def test_duplicate_hashes_in_same_message_are_looked_up_once(keyed, router, make_ctx):
    a1 = _art(id="att0")
    a2 = _art(id="att1/copia.zip/factura.exe", depth=1, parent_id="att1")
    mb = router.post(MB_API_URL).mock(return_value=_mb_ok(a1.sha256))
    an = ReputationAnalyzer(keyed)
    ctx = make_ctx()
    r1, r2 = await asyncio.gather(an.analyze(ctx, a1), an.analyze(ctx, a2))
    assert mb.call_count == 1
    assert len(r1) + len(r2) == 1


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("AgentTesla", "AgentTesla"),
        ("agent_tesla", "AgentTesla"),
        ("RemcosRAT", "Remcos"),
        ("win.remcos", "Remcos"),  # id estilo Malpedia
        ("win.unknownfamilyx", "unknownfamilyx"),
        ("LummaStealer", "Lumma Stealer"),
        ("Formbook", "FormBook"),
        ("RedLineStealer", "RedLine Stealer"),
        ("404Keylogger", "Snake Keylogger"),
        ("CloudEyE", "GuLoader"),
        ("Bladabindi", "njRAT"),
        ("AveMaria", "Warzone RAT"),
        ("Generic", None),
        ("Kryptik", None),
        ("123456", None),
        ("", None),
        (None, None),
        ("XehookStealer", "XehookStealer"),
        ("Msilzilla-9973231-0", "Msilzilla"),
    ],
)
def test_canonical_family(raw, expected):
    assert canonical_family(raw) == expected


def test_token_bucket_refills_over_time():
    now = [0.0]
    bucket = TokenBucket(rate_per_minute=4, capacity=4, clock=lambda: now[0])
    assert [bucket.try_acquire() for _ in range(5)] == [True, True, True, True, False]
    now[0] += 15.0
    assert bucket.try_acquire() is True
    assert bucket.try_acquire() is False
    now[0] += 3600
    assert sum(bucket.try_acquire() for _ in range(10)) == 4  # nunca supera la capacidad


async def test_token_bucket_waits_briefly_when_next_token_is_close():
    bucket = TokenBucket(rate_per_minute=600, capacity=1)  # un token cada 0.1 s
    assert await bucket.acquire(0.0) is True
    assert await bucket.acquire(0.0) is False
    assert await bucket.acquire(1.0) is True  # espera ~0.1 s
