from __future__ import annotations

import asyncio
import time
from email.utils import formatdate

import httpx
import pytest

from centinela.connectors import _http as http

URL = "https://api.example.test/v1/things"


def test_parse_retry_after_variants():
    assert http.parse_retry_after("7") == 7.0
    assert http.parse_retry_after(" 2.5 ") == 2.5
    assert http.parse_retry_after(None) is None
    assert http.parse_retry_after("") is None
    assert http.parse_retry_after("mañana") is None
    assert http.parse_retry_after("x" * 500) is None  # hostil: largo
    assert http.parse_retry_after("-5") == 0.0
    now = time.time()
    future = formatdate(now + 30, usegmt=True)
    assert 25 <= http.parse_retry_after(future, now=now) <= 31
    assert http.parse_retry_after(formatdate(now - 100, usegmt=True), now=now) == 0.0


def test_backoff_delay_bounded_and_growing():
    assert http.backoff_delay(0, base=1, cap=60, rng=lambda: 1.0) == 1.0
    assert http.backoff_delay(3, base=1, cap=60, rng=lambda: 1.0) == 8.0
    assert http.backoff_delay(50, base=1, cap=60, rng=lambda: 1.0) == 60.0
    assert http.backoff_delay(3, base=1, cap=60, rng=lambda: 0.0) == 4.0  # jitter: mitad mínima


def test_safe_url_strips_query():
    assert http.safe_url("https://h.test/a/b?$deltatoken=SECRETO&x=1#f") == "https://h.test/a/b"


def test_recent_ids_is_bounded():
    r = http.RecentIds(maxlen=3)
    for i in range(10):
        r.add(str(i))
    assert len(r) == 3 and "9" in r and "0" not in r


async def test_retry_after_honored_on_429(router, sleeps):
    route = router.get(URL).mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "7"}),
            httpx.Response(503),
            httpx.Response(200, json={"ok": True}),
        ]
    )
    async with httpx.AsyncClient() as c:
        resp = await http.request(c, "GET", URL)
    assert resp.status_code == 200 and resp.json() == {"ok": True}
    assert route.call_count == 3
    assert sleeps[0] == 7.0  # Retry-After respetado
    assert 0 < sleeps[1] <= 2.0  # backoff exponencial sin Retry-After


async def test_retry_after_capped(router, sleeps):
    router.get(URL).mock(
        side_effect=[httpx.Response(429, headers={"Retry-After": "99999"}), httpx.Response(200)]
    )
    async with httpx.AsyncClient() as c:
        await http.request(c, "GET", URL, policy=http.RetryPolicy(max_retry_after=120))
    assert sleeps == [120]


async def test_retries_exhausted_raise_with_retry_after(router, sleeps):
    router.get(URL).mock(return_value=httpx.Response(503, headers={"Retry-After": "11"}))
    async with httpx.AsyncClient() as c:
        with pytest.raises(http.HttpError) as ei:
            await http.request(c, "GET", URL, policy=http.RetryPolicy(max_attempts=3))
    assert ei.value.status == 503 and ei.value.retry_after == 11.0
    assert len(sleeps) == 2


async def test_non_retryable_status_returned_without_retry(router, sleeps):
    route = router.get(URL).mock(
        return_value=httpx.Response(404, json={"error": {"code": "ErrorItemNotFound"}})
    )
    async with httpx.AsyncClient() as c:
        resp = await http.request(c, "GET", URL)
    assert resp.status_code == 404 and resp.error_code() == "ErrorItemNotFound"
    assert route.call_count == 1 and sleeps == []
    with pytest.raises(http.HttpError) as ei:
        resp.raise_for_status("ctx")
    assert "ErrorItemNotFound" in str(ei.value) and "?" not in str(ei.value)


async def test_network_errors_are_retried(router, sleeps):
    route = router.get(URL).mock(
        side_effect=[httpx.ConnectError("boom"), httpx.ReadTimeout("lento"), httpx.Response(200)]
    )
    async with httpx.AsyncClient() as c:
        resp = await http.request(c, "GET", URL)
    assert resp.ok and route.call_count == 3 and len(sleeps) == 2


async def test_network_errors_exhausted(router, sleeps):
    router.get(URL).mock(side_effect=httpx.ConnectError("boom"))
    async with httpx.AsyncClient() as c:
        with pytest.raises(http.HttpError) as ei:
            await http.request(c, "GET", URL, policy=http.RetryPolicy(max_attempts=2))
    assert isinstance(ei.value.__cause__, httpx.ConnectError)


async def test_401_forces_one_token_refresh(router, sleeps):
    seen_auth: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_auth.append(request.headers["Authorization"])
        return httpx.Response(401) if len(seen_auth) == 1 else httpx.Response(200)

    router.get(URL).mock(side_effect=handler)
    calls: list[bool] = []

    async def token(force: bool) -> str:
        calls.append(force)
        return "nuevo" if force else "viejo"

    async with httpx.AsyncClient() as c:
        resp = await http.request(c, "GET", URL, token=token)
    assert resp.ok
    assert seen_auth == ["Bearer viejo", "Bearer nuevo"]
    assert True in calls


async def test_401_twice_is_returned(router, sleeps):
    route = router.get(URL).mock(return_value=httpx.Response(401))

    async def token(force: bool) -> str:
        return "t"

    async with httpx.AsyncClient() as c:
        resp = await http.request(c, "GET", URL, token=token)
    assert resp.status_code == 401 and route.call_count == 2  # un solo refresh, sin loop infinito


async def test_body_cap_streaming_and_content_length(router):
    router.get(URL).mock(return_value=httpx.Response(200, content=b"x" * 5000))
    async with httpx.AsyncClient() as c:
        with pytest.raises(http.ResponseTooLarge) as info:
            await http.request(c, "GET", URL, max_body=1000)
        assert info.value.size == 5000  # Content-Length declarado: tamaño real conocido
        resp = await http.request(c, "GET", URL, max_body=5000)
        assert len(resp.content) == 5000


async def test_body_cap_chunked_without_content_length(router):
    async def chunks():
        for _ in range(10):
            yield b"x" * 1000

    router.get(URL).mock(return_value=httpx.Response(200, content=chunks()))
    async with httpx.AsyncClient() as c:
        with pytest.raises(http.ResponseTooLarge) as info:
            await http.request(c, "GET", URL, max_body=2500)
    assert info.value.size is None  # sin Content-Length: solo se sabe que supera el tope


async def test_custom_retry_predicate(router, sleeps):
    route = router.get(URL).mock(
        side_effect=[
            httpx.Response(403, json={"error": {"errors": [{"reason": "userRateLimitExceeded"}]}}),
            httpx.Response(200),
        ]
    )
    async with httpx.AsyncClient() as c:
        resp = await http.request(c, "GET", URL, retry_if=lambda r: r.error_code() == "userRateLimitExceeded")
    assert resp.ok and route.call_count == 2


async def test_stop_interrupts_retry_wait(router):
    router.get(URL).mock(return_value=httpx.Response(503, headers={"Retry-After": "3600"}))
    stop = asyncio.Event()
    async with httpx.AsyncClient() as c:
        task = asyncio.create_task(http.request(c, "GET", URL, stop=stop))
        await asyncio.sleep(0.05)
        stop.set()
        t0 = time.monotonic()
        with pytest.raises(http.Stopped):
            await asyncio.wait_for(task, 2)
    assert time.monotonic() - t0 < 1.5


async def test_invalid_json_raises_http_error(router):
    router.get(URL).mock(return_value=httpx.Response(200, content=b"{no es json"))
    async with httpx.AsyncClient() as c:
        resp = await http.request(c, "GET", URL)
    with pytest.raises(http.HttpError):
        resp.json()


async def test_wait_any_returns_on_wake_and_timeout():
    stop, wake = asyncio.Event(), asyncio.Event()
    t0 = time.monotonic()
    await http.wait_any(stop, wake, 0.05)
    assert time.monotonic() - t0 < 1
    asyncio.get_running_loop().call_later(0.02, wake.set)
    await asyncio.wait_for(http.wait_any(stop, wake, 30), 2)


def test_time_helpers():
    assert http.utc_from_ms("1700000000000").year == 2023
    assert http.utc_from_ms("basura") is None
    assert http.utc_from_ms(-5) is None
    assert http.parse_iso8601("2026-10-03T12:00:00Z").tzinfo is not None
    seven = http.parse_iso8601("2026-10-03T12:00:00.1234567Z")  # 7 decimales (.NET/Graph)
    assert seven is not None and seven.microsecond == 123456
    assert http.parse_iso8601("no-fecha") is None
    assert http.iso_utc(http.parse_iso8601("2026-10-03T12:00:00+03:00")) == "2026-10-03T09:00:00Z"
