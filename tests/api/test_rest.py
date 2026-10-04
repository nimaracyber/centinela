"""API REST /api/v1 y endpoints sin login (/healthz, /readyz, /metrics)."""

from __future__ import annotations

import pytest

from centinela import metrics
from centinela.core.models import VerdictLevel
from tests.api.conftest import XSS_SUBJECT
from tests.api.fakes import make_artifact, make_result

# --------------------------------------------------------------------------- autenticación


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/api/v1/results"),
        ("GET", "/api/v1/results/00000000-0000-0000-0000-000000000000"),
        ("GET", "/api/v1/stats"),
        ("GET", "/api/v1/campaigns"),
        ("POST", "/api/v1/results/00000000-0000-0000-0000-000000000000/false-positive"),
    ],
)
async def test_api_requires_session(client, method, path):
    resp = await client.request(method, path, headers={"X-CSRF-Token": "x"})
    assert resp.status_code == 401
    assert resp.headers["content-type"].startswith("application/json")
    assert resp.json()["detail"].startswith("No autenticado")


# --------------------------------------------------------------------------- resultados


async def test_results_list_and_filters(auth_client, populated, malicious_result):
    resp = await auth_client.get("/api/v1/results")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 5 and body["limit"] == 50 and body["offset"] == 0
    assert {"id", "level", "subject", "false_positive", "malware_families"} <= set(body["items"][0])
    # JSON: el asunto hostil viaja tal cual (el JSON no se interpreta como HTML)
    assert any(item["subject"] == XSS_SUBJECT for item in body["items"])

    body = (await auth_client.get("/api/v1/results", params={"level": "malicious"})).json()
    assert [i["id"] for i in body["items"]] == [str(malicious_result.id)]
    body = (await auth_client.get("/api/v1/results", params={"min_level": "suspicious"})).json()
    assert body["total"] == 2
    body = (await auth_client.get("/api/v1/results", params={"q": "presupuesto"})).json()
    assert body["total"] == 1
    sha = malicious_result.artifacts[0].sha256
    body = (await auth_client.get("/api/v1/results", params={"sha256": sha.upper()})).json()
    assert body["total"] == 1
    body = (await auth_client.get("/api/v1/results", params={"family": "AsyncRAT"})).json()
    assert body["total"] == 1
    body = (await auth_client.get("/api/v1/results", params={"limit": 2, "offset": 1})).json()
    assert len(body["items"]) == 2 and body["total"] == 5


async def test_results_since_until_naive_is_utc(auth_client, store, populated):
    resp = await auth_client.get(
        "/api/v1/results", params={"since": "2026-01-01T00:00:00", "until": "2030-01-01T00:00:00Z"}
    )
    assert resp.status_code == 200
    flt = store.calls[-1][1]
    assert flt.since.tzinfo is not None and flt.until.tzinfo is not None


@pytest.mark.parametrize(
    "params",
    [
        {"limit": 201},
        {"limit": 0},
        {"offset": -1},
        {"level": "terrible"},
        {"sha256": "zz"},
        {"q": "<script>" + "x" * 201},
        {"since": "<script>ayer"},
        {"connector": "<script>" + "c" * 80},
    ],
)
async def test_results_validation(auth_client, params):
    resp = await auth_client.get("/api/v1/results", params=params)
    assert resp.status_code == 422
    body = resp.json()
    assert body["detail"] == "Parámetros inválidos."
    assert body["errors"] and all(set(e) == {"loc", "msg"} for e in body["errors"])
    assert "<script>" not in resp.text  # no se refleja lo que mandó el cliente


async def test_results_limit_200_allowed(auth_client, store):
    store.add(*[make_result() for _ in range(210)])
    body = (await auth_client.get("/api/v1/results", params={"limit": 200})).json()
    assert len(body["items"]) == 200 and body["total"] == 210


async def test_result_detail(auth_client, store, malicious_result):
    resp = await auth_client.get(f"/api/v1/results/{malicious_result.id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == str(malicious_result.id)
    assert data["verdict"]["level"] == "malicious"
    assert data["false_positive"] is False
    assert data["false_positive_by"] is None and data["false_positive_at"] is None
    assert data["truncated"] is False
    assert data["artifacts"][0]["sha256"] == malicious_result.artifacts[0].sha256
    assert data["artifacts"][0]["password_protected"] is False
    assert data["artifacts"][0]["listing_only"] is False
    assert "data" not in data["artifacts"][0]  # nunca contenido de archivos
    # la detalle no hace consultas de listado: todo viene de get_result
    assert not [c for c in store.calls if c[0] == "list_results"]
    assert (await auth_client.get("/api/v1/results/no-es-uuid")).status_code == 404
    assert (await auth_client.get("/api/v1/results/11111111-1111-1111-1111-111111111111")).status_code == 404


# --------------------------------------------------------------------------- stats y campañas


async def test_stats(auth_client, store, populated):
    resp = await auth_client.get("/api/v1/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 5 and data["hours"] == 24 and data["bucket"] == "hour"
    assert data["by_level"]["malicious"] == 1
    assert data["top_families"] == [["AsyncRAT", 1]]
    assert store.calls[-1][0] == "stats" and store.calls[-1][2] == "hour"
    data = (await auth_client.get("/api/v1/stats", params={"hours": 168})).json()
    assert data["bucket"] == "day"
    assert (await auth_client.get("/api/v1/stats", params={"hours": 0})).status_code == 422
    assert (await auth_client.get("/api/v1/stats", params={"hours": 100_000})).status_code == 422


async def test_campaigns_api(auth_client, store):
    shared = make_artifact("pago.img", detected_type="img", seed="camp")
    for mb in ("a@empresa.com", "b@empresa.com"):
        store.add(make_result(level=VerdictLevel.SUSPICIOUS, mailbox=mb, artifacts=[shared]))
    data = (await auth_client.get("/api/v1/campaigns")).json()
    assert data["days"] == 30
    assert len(data["items"]) == 1
    assert data["items"][0]["message_count"] == 2
    assert data["items"][0]["mailboxes"] == ["a@empresa.com", "b@empresa.com"]
    assert data["include_clean"] is False and store.calls[-1][-1] is False
    assert (await auth_client.get("/api/v1/campaigns", params={"min_messages": 1})).status_code == 422
    assert (await auth_client.get("/api/v1/campaigns", params={"limit": 500})).status_code == 422
    # include_clean: también cuenta el mismo adjunto en mails limpios (ej. logos de firma)
    logo = make_artifact("logo.png", detected_type="image/png", seed="logo")
    for mb in ("a@empresa.com", "b@empresa.com"):
        store.add(make_result(level=VerdictLevel.CLEAN, mailbox=mb, artifacts=[logo]))
    data = (await auth_client.get("/api/v1/campaigns", params={"include_clean": "true"})).json()
    assert data["include_clean"] is True and store.calls[-1][-1] is True
    assert {c["filename"] for c in data["items"]} == {"pago.img", "logo.png"}


async def test_result_detail_truncated_and_artifact_flags(auth_client, store):
    r = make_result(
        level=VerdictLevel.SUSPICIOUS,
        truncated=True,
        artifacts=[make_artifact("x.zip", password_protected=True, listing_only=True)],
    )
    store.add(r)
    data = (await auth_client.get(f"/api/v1/results/{r.id}")).json()
    assert data["truncated"] is True
    art = data["artifacts"][0]
    assert art["password_protected"] is True and art["listing_only"] is True and art["sha256"] == ""


# --------------------------------------------------------------------------- falso positivo por API


async def test_false_positive_api_requires_csrf_header(auth_client, store, malicious_result, csrf):
    url = f"/api/v1/results/{malicious_result.id}/false-positive"
    resp = await auth_client.post(url, json={"value": True})
    assert resp.status_code == 403
    assert "CSRF" in resp.json()["detail"]
    resp = await auth_client.post(url, json={"value": True}, headers={"X-CSRF-Token": "falso"})
    assert resp.status_code == 403
    # el token en el cuerpo/formulario no sirve: tiene que ser el header
    resp = await auth_client.post(url, data={"csrf_token": csrf})
    assert resp.status_code == 403
    assert store.fp[malicious_result.id]["value"] is False

    resp = await auth_client.post(url, json={"value": True, "note": "ok"}, headers={"X-CSRF-Token": csrf})
    assert resp.status_code == 200
    assert resp.json() == {"id": str(malicious_result.id), "false_positive": True}
    assert store.fp[malicious_result.id] == {"value": True, "user": "admin", "note": "ok"}
    detail = (await auth_client.get(f"/api/v1/results/{malicious_result.id}")).json()
    assert detail["false_positive"] is True
    assert detail["false_positive_by"] == "admin" and detail["false_positive_note"] == "ok"
    assert detail["false_positive_at"]

    resp = await auth_client.post(url, json={"value": False}, headers={"X-CSRF-Token": csrf})
    assert resp.json()["false_positive"] is False
    # sin cuerpo: marca (default value=True)
    resp = await auth_client.post(url, headers={"X-CSRF-Token": csrf})
    assert resp.status_code == 200 and resp.json()["false_positive"] is True


async def test_false_positive_api_validation(auth_client, malicious_result, csrf):
    url = f"/api/v1/results/{malicious_result.id}/false-positive"
    headers = {"X-CSRF-Token": csrf}
    assert (await auth_client.post(url, json={"note": "n" * 501}, headers=headers)).status_code == 422
    assert (await auth_client.post(url, json={"value": True, "extra": 1}, headers=headers)).status_code == 422
    assert (await auth_client.post(url, json={"value": "tal vez"}, headers=headers)).status_code == 422
    bad = "/api/v1/results/11111111-1111-1111-1111-111111111111/false-positive"
    assert (await auth_client.post(bad, json={}, headers=headers)).status_code == 404
    assert (
        await auth_client.post("/api/v1/results/x/false-positive", json={}, headers=headers)
    ).status_code == 404


# --------------------------------------------------------------------------- sin login


async def test_healthz(client):
    resp = await client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


async def test_readyz_ok_only_booleans_and_cached(client, runtime):
    resp = await client.get("/readyz")
    assert resp.status_code == 200
    body = resp.json()
    assert body == {"ready": True, "db": True, "redis": True, "degraded": False}
    await client.get("/readyz")
    assert runtime.health_calls == 1  # caché corta: un endpoint sin login no martilla la base


async def test_readyz_not_ready_without_details(client, runtime):
    runtime.health_result = {
        "ok": False,
        "db": {"ok": False, "backend": "postgresql", "error": "OperationalError: postgres://u:p@db refused"},
        "redis": {"ok": True, "enabled": True},
        "degraded": ["clamav"],
    }
    resp = await client.get("/readyz")
    assert resp.status_code == 503
    body = resp.json()
    assert body == {"ready": False, "db": False, "redis": True, "degraded": True}
    assert all(isinstance(v, bool) for v in body.values())
    assert "postgres" not in resp.text


async def test_readyz_when_health_raises(client, runtime):
    runtime.health_exc = RuntimeError("boom secreto")
    resp = await client.get("/readyz")
    assert resp.status_code == 503
    assert resp.json()["ready"] is False
    assert "secreto" not in resp.text


async def test_metrics_exposed_without_login(client):
    metrics.MESSAGES_INGESTED.labels(connector="test-api").inc()
    resp = await client.get("/metrics")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    assert "centinela_messages_analyzed_total" in resp.text
    assert 'centinela_messages_ingested_total{connector="test-api"}' in resp.text
