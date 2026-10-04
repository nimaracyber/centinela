"""API REST JSON `/api/v1` (misma sesión que el dashboard; los POST exigen el header X-CSRF-Token).

    GET  /api/v1/results?level=&min_level=&connector=&mailbox=&q=&sha256=&family=&since=&until=
                         &include_false_positives=&limit=(1..200)&offset=
    GET  /api/v1/results/{id}                 -> AnalysisResult (incluye truncated y false_positive*)
    GET  /api/v1/stats?hours=24               -> Stats (bucket por hora hasta 72 h, por día después)
    GET  /api/v1/campaigns?days=30&min_messages=2&limit=50&include_clean=false
    POST /api/v1/results/{id}/false-positive  {"value": true, "note": "..."}   (header X-CSRF-Token)

Sin sesión => 401. El token CSRF de la sesión está en `<meta name="csrf-token">` de cada página.
Nunca se devuelven adjuntos (no se guardan): solo metadatos, hashes y hallazgos.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from centinela.api.auth import Session, require_api_csrf, require_api_session
from centinela.api.views import MAX_NOTE_CHARS
from centinela.core.models import VerdictLevel, utcnow
from centinela.storage.protocol import ResultFilter

if TYPE_CHECKING:
    from centinela.api.app import DashboardContext

log = logging.getLogger(__name__)

MAX_LIMIT = 200
MAX_OFFSET = 1_000_000
MAX_STATS_HOURS = 24 * 90
HOURLY_BUCKET_MAX_HOURS = 72

router = APIRouter(prefix="/api/v1")


class FalsePositiveBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    value: bool = True
    note: str = Field(default="", max_length=MAX_NOTE_CHARS)


def _ctx(request: Request) -> DashboardContext:
    return request.app.state.centinela


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt


def _parse_id(value: str) -> uuid.UUID:
    try:
        if len(value) <= 64:
            return uuid.UUID(value)
    except ValueError:
        pass
    raise HTTPException(status_code=404, detail="No existe ese resultado.")


@router.get("/results")
async def list_results(
    request: Request,
    session: Session = Depends(require_api_session),  # noqa: B008
    level: VerdictLevel | None = None,
    min_level: VerdictLevel | None = None,
    connector: str | None = Query(None, max_length=64),
    mailbox: str | None = Query(None, max_length=320),
    q: str | None = Query(None, max_length=200),
    sha256: str | None = Query(None, pattern=r"^[0-9a-fA-F]{64}$"),
    family: str | None = Query(None, max_length=200),
    since: datetime | None = None,
    until: datetime | None = None,
    include_false_positives: bool = True,
    limit: int = Query(50, ge=1, le=MAX_LIMIT),
    offset: int = Query(0, ge=0, le=MAX_OFFSET),
) -> dict[str, Any]:
    flt = ResultFilter(
        level=level,
        min_level=min_level,
        connector=connector or None,
        mailbox=mailbox or None,
        q=q or None,
        sha256=sha256.lower() if sha256 else None,
        family=family or None,
        since=_aware(since),
        until=_aware(until),
        include_false_positives=include_false_positives,
    )
    items, total = await _ctx(request).store.list_results(flt, limit=limit, offset=offset)
    return {
        "items": [item.model_dump(mode="json") for item in items],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/results/{result_id}")
async def get_result(
    request: Request,
    result_id: str,
    session: Session = Depends(require_api_session),  # noqa: B008
) -> dict[str, Any]:
    result = await _ctx(request).store.get_result(_parse_id(result_id))
    if result is None:
        raise HTTPException(status_code=404, detail="No existe ese resultado.")
    return result.model_dump(mode="json")  # false_positive* y truncated vienen del storage


@router.get("/stats")
async def stats(
    request: Request,
    session: Session = Depends(require_api_session),  # noqa: B008
    hours: int = Query(24, ge=1, le=MAX_STATS_HOURS),
) -> dict[str, Any]:
    bucket = "hour" if hours <= HOURLY_BUCKET_MAX_HOURS else "day"
    result = await _ctx(request).store.stats(utcnow() - timedelta(hours=hours), bucket=bucket)
    data = result.model_dump(mode="json")
    data["hours"] = hours
    data["bucket"] = bucket
    return data


@router.get("/campaigns")
async def campaigns(
    request: Request,
    session: Session = Depends(require_api_session),  # noqa: B008
    days: int = Query(30, ge=1, le=365),
    min_messages: int = Query(2, ge=2, le=10_000),
    limit: int = Query(50, ge=1, le=MAX_LIMIT),
    include_clean: bool = False,
) -> dict[str, Any]:
    items = await _ctx(request).store.campaigns(
        utcnow() - timedelta(days=days), min_messages=min_messages, limit=limit, include_clean=include_clean
    )
    return {"items": [c.model_dump(mode="json") for c in items], "days": days, "include_clean": include_clean}


@router.post("/results/{result_id}/false-positive")
async def set_false_positive(
    request: Request,
    result_id: str,
    session: Session = Depends(require_api_csrf),  # noqa: B008
    body: FalsePositiveBody | None = Body(default=None),  # noqa: B008
) -> dict[str, Any]:
    rid = _parse_id(result_id)
    payload = body or FalsePositiveBody()
    note = "".join(ch if ch.isprintable() else " " for ch in payload.note).strip()
    if not await _ctx(request).store.set_false_positive(rid, payload.value, user=session.user, note=note):
        raise HTTPException(status_code=404, detail="No existe ese resultado.")
    log.info(
        "resultado %s %s como falso positivo por %s (API)",
        rid,
        "marcado" if payload.value else "desmarcado",
        session.user,
    )
    return {"id": str(rid), "false_positive": payload.value}


__all__ = ["router"]
