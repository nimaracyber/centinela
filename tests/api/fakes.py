"""Fakes para los tests del dashboard: ResultStore en memoria (implementa el protocolo) y un runtime mínimo.

No importa storage/db.py (lo escribe otro módulo): el dashboard solo depende del protocolo.
"""

from __future__ import annotations

import hashlib
import uuid
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

from centinela.core.config import Settings
from centinela.core.models import (
    AnalysisResult,
    ArtifactSummary,
    ExtractedUrl,
    Finding,
    FindingCategory,
    MessageRef,
    Severity,
    Verdict,
    VerdictLevel,
    utcnow,
)
from centinela.storage.protocol import Campaign, ResultFilter, ResultListItem, Stats

THREATS = {VerdictLevel.SUSPICIOUS, VerdictLevel.MALICIOUS}


def sha(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def make_artifact(
    filename: str | None,
    *,
    id: str = "att0",
    detected_type: str = "unknown",
    depth: int = 0,
    parent_id: str | None = None,
    seed: str | None = None,
    size: int = 1234,
    encrypted: bool = False,
    password_protected: bool = False,
    listing_only: bool = False,
    note: str | None = None,
) -> ArtifactSummary:
    s = seed or f"{id}:{filename}"
    return ArtifactSummary(
        id=id,
        filename=filename,
        declared_content_type="application/octet-stream",
        detected_type=detected_type,
        size=size,
        # listing_only: entrada listada pero no extraída => sin hashes (contrato de Artifact)
        sha256="" if listing_only else sha(s),
        sha1="" if listing_only else hashlib.sha1(s.encode()).hexdigest(),  # noqa: S324
        md5="" if listing_only else hashlib.md5(s.encode()).hexdigest(),  # noqa: S324
        depth=depth,
        parent_id=parent_id,
        encrypted=encrypted,
        password_protected=password_protected,
        listing_only=listing_only,
        extraction_note=note,
    )


def make_finding(
    rule: str = "pe.attached_executable",
    *,
    title: str = "Ejecutable adjunto",
    severity: Severity = Severity.MEDIUM,
    score: int = 35,
    category: FindingCategory = FindingCategory.SUSPICIOUS_FILE,
    artifact_id: str | None = None,
    family: str | None = None,
    description: str = "Un programa de Windows llegó adjunto al mail.",
    evidence: dict[str, Any] | None = None,
) -> Finding:
    return Finding(
        analyzer=rule.split(".", 1)[0],
        rule=rule,
        title=title,
        description=description,
        category=category,
        severity=severity,
        score=score,
        artifact_id=artifact_id,
        malware_family=family,
        evidence=evidence or {},
    )


_counter = 0


def make_result(
    *,
    level: VerdictLevel | str = VerdictLevel.CLEAN,
    subject: str = "Hola",
    from_addr: str | None = "juan@proveedor.com",
    from_display: str | None = "Juan Pérez",
    mailbox: str = "ventas@empresa.com",
    connector: str = "imap-ventas",
    received_at: datetime | None = None,
    artifacts: list[ArtifactSummary] | None = None,
    findings: list[Finding] | None = None,
    urls: list[ExtractedUrl] | None = None,
    families: list[str] | None = None,
    score: int | None = None,
    summary: str | None = None,
    errors: list[str] | None = None,
    actions: list[str] | None = None,
    truncated: bool = False,
) -> AnalysisResult:
    global _counter
    _counter += 1
    level = VerdictLevel(level)
    default_scores = {"clean": 0, "suspicious": 45, "malicious": 95, "error": 0}
    return AnalysisResult(
        ref=MessageRef(connector=connector, mailbox=mailbox, remote_id=f"INBOX:1:{_counter}", folder="INBOX"),
        message_id=f"<msg-{_counter}@proveedor.com>",
        subject=subject,
        from_addr=from_addr,
        from_display=from_display,
        to=[mailbox],
        received_at=received_at or utcnow() - timedelta(minutes=_counter % 50),
        duration_ms=850,
        size=48_000,
        artifacts=artifacts or [],
        urls=urls or [],
        findings=findings or [],
        verdict=Verdict(
            level=level,
            score=default_scores[level.value] if score is None else score,
            summary=summary or f"Resumen {level.value}",
            malware_families=families or [],
        ),
        errors=errors or [],
        actions=actions or [],
        truncated=truncated,
    )


class FakeResultStore:
    """ResultStore en memoria, con la semántica del protocolo (filtros, stats, campañas, falsos positivos)."""

    def __init__(self) -> None:
        self.results: dict[uuid.UUID, AnalysisResult] = {}
        self.fp: dict[uuid.UUID, dict[str, Any]] = {}
        self.fp_at: dict[uuid.UUID, datetime] = {}
        self.calls: list[tuple[Any, ...]] = []
        self.fail_with: Exception | None = None

    def _check(self) -> None:
        if self.fail_with is not None:
            raise self.fail_with

    def add(self, *results: AnalysisResult) -> list[AnalysisResult]:
        for r in results:
            self.results[r.id] = r
            self.fp.setdefault(r.id, {"value": False, "user": None, "note": ""})
        return list(results)

    def is_fp(self, rid: uuid.UUID) -> bool:
        return bool(self.fp.get(rid, {}).get("value"))

    async def init(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def has_ref(self, ref: MessageRef) -> bool:
        return any(r.ref == ref for r in self.results.values())

    async def save_result(self, result: AnalysisResult) -> bool:
        if await self.has_ref(result.ref):
            return False
        self.add(result)
        return True

    async def get_result(self, result_id: uuid.UUID) -> AnalysisResult | None:
        self._check()
        self.calls.append(("get_result", result_id))
        r = self.results.get(result_id)
        if r is None:
            return None
        # como el storage real: false_positive* se completan desde el feedback guardado
        fb = self.fp.get(result_id, {})
        touched = result_id in self.fp_at
        return r.model_copy(
            deep=True,
            update={
                "false_positive": bool(fb.get("value")),
                "false_positive_by": fb.get("user") if touched else None,
                "false_positive_note": (fb.get("note") or None) if touched else None,
                "false_positive_at": self.fp_at.get(result_id),
            },
        )

    def _match(self, r: AnalysisResult, flt: ResultFilter) -> bool:
        if flt.ids is not None and r.id not in set(flt.ids):
            return False
        lv = r.verdict.level
        if flt.level is not None and lv != flt.level:
            return False
        if flt.min_level is not None and lv.rank < flt.min_level.rank:
            return False
        if flt.connector and r.ref.connector != flt.connector:
            return False
        if flt.mailbox and r.ref.mailbox.lower() != flt.mailbox.strip().lower():
            return False
        if flt.q:
            q = flt.q.lower()
            hay = [r.subject, r.from_addr or "", r.from_display or ""] + [
                a.filename or "" for a in r.artifacts
            ]
            hit = any(q in h.lower() for h in hay) or any(a.sha256.startswith(q) for a in r.artifacts)
            if not hit:
                return False
        if flt.sha256 and not any(a.sha256 == flt.sha256.lower() for a in r.artifacts):
            return False
        if flt.family:
            fam = flt.family.lower()
            fams = [f.lower() for f in r.verdict.malware_families] + [
                (f.malware_family or "").lower() for f in r.findings
            ]
            if fam not in fams:
                return False
        if flt.since is not None and r.received_at < flt.since:
            return False
        if flt.until is not None and r.received_at > flt.until:
            return False
        return not (not flt.include_false_positives and self.is_fp(r.id))

    def _item(self, r: AnalysisResult) -> ResultListItem:
        return ResultListItem(
            id=r.id,
            connector=r.ref.connector,
            mailbox=r.ref.mailbox,
            subject=r.subject,
            from_addr=r.from_addr,
            from_display=r.from_display,
            received_at=r.received_at,
            analyzed_at=r.analyzed_at,
            level=r.verdict.level,
            score=r.verdict.score,
            summary=r.verdict.summary,
            malware_families=list(r.verdict.malware_families),
            artifact_count=len(r.artifacts),
            finding_count=len(r.findings),
            false_positive=self.is_fp(r.id),
        )

    async def list_results(
        self, flt: ResultFilter, *, limit: int = 50, offset: int = 0
    ) -> tuple[list[ResultListItem], int]:
        self._check()
        self.calls.append(("list_results", flt, limit, offset))
        rows = [r for r in self.results.values() if self._match(r, flt)]
        rows.sort(key=lambda r: (r.received_at, str(r.id)), reverse=True)
        return [self._item(r) for r in rows[offset : offset + limit]], len(rows)

    async def stats(self, since: datetime, *, bucket: str = "hour") -> Stats:
        self._check()
        self.calls.append(("stats", since, bucket))
        rows = [r for r in self.results.values() if r.received_at >= since]
        st = Stats(since=since)
        st.total = len(rows)
        st.by_level = dict(Counter(r.verdict.level.value for r in rows))
        st.by_connector = dict(Counter(r.ref.connector for r in rows))
        fams: Counter[str] = Counter()
        senders: Counter[str] = Counter()
        rules: Counter[str] = Counter()
        for r in rows:
            fams.update(set(r.verdict.malware_families))
            if r.verdict.level in THREATS and r.from_addr:
                senders[r.from_addr] += 1
            rules.update({f.rule for f in r.findings if f.severity > Severity.INFO})
        st.top_families = sorted(fams.items(), key=lambda kv: (-kv[1], kv[0]))[:10]
        st.top_senders = sorted(senders.items(), key=lambda kv: (-kv[1], kv[0]))[:10]
        st.top_rules = sorted(rules.items(), key=lambda kv: (-kv[1], kv[0]))[:10]
        st.avg_duration_ms = sum(r.duration_ms for r in rows) / len(rows) if rows else 0.0
        step = timedelta(days=1) if bucket == "day" else timedelta(hours=1)

        def floor(dt: datetime) -> datetime:
            dt = dt.astimezone(UTC)
            return (
                dt.replace(hour=0, minute=0, second=0, microsecond=0)
                if bucket == "day"
                else dt.replace(minute=0, second=0, microsecond=0)
            )

        cursor, end = floor(since), floor(utcnow())
        table: dict[str, dict[str, Any]] = {}
        while cursor <= end:
            key = cursor.isoformat()
            table[key] = {"bucket": key, "clean": 0, "suspicious": 0, "malicious": 0, "error": 0}
            cursor += step
        for r in rows:
            slot = table.get(floor(r.received_at).isoformat())
            if slot is not None:
                slot[r.verdict.level.value] += 1
        st.timeline = list(table.values())
        return st

    async def campaigns(
        self, since: datetime, *, min_messages: int = 2, limit: int = 50, include_clean: bool = False
    ) -> list[Campaign]:
        self._check()
        self.calls.append(("campaigns", since, min_messages, limit, include_clean))
        groups: dict[str, list[tuple[AnalysisResult, ArtifactSummary]]] = {}
        for r in self.results.values():
            if r.received_at < since:
                continue
            if not include_clean and (r.verdict.level not in THREATS or self.is_fp(r.id)):
                continue
            for a in r.artifacts:
                if a.sha256:
                    groups.setdefault(a.sha256, []).append((r, a))
        out: list[Campaign] = []
        for sha256, pairs in groups.items():
            ids = {r.id for r, _ in pairs}
            if len(ids) < min_messages:
                continue
            out.append(
                Campaign(
                    sha256=sha256,
                    filename=pairs[0][1].filename,
                    detected_type=pairs[0][1].detected_type,
                    first_seen=min(r.received_at for r, _ in pairs),
                    last_seen=max(r.received_at for r, _ in pairs),
                    message_count=len(ids),
                    mailboxes=sorted({r.ref.mailbox for r, _ in pairs}),
                    max_level=max((r.verdict.level for r, _ in pairs), key=lambda lv: lv.rank),
                    malware_families=sorted({f for r, _ in pairs for f in r.verdict.malware_families}),
                )
            )
        out.sort(key=lambda c: (-c.message_count, c.sha256))
        return out[:limit]

    async def record_actions(self, result_id: uuid.UUID, actions: list[str]) -> None:
        r = self.results.get(result_id)
        if r is not None:
            r.actions = [*r.actions, *[a for a in actions if a not in r.actions]]

    async def set_false_positive(
        self, result_id: uuid.UUID, value: bool, *, user: str, note: str = ""
    ) -> bool:
        self._check()
        self.calls.append(("set_false_positive", result_id, value, user, note))
        if result_id not in self.results:
            return False
        self.fp[result_id] = {"value": bool(value), "user": user, "note": note}
        self.fp_at[result_id] = utcnow()
        return True

    async def purge_older_than(self, cutoff: datetime) -> int:
        old = [rid for rid, r in self.results.items() if r.received_at < cutoff]
        for rid in old:
            del self.results[rid]
        return len(old)


def default_health() -> dict[str, Any]:
    return {
        "version": "0.1.0",
        "role": "all",
        "started_at": "2026-10-01T12:00:00+00:00",
        "db": {"ok": True, "backend": "sqlite"},
        "redis": {"ok": True, "enabled": False},
        "queue": {"backend": "memory", "depth": 0, "dead_letters": 0},
        "clamav": {"ok": True},
        "connectors": {
            "imap-ventas": {
                "ok": True,
                "type": "imap",
                "host": "mail.empresa.com",
                "mailbox": "ventas@empresa.com",
            },
        },
        "analyzers": ["headers", "urls", "yara", "clamav"],
        "alert_channels": ["telegram"],
        "ok": True,
        "status": "ok",
        "degraded": [],
    }


class FakeRuntime:
    def __init__(
        self, settings: Settings, storage: FakeResultStore, health: dict[str, Any] | None = None
    ) -> None:
        self.settings = settings
        self.storage = storage
        self.health_result: dict[str, Any] = health if health is not None else default_health()
        self.health_exc: BaseException | None = None
        self.health_calls = 0

    async def health(self) -> dict[str, Any]:
        self.health_calls += 1
        if self.health_exc is not None:
            raise self.health_exc
        return self.health_result


class LegacyRuntime:
    """Como `centinela.runtime.Runtime`: expone el store como `.store` (no `.storage`)."""

    def __init__(self, settings: Settings, store: FakeResultStore) -> None:
        self.settings = settings
        self.store = store

    async def health(self) -> dict[str, Any]:
        return default_health()
