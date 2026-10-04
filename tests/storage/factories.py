"""Fábricas de AnalysisResult sintéticos para tests de storage/runtime (sin malware real)."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from datetime import datetime, timedelta

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


def sha(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def artifact(
    name: str, seed: str | None = None, *, id: str = "att0", detected_type: str = "pe"
) -> ArtifactSummary:
    data_seed = seed or name
    return ArtifactSummary(
        id=id,
        filename=name,
        declared_content_type="application/octet-stream",
        detected_type=detected_type,
        size=1234,
        sha256=sha(data_seed),
        sha1=hashlib.sha1(data_seed.encode()).hexdigest(),  # noqa: S324
        md5=hashlib.md5(data_seed.encode()).hexdigest(),  # noqa: S324
    )


def finding(
    rule: str = "pe.stealer_imports",
    *,
    artifact_id: str | None = "att0",
    severity: Severity = Severity.HIGH,
    score: int = 70,
    family: str | None = None,
    category: FindingCategory = FindingCategory.SUSPICIOUS_FILE,
    evidence: dict | None = None,
) -> Finding:
    return Finding(
        analyzer=rule.split(".", 1)[0],
        rule=rule,
        title="Hallazgo de prueba",
        description="Descripción para un no-técnico.",
        category=category,
        severity=severity,
        score=score,
        artifact_id=artifact_id,
        malware_family=family,
        evidence=evidence or {"detalle": "inerte"},
    )


def make_result(
    remote_id: str = "1",
    *,
    level: VerdictLevel = VerdictLevel.CLEAN,
    score: int = 0,
    connector: str = "test",
    mailbox: str = "ventas@empresa.com",
    subject: str = "Hola",
    from_addr: str | None = "juan@proveedor.com",
    from_display: str | None = "Juan",
    message_id: str | None = None,
    received_at: datetime | None = None,
    age: timedelta | None = None,
    artifacts: Sequence[ArtifactSummary] = (),
    findings: Sequence[Finding] = (),
    families: Sequence[str] = (),
    duration_ms: int = 100,
    actions: Sequence[str] = (),
    errors: Sequence[str] = (),
    urls: Sequence[ExtractedUrl] = (),
) -> AnalysisResult:
    when = received_at or (utcnow() - (age or timedelta(minutes=1)))
    return AnalysisResult(
        ref=MessageRef(connector=connector, mailbox=mailbox, remote_id=remote_id, folder="INBOX"),
        message_id=message_id,
        subject=subject,
        from_addr=from_addr,
        from_display=from_display,
        to=[mailbox],
        received_at=when,
        duration_ms=duration_ms,
        size=2048,
        artifacts=list(artifacts),
        urls=list(urls),
        findings=list(findings),
        verdict=Verdict(
            level=level, score=score, summary="Resumen de prueba.", malware_families=list(families)
        ),
        errors=list(errors),
        actions=list(actions),
    )


def malicious_result(
    remote_id: str, *, mailbox: str = "ventas@empresa.com", seed: str = "agenttesla-sample", **kw
) -> AnalysisResult:
    return make_result(
        remote_id,
        level=VerdictLevel.MALICIOUS,
        score=95,
        mailbox=mailbox,
        artifacts=[artifact("factura.pdf.exe", seed)],
        findings=[
            finding(
                "yara.AgentTesla",
                severity=Severity.CRITICAL,
                score=95,
                family="AgentTesla",
                category=FindingCategory.MALWARE,
            )
        ],
        families=["AgentTesla"],
        **kw,
    )
