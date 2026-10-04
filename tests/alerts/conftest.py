"""Fixtures de los tests de alertas: resultados sintéticos (sin malware real ni red real)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from centinela.core.models import (
    AnalysisResult,
    ArtifactSummary,
    Finding,
    FindingCategory,
    MessageRef,
    Severity,
    Verdict,
    VerdictLevel,
)

SHA_ZIP = "a" * 64
SHA_EXE = "b" * 64
PHISH_URL = "https://pagos-afip.com/login.php?token=XYZ"
BODY_SECRET = "TEXTO-DEL-CUERPO-QUE-NO-DEBE-SALIR"
RECEIVED = datetime(2026, 10, 3, 17, 32, 0, tzinfo=UTC)


def make_result(
    *,
    level: VerdictLevel = VerdictLevel.MALICIOUS,
    score: int = 97,
    summary: str = "El adjunto factura.pdf.exe es un programa que roba contraseñas (AgentTesla).",
    subject: str = "Factura vencida N° 4471",
    from_addr: str | None = "cobranzas@pagos-afip.com",
    from_display: str | None = "AFIP Cobranzas",
    to: list[str] | None = None,
    artifacts: list[ArtifactSummary] | None = None,
    findings: list[Finding] | None = None,
    families: list[str] | None = None,
    mailbox: str = "ventas@empresa.com",
    message_id: str | None = "<abc123@pagos-afip.com>",
) -> AnalysisResult:
    return AnalysisResult(
        ref=MessageRef(connector="imap-ventas", mailbox=mailbox, remote_id="INBOX:1:42"),
        message_id=message_id,
        subject=subject,
        from_addr=from_addr,
        from_display=from_display,
        to=to if to is not None else ["ventas@empresa.com"],
        received_at=RECEIVED,
        analyzed_at=RECEIVED,
        artifacts=artifacts if artifacts is not None else [],
        findings=findings if findings is not None else [],
        verdict=Verdict(level=level, score=score, summary=summary, malware_families=families or []),
    )


def stealer_result(**kw) -> AnalysisResult:
    """Mail malicioso: ZIP con un .exe de doble extensión firmado como AgentTesla + link de phishing."""
    artifacts = [
        ArtifactSummary(id="att0", filename="factura.zip", detected_type="zip", size=2048, sha256=SHA_ZIP),
        ArtifactSummary(
            id="att0/factura.zip/factura.pdf.exe",
            filename="factura.pdf.exe",
            detected_type="pe",
            size=4096,
            sha256=SHA_EXE,
            depth=1,
            parent_id="att0",
        ),
    ]
    findings = [
        Finding(
            analyzer="yara",
            rule="yara.AgentTesla",
            title="Firma de AgentTesla",
            description="Coincide con AgentTesla, un programa que roba contraseñas.",
            category=FindingCategory.MALWARE,
            severity=Severity.CRITICAL,
            score=95,
            artifact_id="att0/factura.zip/factura.pdf.exe",
            malware_family="AgentTesla",
            evidence={"matched_strings": [BODY_SECRET], "offset": 1234},
        ),
        Finding(
            analyzer="filename",
            rule="file.double_extension",
            title="Ejecutable disfrazado de PDF",
            category=FindingCategory.SUSPICIOUS_FILE,
            severity=Severity.HIGH,
            score=70,
            artifact_id="att0/factura.zip/factura.pdf.exe",
        ),
        Finding(
            analyzer="urls",
            rule="url.lookalike_domain",
            title="Link a un dominio que imita a la AFIP",
            category=FindingCategory.PHISHING,
            severity=Severity.MEDIUM,
            score=35,
            evidence={"url": PHISH_URL, "context": BODY_SECRET},
        ),
        Finding(
            analyzer="headers",
            rule="headers.info",
            title="Mail recibido por IMAP",
            category=FindingCategory.POLICY,
            severity=Severity.INFO,
            score=0,
        ),
    ]
    kw.setdefault("artifacts", artifacts)
    kw.setdefault("findings", findings)
    kw.setdefault("families", ["AgentTesla"])
    kw.setdefault("to", ["ventas@empresa.com", "juan@empresa.com", "cliente@externo.com"])
    return make_result(**kw)


def bec_result(**kw) -> AnalysisResult:
    """Mail sospechoso sin adjuntos: suplantación + pedido de cambio de CBU (BEC)."""
    findings = [
        Finding(
            analyzer="headers",
            rule="headers.dmarc_fail",
            title="El remitente no pasó DMARC",
            category=FindingCategory.SPOOFING,
            severity=Severity.MEDIUM,
            score=30,
        ),
        Finding(
            analyzer="content",
            rule="content.bec.bank_change",
            title="Pide cambiar el CBU para los pagos",
            description="El mail pide transferir a una nueva cuenta bancaria.",
            category=FindingCategory.PHISHING,
            severity=Severity.MEDIUM,
            score=35,
        ),
    ]
    kw.setdefault("level", VerdictLevel.SUSPICIOUS)
    kw.setdefault("score", 48)
    kw.setdefault("summary", "Un supuesto proveedor pide cambiar la cuenta bancaria para los pagos.")
    kw.setdefault("subject", "Nuevos datos bancarios")
    kw.setdefault("findings", findings)
    return make_result(**kw)


@pytest.fixture
def alert_settings(settings):
    settings.actions.alerts.dashboard_base_url = "https://centinela.empresa.com/"
    settings.general.company_name = "Ferretería El Tornillo"
    return settings


@pytest.fixture
def malicious():
    return stealer_result()


@pytest.fixture
def suspicious_bec():
    return bec_result()
