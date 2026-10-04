"""Mail más grande que `limits.max_message_bytes`: el conector manda solo los encabezados (truncated=True)
y el pipeline + scoring tienen que dejarlo al menos SOSPECHOSO con un resumen entendible."""

from __future__ import annotations

from centinela.core.cache import MemoryCache
from centinela.core.models import RawMessage, VerdictLevel
from centinela.core.pipeline import Pipeline
from tests.helpers import make_ref

MB = 1024 * 1024
HEADERS_ONLY = (
    b"From: Juan <juan@proveedor.com>\r\n"
    b"To: ventas@empresa.com\r\n"
    b"Subject: Factura vencida\r\n"
    b"Message-ID: <grande-1@proveedor.com>\r\n"
    b"\r\n"
)


async def test_truncated_message_is_suspicious_end_to_end(settings, http):
    pipeline = Pipeline(settings, [], http, MemoryCache())
    raw = RawMessage(ref=make_ref(), raw=HEADERS_ONLY, truncated=True, original_size=80 * MB)
    result = await pipeline.analyze(raw)

    assert result.truncated is True
    assert result.subject == "Factura vencida" and result.from_addr == "juan@proveedor.com"
    assert [f.rule for f in result.findings] == ["policy.message_too_large"]
    assert result.verdict.level == VerdictLevel.SUSPICIOUS
    assert result.verdict.score >= settings.scoring.suspicious_threshold
    assert result.verdict.summary.startswith(
        "Este correo es sospechoso: supera el tamaño máximo que se puede analizar"
    )
    assert "adjuntos no se revisaron" in result.verdict.summary
    assert result.errors == []


async def test_same_headers_not_truncated_are_clean(settings, http):
    pipeline = Pipeline(settings, [], http, MemoryCache())
    result = await pipeline.analyze(RawMessage(ref=make_ref(), raw=HEADERS_ONLY))
    assert result.truncated is False and result.findings == []
    assert result.verdict.level == VerdictLevel.CLEAN


async def test_truncated_message_stays_suspicious_with_high_thresholds(settings, http):
    settings.scoring.suspicious_threshold = 50
    settings.scoring.malicious_threshold = 90
    pipeline = Pipeline(settings, [], http, MemoryCache())
    raw = RawMessage(ref=make_ref(), raw=HEADERS_ONLY, truncated=True, original_size=80 * MB)
    result = await pipeline.analyze(raw)
    assert result.verdict.level == VerdictLevel.SUSPICIOUS and result.verdict.score == 50
