"""Helpers de mails demasiado grandes (connectors/_headers.py): se analizan solo los encabezados."""

from __future__ import annotations

import email
import time
from datetime import UTC, datetime

import pytest

from centinela.connectors._headers import (
    MAX_HEADER_BYTES,
    header_cap,
    header_section,
    headers_from_api,
    oversize_raw,
)
from centinela.core.cache import MemoryCache
from centinela.core.models import FindingCategory, Severity
from centinela.core.pipeline import Pipeline
from tests.helpers import build_eml, make_ref

# --------------------------------------------------------------------------- header_section


def test_header_section_stops_at_first_blank_line():
    eml = b"From: a@b.com\r\nSubject: hola\r\n\r\ncuerpo\r\n\r\nmas cuerpo"
    assert header_section(eml) == b"From: a@b.com\r\nSubject: hola\r\n\r\n"
    lf = b"From: a@b.com\nSubject: hola\n\ncuerpo"
    assert header_section(lf) == b"From: a@b.com\nSubject: hola\n\n"


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"", b"\r\n"),
        (b"\r\n\r\ncuerpo sin headers", b"\r\n"),
        (b"\ncuerpo", b"\r\n"),
        (b"Subject: solo headers", b"Subject: solo headers\r\n\r\n"),
        (b"Subject: x\r\nFrom: y\r\n", b"Subject: x\r\nFrom: y\r\n\r\n"),
    ],
)
def test_header_section_edge_cases(data, expected):
    assert header_section(data) == expected


def test_header_section_is_bounded_and_cuts_at_line_end():
    lines = b"".join(b"X-Relleno-%05d: %s\r\n" % (i, b"z" * 80) for i in range(5000))  # ~500 KB, sin cuerpo
    out = header_section(lines + b"\r\ncuerpo", 10_000)
    assert len(out) <= 10_000 and out.endswith(b"\r\n\r\n")
    assert out.count(b"\r\n\r\n") == 1  # ninguna línea quedó cortada a la mitad
    # una sola "línea" gigante sin fin: se descarta entera
    assert header_section(b"X-Gigante: " + b"a" * 1_000_000, 4096) == b"\r\n"


def test_header_section_is_linear_on_hostile_input():
    blob = b"\r" * 3_000_000  # muchos CR sin LF: la regex no debe hacer backtracking
    t0 = time.perf_counter()
    assert len(header_section(blob)) <= MAX_HEADER_BYTES
    assert time.perf_counter() - t0 < 1.0


def test_header_cap():
    assert header_cap(60 * 1024 * 1024) == MAX_HEADER_BYTES
    assert header_cap(2000) == 2000
    assert header_cap(10) == 64


# --------------------------------------------------------------------------- headers_from_api


def test_headers_from_api_builds_rfc5322_block_and_blocks_injection():
    items = [
        {"name": "From", "value": "José Pérez <jose@proveedor.com>"},
        {"name": "Subject", "value": "Hola\r\nBcc: x@evil.example\nX-Otro: y"},
        {"name": "Bad Name:\r\n", "value": "v"},
        {"name": ":::", "value": "sin nombre"},
        {"name": "X-Nulo", "value": "a\0b"},
        {"name": "X-Lone", "value": "\ud800"},  # surrogate suelto (JSON hostil)
        {"name": "X-Num", "value": 5},
        "basura",
        None,
    ]
    out = headers_from_api(items)
    assert (
        out
        == (
            "From: José Pérez <jose@proveedor.com>\r\n"
            "Subject: Hola Bcc: x@evil.example X-Otro: y\r\n"
            "BadName: v\r\n"
            "X-Nulo: a b\r\n"
            "X-Lone: ?\r\n"
            "\r\n"
        ).encode()
    )
    parsed = email.message_from_bytes(out)
    assert parsed["Bcc"] is None and parsed["X-Otro"] is None


def test_headers_from_api_limits():
    many = [{"name": "X-H", "value": "v"} for _ in range(10_000)]
    assert headers_from_api(many, max_fields=10).count(b"X-H: v\r\n") == 10
    big = [{"name": "X-H", "value": "v" * 1000} for _ in range(100)]
    out = headers_from_api(big, max_bytes=5000)
    assert len(out) <= 5000 and out.endswith(b"\r\n\r\n")
    assert headers_from_api(None) == b"\r\n" and headers_from_api([]) == b"\r\n"


# --------------------------------------------------------------------------- oversize_raw


def test_oversize_raw_sets_flags_and_lower_bound():
    ref = make_ref("big")
    when = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)
    raw = oversize_raw(ref, b"Subject: x\r\n\r\n", original_size=5000, limit=1000, received_at=when)
    assert raw.truncated is True and raw.original_size == 5000 and raw.received_at == when
    assert raw.raw == b"Subject: x\r\n\r\n" and raw.ref == ref
    # desconocido o "menor que el límite" (el origen mintió): cota inferior límite + 1
    assert oversize_raw(ref, b"\r\n", original_size=None, limit=1000).original_size == 1001
    assert oversize_raw(ref, b"\r\n", original_size=10, limit=1000).original_size == 1001


# --------------------------------------------------------------------------- integración con el pipeline


async def test_pipeline_flags_headers_only_message(settings, http):
    """Lo que emiten los conectores produce el hallazgo POLICY y se sigue viendo el remitente."""
    settings.limits.max_message_bytes = 1000
    eml = build_eml(
        subject="Factura", attachments=[("f.zip", b"PK\x03\x04" + b"\0" * 5000, "application/zip")]
    )
    raw = oversize_raw(make_ref("big"), header_section(eml), original_size=len(eml), limit=1000)
    pipeline = Pipeline(settings, [], http, MemoryCache())
    result = await pipeline.analyze(raw)
    assert result.truncated is True
    assert result.subject == "Factura" and result.from_addr == "juan@proveedor.com"
    (finding,) = [f for f in result.findings if f.rule == "policy.message_too_large"]
    assert finding.category == FindingCategory.POLICY and finding.severity == Severity.MEDIUM
    assert finding.evidence["tamano_bytes"] == len(eml)
    assert result.artifacts == []
