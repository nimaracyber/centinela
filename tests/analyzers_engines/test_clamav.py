"""ClamAVAnalyzer contra un clamd FALSO (servidor asyncio en 127.0.0.1, puerto efímero)."""

from __future__ import annotations

import asyncio
import logging
import socket
import struct

import pytest

from centinela.analyzers.clamav import (
    ClamAVAnalyzer,
    ClamdError,
    classify_signature,
    finding_for_signature,
)
from centinela.core.models import Artifact, FindingCategory, Severity
from tests.helpers import eicar, make_artifact


class FakeClamd:
    """Implementa lo justo del protocolo de clamd para los tests."""

    def __init__(self) -> None:
        self.reply: bytes = b"stream: OK\0"
        self.mode = "normal"  # normal | hang | close | garbage
        self.limit: int | None = None  # simula StreamMaxLength
        self.streams: list[bytes] = []
        self.commands: list[bytes] = []
        self.chunk_sizes: list[int] = []
        self.release = asyncio.Event()  # libera los handlers en modo "hang" al terminar el test

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            cmd = await reader.readuntil(b"\0")
            self.commands.append(cmd)
            if cmd == b"zPING\0":
                writer.write(b"PONG\0")
            elif cmd == b"zVERSION\0":
                writer.write(b"ClamAV 1.4.1/27420/Sat Oct  3 08:00:00 2026\0")
            elif cmd == b"zINSTREAM\0":
                data = bytearray()
                while True:
                    (size,) = struct.unpack(">I", await reader.readexactly(4))
                    if size == 0:
                        break
                    self.chunk_sizes.append(size)
                    data += await reader.readexactly(size)
                    if self.limit is not None and len(data) > self.limit:
                        writer.write(b"INSTREAM size limit exceeded. ERROR\0")
                        await writer.drain()
                        self.streams.append(bytes(data))
                        return
                self.streams.append(bytes(data))
                if self.mode == "hang":
                    await asyncio.wait_for(self.release.wait(), timeout=30)
                    return
                elif self.mode == "close":
                    return
                elif self.mode == "garbage":
                    writer.write(b"que es esto\0")
                else:
                    writer.write(self.reply)
            else:
                writer.write(b"UNKNOWN COMMAND\0")
            await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()


@pytest.fixture
async def clamd(settings):
    fake = FakeClamd()
    server = await asyncio.start_server(fake.handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    settings.analyzers.clamav.host = "127.0.0.1"
    settings.analyzers.clamav.port = port
    settings.analyzers.clamav.timeout_s = 3.0
    try:
        yield fake
    finally:
        fake.release.set()
        server.close()
        await server.wait_closed()


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def test_clean_file_streams_all_bytes_in_chunks(settings, clamd, make_ctx):
    data = bytes(range(256)) * 3000  # ~750 KB: varios bloques de 256 KB
    an = ClamAVAnalyzer(settings)
    findings = await an.analyze(make_ctx(), make_artifact(data, "planilla.xlsx", "ooxml"))
    assert findings == []
    assert clamd.commands == [b"zINSTREAM\0"]
    assert clamd.streams == [data]  # el framing (longitud big-endian + datos + 0) llegó intacto
    assert len(clamd.chunk_sizes) >= 3 and max(clamd.chunk_sizes) <= 256 * 1024


async def test_malware_signature_maps_to_critical_family_finding(settings, clamd, make_ctx):
    clamd.reply = b"stream: Win.Trojan.AgentTesla-9876543-0 FOUND\0"
    an = ClamAVAnalyzer(settings)
    findings = await an.analyze(make_ctx(), make_artifact(b"inerte", "cotizacion.exe", "pe", id="att1"))
    assert len(findings) == 1
    f = findings[0]
    assert f.rule == "clamav.Win.Trojan.AgentTesla-9876543-0"
    assert f.category == FindingCategory.MALWARE
    assert f.severity == Severity.CRITICAL and f.score == 95
    assert f.malware_family == "AgentTesla"
    assert f.artifact_id == "att1"
    assert f.evidence["signature"] == "Win.Trojan.AgentTesla-9876543-0"
    assert f.evidence["official"] is True
    assert "AgentTesla" in f.title


async def test_eicar_is_reported_for_end_to_end_tests(settings, clamd, make_ctx):
    clamd.reply = b"stream: Win.Test.EICAR_HDB-1 FOUND\0"
    an = ClamAVAnalyzer(settings)
    findings = await an.analyze(make_ctx(), make_artifact(eicar(), "eicar.com", "text"))
    assert clamd.streams == [eicar()]
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].malware_family == "EICAR-Test-File"
    assert "EICAR" in findings[0].title


async def test_allmatch_multiple_results(settings, clamd, make_ctx):
    clamd.reply = (
        b"stream: Win.Malware.Remcos-10012345-0 FOUND\0"
        b"stream: Heuristics.Phishing.Email.SpoofedDomain FOUND\0"
        b"stream: Win.Malware.Remcos-10012345-0 FOUND\0"
    )
    an = ClamAVAnalyzer(settings)
    findings = await an.analyze(make_ctx(), make_artifact(b"x" * 10, "a.bin"))
    assert [f.malware_family for f in findings] == ["Remcos", None]
    assert findings[1].category == FindingCategory.PHISHING


async def test_clamd_size_limit_reply_is_policy_info(settings, clamd, make_ctx):
    clamd.limit = 1000
    an = ClamAVAnalyzer(settings)
    findings = await an.analyze(make_ctx(), make_artifact(b"A" * 600_000, "grande.iso", "iso"))
    assert len(findings) == 1
    f = findings[0]
    assert f.rule == "clamav.too_large"
    assert f.category == FindingCategory.POLICY and f.severity == Severity.INFO and f.score == 0
    assert f.evidence["clamd_limit"] is True


async def test_local_size_cap_skips_without_connecting(settings, clamd, make_ctx):
    an = ClamAVAnalyzer(settings)
    an.max_stream_bytes = 100
    findings = await an.analyze(make_ctx(), make_artifact(b"B" * 101, "x.bin"))
    assert findings[0].rule == "clamav.too_large" and findings[0].evidence["clamd_limit"] is False
    assert clamd.commands == []


async def test_max_stream_bytes_comes_from_config(settings, clamd, make_ctx):
    settings.analyzers.clamav.max_stream_bytes = 1000
    an = ClamAVAnalyzer(settings)
    assert an.max_stream_bytes == 1000
    findings = await an.analyze(make_ctx(), make_artifact(b"C" * 1001, "grande.bin"))
    assert findings[0].rule == "clamav.too_large" and findings[0].evidence["limit"] == 1000
    assert "1000 bytes" in findings[0].description
    assert clamd.commands == []  # nunca llegó a clamd
    assert await an.analyze(make_ctx(), make_artifact(b"C" * 1000, "justo.bin")) == []
    assert clamd.streams == [b"C" * 1000]
    settings.analyzers.clamav.max_stream_bytes = 0  # valor inválido: se usa el default
    assert ClamAVAnalyzer(settings).max_stream_bytes == 25 * 1024 * 1024


async def test_listing_only_artifacts_are_not_scanned(settings, clamd, make_ctx):
    an = ClamAVAnalyzer(settings)
    listed = Artifact(
        id="att0/f.exe", filename="f.exe", size=5000, depth=1, parent_id="att0", listing_only=True
    )
    assert not an.accepts(listed)
    assert await an.analyze(make_ctx(), listed) == []
    # contrato roto (listado pero con bytes): igual no se escanea
    weird = make_artifact(b"x" * 10, "f.exe").model_copy(update={"listing_only": True})
    assert not an.accepts(weird)
    assert await an.analyze(make_ctx(), weird) == []
    assert clamd.commands == []


async def test_clamd_error_reply_raises(settings, clamd, make_ctx):
    clamd.reply = b"stream: Can't allocate memory ERROR\0"
    an = ClamAVAnalyzer(settings)
    with pytest.raises(ClamdError):
        await an.analyze(make_ctx(), make_artifact(b"x", "x.bin"))


@pytest.mark.parametrize("mode", ["garbage", "close"])
async def test_unexpected_or_missing_reply_raises(settings, clamd, make_ctx, mode):
    clamd.mode = mode
    an = ClamAVAnalyzer(settings)
    with pytest.raises(ClamdError):
        await an.analyze(make_ctx(), make_artifact(b"x", "x.bin"))


async def test_hung_clamd_times_out_as_connection_error(settings, clamd, make_ctx):
    clamd.mode = "hang"
    settings.analyzers.clamav.timeout_s = 0.5
    an = ClamAVAnalyzer(settings)
    with pytest.raises(ConnectionError, match="no respondió"):
        await an.analyze(make_ctx(), make_artifact(b"x", "x.bin"))


async def test_clamd_down_setup_does_not_fail_but_analyze_raises(settings, make_ctx, caplog):
    settings.analyzers.clamav.host = "127.0.0.1"
    settings.analyzers.clamav.port = _free_port()
    settings.analyzers.clamav.timeout_s = 5.0
    an = ClamAVAnalyzer(settings)
    with caplog.at_level(logging.WARNING, logger="centinela.analyzers.clamav"):
        await an.setup()  # no levanta
    assert "clamd no responde" in caplog.text
    assert await an.ping() is False
    with pytest.raises(ConnectionError):
        await an.analyze(make_ctx(), make_artifact(b"x", "x.bin"))


async def test_ping_version_and_setup_with_live_clamd(settings, clamd):
    an = ClamAVAnalyzer(settings)
    assert await an.ping() is True
    await an.setup()
    assert an.engine_version and an.engine_version.startswith("ClamAV 1.4.1")
    assert b"zPING\0" in clamd.commands and b"zVERSION\0" in clamd.commands


async def test_engine_version_is_added_to_evidence(settings, clamd, make_ctx):
    clamd.reply = b"stream: Doc.Downloader.Emotet-123-0 FOUND\0"
    an = ClamAVAnalyzer(settings)
    await an.setup()
    findings = await an.analyze(make_ctx(), make_artifact(b"x", "x.doc", "ole"))
    assert findings[0].evidence["engine_version"].startswith("ClamAV")
    assert findings[0].malware_family == "Emotet"


async def test_concurrent_scans_each_get_their_own_connection(settings, clamd, make_ctx):
    an = ClamAVAnalyzer(settings)
    ctx = make_ctx()
    payloads = [bytes([i]) * (1000 + i) for i in range(12)]
    results = await asyncio.gather(
        *(an.analyze(ctx, make_artifact(p, f"f{i}", id=f"att{i}")) for i, p in enumerate(payloads))
    )
    assert results == [[]] * 12
    assert sorted(clamd.streams) == sorted(payloads)


def test_accepts_and_enabled(settings):
    an = ClamAVAnalyzer(settings)
    assert an.accepts(make_artifact(b"x", "x"))
    assert not an.accepts(make_artifact(b"", "vacio"))
    assert ClamAVAnalyzer.enabled(settings)
    settings.analyzers.clamav.enabled = False
    assert not ClamAVAnalyzer.enabled(settings)


@pytest.mark.parametrize(
    "sig,kind,category,severity,family",
    [
        (
            "Win.Trojan.AgentTesla-9876543-0",
            "malware",
            FindingCategory.MALWARE,
            Severity.CRITICAL,
            "AgentTesla",
        ),
        ("Win.Malware.Remcos-10002323-0", "malware", FindingCategory.MALWARE, Severity.CRITICAL, "Remcos"),
        (
            "Win.Packed.Msilzilla-9973231-0",
            "malware",
            FindingCategory.MALWARE,
            Severity.CRITICAL,
            "Msilzilla",
        ),
        ("Win.Trojan.Agent-1234567-0", "malware", FindingCategory.MALWARE, Severity.CRITICAL, None),
        ("Win.Malware.Zusy-9999999-0", "malware", FindingCategory.MALWARE, Severity.CRITICAL, None),
        ("Xls.Downloader.Generic-1-0", "malware", FindingCategory.MALWARE, Severity.CRITICAL, None),
        (
            "Win.Ransomware.Lockbit-9950000-1",
            "malware",
            FindingCategory.MALWARE,
            Severity.CRITICAL,
            "LockBit",
        ),
        ("Eicar-Signature", "test", FindingCategory.MALWARE, Severity.CRITICAL, "EICAR-Test-File"),
        (
            "Heuristics.Phishing.Email.SpoofedDomain",
            "phishing",
            FindingCategory.PHISHING,
            Severity.MEDIUM,
            None,
        ),
        ("Heuristics.Encrypted.Zip", "policy", FindingCategory.POLICY, Severity.INFO, None),
        ("Heuristics.Limits.Exceeded.MaxFileSize", "policy", FindingCategory.POLICY, Severity.INFO, None),
        ("Heuristics.OLE2.ContainsMacros", "heuristic", FindingCategory.SUSPICIOUS_FILE, Severity.LOW, None),
        ("Heuristics.Broken.Executable", "heuristic", FindingCategory.SUSPICIOUS_FILE, Severity.LOW, None),
        (
            "Heuristics.Macro.Sheet.Hidden",
            "heuristic",
            FindingCategory.SUSPICIOUS_FILE,
            Severity.MEDIUM,
            None,
        ),
        ("PUA.Win.Tool.Netcat-1", "pua", FindingCategory.SUSPICIOUS_FILE, Severity.LOW, None),
        ("Html.Phishing.Bank-12345-0", "phishing", FindingCategory.PHISHING, Severity.MEDIUM, None),
        (
            "Win.Tool.Mimikatz-6993232-0",
            "heuristic",
            FindingCategory.SUSPICIOUS_FILE,
            Severity.HIGH,
            "Mimikatz",
        ),
        ("Win.Adware.Browsefox-1-0", "pua", FindingCategory.SUSPICIOUS_FILE, Severity.LOW, None),
        (
            "Sanesecurity.Foxhole.Zip_exe.UNOFFICIAL",
            "heuristic",
            FindingCategory.SUSPICIOUS_FILE,
            Severity.MEDIUM,
            None,
        ),
        (
            "Sanesecurity.Badmacro.Doc.vbaproject.UNOFFICIAL",
            "heuristic",
            FindingCategory.SUSPICIOUS_FILE,
            Severity.HIGH,
            None,
        ),
        (
            "Sanesecurity.Phishing.Bank.12345.UNOFFICIAL",
            "phishing",
            FindingCategory.PHISHING,
            Severity.MEDIUM,
            None,
        ),
        ("Sanesecurity.Spam.27631.UNOFFICIAL", "spam", FindingCategory.PHISHING, Severity.LOW, None),
        ("Sanesecurity.Jurlbl.e54fd8.UNOFFICIAL", "spam", FindingCategory.PHISHING, Severity.LOW, None),
        (
            "SecuriteInfo.com.Trojan.AgentTesla.1234.UNOFFICIAL",
            "malware",
            FindingCategory.MALWARE,
            Severity.HIGH,
            "AgentTesla",
        ),
        ("YARA.AsyncRAT_payload.UNOFFICIAL", "malware", FindingCategory.MALWARE, Severity.HIGH, "AsyncRAT"),
        (
            "MiscreantPunch.Generic.Malware.UNOFFICIAL",
            "malware",
            FindingCategory.MALWARE,
            Severity.HIGH,
            None,
        ),
        ("Worm.Mydoom.M", "malware", FindingCategory.MALWARE, Severity.CRITICAL, None),
    ],
)
def test_classify_signature(sig, kind, category, severity, family):
    info = classify_signature(sig)
    assert (info.kind, info.category, info.severity, info.family) == (kind, category, severity, family)
    assert info.official == (not sig.endswith(".UNOFFICIAL"))


def test_rule_ids_are_sanitized_and_bounded():
    f = finding_for_signature("Weird Sig/../\x00name" + "x" * 500 + " FOUND", "att0")
    assert f.rule.startswith("clamav.")
    assert len(f.rule) <= len("clamav.") + 120
    assert all(c.isalnum() or c in "._-" for c in f.rule)
