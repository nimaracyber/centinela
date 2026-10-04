"""Tests de FileTypeAnalyzer. Muestras sintéticas e inertes (solo bytes de cabecera, nada ejecutable)."""

from __future__ import annotations

import pytest

from centinela.analyzers.filetype import FileTypeAnalyzer, clean_filename, real_extension, visual_filename
from centinela.core.models import Artifact, FindingCategory, ParsedMessage, Severity
from tests.helpers import make_artifact, make_ref

MZ = b"MZ" + b"\x00" * 62  # cabecera inerte; el tipo lo fija el test (detected_type)


def art(name: str | None, detected: str, *, id: str = "att0", depth: int = 0, parent: str | None = None,
        declared: str | None = None, encrypted: bool = False, note: str | None = None) -> Artifact:  # fmt: skip
    a = make_artifact(
        MZ, name, detected, id=id, depth=depth, parent_id=parent, declared_content_type=declared
    )
    a.encrypted = encrypted
    a.extraction_note = note
    return a


async def run(make_ctx, target: Artifact, others: list[Artifact] | None = None):
    arts = [target, *(others or [])]
    ctx = make_ctx(ParsedMessage(ref=make_ref(), artifacts=arts))
    analyzer = FileTypeAnalyzer(ctx.settings)
    assert analyzer.accepts(target)
    return await analyzer.analyze(ctx, target)


def by_rule(findings):
    return {f.rule: f for f in findings}


# --------------------------------------------------------------------------- extensiones peligrosas


@pytest.mark.parametrize(
    ("name", "detected", "score"),
    [
        ("factura.exe", "pe", 45),
        ("Factura.EXE", "pe", 45),
        ("pago.scr", "pe", 45),
        ("script.js", "script/js", 45),
        ("doc.vbs", "script/vbs", 45),
        ("run.ps1", "script/ps1", 45),
        ("instalar.bat", "script/bat", 45),
        ("doc.lnk", "lnk", 45),
        ("app.hta", "html", 45),
        ("pedido.one", "onenote", 40),
        ("acceso.url", "url_shortcut", 40),
        ("consulta.iqy", "iqy", 40),
        ("setup.msi", "msi", 45),
        ("addin.xll", "pe", 45),
        ("lib.dll", "pe", 40),
        ("ayuda.chm", "chm", 40),
        ("cambios.reg", "reg", 45),
        ("paquete.msix", "zip", 45),
        ("x.settingcontent-ms", "settingcontent", 45),
        ("buscar.search-ms", "search-ms", 40),
        ("consola.msc", "xml", 40),
    ],
)
async def test_dangerous_extension(make_ctx, name, detected, score):
    r = by_rule(await run(make_ctx, art(name, detected)))
    f = r["filetype.dangerous_extension"]
    assert f.score == score and f.severity == Severity.MEDIUM
    assert f.category == FindingCategory.SUSPICIOUS_FILE
    assert f.artifact_id == "att0"
    assert f.description  # explicación en español para el dueño


@pytest.mark.parametrize(
    "name",
    [
        "factura.pdf.exe",
        "factura.pdf      .exe",
        "foto.jpg.scr",
        "factura.pdf_____________.scr",
        "Factura N° 12.2024.pdf.js",
        "documento.docx.lnk",
        "fotos.zip.exe",
        "factura.pdf.iso",
        "presupuesto.xlsx  .hta",
        "factura.PDF.Exe",
    ],
)
async def test_double_extension(make_ctx, name):
    r = by_rule(await run(make_ctx, art(name, "pe")))
    f = r["filetype.double_extension"]
    assert f.score == 75 and f.severity == Severity.HIGH
    assert "filetype.dangerous_extension" not in r  # subsumida, no se cuenta dos veces


async def test_padded_without_inner_ext(make_ctx):
    f = by_rule(await run(make_ctx, art("factura                         .exe", "pe")))[
        "filetype.double_extension"
    ]
    assert f.evidence["padded"] is True


@pytest.mark.parametrize(
    "name", ["setup.exe", "v1.2.3.exe", "factura.2024.exe", "informe.final.pdf", "a.b.c.docx"]
)
async def test_double_extension_negative(make_ctx, name):
    detected = "pe" if name.endswith(".exe") else "pdf" if name.endswith(".pdf") else "ooxml"
    assert "filetype.double_extension" not in by_rule(await run(make_ctx, art(name, detected)))


@pytest.mark.parametrize(
    ("name", "visual"),
    [
        ("Factura\u202efdp.exe", "Facturaexe.pdf"),
        ("pago\u202excod.scr", "pagorcs.docx"),
        ("informe\u200e.pdf", "informe.pdf"),
        ("\u2067fdp.exe\u2069doc", "exe.pdfdoc"),
    ],
)
async def test_rtlo(make_ctx, name, visual):
    r = by_rule(await run(make_ctx, art(name, "pe")))
    f = r["filetype.rtlo"]
    assert f.score == 80 and f.severity == Severity.HIGH
    assert f.evidence["visual_name"] == visual
    assert "<U+" in f.evidence["filename"]  # el nombre se muestra con los caracteres escapados
    assert "filetype.double_extension" not in r and "filetype.dangerous_extension" not in r


def test_filename_helpers():
    assert clean_filename("factura.pdf. . ") == "factura.pdf"  # Windows quita puntos/espacios finales
    assert real_extension("factura.pdf.") == "pdf"
    assert real_extension("dir\\sub/factura.EXE") == "exe"
    assert real_extension("sin_extension") == ""
    assert real_extension(None) == ""
    assert real_extension("fac\u200btura.e\u200bxe") == "exe"
    assert visual_filename("abc\u202efdp.exe") == "abcexe.pdf"


# --------------------------------------------------------------------------- tipo real vs extensión


@pytest.mark.parametrize(
    ("name", "detected", "score", "severity"),
    [
        ("factura.pdf", "pe", 80, Severity.HIGH),
        ("foto.jpg", "script/js", 80, Severity.HIGH),
        ("contrato.docx", "lnk", 80, Severity.HIGH),
        ("planilla.xlsx", "msi", 80, Severity.HIGH),
        ("factura.pdf", "script/hta", 80, Severity.HIGH),
        ("factura.pdf", "zip", 40, Severity.MEDIUM),
        ("factura.pdf", "rar", 40, Severity.MEDIUM),
        ("factura.pdf", "html", 35, Severity.MEDIUM),
        ("notas.txt", "script/bat", 25, Severity.MEDIUM),
        ("factura.doc", "rtf", 0, Severity.INFO),
        ("planilla.xls", "html", 0, Severity.INFO),
        ("logo.jpg", "image/png", 0, Severity.INFO),
        ("contrato.docx", "ole", 0, Severity.INFO),  # OOXML cifrado
        ("contrato.docx", "zip", 0, Severity.INFO),  # docx sin [Content_Types].xml: no es un "disfraz"
        ("notas.txt", "html", 0, Severity.INFO),
    ],
)
async def test_type_mismatch(make_ctx, name, detected, score, severity):
    f = by_rule(await run(make_ctx, art(name, detected)))["filetype.type_mismatch"]
    assert (f.score, f.severity) == (score, severity)


@pytest.mark.parametrize(
    ("name", "detected"),
    [("data.bin", "pe"), ("archivo", "pe"), ("datos.dat", "script/ps1"), ("fotos.zip", "pe")],
)
async def test_hidden_executable(make_ctx, name, detected):
    f = by_rule(await run(make_ctx, art(name, detected)))["filetype.hidden_executable"]
    assert f.score == 40


async def test_content_type_mismatch(make_ctx):
    r = by_rule(await run(make_ctx, art("pago.exe", "pe", declared="application/pdf")))
    assert r["filetype.content_type_mismatch"].score == 30
    assert "filetype.dangerous_extension" in r
    r2 = by_rule(await run(make_ctx, art("pago.exe", "pe", declared="application/octet-stream")))
    assert "filetype.content_type_mismatch" not in r2
    r3 = by_rule(await run(make_ctx, art("factura.pdf", "pdf", declared="application/pdf; name=factura.pdf")))
    assert r3 == {}


# --------------------------------------------------------------------------- contenedores


@pytest.mark.parametrize(
    ("name", "detected"),
    [("imagen.iso", "iso"), ("disco.vhdx", "vhdx"), ("x.img", "img"), ("factura.zip", "udf")],
)
async def test_disk_image(make_ctx, name, detected):
    r = by_rule(await run(make_ctx, art(name, detected)))
    f = r["filetype.disk_image"]
    assert f.score == 45 and f.severity == Severity.MEDIUM
    assert "iso" in f.description and "Windows" in f.description
    assert "filetype.dangerous_extension" not in r


async def test_encrypted_archive(make_ctx):
    f = by_rule(await run(make_ctx, art("factura.zip", "zip", encrypted=True)))["filetype.encrypted_archive"]
    assert f.score == 35 and f.category == FindingCategory.POLICY


@pytest.mark.parametrize(
    ("note", "rule", "score"),
    [
        ("límite de profundidad alcanzado", "filetype.extraction_limit", 30),
        ("posible bomba de compresión (ratio 5000)", "filetype.extraction_limit", 30),
        ("presupuesto total de extracción agotado", "filetype.extraction_limit", 30),
        ("too many entries", "filetype.extraction_limit", 30),
        ("error CRC en una entrada", "filetype.extraction_note", 0),
    ],
)
async def test_extraction_notes(make_ctx, note, rule, score):
    f = by_rule(await run(make_ctx, art("datos.zip", "zip", note=note)))[rule]
    assert f.score == score and f.category == FindingCategory.POLICY


async def test_archive_with_single_executable(make_ctx):
    z = art("factura.zip", "zip", id="att0")
    exe = art("factura.exe", "pe", id="att0/factura.exe", depth=1, parent="att0")
    zr = by_rule(await run(make_ctx, z, [exe]))
    assert zr["filetype.archive_only_executable"].score == 70
    assert zr["filetype.archive_only_executable"].severity == Severity.HIGH
    er = by_rule(await run(make_ctx, exe, [z]))
    assert er["filetype.executable_in_archive"].score == 65
    assert "factura.zip" in er["filetype.executable_in_archive"].description
    assert "filetype.dangerous_extension" not in er


async def test_onenote_inside_archive_still_flagged(make_ctx):
    one = art("pedido.one", "onenote", id="att0/pedido.one", depth=1, parent="att0")
    r = by_rule(await run(make_ctx, one, [art("pedido.zip", "zip")]))
    assert r["filetype.dangerous_extension"].score == 40
    assert "filetype.executable_in_archive" not in r


async def test_nested_zip_iso_lnk(make_ctx):
    z = art("pedido.zip", "zip", id="att0")
    iso = art("pedido.iso", "iso", id="att0/pedido.iso", depth=1, parent="att0")
    lnk = art("pedido.pdf.lnk", "lnk", id="att0/pedido.iso/pedido.pdf.lnk", depth=2, parent="att0/pedido.iso")
    ini = art("autorun.inf", "text", id="att0/pedido.iso/autorun.inf", depth=2, parent="att0/pedido.iso")
    others = [iso, lnk, ini]
    zr = by_rule(await run(make_ctx, z, others))
    assert "filetype.archive_only_executable" in zr  # baja zip -> iso -> lnk
    ir = by_rule(await run(make_ctx, iso, [z, lnk, ini]))
    assert "filetype.archive_only_executable" in ir and "filetype.disk_image" in ir
    lr = by_rule(await run(make_ctx, lnk, [z, iso, ini]))
    assert "filetype.double_extension" in lr


async def test_archive_with_junk_and_exe(make_ctx):
    z = art("f.zip", "zip", id="att0")
    kids = [
        art("__MACOSX/._f.exe", "unknown", id="att0/m", depth=1, parent="att0"),
        art(".DS_Store", "unknown", id="att0/d", depth=1, parent="att0"),
        art("f.exe", "pe", id="att0/f.exe", depth=1, parent="att0"),
    ]
    assert "filetype.archive_only_executable" in by_rule(await run(make_ctx, z, kids))


async def test_archive_mixed_content_not_flagged(make_ctx):
    z = art("docs.zip", "zip", id="att0")
    kids = [
        art("factura.pdf", "pdf", id="att0/a", depth=1, parent="att0"),
        art("remito.pdf", "pdf", id="att0/b", depth=1, parent="att0"),
    ]
    assert await run(make_ctx, z, kids) == []
    kids.append(art("tool.exe", "pe", id="att0/c", depth=1, parent="att0"))
    assert "filetype.archive_only_executable" not in by_rule(await run(make_ctx, z, kids))


async def test_html_attachment_low(make_ctx):
    f = by_rule(await run(make_ctx, art("Factura.html", "html")))["filetype.html_attachment"]
    assert f.score == 10 and f.severity == Severity.LOW


# --------------------------------------------------------------------------- falsos positivos


@pytest.mark.parametrize(
    ("name", "detected"),
    [
        ("factura.pdf", "pdf"),
        ("foto.jpg", "image/jpeg"),
        ("logo.png", "image/png"),
        ("planilla.xlsx", "ooxml"),
        ("presupuesto.docx", "ooxml"),
        ("contrato.doc", "ole"),
        ("datos.csv", "text"),
        ("documentos.zip", "zip"),
        ("Factura B 0003-00001234.pdf", "pdf"),
        ("v1.2.3.pdf", "pdf"),
        ("informe.odt", "zip"),
        ("video.mp4", "unknown"),
        (None, "image/png"),
    ],
)
async def test_benign_attachments(make_ctx, name, detected):
    assert await run(make_ctx, art(name, detected)) == []


# --------------------------------------------------------------------------- input hostil


@pytest.mark.parametrize(
    "name",
    [
        None,
        "",
        "....",
        "a" * 10_000 + ".exe",
        "factura\x00.pdf.exe",
        "../../../evil.exe",
        "C:\\Windows\\evil.exe",
        "\u202e\u202e\u202e",
        "\u202e" * 5000 + "exe.pdf",
        ".exe",
        "x." + "e" * 1000,
        "\ud800.exe",
    ],
    ids=lambda s: ascii((s or "")[:30]),
)
async def test_hostile_filenames(make_ctx, name):
    out = await run(make_ctx, art(name, "pe"))
    assert isinstance(out, list)
    for f in out:
        assert len(f.title) <= 300
        assert len(str(f.evidence.get("filename", ""))) <= 300


async def test_path_traversal_name_uses_basename(make_ctx):
    r = by_rule(
        await run(
            make_ctx,
            art("../../../evil.exe", "pe", id="att0/x", depth=1, parent="att0"),
            [art("a.zip", "zip")],
        )
    )
    assert r["filetype.executable_in_archive"].evidence["extension"] == "exe"


async def test_self_parent_loop_does_not_hang(make_ctx):
    a = art("loop.zip", "zip", id="att0", parent="att0")
    b = art("b.zip", "zip", id="att0/b", depth=1, parent="att0")
    c = art("c.zip", "zip", id="att0/b/c", depth=2, parent="att0/b")
    b2 = art("b2.zip", "zip", id="att0/b/c/b2", depth=3, parent="att0/b/c")
    out = await run(make_ctx, a, [b, c, b2])
    assert isinstance(out, list)
