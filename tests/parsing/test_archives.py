from __future__ import annotations

import bz2
import gzip
import hashlib
import lzma
import os
import time
import zipfile

import pytest

from centinela.core.config import LimitsConfig
from centinela.core.models import Artifact
from centinela.parsing import archives
from centinela.parsing.archives import (
    NOTE_DEPTH,
    NOTE_DUPLICATE,
    NOTE_ENCRYPTED,
    NOTE_MAX_ARTIFACTS,
    NOTE_RAR_UNSUPPORTED,
    NOTE_SUSPICIOUS_PATH,
    NOTE_SYMLINK,
    NOTE_TIMEOUT,
    NOTE_TOO_LARGE,
    NOTE_UNSUPPORTED,
    NOTE_ZIP_BOMB,
    ExtractionBudget,
    can_expand,
    child_label,
    expand,
    password_candidates,
)
from centinela.parsing.filetype import detect_type
from tests.helpers import make_artifact
from tests.parsing import samples

MB = 1024 * 1024


def art(data: bytes, filename: str, *, id: str = "att0", depth: int = 0) -> Artifact:  # noqa: A002
    return make_artifact(data, filename, detect_type(data, filename), id=id, depth=depth)


def run(a: Artifact, limits: LimitsConfig | None = None, passwords: list[str] | None = None, budget=None):
    limits = limits or LimitsConfig(archive_passwords=[])
    budget = budget or ExtractionBudget.from_limits(limits)
    return expand(a, limits, passwords or [], budget)


def by_name(children: list[Artifact]) -> dict[str, Artifact]:
    return {c.filename: c for c in children}


EMPTY_HASHES = {
    hashlib.md5(b"").hexdigest(),
    hashlib.sha1(b"").hexdigest(),
    hashlib.sha256(b"").hexdigest(),
}


def assert_listing_only(a: Artifact) -> None:
    """Hijo solo listado: sin datos y con los hashes VACÍOS (nunca el hash de b"", que la reputación
    confundiría con un archivo real). Las banderas de contraseña van en el contenedor, no en la entrada."""
    assert a.listing_only is True
    assert a.data == b""
    assert (a.md5, a.sha1, a.sha256) == ("", "", "")
    assert not {a.md5, a.sha1, a.sha256} & EMPTY_HASHES
    assert not a.encrypted and not a.password_protected


def assert_extracted(a: Artifact) -> None:
    assert a.listing_only is False
    assert a.data and a.sha256 == hashlib.sha256(a.data).hexdigest()


# --------------------------------------------------------------------------- zip


def test_zip_children_have_ids_hashes_types_and_depth():
    pe = samples.minimal_pe()
    parent = art(samples.zip_bytes({"docs/factura.pdf.exe": pe, "leeme.txt": b"hola"}), "factura.zip")
    kids = run(parent)
    assert [k.id for k in kids] == ["att0/factura.pdf.exe", "att0/leeme.txt"]
    exe = kids[0]
    assert exe.detected_type == "pe"
    assert exe.sha256 == hashlib.sha256(pe).hexdigest()
    assert exe.md5 == hashlib.md5(pe).hexdigest()
    assert exe.sha1 == hashlib.sha1(pe).hexdigest()
    assert exe.size == len(pe) and exe.data == pe
    assert exe.depth == 1 and exe.parent_id == "att0"
    assert all(not k.listing_only for k in kids)
    assert parent.extraction_note is None and not parent.encrypted and not parent.password_protected


def test_zip_traversal_absolute_and_drive_names_are_only_labels(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    entries = [
        {"name": "../../../../Windows/Temp/evil.exe", "data": samples.minimal_pe()},
        {"name": "/etc/cron.d/x.sh", "data": b"#!/bin/sh\necho x"},
        {"name": "C:\\Users\\Public\\run.bat", "data": b"@echo off\r\necho x"},
    ]
    kids = run(art(samples.raw_zip(entries), "x.zip"))
    names = [k.filename for k in kids]
    assert names == ["evil.exe", "x.sh", "run.bat"]
    assert all(NOTE_SUSPICIOUS_PATH in (k.extraction_note or "") for k in kids)
    assert all("/" not in k.id.split("att0/", 1)[1] for k in kids)
    assert list(tmp_path.iterdir()) == []  # nada se escribió a disco


def test_zip_duplicate_names_get_unique_ids():
    entries = [
        {"name": "a.exe", "data": b"uno"},
        {"name": "dir/a.exe", "data": b"dos"},
        {"name": "a.exe", "data": b"tres"},
    ]
    kids = run(art(samples.raw_zip(entries), "x.zip"))
    assert [k.id for k in kids] == ["att0/a.exe", "att0/a.exe~2", "att0/a.exe~3"]
    assert {k.data for k in kids} == {b"uno", b"dos", b"tres"}


def test_zip_symlink_entries_ignored():
    entries = [
        {"name": "link", "data": b"/etc/passwd", "create_system": 3, "external_attr": (0o120777 << 16)},
        {"name": "ok.txt", "data": b"hola"},
    ]
    parent = art(samples.raw_zip(entries), "x.zip")
    kids = run(parent)
    assert [k.filename for k in kids] == ["ok.txt"]
    assert NOTE_SYMLINK in parent.extraction_note


def test_zip_bomb_by_compression_ratio():
    parent = art(samples.zip_bytes({"bomba.bin": b"\x00" * (20 * MB), "ok.txt": b"hola"}), "bomba.zip")
    kids = run(parent)
    assert NOTE_ZIP_BOMB in parent.extraction_note
    bomb = by_name(kids)["bomba.bin"]
    assert_listing_only(bomb)
    assert bomb.size == 20 * MB  # tamaño declarado
    assert by_name(kids)["ok.txt"].data == b"hola"  # las demás entradas se siguen procesando
    assert_extracted(by_name(kids)["ok.txt"])


def test_zip_bomb_by_total_budget_stops_extraction():
    limits = LimitsConfig(max_total_extracted_bytes=MB, archive_passwords=[])
    blobs = {f"r{i}.bin": os.urandom(400 * 1024) for i in range(4)}  # incompresible: el ratio no salta
    parent = art(samples.zip_bytes(blobs), "x.zip")
    budget = ExtractionBudget.from_limits(limits)
    kids = run(parent, limits, budget=budget)
    assert len(kids) == 2
    assert NOTE_ZIP_BOMB in parent.extraction_note
    assert budget.remaining_bytes >= 0


def test_zip_declared_size_lie_is_bounded():
    # el central directory declara 10 bytes pero el stream descomprime 5 MB
    entries = [{"name": "mentira.bin", "data": b"A" * (5 * MB), "declared_size": 10}]
    kids = run(art(samples.raw_zip(entries), "x.zip"))
    assert kids[0].size <= 10  # nunca se lee más de lo declarado/permitido


def test_zip_oversized_entry_listed_without_data():
    limits = LimitsConfig(max_artifact_bytes=1000, archive_passwords=[])
    parent = art(samples.zip_bytes({"grande.bin": os.urandom(5000), "chico.txt": b"x"}), "x.zip")
    kids = by_name(run(parent, limits))
    assert NOTE_TOO_LARGE in kids["grande.bin"].extraction_note
    assert_listing_only(kids["grande.bin"])
    assert kids["grande.bin"].size == 5000
    assert kids["chico.txt"].data == b"x"


def test_zip_crc_mismatch_kept_with_note():
    data = bytearray(samples.zip_bytes({"a.txt": b"hola mundo"}, method=zipfile.ZIP_STORED))
    pos = data.find(b"hola mundo")
    data[pos] = ord("H")  # corrompe el contenido: el CRC ya no coincide
    kids = run(art(bytes(data), "x.zip"))
    assert kids[0].data == b"Hola mundo"
    assert "CRC" in kids[0].extraction_note


def test_corrupt_zip_does_not_crash():
    parent = art(b"PK\x03\x04" + b"\xff" * 100, "roto.zip")
    assert run(parent) == []
    assert "dañado" in parent.extraction_note


# --------------------------------------------------------------------------- contraseñas


def test_zipcrypto_opened_with_candidate_password():
    entries = [{"name": "factura.exe", "data": samples.minimal_pe(), "password": "4455"}]
    parent = art(samples.raw_zip(entries), "factura.zip")
    kids = run(parent, passwords=["nope", "4455"])
    assert kids[0].data == samples.minimal_pe() and kids[0].detected_type == "pe"
    assert_extracted(kids[0])
    # tenía contraseña (técnica de evasión) aunque se haya podido abrir
    assert parent.password_protected is True and parent.encrypted is False
    assert not kids[0].password_protected and not kids[0].encrypted
    assert NOTE_ENCRYPTED in parent.extraction_note
    assert "4455" not in parent.extraction_note and "4455" not in kids[0].extraction_note


def test_zipcrypto_without_password_is_encrypted_listing():
    entries = [{"name": "factura.pdf.exe", "data": samples.minimal_pe(), "password": "s3cr3t-unico"}]
    parent = art(samples.raw_zip(entries), "factura.zip")
    kids = run(parent, passwords=["1234"])
    assert parent.encrypted is True and parent.password_protected is True
    assert len(kids) == 1
    k = kids[0]
    assert k.filename == "factura.pdf.exe"
    assert_listing_only(k)
    assert k.size == len(samples.minimal_pe())
    assert NOTE_ENCRYPTED in k.extraction_note


def test_zipcrypto_many_locked_entries_all_listed():
    entries = [
        {"name": f"f{i}.exe", "data": b"MZ" + bytes([i]) * 50, "password": "zz-unica"} for i in range(6)
    ]
    parent = art(samples.raw_zip(entries), "x.zip")
    kids = run(parent, passwords=["a1", "b2", "c3"])
    assert len(kids) == 6
    for k in kids:
        assert_listing_only(k)  # una sola contraseña: la bandera está UNA vez, en el contenedor
    assert parent.encrypted and parent.password_protected
    assert "6 archivo(s)" in parent.extraction_note


def test_zip_mixed_plain_and_locked_entries():
    entries = [
        {"name": "leeme.txt", "data": b"hola"},
        {"name": "factura.exe", "data": samples.minimal_pe(), "password": "no-esta"},
    ]
    parent = art(samples.raw_zip(entries), "x.zip")
    kids = by_name(run(parent, passwords=["1234"]))
    assert_extracted(kids["leeme.txt"])
    assert_listing_only(kids["factura.exe"])
    assert parent.password_protected and parent.encrypted  # quedó contenido protegido sin abrir


def test_zip_locked_entry_over_size_limit_still_marks_password():
    limits = LimitsConfig(max_artifact_bytes=100, archive_passwords=[])
    entries = [{"name": "grande.exe", "data": os.urandom(500), "password": "x1"}]
    parent = art(samples.raw_zip(entries), "x.zip")
    kids = run(parent, limits)
    assert_listing_only(kids[0])
    assert parent.password_protected is True
    assert parent.encrypted is False  # no se probó ninguna contraseña: se cortó por tamaño


def test_zipcrypto_password_reused_across_entries():
    entries = [
        {"name": f"f{i}.txt", "data": f"contenido {i}".encode(), "password": "clave-77"} for i in range(4)
    ]
    kids = run(art(samples.raw_zip(entries), "x.zip"), passwords=["x", "y", "clave-77"])
    assert [k.data for k in kids] == [f"contenido {i}".encode() for i in range(4)]


def test_zipcrypto_default_limits_passwords_are_tried():
    entries = [{"name": "a.txt", "data": b"contenido", "password": "infected"}]
    parent = art(samples.raw_zip(entries), "x.zip")
    kids = run(parent, LimitsConfig())  # "infected" está en archive_passwords por defecto
    assert kids[0].data == b"contenido"


@pytest.mark.parametrize(
    "vector",
    [samples.ZIPCRYPTO_7Z_ZIP, samples.AES256_ZIP, samples.AES128_STORED_ZIP],
    ids=["zipcrypto", "aes256", "aes128"],
)
def test_real_7zip_vectors_open_with_password(vector):
    parent = art(vector, "factura.zip")
    kids = run(parent, passwords=["4455"])
    assert kids[0].data == samples.AES_PLAINTEXT
    assert_extracted(kids[0])
    assert not parent.encrypted and parent.password_protected


@pytest.mark.parametrize("vector", [samples.AES256_ZIP, samples.AES128_STORED_ZIP], ids=["aes256", "aes128"])
def test_aes_zip_wrong_password_marks_encrypted(vector):
    parent = art(vector, "factura.zip")
    kids = run(parent, passwords=["0000", "infected"])
    assert parent.encrypted is True and parent.password_protected is True
    assert kids[0].filename == "factura.txt"
    assert_listing_only(kids[0])


def test_password_candidates_order_dedupe_and_cap():
    limits = LimitsConfig(archive_passwords=["infected", "1234"])
    got = password_candidates(["4455", "1234", "", "4455"] + [f"p{i}" for i in range(30)], limits)
    assert got[:2] == ["4455", "1234"]
    assert len(got) == 16 and len(set(got)) == 16


# --------------------------------------------------------------------------- recursión / presupuesto


def test_depth_limit_noted():
    data = samples.zip_bytes({"payload.txt": b"x"})
    for i in range(6):
        data = samples.zip_bytes({f"nivel{i}.zip": data})
    limits = LimitsConfig(max_archive_depth=3, archive_passwords=[])
    budget = ExtractionBudget.from_limits(limits)
    queue = [art(data, "top.zip")]
    seen = []
    while queue:
        a = queue.pop()
        seen.append(a)
        queue.extend(expand(a, limits, [], budget))
    assert max(a.depth for a in seen) == 3
    deepest = [a for a in seen if a.depth == 3][0]
    assert NOTE_DEPTH in deepest.extraction_note


def test_repeated_container_expanded_once():
    inner = samples.zip_bytes({"a.exe": samples.minimal_pe()})
    outer = samples.zip_bytes({"uno.zip": inner, "dos.zip": inner})
    limits = LimitsConfig(archive_passwords=[])
    budget = ExtractionBudget.from_limits(limits)
    top = art(outer, "x.zip")
    kids = expand(top, limits, [], budget)
    first = expand(kids[0], limits, [], budget)
    second = expand(kids[1], limits, [], budget)
    assert len(first) == 1 and second == []
    assert NOTE_DUPLICATE in kids[1].extraction_note and kids[0].id in kids[1].extraction_note


def test_quine_like_self_reference_not_expanded_twice():
    data = samples.zip_bytes({"a.txt": b"x"})
    limits = LimitsConfig(archive_passwords=[])
    budget = ExtractionBudget.from_limits(limits)
    a1 = art(data, "q.zip", id="att0")
    a2 = art(data, "q.zip", id="att0/q.zip", depth=1)  # mismo contenido que un ancestro
    assert expand(a1, limits, [], budget)
    assert expand(a2, limits, [], budget) == []
    assert NOTE_DUPLICATE in a2.extraction_note


def test_max_artifacts_budget():
    limits = LimitsConfig(max_artifacts=10, archive_passwords=[])
    parent = art(samples.zip_bytes({f"f{i}.txt": f"{i}".encode() for i in range(50)}), "x.zip")
    kids = run(parent, limits)
    assert len(kids) == 10
    assert NOTE_MAX_ARTIFACTS in parent.extraction_note


def test_deadline_exceeded():
    limits = LimitsConfig(archive_passwords=[])
    budget = ExtractionBudget.from_limits(limits)
    budget.deadline = time.monotonic() - 1
    parent = art(samples.zip_bytes({"a.txt": b"x"}), "x.zip")
    assert expand(parent, limits, [], budget) == []
    assert NOTE_TIMEOUT in parent.extraction_note


def test_non_containers_and_jar_not_expanded():
    assert run(art(b"hola", "a.txt")) == []
    assert run(art(samples.minimal_pe(), "a.exe")) == []
    jar = art(samples.zip_bytes({"META-INF/MANIFEST.MF": b"Main-Class: A", "A.class": b"x"}), "a.jar")
    assert jar.detected_type == "jar"
    assert not can_expand(jar)
    assert run(jar) == []
    empty = make_artifact(b"", "x.zip", "zip")
    assert run(empty) == []


# --------------------------------------------------------------------------- otros formatos


def test_ooxml_only_embeddings():
    docx = samples.zip_bytes(
        {
            "[Content_Types].xml": b"<Types/>",
            "word/document.xml": b"<w:document/>",
            "word/vbaProject.bin": b"\xd0\xcf\x11\xe0vba",
            "word/embeddings/oleObject1.bin": samples.ole_bytes(),
            "word/embeddings/Microsoft_Excel_Worksheet.xlsx": samples.zip_bytes(
                {"[Content_Types].xml": b"x"}
            ),
        }
    )
    parent = art(docx, "factura.docx")
    assert parent.detected_type == "ooxml"
    kids = run(parent)
    assert sorted(k.filename for k in kids) == ["Microsoft_Excel_Worksheet.xlsx", "oleObject1.bin"]
    assert {k.detected_type for k in kids} == {"ole", "ooxml"}


def test_ooxml_without_embeddings_has_no_children():
    docx = samples.zip_bytes({"[Content_Types].xml": b"<Types/>", "word/document.xml": b"<w:document/>"})
    assert run(art(docx, "carta.docx")) == []


def test_7z_plain_and_password():
    plain = art(samples.seven_zip({"a/factura.exe": samples.minimal_pe(), "b.txt": b"hola"}), "x.7z")
    kids = by_name(run(plain))
    assert kids["factura.exe"].detected_type == "pe" and kids["b.txt"].data == b"hola"
    assert not plain.password_protected and not plain.encrypted

    locked = art(samples.seven_zip({"factura.exe": samples.minimal_pe()}, password="clave99"), "x.7z")
    kids = run(locked, passwords=["clave99"])
    assert kids[0].data == samples.minimal_pe()
    assert_extracted(kids[0])
    assert locked.password_protected and not locked.encrypted

    locked2 = art(samples.seven_zip({"factura.exe": samples.minimal_pe()}, password="clave99"), "y.7z")
    kids = run(locked2, passwords=["otra"])
    assert locked2.encrypted and locked2.password_protected
    assert kids[0].filename == "factura.exe"
    assert_listing_only(kids[0])


def test_7z_header_encryption():
    blob = samples.seven_zip({"oculto.exe": samples.minimal_pe()}, password="x1y2", header_encryption=True)
    locked = art(blob, "x.7z")
    assert run(locked, passwords=["nop"]) == []
    assert locked.encrypted and locked.password_protected and NOTE_ENCRYPTED in locked.extraction_note
    opened = art(blob, "x.7z", id="att1")
    kids = run(opened, passwords=["nop", "x1y2"])
    assert kids[0].filename == "oculto.exe" and kids[0].detected_type == "pe"
    assert opened.password_protected and not opened.encrypted


def test_7z_bomb_detected_before_extraction():
    blob = samples.seven_zip({"cero.bin": b"\x00" * (30 * MB)})
    parent = art(blob, "x.7z")
    kids = run(parent)
    assert NOTE_ZIP_BOMB in parent.extraction_note
    assert_listing_only(kids[0])


def test_rar_stored_entry_extracted_in_pure_python():
    parent = art(samples.RAR_STORED, "factura.rar")
    kids = run(parent)
    assert kids[0].filename == "factura.txt" and kids[0].data == samples.RAR_STORED_CONTENT
    assert_extracted(kids[0])
    assert not parent.password_protected and not parent.encrypted


def _no_rar_tool(monkeypatch):
    import rarfile

    def no_tool(*args, **kwargs):
        raise rarfile.RarCannotExec("Cannot find working tool")

    monkeypatch.setattr(rarfile, "tool_setup", no_tool)
    monkeypatch.setattr(rarfile.RarFile, "open", lambda self, *a, **k: no_tool())


def test_rar_compressed_without_tool_is_listed(monkeypatch):
    _no_rar_tool(monkeypatch)
    parent = art(samples.RAR_COMPRESSED, "big.rar")
    kids = run(parent)
    assert kids[0].filename == "big.txt" and kids[0].size == 3000
    assert_listing_only(kids[0])
    assert NOTE_RAR_UNSUPPORTED in parent.extraction_note
    assert not parent.password_protected and not parent.encrypted


@pytest.mark.parametrize("passwords", [[], ["1234"]], ids=["sin-candidatas", "candidata-sin-unrar"])
def test_rar_encrypted_entry_not_opened_marks_container(monkeypatch, passwords):
    _no_rar_tool(monkeypatch)  # sin unrar no se puede ni probar la contraseña: igual queda "sin abrir"
    parent = art(samples.RAR_ENCRYPTED, "x.rar")
    kids = run(parent, passwords=passwords)
    assert kids[0].filename == "factura.txt"
    assert_listing_only(kids[0])
    assert parent.password_protected is True and parent.encrypted is True
    assert NOTE_ENCRYPTED in parent.extraction_note


@pytest.mark.parametrize(
    ("blob", "name", "locked"),
    [
        (samples.RAR_STORED, "factura.txt", False),
        (samples.RAR_COMPRESSED, "big.txt", False),
        (samples.RAR_ENCRYPTED, "factura.txt", True),
    ],
    ids=["stored", "comprimido", "cifrado"],
)
def test_rar_external_extraction_disabled_only_lists(monkeypatch, blob, name, locked):
    import rarfile

    def forbidden(*args, **kwargs):
        raise AssertionError("con allow_external_unrar=False no se abre ninguna entrada")

    monkeypatch.setattr(rarfile.RarFile, "open", forbidden)
    monkeypatch.setattr(rarfile, "tool_setup", forbidden)
    limits = LimitsConfig(allow_external_unrar=False, archive_passwords=[])
    parent = art(blob, "x.rar")
    kids = run(parent, limits, passwords=["1234"])
    assert [k.filename for k in kids] == [name]
    assert_listing_only(kids[0])
    assert kids[0].size > 0  # nombre y tamaño sí se listan
    assert archives.NOTE_RAR_DISABLED in kids[0].extraction_note
    assert archives.NOTE_RAR_DISABLED in parent.extraction_note
    assert parent.password_protected is locked and parent.encrypted is locked
    # la nota no habla de "límites": es una decisión de configuración, no un tope de seguridad alcanzado
    assert "límite" not in parent.extraction_note and "limit" not in parent.extraction_note.replace(
        "allow_external_unrar", ""
    )


def test_gzip_bzip2_xz_single_stream():
    for comp, ext, kind in (
        (gzip.compress, "gz", "gzip"),
        (bz2.compress, "bz2", "bzip2"),
        (lzma.compress, "xz", "xz"),
    ):
        parent = art(comp(samples.minimal_pe()), f"factura.exe.{ext}")
        assert parent.detected_type == kind
        kids = run(parent)
        assert kids[0].filename == "factura.exe" and kids[0].detected_type == "pe"


def test_gzip_original_name_from_header_and_tgz():
    import io

    buf = io.BytesIO()
    with gzip.GzipFile(filename="pedido.js", mode="wb", fileobj=buf) as g:
        g.write(b"var x = new ActiveXObject('a');")
    assert run(art(buf.getvalue(), "x.gz"))[0].filename == "pedido.js"
    tgz = art(gzip.compress(samples.tar_bytes({"a.txt": b"x"})), "paquete.tgz")
    kid = run(tgz)[0]
    assert kid.filename == "paquete.tar" and kid.detected_type == "tar"


def test_gzip_bomb():
    parent = art(gzip.compress(b"\x00" * (60 * MB)), "x.gz")
    kids = run(parent)
    assert NOTE_ZIP_BOMB in parent.extraction_note
    assert all(k.data == b"" for k in kids)


def test_truncated_gzip_keeps_partial_data_with_note():
    data = gzip.compress(b"hola mundo " * 1000)
    kids = run(art(data[: len(data) // 2], "x.gz"))
    assert kids and "truncado" in kids[0].extraction_note


def test_tar_regular_files_only():
    blob = samples.tar_bytes(
        {"../escape.sh": b"#!/bin/sh\nrm -rf /", "ok.txt": b"hola"}, symlinks={"link": "/etc/passwd"}
    )
    parent = art(blob, "x.tar")
    kids = by_name(run(parent))
    assert set(kids) == {"escape.sh", "ok.txt"}
    assert NOTE_SUSPICIOUS_PATH in kids["escape.sh"].extraction_note
    assert NOTE_SYMLINK in parent.extraction_note


@pytest.mark.parametrize(
    ("joliet", "udf"), [(True, False), (False, False), (True, True)], ids=["joliet", "iso9660", "udf"]
)
def test_iso_in_memory(joliet, udf):
    blob = samples.iso_bytes(
        {"factura.pdf.exe": samples.minimal_pe(), "leeme.txt": b"hola"}, joliet=joliet, udf=udf
    )
    parent = art(blob, "factura.iso")
    assert parent.detected_type == "iso"
    kids = run(parent)
    datas = {k.data for k in kids}
    assert samples.minimal_pe() in datas and b"hola" in datas
    if joliet or udf:
        assert "factura.pdf.exe" in {k.filename for k in kids}
    else:
        assert all(";" not in (k.filename or "") for k in kids)


def test_iso_named_img_detected_by_magic():
    blob = samples.iso_bytes({"a.exe": samples.minimal_pe()})
    parent = art(blob, "factura.img")
    assert parent.detected_type == "iso"
    assert run(parent)[0].detected_type == "pe"


def test_corrupt_iso_notes_unsupported():
    data = bytearray(0x9000)
    data[0x8001:0x8006] = b"CD001"
    parent = art(bytes(data), "x.iso")
    assert run(parent) == []
    assert NOTE_UNSUPPORTED in parent.extraction_note or "dañado" in parent.extraction_note


def test_pdf_embedded_files():
    blob = samples.pdf_with_attachment("factura.exe", samples.minimal_pe())
    parent = art(blob, "factura.pdf")
    kids = run(parent)
    assert kids[0].filename == "factura.exe" and kids[0].detected_type == "pe"


def test_pdf_without_attachments():
    assert run(art(samples.plain_pdf(), "x.pdf")) == []


@pytest.mark.parametrize(
    ("user_password", "candidates", "protected", "locked"),
    [
        ("", [], False, False),  # solo contraseña de dueño (permisos): típico de facturas legítimas
        ("clave-77", ["otra", "clave-77"], True, False),
        ("clave-77", ["otra"], True, True),
    ],
    ids=["solo-permisos", "abierto-con-candidata", "sin-abrir"],
)
def test_pdf_password_flags(user_password, candidates, protected, locked):
    blob = samples.encrypted_pdf_with_attachment(
        "factura.exe", samples.minimal_pe(), user_password, "duenio-x9"
    )
    parent = art(blob, "factura.pdf")
    assert parent.detected_type == "pdf"
    kids = run(parent, passwords=candidates)
    assert parent.password_protected is protected and parent.encrypted is locked
    if locked:
        assert kids == [] and NOTE_ENCRYPTED in parent.extraction_note
    else:
        assert kids[0].filename == "factura.exe" and kids[0].detected_type == "pe"
        assert_extracted(kids[0])
    assert "clave-77" not in (parent.extraction_note or "")


def test_onenote_embedded_payloads():
    hta = b'<html><HTA:APPLICATION/><script language="VBScript">x</script></html>'
    parent = art(samples.onenote_bytes([hta, samples.minimal_pe()]), "doc.one")
    kids = run(parent)
    assert [k.detected_type for k in kids] == ["script/hta", "pe"]
    assert kids[0].id == "att0/embebido0"


def test_onenote_truncated_length_does_not_crash():
    blob = (
        samples.ONENOTE_GUID
        + b"\x00" * 100
        + samples.FDSO_HEADER
        + (2**40).to_bytes(8, "little")
        + b"\x00" * 20
    )
    parent = art(blob, "x.one")
    assert run(parent) == []
    assert "truncado" in parent.extraction_note


@pytest.mark.parametrize("compress", [True, False], ids=["mszip", "stored"])
def test_cab_extraction(compress):
    big = os.urandom(40_000) + b"A" * 30_000  # cruza varios bloques de 32 KB
    parent = art(
        samples.cab_bytes([("factura.exe", samples.minimal_pe()), ("big.bin", big)], compress=compress),
        "x.cab",
    )
    kids = by_name(run(parent))
    assert kids["factura.exe"].data == samples.minimal_pe()
    assert kids["big.bin"].data == big


def test_cab_lzx_unsupported_lists_entries():
    parent = art(samples.cab_bytes([("a.exe", b"xx")], compress=False, lzx=True), "x.cab")
    kids = run(parent)
    assert kids[0].filename == "a.exe" and kids[0].size == 2
    assert_listing_only(kids[0])
    assert NOTE_UNSUPPORTED in parent.extraction_note


def test_tnef_winmail_dat():
    blob = samples.tnef_bytes(
        [("FACTUR~1.EXE", samples.minimal_pe(), "factura pendiente.pdf.exe"), ("leeme.txt", b"hola", None)]
    )
    parent = art(blob, "winmail.dat")
    assert can_expand(parent)
    kids = run(parent)
    assert [k.filename for k in kids] == ["factura pendiente.pdf.exe", "leeme.txt"]
    assert kids[0].detected_type == "pe"


def test_tnef_truncated():
    blob = samples.tnef_bytes([("a.txt", b"hola" * 100, None)])
    parent = art(blob[:-50], "winmail.dat")
    run(parent)
    assert "truncado" in parent.extraction_note


@pytest.mark.parametrize("kind", ["vhd", "vhdx", "img"])
def test_unsupported_disk_images_noted(kind):
    blob = {
        "vhd": b"conectix" + b"\x00" * 1024,
        "vhdx": b"vhdxfile" + b"\x00" * 1024,
        "img": b"\xeb\x3c\x90" + b"\x00" * 0x33 + b"FAT12" + b"\x00" * (510 - 0x3B) + b"\x55\xaa",
    }[kind]
    parent = art(blob, f"x.{kind}")
    assert parent.detected_type == kind
    assert run(parent) == []
    assert NOTE_UNSUPPORTED in parent.extraction_note


@pytest.mark.parametrize(
    "blob,name",
    [
        (b"7z\xbc\xaf\x27\x1c" + b"\xff" * 64, "x.7z"),
        (b"Rar!\x1a\x07\x01\x00" + b"\xff" * 64, "x.rar"),
        (b"\x1f\x8b" + b"\xff" * 64, "x.gz"),
        (b"BZh9" + b"\xff" * 64, "x.bz2"),
        (b"\xfd7zXZ\x00" + b"\xff" * 64, "x.xz"),
        (b"MSCF\x00\x00\x00\x00" + b"\xff" * 64, "x.cab"),
        (b"%PDF-1.4\n" + b"\xff" * 64, "x.pdf"),
        (samples.ONENOTE_GUID + b"\xff" * 64, "x.one"),
        (b"\x78\x9f\x3e\x22" + b"\xff" * 64, "winmail.dat"),
    ],
    ids=["7z", "rar", "gz", "bz2", "xz", "cab", "pdf", "one", "tnef"],
)
def test_garbage_containers_never_raise(blob, name):
    parent = art(blob, name)
    kids = run(parent)
    assert isinstance(kids, list)


def test_ole_package_payload_extracted():
    js = b"var sh = new ActiveXObject('WScript.Shell'); sh.Run('calc');"
    blob = samples.cfb_bytes(
        {
            "\x01Ole10Native": samples.ole10native("factura.js", js),
            "\x01CompObj": b"\x01\x00\xfe\xff" + b"\x00" * 60,
        }
    )
    parent = art(blob, "oleObject1.bin")
    assert parent.detected_type == "ole"
    kids = run(parent)
    assert len(kids) == 1
    assert kids[0].filename == "factura.js" and kids[0].data == js and kids[0].detected_type == "script/js"
    assert kids[0].id == "att0/factura.js"


def test_ole_large_package_payload_in_regular_sectors():
    pe = samples.minimal_pe() + os.urandom(20_000)
    blob = samples.cfb_bytes({"ObjectPool/_1234/\x01Ole10Native": samples.ole10native("setup.exe", pe)})
    kids = run(art(blob, "viejo.doc"))
    assert kids[0].filename == "setup.exe" and kids[0].data == pe and kids[0].detected_type == "pe"


def test_ole_document_without_objects_has_no_children():
    blob = samples.cfb_bytes(
        {"WordDocument": b"\x00" * 5000, "1Table": b"\x00" * 300, "\x05SummaryInformation": b"\x00" * 100}
    )
    parent = art(blob, "carta.doc")
    assert run(parent) == []
    assert parent.extraction_note is None


def test_outlook_msg_attachments_and_body():
    msg = samples.outlook_msg(
        [("factura.pdf.exe", samples.minimal_pe()), ("leeme.txt", b"hola")],
        body="Pagar en https://evil.example/x",
    )
    parent = art(msg, "reenviado.msg")
    assert parent.detected_type == "ole"
    kids = by_name(run(parent))
    assert kids["factura.pdf.exe"].detected_type == "pe"
    assert kids["leeme.txt"].data == b"hola"
    body = kids["cuerpo_mensaje.txt"]
    assert "https://evil.example/x" in body.data.decode()
    assert body.extraction_note == archives.NOTE_MSG_BODY  # así lo reconoce mime.py (contraseñas)


def test_outlook_msg_embedded_message_is_listing_only():
    streams = {
        "__properties_version1.0": b"\x00" * 32,
        "__attach_version1.0_#00000000/__substg1.0_3707001F": "reenvio.msg".encode("utf-16-le"),
        "__attach_version1.0_#00000000/__substg1.0_3701000D/__properties_version1.0": b"\x00" * 32,
    }
    kids = run(art(samples.cfb_bytes(streams), "x.msg"))
    assert [k.filename for k in kids] == ["reenvio.msg"]
    assert_listing_only(kids[0])


def test_build_artifact_listing_has_no_hashes_and_extracted_has_them():
    listed = archives.build_artifact(
        id="att0/a.exe", data=b"", filename="a.exe", depth=1, parent_id="att0", listing_size=1234
    )
    assert listed.size == 1234 and listed.detected_type == "unknown"
    assert_listing_only(listed)
    empty_file = archives.build_artifact(
        id="att0/vacio.txt", data=b"", filename="vacio.txt", depth=1, parent_id="att0"
    )
    assert empty_file.listing_only is False  # un archivo vacío REAL sí se extrajo: su hash es correcto
    assert empty_file.sha256 == hashlib.sha256(b"").hexdigest()


def test_msi_embedded_cab_and_custom_action_binary():
    streams = {
        samples.msi_stream_name("Binary.aicustact.dll"): samples.minimal_pe(),
        samples.msi_stream_name("Disk1.cab"): samples.cab_bytes([("payload.exe", samples.minimal_pe())]),
        samples.msi_stream_name("Property"): b"ProductName\x00Instalador\x00" * 10,
    }
    parent = art(samples.cfb_bytes(streams, samples.MSI_CLSID), "setup.msi")
    assert parent.detected_type == "msi"
    kids = by_name(run(parent))
    assert set(kids) == {"Binary.aicustact.dll", "Disk1.cab"}
    assert kids["Binary.aicustact.dll"].detected_type == "pe"
    inner = run(kids["Disk1.cab"])
    assert inner[0].filename == "payload.exe" and inner[0].detected_type == "pe"


def test_garbage_ole_never_raises():
    parent = art(bytes.fromhex("D0CF11E0A1B11AE1") + os.urandom(2000), "x.doc")
    assert run(parent) == []
    assert "dañado" in (parent.extraction_note or "")


def test_child_label_helper():
    assert child_label("../../a/b/c.exe", 0) == ("c.exe", "c.exe", True)
    assert child_label("C:evil.exe", 0) == ("evil.exe", "evil.exe", True)
    assert child_label("ok/dir/file.txt", 0) == ("file.txt", "file.txt", False)
    assert child_label("", 3) == ("entrada3", None, False)
    label, filename, _ = child_label("factura\u202efdp.exe\x00\x01", 0)
    assert filename == "factura\u202efdp.exe"  # RTLO se conserva (lo detecta el analizador), controles no


def test_module_exposes_note_vocabulary():
    assert archives.NOTE_ZIP_BOMB.startswith("posible zip-bomb")
    assert archives.NOTE_UNSUPPORTED == "contenedor no soportado para extracción"
