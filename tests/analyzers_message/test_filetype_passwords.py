"""FileTypeAnalyzer con el contrato nuevo: `password_protected`, entradas "solo listadas" (`listing_only`) y
notas de extracción con el vocabulario de parsing/archives.py. Muestras inertes (solo metadatos)."""

from __future__ import annotations

import pytest

from centinela.analyzers.filetype import FileTypeAnalyzer, classify_note
from centinela.core.models import Artifact, FindingCategory, ParsedMessage, Severity
from centinela.parsing.archives import (
    NOTE_DEPTH,
    NOTE_DUPLICATE,
    NOTE_ENCRYPTED,
    NOTE_MSG_BODY,
    NOTE_NOT_EXTRACTED,
    NOTE_TIMEOUT,
    NOTE_TOO_LARGE,
    NOTE_UNSUPPORTED,
    NOTE_ZIP_BOMB,
)
from tests.helpers import make_artifact, make_ref

LOCKED_NOTE = f"{NOTE_NOT_EXTRACTED}: {NOTE_ENCRYPTED}: no se encontró la contraseña"


def art(name: str, detected: str, *, id: str = "att0", depth: int = 0, parent: str | None = None,
        note: str | None = None) -> Artifact:  # fmt: skip
    a = make_artifact(b"PK\x03\x04" + b"\x00" * 60, name, detected, id=id, depth=depth, parent_id=parent)
    a.extraction_note = note
    return a


def listed(name: str, *, id: str, parent: str = "att0", depth: int = 1, note: str | None = LOCKED_NOTE,
           detected: str = "unknown") -> Artifact:  # fmt: skip
    """Entrada solo listada (como la crea parsing/archives.py): sin datos y sin hashes."""
    return Artifact(
        id=id, filename=name, detected_type=detected, size=48_000, depth=depth, parent_id=parent,
        listing_only=True, extraction_note=note,
    )  # fmt: skip


def protected_zip(name: str = "factura.zip", *, encrypted: bool, id: str = "att0", depth: int = 0,
                  parent: str | None = None) -> Artifact:  # fmt: skip
    note = (
        f"{NOTE_ENCRYPTED}: 1 archivo(s) no se pudieron abrir"
        if encrypted
        else f"{NOTE_ENCRYPTED}: se abrió con una contraseña candidata"
    )
    z = art(name, "zip", id=id, depth=depth, parent=parent, note=note)
    z.password_protected = True
    z.encrypted = encrypted
    return z


def by_rule(findings):
    return {f.rule: f for f in findings}


def on(findings, artifact_id: str):
    return by_rule([f for f in findings if f.artifact_id == artifact_id])


async def run_all(make_ctx, arts: list[Artifact]) -> list:
    """Corre el analizador sobre TODOS los artifacts del mensaje (como el pipeline)."""
    ctx = make_ctx(ParsedMessage(ref=make_ref(), artifacts=arts))
    analyzer = FileTypeAnalyzer(ctx.settings)
    out = []
    for a in arts:
        assert analyzer.accepts(a)  # las entradas solo listadas también se analizan (por el nombre)
        out += await analyzer.analyze(ctx, a)
    return out


# --------------------------------------------------------------------------- entradas solo listadas


async def test_encrypted_zip_with_listed_exe_is_detected_by_name(make_ctx):
    z = protected_zip(encrypted=True)
    exe = listed("factura.exe", id="att0/factura.exe")
    findings = await run_all(make_ctx, [z, exe])
    on_zip, on_exe = on(findings, "att0"), on(findings, "att0/factura.exe")

    enc = on_zip["filetype.encrypted_archive"]
    assert (enc.score, enc.severity, enc.category) == (35, Severity.MEDIUM, FindingCategory.POLICY)
    assert enc.evidence["opened"] is False and enc.evidence["entries"] == ["factura.exe"]
    assert "factura.exe" in enc.description
    only = on_zip["filetype.archive_only_executable"]  # antes se salteaba si el zip estaba cifrado
    assert only.score == 70 and only.evidence["children_listing_only"] is True
    assert "filetype.extraction_note" not in on_zip  # la nota de cifrado ya la explica la regla de contraseña

    ex = on_exe["filetype.executable_in_archive"]
    assert ex.score == 65 and ex.evidence["listing_only"] is True
    assert "por el nombre" in ex.description
    assert set(on_exe) == {"filetype.executable_in_archive"}  # ni nota ni contraseña repetidas en la entrada
    high = {f.rule for f in findings if f.severity >= Severity.HIGH}
    assert {"filetype.archive_only_executable", "filetype.executable_in_archive"} <= high


async def test_listed_double_extension_and_rtlo_by_name(make_ctx):
    z = protected_zip(encrypted=True)
    dbl = listed("factura.pdf.exe", id="att0/a")
    rtlo = listed("pago‮xcod.scr", id="att0/b")
    findings = await run_all(make_ctx, [z, dbl, rtlo])
    assert "filetype.double_extension" in on(findings, "att0/a")
    assert "filetype.rtlo" in on(findings, "att0/b")
    assert "filetype.archive_only_executable" in on(findings, "att0")


async def test_listed_entries_skip_content_based_rules(make_ctx):
    # una entrada sin contenido no tiene "tipo real": nada de type_mismatch / hidden_executable / content-type
    z = protected_zip(encrypted=True)
    a = listed("notas.txt", id="att0/notas.txt", detected="script/bat")
    b = listed("foto.jpg", id="att0/foto.jpg", detected="pe")
    b.declared_content_type = "image/jpeg"
    c = listed("datos.bin", id="att0/datos.bin", detected="pe")
    findings = await run_all(make_ctx, [z, a, b, c])
    rules = {f.rule for f in findings if f.artifact_id != "att0"}
    assert not rules & {
        "filetype.type_mismatch",
        "filetype.hidden_executable",
        "filetype.content_type_mismatch",
    }


async def test_listed_too_large_entry_is_an_extraction_limit(make_ctx):
    z = art("pack.zip", "zip")
    big = listed(
        "instalador.exe",
        id="att0/instalador.exe",
        note=f"{NOTE_NOT_EXTRACTED}: {NOTE_TOO_LARGE} (más de 50 MB)",
    )
    on_big = on(await run_all(make_ctx, [z, big]), "att0/instalador.exe")
    assert on_big["filetype.extraction_limit"].score == 30
    assert on_big["filetype.executable_in_archive"].score == 65


async def test_nested_zip_then_encrypted_zip_with_listed_exe(make_ctx):
    # pedido.zip -> factura.zip (cifrado) -> factura.exe (solo listado): baja dos niveles
    outer = art("pedido.zip", "zip")
    inner = protected_zip("factura.zip", encrypted=True, id="att0/factura.zip", depth=1, parent="att0")
    exe = listed("factura.exe", id="att0/factura.zip/factura.exe", parent="att0/factura.zip", depth=2)
    findings = await run_all(make_ctx, [outer, inner, exe])
    assert on(findings, "att0")["filetype.archive_only_executable"].evidence["children"] == ["factura.exe"]
    assert on(findings, "att0/factura.zip")["filetype.encrypted_archive"].score == 35


# --------------------------------------------------------------------------- contraseña: una vez, en el contenedor


async def test_one_password_counts_once_not_per_entry(make_ctx):
    # parser viejo: cada entrada bloqueada también traía encrypted=True; igual debe contar UNA vez
    z = protected_zip(encrypted=True)
    kids = [listed(f"doc{i}.pdf", id=f"att0/doc{i}.pdf") for i in range(4)]
    for k in kids:
        k.encrypted = True
    findings = await run_all(make_ctx, [z, *kids])
    assert [f.artifact_id for f in findings if f.rule == "filetype.encrypted_archive"] == ["att0"]
    assert "filetype.archive_only_executable" not in {f.rule for f in findings}  # solo PDFs listados


async def test_password_protected_but_opened_is_weaker_medium(make_ctx):
    z = protected_zip(encrypted=False)
    pdf = art(
        "factura.pdf", "pdf", id="att0/factura.pdf", depth=1, parent="att0",
        note=f"{NOTE_ENCRYPTED}: abierto con una contraseña candidata",
    )  # fmt: skip
    findings = await run_all(make_ctx, [z, pdf])
    enc = by_rule(findings)["filetype.encrypted_archive"]
    assert enc.artifact_id == "att0"
    assert (enc.score, enc.severity, enc.category) == (25, Severity.MEDIUM, FindingCategory.POLICY)
    assert enc.evidence["opened"] is True and enc.evidence["password_protected"] is True
    assert "revisó su contenido" in enc.description
    assert on(findings, "att0/factura.pdf") == {}


async def test_encrypted_without_password_flag_still_counts(make_ctx):
    z = art("factura.7z", "7z")
    z.encrypted = True  # parser viejo: solo encrypted
    findings = await run_all(make_ctx, [z])
    assert by_rule(findings)["filetype.encrypted_archive"].score == 35


async def test_nested_locked_archive_inside_opened_one_is_reported(make_ctx):
    outer = protected_zip("pedido.zip", encrypted=False)
    inner = protected_zip("factura.zip", encrypted=True, id="att0/factura.zip", depth=1, parent="att0")
    findings = await run_all(make_ctx, [outer, inner])
    enc = {f.artifact_id: f.score for f in findings if f.rule == "filetype.encrypted_archive"}
    assert enc == {"att0": 25, "att0/factura.zip": 35}  # el de adentro quedó cerrado: señal más fuerte
    # dos comprimidos abiertos con contraseña, uno dentro del otro: una sola vez
    inner_open = protected_zip("factura.zip", encrypted=False, id="att0/factura.zip", depth=1, parent="att0")
    findings = await run_all(make_ctx, [outer, inner_open])
    assert [f.artifact_id for f in findings if f.rule == "filetype.encrypted_archive"] == ["att0"]


@pytest.mark.parametrize(
    ("name", "detected"), [("factura.pdf", "pdf"), ("planilla.xlsx", "ooxml"), ("a.doc", "ole")]
)
async def test_encrypted_documents_are_left_to_their_analyzers(make_ctx, name, detected):
    d = art(name, detected)
    d.encrypted = d.password_protected = True
    assert "filetype.encrypted_archive" not in by_rule(await run_all(make_ctx, [d]))


# --------------------------------------------------------------------------- notas de extracción


@pytest.mark.parametrize(
    ("note", "kind"),
    [
        (NOTE_ZIP_BOMB, "limit"),
        (f"{NOTE_DEPTH} (4 niveles)", "limit"),
        (NOTE_TIMEOUT, "limit"),  # antes no se reconocía como límite
        (f"{NOTE_NOT_EXTRACTED}: {NOTE_TOO_LARGE} (más de 50 MB)", "limit"),
        (f"{NOTE_NOT_EXTRACTED}: {NOTE_ZIP_BOMB}", "limit"),
        (f"{NOTE_DUPLICATE}: idéntico a att1", "info"),
        (f"{NOTE_UNSUPPORTED} (vhd)", "info"),
        (f"{NOTE_NOT_EXTRACTED}: entrada dañada (BadZipFile)", "info"),
        (f"{NOTE_ENCRYPTED}: se abrió con una contraseña candidata", "silent"),
        (LOCKED_NOTE, "silent"),
        (NOTE_MSG_BODY, "silent"),
        ("posible bomba de compresión (ratio 5000)", "limit"),  # notas de otros productores: por palabras
        ("error CRC en una entrada", "info"),
    ],
)
def test_classify_note_uses_archive_vocabulary(note, kind):
    assert classify_note(note) == kind


@pytest.mark.parametrize(
    ("note", "rule", "shown"),
    [
        (f"{NOTE_ENCRYPTED}: 1 archivo(s) no se pudieron abrir; {NOTE_TIMEOUT}", "filetype.extraction_limit",
         NOTE_TIMEOUT),
        (f"{NOTE_DUPLICATE}: idéntico a att1", "filetype.extraction_note", NOTE_DUPLICATE),
        (f"{NOTE_ENCRYPTED}: se abrió con una contraseña candidata", None, None),
        (NOTE_MSG_BODY, None, None),
    ],
)  # fmt: skip
async def test_extraction_note_findings_from_constants(make_ctx, note, rule, shown):
    r = by_rule(await run_all(make_ctx, [art("datos.zip", "zip", note=note)]))
    note_rules = {k for k in r if k in ("filetype.extraction_limit", "filetype.extraction_note")}
    if rule is None:
        assert note_rules == set()
    else:
        assert note_rules == {rule}
        assert r[rule].evidence["note"].startswith(shown)
        assert NOTE_ENCRYPTED not in r[rule].evidence["note"]  # la parte de contraseña no se repite


async def test_hostile_note_is_bounded(make_ctx):
    note = "; ".join([NOTE_TIMEOUT] * 5000)
    r = by_rule(await run_all(make_ctx, [art("datos.zip", "zip", note=note)]))
    assert len(r["filetype.extraction_limit"].evidence["note"]) <= 300


async def test_analyzer_uses_ctx_children(make_ctx):
    # los hijos están en otro orden y con otros artifacts en el medio
    z = art("factura.zip", "zip", id="att0")
    other = art("logo.png", "image/png", id="att1")
    exe = make_artifact(b"MZ", "factura.exe", "pe", id="att0/factura.exe", depth=1, parent_id="att0")
    ctx = make_ctx(ParsedMessage(ref=make_ref(), artifacts=[exe, other, z]))
    assert ctx.children("att0") == [exe]
    out = by_rule(await FileTypeAnalyzer(ctx.settings).analyze(ctx, z))
    assert out["filetype.archive_only_executable"].evidence["children"] == ["factura.exe"]
