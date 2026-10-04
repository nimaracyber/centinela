from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from datetime import UTC, datetime, timedelta

import pytest

from centinela.core.config import LimitsConfig
from centinela.core.models import ArtifactSummary, ParsedMessage
from centinela.parsing.mime import (
    decode_bytes,
    decode_rfc2047,
    find_password_candidates,
    html_to_text,
    message_password_candidates,
    parse_message,
)
from tests.helpers import build_eml, eicar, make_raw
from tests.parsing import samples

LIMITS = LimitsConfig()


def parse(eml: bytes, limits: LimitsConfig = LIMITS):
    return parse_message(make_raw(eml), limits)


def mime(headers: str, body: bytes = b"") -> bytes:
    """Arma un mail crudo a mano (CRLF) para casos malformados."""
    return headers.replace("\n", "\r\n").encode("utf-8") + b"\r\n" + body


def arts(pm):
    return {a.id: a for a in pm.artifacts}


# --------------------------------------------------------------------------- headers


def test_basic_headers_and_addresses():
    eml = build_eml(
        subject="Pedido 123",
        from_='"Ana Pérez" <ANA@Cliente.com.ar>',
        to="ventas@empresa.com, Compras <compras@empresa.com>",
        headers={
            "Cc": "jefe@empresa.com",
            "Reply-To": "otra@gmail.com, tercera@yahoo.com",
            "Return-Path": "<Bounce@Cliente.com.ar>",
            "Date": "Tue, 01 Oct 2024 10:00:00 -0300",
        },
    )
    pm = parse(eml)
    assert pm.subject == "Pedido 123"
    assert pm.from_addr == "ana@cliente.com.ar"
    assert pm.from_display == "Ana Pérez"
    assert pm.to == ["ventas@empresa.com", "compras@empresa.com"]
    assert pm.cc == ["jefe@empresa.com"]
    assert pm.reply_to == ["otra@gmail.com", "tercera@yahoo.com"]
    assert pm.return_path == "bounce@cliente.com.ar"
    assert pm.message_id == "<test-1@proveedor.com>"
    assert pm.date == datetime(2024, 10, 1, 13, 0, tzinfo=UTC)
    assert pm.date.utcoffset() == timedelta(hours=-3)
    assert pm.header("subject") == "Pedido 123"
    assert [k for k, _ in pm.headers][:3] == ["Subject", "From", "To"]
    assert pm.size == len(eml)
    assert pm.parse_errors == []
    assert pm.body_text.strip() == "Texto"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("=?utf-8?B?RmFjdHVyYSDDsQ==?=", "Factura ñ"),
        ("=?utf-8?B?RmFjdHVyYSDDsQ?=", "Factura ñ"),  # padding faltante
        ("=?iso-8859-1?Q?Contrase=F1a_vencida?=", "Contraseña vencida"),
        ("=?utf-8?Q?Hola?= =?utf-8?Q?_mundo?=", "Hola mundo"),  # palabras adyacentes se unen
        ("Aviso: =?UTF-8?Q?pago_pendiente?= hoy", "Aviso: pago pendiente hoy"),
        ("=?x-desconocido?Q?caf=E9?=", "café"),  # charset inválido -> fallback
        ("=?utf-8*es?Q?se=C3=B1al?=", "señal"),  # RFC 2231 con idioma
        ("=?utf-8?B?!!!?=", ""),
        ("texto sin codificar", "texto sin codificar"),
    ],
)
def test_rfc2047_decoding(raw, expected):
    assert decode_rfc2047(raw) == expected


def test_rfc2047_subject_and_display_name_in_message():
    eml = build_eml(
        subject="=?utf-8?B?VHUgY3VlbnRhIHNlcsOhIHN1c3BlbmRpZGE=?=",
        from_="=?utf-8?Q?Banco_Naci=C3=B3n?= <alertas@bna-seguridad.example>",
    )
    pm = parse(eml)
    assert pm.subject == "Tu cuenta será suspendida"
    assert pm.from_display == "Banco Nación"
    assert pm.from_addr == "alertas@bna-seguridad.example"


def test_display_name_containing_an_address_does_not_fool_parser():
    eml = mime(
        'From: "soporte@empresa.com" <atacante@evil.example>\nTo: a@empresa.com\nSubject: x\n', b"hola"
    )
    pm = parse(eml)
    assert pm.from_addr == "atacante@evil.example"
    assert pm.from_display == "soporte@empresa.com"


def test_raw_8bit_headers_utf8_and_latin1():
    raw = (
        b"From: Jos\xe9 P\xe9rez <jose@x.example>\r\n"  # latin-1 crudo
        b"Subject: Factura n\xc3\xbamero 5\r\n"  # utf-8 crudo
        b"To: a@b.example\r\n\r\nhola"
    )
    pm = parse(raw)
    assert pm.subject == "Factura número 5"
    assert pm.from_display == "José Pérez"


def test_invalid_date_and_null_return_path():
    eml = mime("From: a@b.example\nDate: ayer a la tarde\nReturn-Path: <>\nSubject: x\n", b"hola")
    pm = parse(eml)
    assert pm.date is None
    assert pm.return_path is None


def test_naive_date_becomes_utc():
    pm = parse(mime("From: a@b.example\nDate: Tue, 01 Oct 2024 10:00:00 -0000\n", b"x"))
    assert pm.date is not None and pm.date.tzinfo is not None
    assert pm.date.astimezone(UTC).hour == 10


# --------------------------------------------------------------------------- cuerpos y charsets


def test_charset_fallbacks():
    assert decode_bytes("año".encode("cp1252"), "utf-8") == "año"
    assert decode_bytes("año".encode(), "charset-inventado") == "año"
    assert decode_bytes(b"\x81\x8d\x8f", None) == "\x81\x8d\x8f"  # nada decodifica: latin-1 nunca falla


def test_mislabeled_charset_body():
    body = "Contraseña: 1234 — pagá hoy".encode("cp1252")
    eml = mime(
        "From: a@b.example\nSubject: x\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 8bit\n",
        body,
    )
    pm = parse(eml)
    assert "Contraseña: 1234" in pm.body_text


def test_html_only_mail_gets_text_body_and_urls():
    eml = mime(
        "From: a@b.example\nSubject: x\nContent-Type: text/html; charset=utf-8\n",
        b"<html><body><p>Su cuenta ser\xc3\xa1 bloqueada.</p><script>var x=1;</script>"
        b'<a href="https://mercadopag0-login.example/ingresar">https://www.mercadopago.com.ar</a></body></html>',
    )
    pm = parse(eml)
    assert "Su cuenta será bloqueada." in pm.body_text
    assert "var x" not in pm.body_text
    assert pm.body_html.startswith("<html>")
    u = [u for u in pm.urls if u.source == "body_html"]
    assert u[0].url == "https://mercadopag0-login.example/ingresar"
    assert u[0].display_text == "https://www.mercadopago.com.ar"


def test_urls_from_text_and_html_bodies():
    eml = build_eml(
        text="Pagá acá: https://pagos.evil.example/factura?id=1 o www.otro.example",
        html='<a href="https://pagos.evil.example/factura?id=1">Pagar</a>',
    )
    pm = parse(eml)
    pairs = {(u.source, u.url) for u in pm.urls}
    assert ("body_text", "https://pagos.evil.example/factura?id=1") in pairs
    assert ("body_text", "http://www.otro.example") in pairs
    assert ("body_html", "https://pagos.evil.example/factura?id=1") in pairs


def test_benign_mail_has_no_artifacts_urls_or_errors():
    pm = parse(build_eml(subject="Reunión", text="Hola, confirmo la reunión del jueves.", html="<p>Hola</p>"))
    assert pm.artifacts == [] and pm.urls == [] and pm.parse_errors == []


def test_html_to_text_helper():
    assert html_to_text("<p>Hola<br>mundo</p><style>x{}</style>") == "Hola\nmundo"
    assert html_to_text("") == ""


# --------------------------------------------------------------------------- adjuntos


def test_attachments_ids_hashes_and_types():
    pe = samples.minimal_pe()
    eml = build_eml(
        attachments=[
            ("factura.pdf.exe", pe, "application/pdf"),
            ("nota.txt", b"hola", "text/plain"),
        ]
    )
    pm = parse(eml)
    a = arts(pm)
    assert list(a) == ["att0", "att1"]
    assert a["att0"].filename == "factura.pdf.exe"
    assert a["att0"].declared_content_type == "application/pdf"  # lo que dice el atacante
    assert a["att0"].detected_type == "pe"  # lo que realmente es
    assert a["att0"].sha256 == hashlib.sha256(pe).hexdigest()
    assert a["att0"].md5 == hashlib.md5(pe).hexdigest()
    assert a["att0"].sha1 == hashlib.sha1(pe).hexdigest()
    assert a["att0"].depth == 0 and a["att0"].parent_id is None
    assert a["att1"].data == b"hola" and a["att1"].detected_type == "text"


def test_eicar_attachment_is_kept_intact():
    pm = parse(build_eml(attachments=[("eicar.com", eicar(), "application/octet-stream")]))
    assert pm.artifacts[0].data == eicar()


def test_inline_image_without_filename_is_artifact():
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 30
    body = (
        b'--R\r\nContent-Type: text/html\r\n\r\n<img src="cid:logo">\r\n'
        b"--R\r\nContent-Type: image/png\r\nContent-ID: <logo>\r\nContent-Transfer-Encoding: base64\r\n\r\n"
        + base64.b64encode(png)
        + b"\r\n--R--\r\n"
    )
    pm = parse(mime('From: a@b.example\nSubject: x\nContent-Type: multipart/related; boundary="R"\n', body))
    assert len(pm.artifacts) == 1
    assert pm.artifacts[0].filename is None and pm.artifacts[0].detected_type == "image/png"
    assert pm.urls == []  # cid: se ignora


def test_rfc2231_filename_with_rtlo_and_rfc2047_name():
    body = (
        b"--B\r\nContent-Type: text/plain\r\n\r\nhola\r\n"
        b"--B\r\nContent-Type: application/octet-stream\r\n"
        b"Content-Disposition: attachment; filename*=utf-8''factura%E2%80%AEfdp.exe\r\n\r\nMZ\r\n"
        b'--B\r\nContent-Type: application/octet-stream; name="=?utf-8?B?cmVjaWJvLnBkZi5leGU=?="\r\n\r\nMZ\r\n'
        b"--B\r\nContent-Type: application/octet-stream\r\n"
        b'Content-Disposition: attachment; filename="..\\..\\Windows\\fact\xc3\xbara.exe"\r\n\r\nMZ\r\n'
        b"--B--\r\n"
    )
    pm = parse(mime('From: a@b.example\nContent-Type: multipart/mixed; boundary="B"\n', body))
    names = [a.filename for a in pm.artifacts]
    assert names == ["factura\u202efdp.exe", "recibo.pdf.exe", "factúra.exe"]


def test_broken_base64_attachment_padding_and_junk():
    pe = samples.minimal_pe()
    b64 = base64.b64encode(pe).rstrip(b"=")
    junk = b64[:40] + b"!!\r\n" + b64[40:] + b"="  # basura, padding incorrecto
    body = (
        b"--B\r\nContent-Type: application/octet-stream; name=x.exe\r\nContent-Transfer-Encoding: base64\r\n\r\n"
        + junk
        + b"\r\n--B--\r\n"
    )
    pm = parse(mime('From: a@b.example\nContent-Type: multipart/mixed; boundary="B"\n', body))
    assert pm.artifacts[0].data == pe


def test_truncated_base64_does_not_produce_base64_text_as_data():
    body = (
        b"--B\r\nContent-Type: application/pdf; name=x.pdf\r\nContent-Transfer-Encoding: base64\r\n\r\n"
        + base64.b64encode(b"%PDF-1.4 contenido")[:-3]
        + b"A\r\n--B--\r\n"
    )
    pm = parse(mime('From: a@b.example\nContent-Type: multipart/mixed; boundary="B"\n', body))
    assert pm.artifacts[0].data.startswith(b"%PDF-1.4")


def test_oversized_attachment_keeps_hashes_but_not_data():
    limits = LimitsConfig(max_artifact_bytes=1000)
    blob = b"A" * 5000
    pm = parse(build_eml(attachments=[("grande.bin", blob, "application/octet-stream")]), limits)
    a = pm.artifacts[0]
    assert a.data == b"" and a.size == 5000
    assert a.sha256 == hashlib.sha256(blob).hexdigest()
    assert a.listing_only is False  # no es "solo listado": tiene los hashes del contenido real
    assert "demasiado grande" in a.extraction_note


def test_oversized_leaf_inside_attached_eml_keeps_hashes():
    from centinela.core.models import ParsedMessage
    from centinela.parsing import mime as mime_mod
    from tests.helpers import make_artifact, make_ref

    blob = os.urandom(5000)
    inner = build_eml(subject="Interno", attachments=[("grande.bin", blob, "application/octet-stream")])
    state = mime_mod._State(ParsedMessage(ref=make_ref()), LimitsConfig())
    state.budget.max_artifact_bytes = 1000  # tope por archivo más chico que el adjunto interno
    kids = mime_mod._expand_eml(make_artifact(inner, "fw.eml", "eml"), state)
    big = {k.filename: k for k in kids}["grande.bin"]
    assert big.data == b"" and big.size == 5000 and big.listing_only is False
    assert big.sha256 == hashlib.sha256(blob).hexdigest()  # como un adjunto directo: hashes para reputación
    assert "solo se calcularon los hashes" in big.extraction_note


def test_oversized_message_parses_headers_only():
    limits = LimitsConfig(max_message_bytes=2000)
    eml = build_eml(subject="Grande", attachments=[("x.bin", b"A" * 10_000, "application/octet-stream")])
    pm = parse(eml, limits)
    assert pm.subject == "Grande" and pm.from_addr == "juan@proveedor.com"
    assert pm.artifacts == [] and pm.body_text == ""
    assert any("demasiado grande" in e for e in pm.parse_errors)
    assert pm.size == len(eml)


def test_zip_in_zip_in_eml_tree_order_and_depth():
    inner = samples.zip_bytes({"factura.pdf.exe": samples.minimal_pe()})
    outer = samples.zip_bytes({"docs/inner.zip": inner, "leeme.txt": b"ver https://evil.example/x"})
    pm = parse(
        build_eml(attachments=[("factura.zip", outer, "application/zip"), ("b.txt", b"x", "text/plain")])
    )
    ids = [a.id for a in pm.artifacts]
    assert ids == ["att0", "att0/inner.zip", "att0/inner.zip/factura.pdf.exe", "att0/leeme.txt", "att1"]
    a = arts(pm)
    assert a["att0/inner.zip/factura.pdf.exe"].depth == 2
    assert a["att0/inner.zip/factura.pdf.exe"].parent_id == "att0/inner.zip"
    assert a["att0/inner.zip/factura.pdf.exe"].detected_type == "pe"
    assert any(u.source == "artifact:att0/leeme.txt" and u.url == "https://evil.example/x" for u in pm.urls)


def test_encrypted_zip_opened_with_password_from_body():
    z = samples.raw_zip([{"name": "factura.exe", "data": samples.minimal_pe(), "password": "Fac-2024"}])
    eml = build_eml(
        text="Le envío la factura. La contraseña del archivo es: Fac-2024\nSaludos",
        attachments=[("factura.zip", z, "application/zip")],
    )
    pm = parse(eml, LimitsConfig(archive_passwords=[]))
    a = arts(pm)
    assert a["att0/factura.exe"].data == samples.minimal_pe()
    assert a["att0/factura.exe"].listing_only is False
    assert a["att0/factura.exe"].sha256 == hashlib.sha256(samples.minimal_pe()).hexdigest()
    # se abrió con la clave del cuerpo, pero tenía contraseña: técnica de evasión que los analizadores ven
    assert a["att0"].password_protected is True
    assert a["att0"].encrypted is False
    summary = ArtifactSummary.from_artifact(a["att0"])
    assert summary.password_protected is True and summary.encrypted is False
    dumped = pm.model_dump_json()
    assert "Fac-2024" not in json.dumps(
        [x.extraction_note for x in pm.artifacts]
    )  # nunca se persiste en notas
    assert '"data"' not in dumped  # el contenido de los archivos no se serializa


def test_encrypted_zip_password_in_subject_and_html():
    z = samples.raw_zip([{"name": "a.js", "data": b"var a = new ActiveXObject('x');", "password": "9911"}])
    eml = build_eml(
        subject="Factura - clave 9911", text="ver adjunto", attachments=[("f.zip", z, "application/zip")]
    )
    assert arts(parse(eml, LimitsConfig(archive_passwords=[])))["att0/a.js"].detected_type == "script/js"
    z2 = samples.raw_zip([{"name": "a.txt", "data": b"x", "password": "senha77"}])
    eml2 = build_eml(
        text="x",
        html="<p>Senha do arquivo: <b>senha77</b></p>",
        attachments=[("f.zip", z2, "application/zip")],
    )
    assert arts(parse(eml2, LimitsConfig(archive_passwords=[])))["att0/a.txt"].data == b"x"


def test_encrypted_zip_without_password_is_flagged():
    z = samples.raw_zip([{"name": "factura.pdf.exe", "data": samples.minimal_pe(), "password": "q8w7e6"}])
    pm = parse(build_eml(text="Adjunto factura", attachments=[("factura.zip", z, "application/zip")]))
    a = arts(pm)
    assert a["att0"].encrypted is True and a["att0"].password_protected is True
    child = a["att0/factura.pdf.exe"]
    assert child.filename == "factura.pdf.exe" and child.size == len(samples.minimal_pe())
    assert child.listing_only is True and child.data == b""
    assert (child.md5, child.sha1, child.sha256) == ("", "", "")  # nunca el hash de b""
    assert hashlib.sha256(b"").hexdigest() not in pm.model_dump_json()
    assert not child.encrypted  # la bandera va una sola vez, en el contenedor


def _locked_zip(password: str, name: str = "factura.exe") -> bytes:
    return samples.raw_zip([{"name": name, "data": samples.minimal_pe(), "password": password}])


def _assert_opened(a, container_id: str, child_name: str = "factura.exe") -> None:
    child = a[f"{container_id}/{child_name}"]
    assert child.data == samples.minimal_pe() and child.listing_only is False
    assert a[container_id].password_protected is True and a[container_id].encrypted is False


def test_password_in_attached_eml_opens_sibling_zip():
    fw = build_eml(subject="Fwd: factura", text="La contraseña del archivo es: Hermano-77")
    pm = parse(
        build_eml(
            text="ver adjuntos",
            attachments=[
                ("factura.zip", _locked_zip("Hermano-77"), "application/zip"),
                ("fw.eml", fw, "message/rfc822"),
            ],
        ),
        LimitsConfig(archive_passwords=[]),
    )
    _assert_opened(arts(pm), "att0")


def test_password_found_later_reopens_already_tried_zip():
    # la clave está en un .eml que viene DENTRO de otro zip, que se abre después del zip cifrado
    fw = build_eml(subject="Re: pedido", text="Te paso la clave: Tarde-4411\nSaludos")
    pm = parse(
        build_eml(
            text="ver adjuntos",
            attachments=[
                ("factura.zip", _locked_zip("Tarde-4411"), "application/zip"),
                ("reenvio.zip", samples.zip_bytes({"mensaje.eml": fw}), "application/zip"),
            ],
        ),
        LimitsConfig(archive_passwords=[]),
    )
    a = arts(pm)
    assert a["att1/mensaje.eml"].detected_type == "eml"
    _assert_opened(a, "att0")
    ids = [x.id for x in pm.artifacts]
    assert len(ids) == len(set(ids))
    # el listado del primer intento se descartó: un solo hijo, el extraído
    assert [x.id for x in pm.artifacts if x.parent_id == "att0"] == ["att0/factura.exe"]
    assert "no se pudieron abrir" not in (a["att0"].extraction_note or "")
    assert "Tarde-4411" not in json.dumps([x.extraction_note for x in pm.artifacts])


def test_locked_zip_without_new_candidates_is_not_retried():
    fw = build_eml(subject="Re: pedido", text="Hola, sin claves por acá")
    pm = parse(
        build_eml(
            attachments=[
                ("factura.zip", _locked_zip("Nadie-la-sabe"), "application/zip"),
                ("reenvio.zip", samples.zip_bytes({"mensaje.eml": fw}), "application/zip"),
            ],
        ),
        LimitsConfig(archive_passwords=[]),
    )
    a = arts(pm)
    assert a["att0"].encrypted and a["att0"].password_protected
    assert [x.id for x in pm.artifacts if x.parent_id == "att0"] == ["att0/factura.exe"]
    assert a["att0/factura.exe"].listing_only
    assert a["att0"].extraction_note.count("no se pudieron abrir") == 1


def test_password_in_attached_outlook_msg_body_opens_its_zip():
    msg = samples.outlook_msg(
        [("factura.zip", _locked_zip("Msg-2024!"))], body="Adjunto la factura. Contraseña: Msg-2024!"
    )
    pm = parse(
        build_eml(attachments=[("reenviado.msg", msg, "application/vnd.ms-outlook")]),
        LimitsConfig(archive_passwords=[]),
    )
    _assert_opened(arts(pm), "att0/factura.zip")


def test_message_password_candidates_for_analyzers():
    fw = build_eml(subject="Factura", text="La contraseña del archivo es: Eml-5544")
    msg = samples.outlook_msg([("x.txt", b"x")], body="pwd=Msg-1212")
    pm = parse(
        build_eml(
            subject="Factura - clave 9911",
            text="Hola, adjunto.",
            html="<p>Senha do arquivo: <b>h7h7h7</b></p>",
            attachments=[
                ("fw.eml", fw, "message/rfc822"),
                ("reenviado.msg", msg, "application/vnd.ms-outlook"),
                ("notas.txt", b"clave: NoDeUnMail99", "text/plain"),  # un .txt cualquiera no es un mail
            ],
        )
    )
    got = message_password_candidates(pm)
    assert got[0] == "9911"  # primero el asunto
    assert {"9911", "h7h7h7", "Eml-5544", "Msg-1212"} <= set(got)
    assert "NoDeUnMail99" not in got
    assert message_password_candidates(pm, limit=2) == got[:2]
    assert message_password_candidates(ParsedMessage(ref=pm.ref)) == []


def test_message_password_candidates_tolerates_hostile_eml_artifact():
    from tests.helpers import make_artifact

    pm = ParsedMessage(
        ref=parse(b"Subject: x\r\n\r\n").ref,
        body_text="clave: Body-777",
        artifacts=[make_artifact(bytes(range(256)) * 100, "roto.eml", "eml")],
    )
    assert message_password_candidates(pm) == ["Body-777"]


def test_zip_bomb_in_mail():
    bomb = samples.zip_bytes({"cero.bin": b"\x00" * (30 * 1024 * 1024)})
    pm = parse(build_eml(attachments=[("x.zip", bomb, "application/zip")]))
    assert "posible zip-bomb" in pm.artifacts[0].extraction_note


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("La contraseña del archivo es: Fac2024!", "Fac2024!"),
        ("clave 1234", "1234"),
        ("Password: abc123.", "abc123"),
        ("senha: 9988", "9988"),
        ("pwd=x7y8", "x7y8"),
        ("Contraseña:\n   5566", "5566"),
        ("contraseña «PAGO24»", "PAGO24"),
        ("Senha do arquivo é 4321", "4321"),
        ("Your password is: hunter22", "hunter22"),
        ("CLAVE DEL ZIP: *7788*", "7788"),
        ("clave: esperanza", "esperanza"),  # "es" no se come el comienzo de la palabra
    ],
)
def test_password_candidates(text, expected):
    assert expected in find_password_candidates(text)


@pytest.mark.parametrize(
    "text",
    [
        "Usá una contraseña segura.",
        "¿Olvidaste tu contraseña?",
        "Hola, te paso el presupuesto",
        "password",
        "",
    ],
)
def test_password_candidates_negative(text):
    assert find_password_candidates(text) == []


def test_attached_eml_parsed_recursively():
    z = samples.raw_zip([{"name": "factura.exe", "data": samples.minimal_pe(), "password": "7788"}])
    inner = build_eml(
        subject="Factura adjunta",
        text="La clave del zip es: 7788",
        html='<a href="https://inner.evil.example/x">Ver factura</a>',
        attachments=[("factura.zip", z, "application/zip")],
    )
    body = (
        b"--B\r\nContent-Type: text/plain\r\n\r\nte reenvio\r\n"
        b'--B\r\nContent-Type: message/rfc822\r\nContent-Disposition: attachment; filename="fw.eml"\r\n\r\n'
        + inner
        + b"\r\n--B--\r\n"
    )
    pm = parse(
        mime('From: a@b.example\nSubject: Fwd\nContent-Type: multipart/mixed; boundary="B"\n', body),
        LimitsConfig(archive_passwords=[]),
    )
    a = arts(pm)
    assert a["att0"].detected_type == "eml" and a["att0"].filename == "fw.eml"
    assert a["att0/factura.zip"].depth == 1 and a["att0/factura.zip"].parent_id == "att0"
    assert a["att0/factura.zip/factura.exe"].detected_type == "pe"
    assert a["att0/factura.zip/factura.exe"].depth == 2
    inner_urls = [u for u in pm.urls if u.source == "artifact:att0"]
    assert inner_urls[0].url == "https://inner.evil.example/x" and inner_urls[0].display_text == "Ver factura"
    assert pm.body_text.strip() == "te reenvio"  # el cuerpo del mail interno no se mezcla con el externo


def test_eml_file_attached_as_octet_stream_is_parsed():
    inner = build_eml(
        subject="Interno", attachments=[("x.exe", samples.minimal_pe(), "application/octet-stream")]
    )
    pm = parse(build_eml(attachments=[("reenviado.eml", inner, "application/octet-stream")]))
    a = arts(pm)
    assert a["att0"].detected_type == "eml"
    assert a["att0/x.exe"].detected_type == "pe"


def test_attached_eml_base64_encoded_rfc822_part():
    inner = build_eml(
        subject="Interno b64", attachments=[("x.exe", samples.minimal_pe(), "application/octet-stream")]
    )
    enc = base64.encodebytes(inner).replace(b"\n", b"\r\n")
    body = (
        b"--B\r\nContent-Type: message/rfc822\r\nContent-Transfer-Encoding: base64\r\n"
        b'Content-Disposition: attachment; filename="interno.eml"\r\n\r\n' + enc + b"--B--\r\n"
    )
    pm = parse(mime('From: a@b.example\nContent-Type: multipart/mixed; boundary="B"\n', body))
    a = arts(pm)
    assert a["att0"].detected_type == "eml"
    assert a["att0/x.exe"].detected_type == "pe"


def test_attached_eml_without_filename_named_from_subject():
    inner = build_eml(subject="Aviso de pago")
    body = b"--B\r\nContent-Type: message/rfc822\r\n\r\n" + inner + b"\r\n--B--\r\n"
    pm = parse(mime('From: a@b.example\nContent-Type: multipart/mixed; boundary="B"\n', body))
    assert pm.artifacts[0].filename == "Aviso de pago.eml"


def test_uuencoded_block_in_body():
    payload = samples.minimal_pe()
    lines = [binascii.b2a_uu(payload[i : i + 45]).decode().rstrip("\n") for i in range(0, len(payload), 45)]
    text = "Adjunto el programa:\nbegin 644 factura.exe\n" + "\n".join(lines) + "\n`\nend\nSaludos"
    pm = parse(build_eml(text=text))
    a = pm.artifacts[0]
    assert a.filename == "factura.exe" and a.data == payload and a.detected_type == "pe"
    assert "uuencode" in a.extraction_note


def test_uuencode_transfer_encoding_part():
    payload = b"hola mundo uu"
    enc = binascii.b2a_uu(payload)
    body = (
        b"--B\r\nContent-Type: application/octet-stream; name=a.bin\r\nContent-Transfer-Encoding: x-uuencode\r\n\r\n"
        b"begin 644 a.bin\r\n" + enc + b"`\r\nend\r\n--B--\r\n"
    )
    pm = parse(mime('From: a@b.example\nContent-Type: multipart/mixed; boundary="B"\n', body))
    assert pm.artifacts[0].data == payload


def test_tnef_winmail_dat_in_mail():
    tnef = samples.tnef_bytes([("FACTUR~1.EXE", samples.minimal_pe(), "factura.pdf.exe")])
    pm = parse(build_eml(attachments=[("winmail.dat", tnef, "application/ms-tnef")]))
    a = arts(pm)
    assert a["att0/factura.pdf.exe"].detected_type == "pe"


def test_html_and_svg_attachment_urls_and_url_shortcut():
    svg = b'<svg xmlns="http://www.w3.org/2000/svg"><a href="https://svg.evil.example/p"><text>Abrir</text></a></svg>'
    lnk = b"[InternetShortcut]\r\nURL=file://203.0.113.9/compartido/factura.exe\r\n"
    page = b'<html><form action="https://harvest.evil.example/post.php"><input type=password></form></html>'
    pm = parse(
        build_eml(
            attachments=[
                ("logo.svg", svg, "image/svg+xml"),
                ("factura.url", lnk, "application/octet-stream"),
                ("login.html", page, "text/html"),
            ]
        )
    )
    got = {(u.source, u.url) for u in pm.urls}
    assert ("artifact:att0", "https://svg.evil.example/p") in got
    assert ("artifact:att1", "file://203.0.113.9/compartido/factura.exe") in got
    assert ("artifact:att2", "https://harvest.evil.example/post.php") in got


def test_iso_and_onenote_and_pdf_attachments_expanded():
    iso = samples.iso_bytes({"factura.exe": samples.minimal_pe()})
    one = samples.onenote_bytes([b"<html><HTA:APPLICATION/><script>x</script></html>"])
    pdf = samples.pdf_with_attachment("p.exe", samples.minimal_pe())
    pm = parse(
        build_eml(
            attachments=[
                ("factura.img", iso, "application/octet-stream"),
                ("nota.one", one, "application/octet-stream"),
                ("doc.pdf", pdf, "application/pdf"),
            ]
        )
    )
    types = {a.id: a.detected_type for a in pm.artifacts}
    assert types["att0"] == "iso" and types["att0/factura.exe"] == "pe"
    assert types["att1"] == "onenote" and types["att1/embebido0"] == "script/hta"
    assert types["att2"] == "pdf" and types["att2/p.exe"] == "pe"


def test_docx_with_embedded_ole_package_full_chain():
    ole = samples.cfb_bytes({"\x01Ole10Native": samples.ole10native("factura.exe", samples.minimal_pe())})
    docx = samples.zip_bytes(
        {
            "[Content_Types].xml": b"<Types/>",
            "word/document.xml": b"<w/>",
            "word/embeddings/oleObject1.bin": ole,
        }
    )
    pm = parse(build_eml(attachments=[("pedido.docx", docx, "application/vnd.openxmlformats")]))
    a = arts(pm)
    assert a["att0"].detected_type == "ooxml"
    assert a["att0/oleObject1.bin"].detected_type == "ole"
    exe = a["att0/oleObject1.bin/factura.exe"]
    assert exe.detected_type == "pe" and exe.depth == 2


def test_outlook_msg_attachment_in_mail_with_body_urls():
    msg = samples.outlook_msg(
        [("factura.pdf.exe", samples.minimal_pe())], body="Ingresá a https://evil.example/login"
    )
    pm = parse(build_eml(attachments=[("reenviado.msg", msg, "application/vnd.ms-outlook")]))
    a = arts(pm)
    assert a["att0/factura.pdf.exe"].detected_type == "pe"
    assert any(
        u.url == "https://evil.example/login" and u.source == "artifact:att0/cuerpo_mensaje.txt"
        for u in pm.urls
    )


def test_max_artifacts_limit_in_message():
    limits = LimitsConfig(max_artifacts=3)
    pm = parse(build_eml(attachments=[(f"f{i}.txt", b"x", "text/plain") for i in range(6)]), limits)
    assert len(pm.artifacts) == 3
    assert any("límite de cantidad" in e for e in pm.parse_errors)


# --------------------------------------------------------------------------- input hostil


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\r\n\r\n",
        bytes(range(256)) * 50,
        b'From: x\r\nContent-Type: multipart/mixed; boundary="\r\n\r\n--\r\n' + bytes(range(256)) * 50,
        b"Content-Type: multipart/mixed\r\n\r\n--x\r\nsin boundary declarado\r\n",
        b"Subject: " + b"A" * 200_000 + b"\r\n\r\nbody",
        b"From: <<<@@@>>>, ,,, <>\r\nTo: ;;;\r\nSubject: =?utf-8?B?=?=\r\n\r\n",
        b'Content-Type: text/plain; charset="utf-7"\r\n\r\n+AGEAYgBj-',
        b"Content-Type: message/rfc822\r\n\r\nFrom: y\r\n\r\nbody",
        b"Content-Transfer-Encoding: base64\r\nContent-Type: application/x\r\n\r\n====",
    ],
    ids=[
        "empty",
        "blank",
        "binary",
        "empty-boundary",
        "no-boundary",
        "huge-header",
        "bad-addresses",
        "utf7",
        "rfc822-top",
        "b64-pad",
    ],
)
def test_hostile_messages_never_raise(raw):
    pm = parse(raw)
    assert pm.size == len(raw)
    json.loads(pm.model_dump_json())  # serializable


def test_deeply_nested_multipart():
    depth = 300
    raw = b'From: a@b.example\r\nContent-Type: multipart/mixed; boundary="b0"\r\n\r\n'
    for i in range(1, depth):
        raw += f'--b{i - 1}\r\nContent-Type: multipart/mixed; boundary="b{i}"\r\n\r\n'.encode()
    raw += f"--b{depth - 1}\r\nContent-Type: application/octet-stream; name=x.exe\r\n\r\nMZ\r\n".encode()
    for i in reversed(range(depth)):
        raw += f"--b{i}--\r\n".encode()
    pm = parse(raw)
    assert pm.from_addr == "a@b.example"
    assert pm.parse_errors  # se registró el exceso de anidamiento (o el fallback a solo headers)


def test_too_many_parts():
    parts = b"".join(b"--B\r\nContent-Type: text/plain; name=f.txt\r\n\r\nx\r\n" for _ in range(2100))
    pm = parse(mime('From: a@b.example\nContent-Type: multipart/mixed; boundary="B"\n', parts + b"--B--\r\n"))
    assert any("partes MIME" in e for e in pm.parse_errors)
    assert len(pm.artifacts) <= LIMITS.max_artifacts


def test_multipart_without_valid_boundary_is_read_as_text():
    raw = mime("From: a@b.example\nContent-Type: multipart/mixed\n", b"Pag\xc3\xa1 en https://evil.example/x")
    pm = parse(raw)
    assert "https://evil.example/x" in pm.body_text
    assert any(u.url == "https://evil.example/x" for u in pm.urls)
