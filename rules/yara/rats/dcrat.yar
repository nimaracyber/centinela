/*
    Centinela - DCRat (DarkCrystal RAT)
    Licencia: Apache-2.0. Indicadores públicos (ver `reference`); reglas escritas para Centinela.
*/

rule RAT_DCRat
{
    meta:
        author = "Centinela"
        description = "Troyano de acceso remoto DCRat (DarkCrystal RAT): se vende barato en foros y permite espiar la computadora, robar contraseñas y descargar más malware."
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dcrat"
        date = "2026-10-03"
        family = "DCRat"
        category = "rat"
        severity = "critical"
        score = 95

    strings:
        // sal de cifrado de la configuración (variante basada en AsyncRAT)
        $salt1 = "DcRatByqwqdanchun" ascii wide fullword
        $salt2 = "DcRat By qwqdanchun" ascii wide

        $a_camera = "havecamera" ascii fullword
        $a_timeout = "timeout 3 > NUL" wide fullword
        $a_start = "START \"\" \"" wide
        // base64 de "/c schtasks /create /f /sc onlogon /rl highest /tn "
        $a_b64_schtasks = "L2Mgc2NodGFza3MgL2NyZWF0ZSAvZiAvc2Mgb25sb2dvbiAvcmwgaGlnaGVzdCAvdG4g" wide
        // base64 de "SOFTWARE\Microsoft\Windows\CurrentVersion\Run\"
        $a_b64_runkey = "U09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVuXA==" wide

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 15MB and
        (
            1 of ($salt*) or
            4 of ($a_*)
        )
}
