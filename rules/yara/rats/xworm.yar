/*
    Centinela - XWorm
    Licencia: Apache-2.0. Indicadores públicos (ver `reference`); reglas escritas para Centinela.
*/

rule RAT_XWorm
{
    meta:
        author = "Centinela"
        description = "Troyano de acceso remoto XWorm: roba contraseñas y billeteras de criptomonedas, registra el teclado y puede descargar ransomware."
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.xworm"
        date = "2026-10-03"
        family = "XWorm"
        category = "rat"
        severity = "critical"
        score = 95

    strings:
        $x_version = "XWorm V" ascii wide
        $x_marker = "<Xwormmm>" ascii wide

        $c_logger = "XLogger" ascii wide fullword
        $c_pong = "ActivatePong" ascii fullword
        $c_report = "ReportWindow" ascii fullword
        $c_connect = "ConnectServer" ascii fullword
        $c_startsp = "startsp" ascii wide fullword
        $c_injrun = "injRun" ascii wide fullword
        $c_xinfo = "Xinfo" ascii wide fullword
        $c_openhide = "openhide" ascii wide fullword
        $c_hidefolder = "hidefolderfile" ascii wide fullword

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 15MB and
        (
            (1 of ($x_*) and 2 of ($c_*)) or
            5 of ($c_*)
        )
}
