/*
    Centinela - QuasarRAT
    Licencia: Apache-2.0. Indicadores públicos (ver `reference`); reglas escritas para Centinela.
    Quasar es una herramienta de administración remota open source muy abusada por criminales.
*/

rule RAT_QuasarRAT
{
    meta:
        author = "Centinela"
        description = "Troyano de acceso remoto QuasarRAT: permite controlar la computadora a distancia, registrar el teclado y robar contraseñas guardadas en el navegador."
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.quasar_rat"
        date = "2026-10-03"
        family = "QuasarRAT"
        category = "rat"
        severity = "critical"
        score = 95

    strings:
        $ns1 = "Quasar.Common.Messages" ascii
        $ns2 = "Quasar.Client" ascii
        $ns3 = "xClient.Core" ascii

        $a_keylog = "GetKeyloggerLogsResponse" ascii fullword
        $a_dlexec = "DoDownloadAndExecute" ascii fullword
        $a_ipify = "http://api.ipify.org/" wide
        $a_cookie = "Domain: {1}{0}Cookie Name: {2}{0}Value: {3}{0}Path: {4}{0}Expired: {5}{0}HttpOnly: {6}{0}Secure: {7}" wide
        $a_onlogon = "\" /sc ONLOGON /tr \"" wide
        $a_passwords = "GetPasswordsResponse" ascii fullword
        $a_shell = "DoShellExecuteResponse" ascii fullword

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 15MB and
        (
            4 of ($a_*) or
            (1 of ($ns*) and 2 of ($a_*))
        )
}
