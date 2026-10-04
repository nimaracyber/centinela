/*
    Centinela - StealC
    Licencia: Apache-2.0. Indicadores públicos (ver `reference`); reglas escritas para Centinela.
*/

rule Stealer_StealC
{
    meta:
        author = "Centinela"
        description = "StealC: ladrón de información (derivado de Vidar/Raccoon) que roba contraseñas, cookies, cuentas de correo y billeteras de criptomonedas, y después se borra a sí mismo."
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.stealc"
        date = "2026-10-03"
        family = "StealC"
        category = "stealer"
        severity = "critical"
        score = 95

    strings:
        $pdb = "C:\\builder_v2\\stealc\\json.h" ascii wide
        $guid = "%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX" ascii wide

        $s_country = "- Country: ISO?" ascii wide
        $s_date = "%d/%d/%d %d:%d:%d" ascii wide
        $s_hwid = "%08lX%04lX%lu" ascii wide
        $s_outlook = "\\Outlook\\accounts.txt" ascii wide
        $s_selfdel = "/c timeout /t 5 & del /f /q" ascii wide

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 15MB and
        (
            $pdb or
            ($guid and $s_selfdel and $s_country) or
            4 of ($s_*)
        )
}
