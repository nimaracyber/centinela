/*
    Centinela - njRAT / Bladabindi
    Licencia: Apache-2.0. Indicadores públicos (ver `reference`); reglas escritas para Centinela.
*/

rule RAT_njRAT
{
    meta:
        author = "Centinela"
        description = "Troyano de acceso remoto njRAT (Bladabindi): muy usado en campañas contra Latinoamérica; roba contraseñas, registra el teclado y da control remoto de la PC."
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.njrat"
        date = "2026-10-03"
        family = "njRAT"
        category = "rat"
        severity = "critical"
        score = 95

    strings:
        $n_separator = "|'|'|" wide
        $n_zone = "SEE_MASK_NOZONECHECKS" wide fullword
        $n_dlerr = "Download ERROR" wide fullword
        $n_exeerr = "Execute ERROR" wide fullword
        $n_upderr = "Update ERROR" wide fullword
        $n_selfdel = "cmd.exe /c ping 0 -n 2 & del \"" wide
        $n_fwdel = "netsh firewall delete allowedprogram \"" wide
        $n_fwadd = "netsh firewall add allowedprogram \"" wide
        $n_sysinfo = "[+] System : " wide

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 15MB and
        4 of ($n_*)
}
