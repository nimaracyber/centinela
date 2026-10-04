/*
    Centinela - Rhadamanthys
    Licencia: Apache-2.0. Indicadores públicos (ver `reference`); reglas escritas para Centinela.
    Solo cadenas documentadas en análisis públicos de los módulos (loader y stealer), combinadas.
*/

rule Stealer_Rhadamanthys
{
    meta:
        author = "Centinela"
        description = "Rhadamanthys: ladrón de información modular que roba contraseñas, sesiones de Telegram y Steam, billeteras de criptomonedas y bases de KeePass."
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rhadamanthys"
        date = "2026-10-03"
        family = "Rhadamanthys"
        category = "stealer"
        severity = "critical"
        score = 95

    strings:
        $l_session = "Session\\%u\\MSCTF.Asm.{%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}" wide
        $l_msctf = "MSCTF.Asm.{%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}" wide
        $l_rundll = " \"%s\",Options_RunDLL %s" wide
        $l_tempdll = "%%TEMP%%\\vcredist_%05x.dll" wide
        $l_appdll = "%%APPDATA%%\\vcredist_%05x.dll" wide
        $l_tequila = "TEQUILABOOMBOOM" ascii wide
        $l_sysrundll = "%Systemroot%\\system32\\rundll32.exe" wide

        $s_tdata = "%s\\tdata\\key_datas" wide
        $s_steam = "\\config\\loginusers.vdf" wide
        $s_keepass = "/bin/KeePassHax.dll" ascii
        $s_nsdll = "%%APPDATA%%\\ns%04x.dll" wide
        $s_pipe = "\\\\.\\pipe\\{%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}" wide
        $s_regsvr = " /s /n /i:\"%s,%u,%u,%u\" \"%s\"" wide
        $s_strbuf = "strbuf(%lx) reallocs: %d, length: %d, size: %d" ascii
        $s_coreftp = "SOFTWARE\\FTPWare\\CoreFTP\\Sites\\%s" wide

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 15MB and
        (
            4 of ($l_*) or
            6 of ($s_*)
        )
}
