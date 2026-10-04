/*
    Centinela - Remcos RAT
    Licencia: Apache-2.0. Indicadores públicos (ver `reference`); reglas escritas para Centinela.
*/

rule RAT_Remcos
{
    meta:
        author = "Centinela"
        description = "Troyano de acceso remoto Remcos: se vende como 'herramienta de administración' pero se usa masivamente en mails de falsas facturas para espiar y robar credenciales."
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.remcos"
        date = "2026-10-03"
        family = "Remcos"
        category = "rat"
        severity = "critical"
        score = 95

    strings:
        $r_watchdog = "Remcos restarted by watchdog!" ascii wide
        $r_mutex = "Mutex_RemWatchdog" ascii wide
        $r_banner = "* Remcos v" ascii wide
        $r_agent = "Remcos Agent initialized (" ascii wide
        $r_upload = "Uploading file to Controller: " ascii wide
        $r_cleared = "[Cleared browsers logins and cookies.]" ascii wide
        $r_chrome = "[Chrome StoredLogins found, cleared!]" ascii wide
        $r_vendor = "Breaking-Security.Net" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 15MB and
        2 of ($r_*)
}
