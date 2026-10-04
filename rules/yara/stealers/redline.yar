/*
    Centinela - RedLine Stealer / META Stealer
    Licencia: Apache-2.0. Indicadores públicos (ver `reference`); reglas escritas para Centinela.
    META Stealer es un clon de RedLine y comparte buena parte del código.
*/

rule Stealer_RedLine
{
    meta:
        author = "Centinela"
        description = "RedLine (o su clon META): roba contraseñas y tarjetas guardadas en el navegador, sesiones de Telegram/Discord, VPN y billeteras de criptomonedas."
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.redline_stealer"
        date = "2026-10-03"
        family = "RedLine Stealer"
        category = "stealer"
        severity = "critical"
        score = 95

    strings:
        $ns_sqlite = "RedLine.Logic.SQLite" ascii
        $ns_gecko = "RedLine.Reburn.Data.Browsers.Gecko" ascii
        $ns_models = "RedLine.Client.Models.Gecko" ascii

        $a_checkip = "ttp://checkip.amazonaws.com/logins.json" wide
        $a_ipinfo = "https://ipinfo.io/ip%appdata%\\" wide
        $a_steam = "Software\\Valve\\SteamLogin Data" wide
        $a_wallets = "get_ScannedWallets" ascii fullword
        $a_scantg = "get_ScanTelegram" ascii fullword
        $a_geckopaths = "get_ScanGeckoBrowsersPaths" ascii fullword
        $a_procs = "<Processes>k__BackingField" ascii
        $a_winver = "<GetWindowsVersion>g__HKLM_GetString|11_0" ascii
        $a_ftp = "<ScanFTP>k__BackingField" ascii
        $a_creds = "DataManager.Data.Credentials" ascii
        $a_enckey = "get_encrypted_key" ascii fullword
        $a_passed = "get_PassedPaths" ascii fullword
        $a_localname = "ChromeGetLocalName" ascii fullword
        $a_scanpw = "ScanPasswords" ascii fullword
        $a_wmiproc = "SELECT * FROM Win32_Process Where SessionId='{0}'" wide
        $a_encuser = "get_encryptedUsername" ascii fullword
        $a_icanhaz = "https://icanhazip.com" wide
        $a_private3 = "GetPrivate3Key" ascii fullword
        $a_grabtg = "get_GrabTelegram" ascii fullword
        $a_grabua = "<GrabUserAgent>k__BackingField" ascii

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 15MB and
        (
            1 of ($ns_*) or
            6 of ($a_*)
        )
}
