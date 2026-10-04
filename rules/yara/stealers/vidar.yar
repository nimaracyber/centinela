/*
    Centinela - Vidar
    Licencia: Apache-2.0. Indicadores públicos (ver `reference`); reglas escritas para Centinela.
*/

rule Stealer_Vidar
{
    meta:
        author = "Centinela"
        description = "Vidar: ladrón de información que se lleva contraseñas, cookies, tarjetas guardadas, billeteras de criptomonedas y archivos del usuario."
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.vidar"
        date = "2026-10-03"
        family = "Vidar"
        category = "stealer"
        severity = "critical"
        score = 95

    strings:
        $w_binance = "BinanceChainWallet" ascii wide fullword
        $w_walletdat = "*wallet*.dat" ascii wide fullword
        $w_monero = "SOFTWARE\\monero-project\\monero-core" ascii wide

        $fmt_cc = "CC\\%s_%s.txt" ascii wide
        $fmt_history = "History\\%s_%s.txt" ascii wide
        $fmt_autofill = "Autofill\\%s_%s.txt" ascii wide

        $d_fixed = "%DRIVE_FIXED%" ascii wide
        $d_removable = "%DRIVE_REMOVABLE%" ascii wide
        $d_indexeddb = "_0.indexeddb.leveldb" ascii wide
        $d_key4 = "key4.db" ascii wide fullword

        $o_avghook = "avghooka.dll" ascii wide
        $o_apilog = "api_log.dll" ascii wide
        $o_babyfox = "babyfox.dll" ascii wide
        $o_vksaver = "vksaver.dll" ascii wide
        $o_delays = "delays.tmp" ascii wide
        $o_wkeys = "\\Monero\\wallet.keys" ascii wide
        $o_wpath = "wallet_path" ascii wide fullword
        $o_honglee = "Hong Lee" ascii wide
        $o_milozs = "milozs" ascii wide

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 15MB and
        (
            (1 of ($w_*) and 2 of ($fmt_*)) or
            all of ($d_*) or
            6 of ($o_*)
        )
}
