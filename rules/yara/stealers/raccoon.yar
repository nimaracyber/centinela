/*
    Centinela - Raccoon Stealer (v2 / "RecordBreaker")
    Licencia: Apache-2.0. Indicadores públicos (ver `reference`); reglas escritas para Centinela.
    La v2 cifra la mayoría de sus cadenas (RC4 + base64); se usan las rutas de compilación y las
    cadenas que quedaron en claro en muestras públicas, siempre combinadas.
*/

rule Stealer_Raccoon
{
    meta:
        author = "Centinela"
        description = "Raccoon Stealer: ladrón de información que roba contraseñas, cookies, billeteras de criptomonedas y sesiones de Telegram, y puede descargar más malware."
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.recordbreaker"
        date = "2026-10-03"
        family = "Raccoon Stealer"
        category = "stealer"
        severity = "critical"
        score = 92

    strings:
        $pdb_v1 = "A:\\_Work\\rc-build-v1-exe\\json.hpp" ascii wide
        $pdb_stealler = "\\stealler\\json.hpp" ascii wide

        $f_ffcookies = "\\ffcookies.txt" ascii wide
        $f_walletdat = "wallet.dat" ascii wide
        $f_netcookies = "0Network\\Cookies" ascii wide

        $id_machine = "machineId=" ascii wide
        $id_config = "configId=" ascii wide

        $x_nss3 = "nss3.dll" ascii wide nocase
        $x_sqlite = "sqlite3.dll" ascii wide nocase
        $x_mozglue = "mozglue.dll" ascii wide nocase
        $x_extsettings = "Local Extension Settings" ascii wide
        $x_tdata = "Telegram Desktop\\tdata" ascii wide

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 15MB and
        (
            1 of ($pdb_*) or
            all of ($f_*) or
            (all of ($id_*) and 3 of ($x_*))
        )
}
