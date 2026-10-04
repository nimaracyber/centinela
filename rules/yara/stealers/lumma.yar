/*
    Centinela - Lumma Stealer (LummaC2)
    Licencia: Apache-2.0. Indicadores públicos (ver `reference`); reglas escritas para Centinela.
    Las versiones viejas tienen cadenas en claro (user-agent, ruta del C2); las nuevas se detectan por
    secuencias de código documentadas.
*/

rule Stealer_Lumma
{
    meta:
        author = "Centinela"
        description = "Lumma Stealer: roba contraseñas, cookies de sesión y billeteras de criptomonedas de los navegadores. Es uno de los ladrones de información más activos."
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lumma"
        date = "2026-10-03"
        family = "Lumma Stealer"
        category = "stealer"
        severity = "critical"
        score = 95

    strings:
        $s_build = "LummaC2 Build" ascii wide
        $s_ua = "TeslaBrowser/5.5" ascii wide
        $s_c2 = "/c2sock" ascii wide
        $s_obf = "576xed" ascii
        $s_dp = "dp.txt" ascii wide fullword

        $c_a1 = { 02 0F B7 16 83 C6 02 66 85 D2 75 EF 66 C7 00 00 00 0F B7 11 }
        $c_a2 = { 0C 0F B7 4C 24 04 66 89 0F 83 C7 02 39 F7 73 0C 01 C3 39 EB }
        $c_f1 = { B8 38 ?2 4? 00 B? [3] 00 B? [3] 00 96 F3 A5 }
        $c_f2 = { 55 53 57 56 81 EC 1? 01 00 00 8B ?? 24 3? 01 00 00 85 ?? 0F 84 ?? 08 00 00 }
        $c_f3 = { 8D 8? E0 ?2 4? 00 8D 74 24 ?? FF 3? 56 5? 68 ?? ?? 45 00 E8 ?? ?? FF FF }

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 15MB and
        (
            $s_build or
            ($s_ua and $s_c2) or
            (#s_obf > 10 and 1 of ($s_ua, $s_c2, $s_dp)) or
            ($c_a1 and $c_a2) or
            2 of ($c_f*)
        )
}
