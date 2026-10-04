/*
    Centinela - abuso de NetSupport Manager ("NetSupport RAT")
    Licencia: Apache-2.0. Indicadores públicos (ver `reference`); reglas escritas para Centinela.

    NetSupport Manager es software legítimo de soporte remoto. Los atacantes mandan por mail una
    copia "portable" (client32.exe + client32.ini + NSM.LIC) configurada en modo silencioso para
    conectarse a su servidor. Un departamento de sistemas real no distribuye el cliente así por mail.
*/

rule RAT_NetSupport_Client32_Config
{
    meta:
        author = "Centinela"
        description = "Archivo de configuración de NetSupport Manager preparado para conectarse en silencio a un servidor externo: es la forma típica en que los atacantes usan este programa como troyano de acceso remoto."
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.netsupportmanager_rat"
        date = "2026-10-03"
        family = "NetSupport RAT"
        category = "rat"
        severity = "high"
        score = 80

    strings:
        $sec_client = "[Client]" ascii wide nocase
        $sec_http = "[HTTP]" ascii wide nocase
        $gateway = "GatewayAddress=" ascii wide nocase
        $gsk = "GSK=" ascii wide nocase

        $q_silent = "silent=1" ascii wide nocase
        $q_systray = "SysTray=0" ascii wide nocase
        $q_hide = "HideWhenIdle=1" ascii wide nocase
        $q_quiet = "quiet=1" ascii wide nocase
        $q_noconnect = "DisableClientConnect=1" ascii wide nocase

    condition:
        filesize < 256KB and
        uint16(0) != 0x5A4D and
        $sec_client and $sec_http and $gateway and $gsk and
        2 of ($q_*)
}

rule RAT_NetSupport_Portable_Archive
{
    meta:
        author = "Centinela"
        description = "Archivo comprimido con una copia portable de NetSupport Manager (cliente + configuración + licencia): es la forma típica en que los atacantes instalan este programa como troyano de acceso remoto."
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.netsupportmanager_rat"
        date = "2026-10-03"
        family = "NetSupport RAT"
        category = "rat"
        severity = "high"
        score = 80

    strings:
        $ini = "client32.ini" ascii wide nocase
        $lic = "NSM.LIC" ascii wide nocase

        $bin_client = "client32.exe" ascii wide nocase
        $bin_pcicl = "PCICL32.DLL" ascii wide nocase
        $bin_htctl = "HTCTL32.DLL" ascii wide nocase
        $bin_tcctl = "TCCTL32.DLL" ascii wide nocase
        $bin_remcmd = "remcmdstub.exe" ascii wide nocase
        $bin_pcicapi = "pcicapi.dll" ascii wide nocase

    condition:
        filesize < 50MB and
        (
            uint32(0) == 0x04034B50 or       // ZIP
            uint32(0) == 0x21726152 or       // RAR ("Rar!")
            uint32(0) == 0xAFBC7A37          // 7z
        ) and
        $ini and $lic and 1 of ($bin_*)
}
