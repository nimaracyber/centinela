/*
    Centinela - VenomRAT
    Licencia: Apache-2.0. Indicadores públicos (ver `reference`); reglas escritas para Centinela.
    VenomRAT deriva de AsyncRAT: puede disparar también RAT_AsyncRAT.
*/

rule RAT_VenomRAT
{
    meta:
        author = "Centinela"
        description = "Troyano de acceso remoto VenomRAT (derivado de AsyncRAT): control remoto oculto (HVNC), robo de contraseñas y registro de teclado."
        reference = "https://www.rapid7.com/blog/post/2024/11/21/a-bag-of-rats-venomrat-vs-asyncrat/"
        date = "2026-10-03"
        family = "VenomRAT"
        category = "rat"
        severity = "critical"
        score = 95

    strings:
        // sal usada para cifrar la configuración
        $salt = "VenomRATByVenom" ascii wide
        $banner = "Venom RAT + HVNC" ascii wide

        $v_datalogs = "DataLogs.conf" ascii wide
        $v_cgrinfo = "CGRInfo" ascii fullword
        $v_dinvoke = "DInvokeCore" ascii fullword
        $v_antiprocess = "AntiProcess" ascii fullword
        $v_antianalysis = "Anti_Analysis" ascii fullword

        $bypass_amsi = "AmsiScanBuffer" ascii wide
        $bypass_etw = "EtwEventWrite" ascii wide

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 15MB and
        (
            $salt or $banner or
            ($v_datalogs and 2 of ($v_*) and 1 of ($bypass_*))
        )
}
