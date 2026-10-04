/*
    Centinela - loaders genéricos que esconden un ejecutable codificado (base64 / invertido / hex)
    Licencia: Apache-2.0. Reglas escritas para Centinela.

    Patrón muy común en mails con "factura.exe" o scripts: un loader .NET (o un script de PowerShell)
    lleva adentro OTRO ejecutable codificado como texto (a veces invertido) y lo carga en memoria con
    Assembly.Load. El ejecutable de adentro suele ser AgentTesla, Remcos, AsyncRAT, etc.

    Cabeceras usadas (inicio de un ejecutable "MZ..." codificado):
      base64            TVqQAAMAAAAEAAAA      (Delphi: TVpQAAIAAAAEAA)
      base64 invertido  AAAAEAAAAMAAQqVT      (Delphi: AAEAAAAIAAQpVT)
      hex               4D5A90000300000004000000FFFF0000
      hex invertido     0000FFFF00000040000000300009A5D4
*/

rule Loader_DotNet_Encoded_PE
{
    meta:
        author = "Centinela"
        description = "Programa .NET que trae escondido adentro otro ejecutable codificado como texto y lo carga en memoria: es la técnica típica de los 'loaders' que instalan troyanos y ladrones de contraseñas."
        reference = "https://attack.mitre.org/techniques/T1027/009/"
        date = "2026-10-03"
        category = "loader"
        severity = "high"
        score = 80

    strings:
        $clr = "mscoree.dll" ascii nocase
        $clr_main1 = "_CorExeMain" ascii
        $clr_main2 = "_CorDllMain" ascii

        $enc_b64 = "TVqQAAMAAAAEAAAA" wide
        $enc_b64_delphi = "TVpQAAIAAAAEAA" wide
        $enc_b64_rev = "AAAAEAAAAMAAQqVT" wide
        $enc_b64_rev_delphi = "AAEAAAAIAAQpVT" wide
        $enc_hex = "4D5A90000300000004000000FFFF0000" wide nocase
        $enc_hex_rev = "0000FFFF00000040000000300009A5D4" wide nocase

        $api_b64 = "FromBase64String" ascii
        $api_rev1 = "StrReverse" ascii
        $api_rev2 = "Reverse" ascii fullword
        $api_hex = "ToByte" ascii fullword

        $load1 = "Load" ascii fullword
        $load2 = "Invoke" ascii fullword
        $load3 = "EntryPoint" ascii

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 30MB and
        $clr and 1 of ($clr_main*) and
        1 of ($enc_*) and 1 of ($api_*) and 1 of ($load*)
}

rule Loader_Script_Reflective_PE
{
    meta:
        author = "Centinela"
        description = "Script que contiene un ejecutable codificado como texto y lo carga directamente en memoria (sin guardarlo en disco) para evitar el antivirus."
        reference = "https://attack.mitre.org/techniques/T1620/"
        date = "2026-10-03"
        category = "loader"
        severity = "high"
        score = 85

    strings:
        $enc_b64 = "TVqQAAMAAAAEAAAA" ascii wide
        $enc_b64_delphi = "TVpQAAIAAAAEAA" ascii wide
        $enc_b64_rev = "AAAAEAAAAMAAQqVT" ascii wide
        $enc_b64_rev_delphi = "AAEAAAAIAAQpVT" ascii wide
        $enc_hex = "4D5A90000300000004000000FFFF0000" ascii wide nocase
        $enc_hex_rev = "0000FFFF00000040000000300009A5D4" ascii wide nocase

        $load_asm = "Reflection.Assembly" ascii wide nocase
        $load_call = "]::Load(" ascii wide nocase
        $load_entry = "EntryPoint.Invoke" ascii wide nocase
        $load_appdomain = "AppDomain]::CurrentDomain.Load(" ascii wide nocase
        $load_vb = "AppDomain.CurrentDomain.Load(" ascii wide nocase

    condition:
        filesize < 30MB and uint16(0) != 0x5A4D and
        1 of ($enc_*) and 1 of ($load_*)
}
