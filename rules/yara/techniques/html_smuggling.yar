/*
    Centinela - HTML smuggling (el HTML "arma" un archivo dentro del navegador y lo descarga)
    Licencia: Apache-2.0. Reglas escritas para Centinela.

    Cabeceras en base64 dentro del JavaScript:
      ZIP  UEsDBBQA / UEsDBAoA / UEsDBC0A     7z  N3q8ryccAA     RAR  UmFyIRoH
      OLE  0M8R4KGxGuE                       EXE TVqQAAMAAAAEAAAA
*/

rule Technique_HTML_Smuggling_Payload
{
    meta:
        author = "Centinela"
        title = "HTML que arma y descarga un archivo comprimido o ejecutable"
        description = "La página adjunta trae escondido un archivo (ZIP, RAR, 7z, ISO, documento o ejecutable) y al abrirla lo 'arma' y lo descarga automáticamente en la computadora, esquivando el filtro de correo. Técnica conocida como HTML smuggling."
        reference = "https://attack.mitre.org/techniques/T1027/006/"
        date = "2026-10-03"
        category = "technique"
        severity = "high"
        score = 80

    strings:
        $blob = /new\s{1,4}Blob\s{0,4}\(/ nocase ascii wide

        $url_create = "createObjectURL" ascii wide nocase
        $url_mssave1 = "msSaveOrOpenBlob" ascii wide nocase
        $url_mssave2 = "msSaveBlob" ascii wide nocase

        $dec_atob = "atob(" ascii wide nocase
        $dec_u8 = "Uint8Array" ascii wide nocase
        $dec_charcode = "charCodeAt" ascii wide nocase

        $dl_prop = /\.download\s{0,4}=/ nocase ascii wide
        $dl_attr = /setAttribute\s{0,4}\(\s{0,4}["']download["']/ nocase ascii wide
        $click = /\.click\s{0,4}\(\s{0,4}\)/ nocase ascii wide
        $dispatch = "dispatchEvent(" ascii wide nocase

        $p_zip20 = "UEsDBBQA" ascii wide
        $p_zip10 = "UEsDBAoA" ascii wide
        $p_zip45 = "UEsDBC0A" ascii wide
        $p_7z = "N3q8ryccAA" ascii wide
        $p_rar = "UmFyIRoH" ascii wide
        $p_ole = "0M8R4KGxGuE" ascii wide
        $p_pe = "TVqQAAMAAAAEAAAA" ascii wide

    condition:
        filesize < 30MB and uint16(0) != 0x5A4D and
        $blob and 1 of ($url_*) and 1 of ($dec_*) and
        (1 of ($dl_*) or 1 of ($url_mssave*)) and
        ($click or $dispatch or 1 of ($url_mssave*)) and
        1 of ($p_*)
}

rule Technique_HTML_Smuggling_Generic
{
    meta:
        author = "Centinela"
        title = "HTML que genera y descarga un archivo automáticamente"
        description = "La página adjunta decodifica datos escondidos y fuerza la descarga de un archivo al abrirla. Algunas aplicaciones web legítimas lo hacen, pero en un adjunto de mail es una técnica típica para colar malware (HTML smuggling)."
        reference = "https://attack.mitre.org/techniques/T1027/006/"
        date = "2026-10-03"
        category = "technique"
        severity = "medium"
        score = 40

    strings:
        $blob = /new\s{1,4}Blob\s{0,4}\(/ nocase ascii wide
        $atob = "atob(" ascii wide nocase
        $url_create = "createObjectURL" ascii wide nocase
        $url_mssave = "msSaveOrOpenBlob" ascii wide nocase
        $dl_prop = /\.download\s{0,4}=/ nocase ascii wide
        $dl_attr = /setAttribute\s{0,4}\(\s{0,4}["']download["']/ nocase ascii wide
        $click = /\.click\s{0,4}\(\s{0,4}\)/ nocase ascii wide

    condition:
        filesize < 30MB and uint16(0) != 0x5A4D and
        not Technique_HTML_Smuggling_Payload and
        $blob and $atob and
        (
            ($url_create and 1 of ($dl_*) and $click) or
            $url_mssave
        )
}
