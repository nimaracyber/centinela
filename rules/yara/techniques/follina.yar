/*
    Centinela - Follina (CVE-2022-30190, ms-msdt) y plantillas/objetos remotos en documentos Office
    Licencia: Apache-2.0. Reglas escritas para Centinela.

    Las reglas sobre XML de Office (relaciones .rels) aplican cuando el XML está descomprimido
    (por ejemplo, partes extraídas de un .docx o documentos guardados como XML/MHT/RTF).
*/

rule Exploit_Follina_MSDT
{
    meta:
        author = "Centinela"
        title = "Ataque 'Follina' (CVE-2022-30190)"
        description = "Contiene una llamada al diagnóstico de Windows (ms-msdt) armada para ejecutar comandos: es el ataque conocido como 'Follina', que infecta la PC con solo abrir o previsualizar un documento."
        reference = "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30190"
        date = "2026-10-03"
        category = "technique"
        severity = "high"
        score = 85

    strings:
        $msdt = "ms-msdt:" ascii wide nocase
        $msdt_urlenc = "%6D%73%2D%6D%73%64%74%3A" ascii wide nocase
        $msdt_href = /location\.href\s{0,20}=\s{0,20}["']ms-msdt:/ nocase ascii wide

        $p_pcw = "PCWDiagnostic" ascii wide nocase
        $p_browse = "IT_BrowseForFile" ascii wide nocase
        $p_rebrowse = "IT_RebrowseForFile" ascii wide nocase
        $p_launch = "IT_LaunchMethod" ascii wide nocase

    condition:
        filesize < 20MB and
        (
            $msdt_href or
            ((1 of ($msdt, $msdt_urlenc)) and 1 of ($p_*))
        )
}

rule Technique_Office_Remote_Template
{
    meta:
        author = "Centinela"
        title = "Documento que carga contenido remoto (plantilla u objeto externo)"
        description = "El documento está armado para descargar una plantilla, página o un objeto desde Internet al abrirlo. Se usa para colar macros o exploits (como Follina) sin que el adjunto los contenga."
        reference = "https://attack.mitre.org/techniques/T1221/"
        date = "2026-10-03"
        category = "technique"
        severity = "high"
        score = 70

    strings:
        $rels = "<Relationships" ascii wide
        $external = "TargetMode=\"External\"" ascii wide nocase

        $bang_html = ".html!" ascii wide nocase
        $bang_htm = ".htm!" ascii wide nocase
        $bang_html_enc = "%2E%68%74%6D%6C%21" ascii wide nocase
        $bang_htm_enc = "%2E%68%74%6D%21" ascii wide nocase
        $mhtml = "mhtml:" ascii wide nocase

        $type_template = "relationships/attachedTemplate" ascii wide nocase
        $type_ole = "relationships/oleObject" ascii wide nocase
        $type_frame = "relationships/frame" ascii wide nocase
        $target_http = /Target\s{0,2}=\s{0,2}["'](https?|file):\/\// nocase ascii wide
        $target_unc = /Target\s{0,2}=\s{0,2}["']\\\\[a-z0-9]/ nocase ascii wide

        // plantillas remotas: las de SharePoint/OneDrive por HTTPS son normales en empresas; se marcan
        // solo las que van por HTTP plano, a una IP, por UNC/WebDAV o a una plantilla con macros
        $tpl_http = /Target\s{0,2}=\s{0,2}["']http:\/\// nocase ascii wide
        $tpl_ip = /Target\s{0,2}=\s{0,2}["']https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[:\/"']/ nocase ascii wide
        $tpl_macro = /Target\s{0,2}=\s{0,2}["']https?:\/\/[^"'\s]{1,300}\.(dotm|docm|xlsm|rtf)["'?]/ nocase ascii wide
        $tpl_unc = /Target\s{0,2}=\s{0,2}["'](file:\/\/|\\\\)[a-z0-9]/ nocase ascii wide

        $rtf_link = " LINK htmlfile \"http" ascii nocase
        $rtf_bang = ".html!\" " ascii nocase

    condition:
        filesize < 20MB and
        (
            (
                $rels and $external and
                (
                    1 of ($bang_*, $mhtml) or
                    (1 of ($type_ole, $type_frame) and 1 of ($target_*)) or
                    ($type_template and 1 of ($tpl_*))
                )
            ) or
            (uint32be(0) == 0x7B5C7274 and $rtf_link and $rtf_bang)
        )
}
