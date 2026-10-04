/*
    Centinela - PowerShell que descarga y ejecuta ("download cradle")
    Licencia: Apache-2.0. Reglas escritas para Centinela.
    Exige SIEMPRE una primitiva de descarga + una de ejecución, para no marcar scripts de
    administración normales.
*/

rule Technique_PowerShell_Download_Cradle
{
    meta:
        author = "Centinela"
        title = "PowerShell que descarga y ejecuta un programa"
        description = "Contiene un comando de PowerShell que baja algo de Internet y lo ejecuta en el momento. Es la forma más común en que un adjunto malicioso instala el virus real."
        reference = "https://attack.mitre.org/techniques/T1059/001/"
        date = "2026-10-03"
        category = "technique"
        severity = "high"
        score = 65

    strings:
        $dl_webclient = "Net.WebClient" ascii wide nocase
        $dl_string = "DownloadString" ascii wide nocase
        $dl_data = "DownloadData" ascii wide nocase
        $dl_file = "DownloadFile" ascii wide nocase
        $dl_iwr = "Invoke-WebRequest" ascii wide nocase
        $dl_irm = "Invoke-RestMethod" ascii wide nocase
        $dl_bits = "Start-BitsTransfer" ascii wide nocase
        $dl_httpclient = "Net.Http.HttpClient" ascii wide nocase
        $dl_iwr_alias = /\b(iwr|irm|curl|wget)\s{1,4}(-Uri\s{1,4})?['"]?https?:\/\// nocase ascii wide

        $ex_iex_long = "Invoke-Expression" ascii wide nocase
        $ex_iex_call = /\biex\s{0,4}[\(\$'"]/ nocase ascii wide
        $ex_iex_pipe = /\|\s{0,4}iex\b/ nocase ascii wide
        $ex_startproc = "Start-Process" ascii wide nocase
        $ex_invokeitem = "Invoke-Item" ascii wide nocase
        $ex_asmload = "Reflection.Assembly]::Load" ascii wide nocase

        $http = "http" ascii wide nocase

        // variantes con -EncodedCommand: base64 del texto en UTF-16LE ("wide base64"); "base64wide"
        // cubre además ese base64 escrito dentro de un archivo UTF-16 (ej.: argumentos de un .lnk)
        $enc_webclient1 = "Net.WebClient" wide base64 base64wide
        $enc_webclient2 = "net.webclient" wide base64 base64wide
        $enc_dlstring1 = "DownloadString" wide base64 base64wide
        $enc_dlstring2 = "downloadstring" wide base64 base64wide
        $enc_dlfile = "DownloadFile" wide base64 base64wide
        $enc_iwr = "Invoke-WebRequest" wide base64 base64wide
        $enc_iex1 = "Invoke-Expression" wide base64 base64wide
        $enc_iex2 = "IEX (" wide base64 base64wide
        $enc_iex3 = "iex(" wide base64 base64wide
        $enc_iex4 = "IEX(" wide base64 base64wide
        $enc_startproc = "Start-Process" wide base64 base64wide

    condition:
        filesize < 10MB and uint16(0) != 0x5A4D and
        (
            (1 of ($dl_*) and 1 of ($ex_*) and $http) or
            (1 of ($enc_webclient*, $enc_dlstring*, $enc_dlfile, $enc_iwr) and 1 of ($enc_iex*, $enc_startproc))
        )
}
