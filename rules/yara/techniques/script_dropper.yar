/*
    Centinela - scripts JS/VBS (Windows Script Host) que descargan y ejecutan
    Licencia: Apache-2.0. Reglas escritas para Centinela.
*/

rule Technique_WSH_Script_Dropper
{
    meta:
        author = "Centinela"
        title = "Script de Windows que descarga y ejecuta un programa"
        description = "Script (JavaScript o VBScript para Windows) que descarga un archivo de Internet, lo guarda y lo ejecuta, o lanza PowerShell oculto. Los archivos .js/.vbs adjuntos casi nunca son legítimos: no los abras."
        reference = "https://attack.mitre.org/techniques/T1059/005/"
        date = "2026-10-03"
        category = "technique"
        severity = "high"
        score = 75

    strings:
        $sh_wscript = "WScript.Shell" ascii wide nocase
        $sh_shellapp = "Shell.Application" ascii wide nocase

        $run_run = /\.Run\s{0,3}[\(\s"']/ nocase ascii wide
        $run_shellexec = "ShellExecute" ascii wide nocase
        $run_exec = ".Exec(" ascii wide nocase

        $dl_msxml = "MSXML2.XMLHTTP" ascii wide nocase
        $dl_msxml_srv = "MSXML2.ServerXMLHTTP" ascii wide nocase
        $dl_ms_xmlhttp = "Microsoft.XMLHTTP" ascii wide nocase
        $dl_winhttp = "WinHttp.WinHttpRequest" ascii wide nocase

        $st_adodb = "ADODB.Stream" ascii wide nocase
        $st_save = "SaveToFile" ascii wide nocase
        $st_body = "responseBody" ascii wide nocase

        $ps = "powershell" ascii wide nocase
        $ps_hidden1 = /\s-w(indowstyle)?\s{1,3}h(idden)?\b/ nocase ascii wide
        $ps_enc = /\s-e(nc|ncodedcommand)?\s{1,3}[A-Za-z0-9+\/]{16}/ nocase ascii wide
        $ps_nop = /\s-nop(rofile)?\b/ nocase ascii wide
        $ps_bypass = /\s-(ep|exec|executionpolicy)\s{1,3}bypass\b/ nocase ascii wide
        $ps_iex = /\biex\b/ nocase ascii wide

    condition:
        filesize < 10MB and uint16(0) != 0x5A4D and
        1 of ($sh_*) and 1 of ($run_*) and
        (
            (1 of ($dl_*) and 1 of ($st_*)) or
            ($ps and 2 of ($ps_*))
        )
}
