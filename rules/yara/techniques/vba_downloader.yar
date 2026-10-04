/*
    Centinela - macro VBA que se ejecuta sola, descarga y ejecuta
    Licencia: Apache-2.0. Reglas escritas para Centinela.

    Pensada para código VBA ya extraído (texto). En un .doc/.xls crudo el código VBA está comprimido
    (MS-OVBA) y las cadenas largas quedan partidas: ahí lo cubre el analizador "office" (oletools).
*/

rule Technique_VBA_AutoExec_Downloader
{
    meta:
        author = "Centinela"
        title = "Macro que se ejecuta sola, descarga y ejecuta un programa"
        description = "El documento trae una macro que arranca sola al abrirlo, descarga algo de Internet y lo ejecuta. Es la técnica clásica de los documentos de Office maliciosos: no habilites macros en documentos recibidos por mail."
        reference = "https://attack.mitre.org/techniques/T1204/002/"
        date = "2026-10-03"
        category = "technique"
        severity = "high"
        score = 80

    strings:
        $vba_attr = "Attribute VB_" ascii wide nocase
        $vba_endsub = "End Sub" ascii wide nocase
        $vba_endfn = "End Function" ascii wide nocase

        $auto_open1 = "AutoOpen" ascii wide nocase fullword
        $auto_open2 = "Auto_Open" ascii wide nocase fullword
        $auto_doc = "Document_Open" ascii wide nocase fullword
        $auto_wb = "Workbook_Open" ascii wide nocase fullword
        $auto_exec = "AutoExec" ascii wide nocase fullword
        $auto_close1 = "Document_Close" ascii wide nocase fullword
        $auto_close2 = "Auto_Close" ascii wide nocase fullword
        $auto_close3 = "AutoClose" ascii wide nocase fullword
        $auto_activate = "Workbook_Activate" ascii wide nocase fullword

        $dl_urlmon = "URLDownloadToFile" ascii wide nocase
        $dl_msxml = "MSXML2.XMLHTTP" ascii wide nocase
        $dl_msxml_srv = "MSXML2.ServerXMLHTTP" ascii wide nocase
        $dl_ms_xmlhttp = "Microsoft.XMLHTTP" ascii wide nocase
        $dl_winhttp = "WinHttp.WinHttpRequest" ascii wide nocase
        $dl_webclient = "Net.WebClient" ascii wide nocase
        $dl_inet = "InternetOpenUrl" ascii wide nocase

        $ex_wshell = "WScript.Shell" ascii wide nocase
        $ex_shellapp = "Shell.Application" ascii wide nocase
        $ex_shellexec = "ShellExecute" ascii wide nocase
        $ex_shell = /\bShell\s{0,2}[\(\s"]/ nocase ascii wide
        $ex_createproc = "CreateProcess" ascii wide nocase
        $ex_wmi = "Win32_Process" ascii wide nocase
        $ex_ps = "powershell" ascii wide nocase

    condition:
        filesize < 20MB and
        1 of ($vba_*) and 1 of ($auto_*) and 1 of ($dl_*) and 1 of ($ex_*)
}
