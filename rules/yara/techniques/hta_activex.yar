/*
    Centinela - aplicaciones HTML (.hta) y HTML con VBScript que usan objetos ActiveX peligrosos
    Licencia: Apache-2.0. Reglas escritas para Centinela.
*/

rule Technique_HTA_ActiveX
{
    meta:
        author = "Centinela"
        title = "Aplicación HTML (HTA) con control total de la PC"
        description = "Archivo HTA (o HTML con VBScript) que usa objetos de Windows capaces de ejecutar comandos, escribir archivos o descargar de Internet. Al abrirlo se ejecuta con los permisos del usuario, sin las protecciones del navegador."
        reference = "https://attack.mitre.org/techniques/T1218/005/"
        date = "2026-10-03"
        category = "technique"
        severity = "high"
        score = 75

    strings:
        $hta = "<HTA:APPLICATION" ascii wide nocase
        $vbs_tag = /<script[^>]{0,60}language\s{0,3}=\s{0,3}["']?vbscript/ nocase ascii wide

        $ax_activex = "ActiveXObject" ascii wide nocase
        $ax_create = "CreateObject" ascii wide nocase
        $ax_get = "GetObject(" ascii wide nocase

        $obj_wshell = "WScript.Shell" ascii wide nocase
        $obj_shellapp = "Shell.Application" ascii wide nocase
        $obj_fso = "Scripting.FileSystemObject" ascii wide nocase
        $obj_adodb = "ADODB.Stream" ascii wide nocase
        $obj_msxml = "MSXML2.XMLHTTP" ascii wide nocase
        $obj_xmlhttp = "Microsoft.XMLHTTP" ascii wide nocase
        $obj_winhttp = "WinHttp.WinHttpRequest" ascii wide nocase
        $obj_wmi = "winmgmts:" ascii wide nocase

    condition:
        filesize < 10MB and uint16(0) != 0x5A4D and
        1 of ($ax_*) and
        (
            ($hta and 1 of ($obj_*)) or
            ($vbs_tag and 1 of ($obj_wshell, $obj_shellapp, $obj_wmi))
        )
}
