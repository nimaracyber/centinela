/*
    Centinela - acceso directo (.lnk) que lanza herramientas de Windows abusadas ("LOLBins")
    Licencia: Apache-2.0. Reglas escritas para Centinela.
*/

rule Technique_LNK_LOLBin_Launcher
{
    meta:
        author = "Centinela"
        title = "Acceso directo que ejecuta comandos ocultos"
        description = "Acceso directo de Windows (.lnk) que en vez de abrir un documento ejecuta PowerShell, cmd, mshta u otra herramienta del sistema con comandos para descargar o ejecutar algo. Es una técnica muy usada para infectar al hacer doble clic."
        reference = "https://attack.mitre.org/techniques/T1204/002/"
        date = "2026-10-03"
        category = "technique"
        severity = "high"
        score = 75

    strings:
        $lol_ps = "powershell" ascii wide nocase
        $lol_pwsh = "pwsh.exe" ascii wide nocase
        $lol_cmd = "cmd.exe" ascii wide nocase
        $lol_mshta = "mshta" ascii wide nocase
        $lol_wscript = "wscript" ascii wide nocase
        $lol_cscript = "cscript" ascii wide nocase
        $lol_rundll = "rundll32" ascii wide nocase
        $lol_regsvr = "regsvr32" ascii wide nocase
        $lol_msiexec = "msiexec" ascii wide nocase
        $lol_certutil = "certutil" ascii wide nocase
        $lol_bitsadmin = "bitsadmin" ascii wide nocase
        $lol_curl = "curl.exe" ascii wide nocase
        $lol_conhost = "conhost.exe" ascii wide nocase
        $lol_forfiles = "forfiles" ascii wide nocase
        $lol_pcalua = "pcalua" ascii wide nocase
        $lol_msbuild = "msbuild" ascii wide nocase
        $lol_cmstp = "cmstp" ascii wide nocase
        $lol_wmic = "wmic" ascii wide nocase fullword
        $lol_finger = "finger.exe" ascii wide nocase
        $lol_hh = "\\hh.exe" ascii wide nocase

        $arg_http = "http://" ascii wide nocase
        $arg_https = "https://" ascii wide nocase
        $arg_hidden = "hidden" ascii wide nocase
        $arg_enc = /\s-e(nc|ncodedcommand)?\s/ nocase ascii wide
        $arg_bypass = "bypass" ascii wide nocase
        $arg_nop = /\s-nop\b/ nocase ascii wide
        $arg_iex = /\biex\b/ nocase ascii wide
        $arg_download = "Download" ascii wide nocase
        $arg_b64 = "FromBase64String" ascii wide nocase
        $arg_js = "javascript:" ascii wide nocase
        $arg_vbs = "vbscript:" ascii wide nocase
        $arg_temp = "%temp%" ascii wide nocase
        $arg_appdata = "%appdata%" ascii wide nocase
        $arg_public = "\\Users\\Public\\" ascii wide nocase
        $arg_min = "/min" ascii wide nocase
        $arg_webdav = "@SSL\\" ascii wide nocase
        $arg_cmd_c = /cmd(\.exe)?\s{1,4}\/[cCkK]\s/ ascii wide

    condition:
        filesize < 5MB and
        uint32(0) == 0x0000004C and uint32(4) == 0x00021401 and
        1 of ($lol_*) and 1 of ($arg_*)
}
