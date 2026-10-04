/*
    Centinela - CVE-2017-11882 / CVE-2018-0802 (Editor de Ecuaciones de Office, EQNEDT32.EXE)
    Licencia: Apache-2.0. Reglas escritas para Centinela a partir de indicadores públicos.

    Sigue siendo de los exploits más usados en mails con "cotizaciones" en RTF/DOC para instalar
    AgentTesla, FormBook, Remcos, etc. en equipos con Office sin parchear.
      - 12 0C 43 00  = dirección de WinExec dentro de EQNEDT32.EXE (usada por el exploit)
      - 0A 01 08 5A 5A = registro FONT desbordado
    RTF ofuscado (espacios o saltos de línea dentro del hex) puede evadir la variante RTF.
*/

rule Exploit_CVE_2017_11882_Equation_Editor
{
    meta:
        author = "Centinela"
        title = "Exploit del Editor de Ecuaciones de Office (CVE-2017-11882)"
        description = "El documento trae un objeto de 'Ecuación' manipulado para aprovechar una falla vieja de Microsoft Office que permite ejecutar un programa con solo abrir el archivo. Se usa mucho en mails de falsas cotizaciones."
        reference = "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-11882"
        date = "2026-10-03"
        category = "technique"
        severity = "high"
        score = 85

    strings:
        // documento OLE (doc/xls) con el objeto de ecuación embebido
        $ole_eqnative = "Equation Native" ascii wide
        $ole_eq3 = "Microsoft Equation 3.0" ascii wide
        $ole_winexec = { 12 0C 43 00 }
        $ole_font = { 0A 01 08 5A 5A }
        $ole_cmd_mshta = "mshta" ascii nocase
        $ole_cmd_http = "http://" ascii nocase
        $ole_cmd_https = "https://" ascii nocase
        $ole_cmd_cmd = "cmd.exe" ascii nocase
        $ole_cmd_cmd2 = "cmd /c" ascii nocase
        $ole_cmd_ps = "powershell" ascii nocase
        $ole_cmd_exe = ".exe" ascii nocase

        // RTF: el objeto va en hex dentro de \objdata
        $rtf_objclass = "Equation.3" ascii nocase
        $rtf_eq3_hex = "4571756174696f6e2e33" ascii nocase
        $rtf_eqnative_hex = "4500710075006100740069006f006e0020004e00610074006900760065" ascii nocase
        $rtf_mseq_hex = "4d6963726f736f6674204571756174696f6e20332e30" ascii nocase
        $rtf_font_hex = "0a01085a5a" ascii nocase
        $rtf_winexec_hex = "120c4300" ascii nocase
        $rtf_mshta_hex = "6d736874612068747470" ascii nocase
        $rtf_mshtaexe_hex = "6d736874612e6578652068747470" ascii nocase
        $rtf_cmd_hex = "636d642e657865202f63" ascii nocase
        $rtf_ps_hex = "706f7765727368656c6c" ascii nocase

    condition:
        filesize < 20MB and
        (
            (
                uint32be(0) == 0xD0CF11E0 and
                1 of ($ole_eqnative, $ole_eq3) and
                ($ole_winexec or $ole_font) and
                1 of ($ole_cmd_*)
            ) or
            (
                (uint32be(0) == 0x7B5C7274 or uint32be(0) == 0x7B5C2A5C) and
                1 of ($rtf_objclass, $rtf_eq3_hex, $rtf_eqnative_hex, $rtf_mseq_hex) and
                (
                    1 of ($rtf_font_hex, $rtf_winexec_hex) or
                    1 of ($rtf_mshta_hex, $rtf_mshtaexe_hex, $rtf_cmd_hex, $rtf_ps_hex)
                )
            )
        )
}
