/*
    Centinela - ejecutable de Windows escondido como texto (base64, invertido, hex, lista de bytes)
    Licencia: Apache-2.0. Reglas escritas para Centinela.

    Nota: los .eml adjuntos NO se escanean con YARA (el parser los abre y escanea sus adjuntos ya
    decodificados), así que un .exe adjunto "normal" no dispara esta regla por su codificación MIME.
*/

rule Technique_Encoded_PE_In_Text
{
    meta:
        author = "Centinela"
        title = "Ejecutable escondido como texto codificado"
        description = "El archivo contiene un programa de Windows (.exe/.dll) disfrazado como texto codificado (base64, invertido o hexadecimal). Es la forma en que scripts, páginas HTML y documentos maliciosos esconden el virus para que no lo vea el filtro de correo."
        reference = "https://attack.mitre.org/techniques/T1027/"
        date = "2026-10-03"
        category = "technique"
        severity = "high"
        score = 70

    strings:
        $b64_mz = "TVqQAAMAAAAEAAAA" ascii wide
        $b64_mz_delphi = "TVpQAAIAAAAEAA" ascii wide
        $b64_dos = "This program cannot be run in DOS mode" base64 base64wide
        $rev_mz = "AAAAEAAAAMAAQqVT" ascii wide
        $rev_mz_delphi = "AAEAAAAIAAQpVT" ascii wide
        $rev_dos = "v1GIT9ERg4Wag4WdyBSZiBCdv5mbhNGItFmcn9mcwBycphGV" ascii wide
        $hex_mz = "4D5A90000300000004000000FFFF0000" ascii wide nocase
        $hex_mz_rev = "0000FFFF00000040000000300009A5D4" ascii wide nocase
        $hex_mz_0x = /0x4d\s{0,2},\s{0,2}0x5a\s{0,2},\s{0,2}0x90\s{0,2},\s{0,2}0x0{1,2}\s{0,2},\s{0,2}0x0?3\s{0,2},/ nocase ascii wide
        $dec_mz = /\b77\s{0,2},\s{0,2}90\s{0,2},\s{0,2}144\s{0,2},\s{0,2}0\s{0,2},\s{0,2}3\s{0,2},\s{0,2}0\s{0,2},\s{0,2}0\s{0,2},\s{0,2}0\b/ ascii wide

    condition:
        filesize < 60MB and
        uint16(0) != 0x5A4D and
        1 of them
}
