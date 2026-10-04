/*
    Centinela - GuLoader (CloudEyE)
    Licencia: Apache-2.0. Indicadores públicos (ver `reference`); reglas escritas para Centinela.

    GuLoader llega como instalador NSIS o como VBS que arma un PowerShell ofuscado. Ese PowerShell:
      - se ejecuta con un truco: lee su propio archivo y saca "IEX" con .SubString(<offset>,3),
      - decodifica cadenas tomando 1 de cada N caracteres (For(...; $i -lt $x.Length-1; $i+=N)),
      - y/o decodifica hex + XOR con [convert]::ToByte($x.Substring($i, 2), 16).
    El instalador NSIS en sí está comprimido y no se ve con YARA: lo cubren ClamAV y la reputación.
*/

rule Loader_GuLoader_PowerShell_Launcher
{
    meta:
        author = "Centinela"
        description = "Comando de PowerShell oculto con el truco típico de GuLoader (lee un archivo y extrae el comando IEX de una posición fija). GuLoader descarga e instala otros programas maliciosos como Remcos o Agent Tesla."
        reference = "https://blog.scrt.ch/2025/03/19/insomnihack-2025-gulosity-writeup/"
        date = "2026-10-03"
        family = "GuLoader"
        category = "loader"
        severity = "high"
        score = 85

    strings:
        $iex_substring = /\.SubString\(\d{3,7},\s{0,2}3\)\s{0,3};\s{0,3}\.\$\w{1,64}\(/ nocase ascii wide
        $gc = "Get-Content" nocase ascii wide

    condition:
        filesize < 10MB and uint16(0) != 0x5A4D and
        $iex_substring and $gc
}

rule Loader_GuLoader_PowerShell_Stage
{
    meta:
        author = "Centinela"
        description = "Script de PowerShell con el método de ofuscación de GuLoader (toma 1 de cada N letras de cada texto para esconder los comandos). GuLoader descarga e instala otros programas maliciosos como Remcos o Agent Tesla."
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cloudeye"
        date = "2026-10-03"
        family = "GuLoader"
        category = "loader"
        severity = "high"
        score = 80

    strings:
        $loop = /For\s{0,3}\(\s{0,3}\$\w{1,64}\s{0,3}=\s{0,3}\d{1,2}\s{0,3};\s{0,3}\$\w{1,64}\s{1,3}-lt\s{1,3}\$\w{1,64}\.(Length|count)\s{0,3}-\s{0,3}1\s{0,3};\s{0,3}\$\w{1,64}\s{0,3}\+=\s{0,3}\(?\s{0,3}\d{1,2}\s{0,3}\)?\s{0,3}\)/ nocase ascii wide
        $substr = ".Substring($" nocase ascii wide

        $dec_hex = /\[convert\]::ToByte\(\$\w{1,64}\.Substring\(\$\w{1,64},\s{0,2}2\),\s{0,2}16\)/ nocase ascii wide
        $dec_iex = /\.SubString\(\d{3,7},\s{0,2}3\)/ nocase ascii wide
        $dec_iexkw = "Invoke-Expression" nocase ascii wide

    condition:
        filesize < 10MB and uint16(0) != 0x5A4D and
        $loop and $substr and 1 of ($dec_*)
}

rule Loader_GuLoader_VB6
{
    meta:
        author = "Centinela"
        description = "Variante de GuLoader escrita en Visual Basic 6 (con chequeos anti-máquina virtual). GuLoader descarga e instala otros programas maliciosos."
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cloudeye"
        date = "2026-10-03"
        family = "GuLoader"
        category = "loader"
        severity = "critical"
        score = 90

    strings:
        $vm_msg = "This program cannot be run under virtual environment or debugging software !" ascii wide

        $q_msvbvm = "msvbvm60.dll" ascii wide nocase
        $q_qga = "C:\\Program Files\\qga\\qga.exe" ascii wide
        $q_qemu = "C:\\Program Files\\Qemu-ga\\qemu-ga.exe" ascii wide
        $q_profile = "USERPROFILE=" ascii wide
        $q_startup = "Startup key" ascii wide

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 10MB and
        ($vm_msg or all of ($q_*))
}
