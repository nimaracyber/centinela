/*
    Centinela - Warzone RAT / Ave Maria
    Licencia: Apache-2.0. Indicadores públicos (ver `reference`); reglas escritas para Centinela.
*/

rule RAT_Warzone_AveMaria
{
    meta:
        author = "Centinela"
        description = "Troyano de acceso remoto Warzone (Ave Maria): roba contraseñas, permite escritorio remoto oculto y escala privilegios en Windows."
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ave_maria"
        date = "2026-10-03"
        family = "Warzone RAT"
        category = "rat"
        severity = "critical"
        score = 95

    strings:
        $w_build = "warzone160" ascii wide
        $w_avemaria = "Ave_Maria Stealer OpenSource" ascii wide
        $w_admin = "Hey I'm Admin" ascii wide
        $w_ellocnak = "\\ellocnak.xml" ascii wide
        $w_rptls = "SOFTWARE\\_rptls" ascii wide
        $w_account = "Accounts\\Account.rec0" ascii wide
        $w_selfdel = "cmd.exe /C ping 1.2.3.4 -n 2 -w 1000 > Nul & Del /f /q " ascii wide
        $w_vnc = "handleStartVncCommand" ascii wide

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 15MB and
        3 of ($w_*)
}
