/*
    Centinela - AsyncRAT
    Licencia: Apache-2.0. Indicadores públicos (ver `reference`); reglas escritas para Centinela.
    AsyncRAT es open source (C#) y tiene muchos derivados (DCRat, VenomRAT...): esta regla puede
    disparar también en esos forks, que tienen sus propias reglas más específicas.
*/

rule RAT_AsyncRAT
{
    meta:
        author = "Centinela"
        description = "Troyano de acceso remoto AsyncRAT: le da al atacante control total de la computadora (ver la pantalla, robar archivos y contraseñas, registrar lo que se teclea)."
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.asyncrat"
        date = "2026-10-03"
        family = "AsyncRAT"
        category = "rat"
        severity = "critical"
        score = 95

    strings:
        // strings del cliente (heap #US en UTF-16 y nombres de métodos en ASCII)
        $s_schtasks = "/c schtasks /create /f /sc onlogon /rl highest /tn \"" wide
        $s_stub = "Stub.exe" wide fullword
        $s_pong = "get_ActivatePong" ascii fullword
        $s_vmware = "vmware" wide fullword
        $s_runkey_rev = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" wide
        $s_ssl = "get_SslClient" ascii fullword
        $s_packet = "Client.Handle_Packet" ascii wide
        $s_masterkey = "masterKey can not be null or empty." wide

        // identificadores de la clase de configuración (Settings) del cliente
        $cfg_sig = "Serversignature" ascii wide fullword
        $cfg_cert = "ServerCertificate" ascii wide fullword
        $cfg_pastebin = "Pastebin" ascii wide fullword
        $cfg_bdos = "BDOS" ascii wide fullword
        $cfg_aes = "Aes256" ascii wide fullword
        $cfg_folder = "InstallFolder" ascii wide fullword
        $cfg_file = "InstallFile" ascii wide fullword
        $cfg_mtx = "MTX" ascii wide fullword
        $cfg_hwid = "Hwid" ascii wide fullword

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 15MB and
        (
            4 of ($s_*) or
            ($cfg_sig and $cfg_cert and 5 of ($cfg_*))
        )
}
