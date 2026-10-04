/*
    Centinela - NanoCore RAT
    Licencia: Apache-2.0. Indicadores públicos (ver `reference`); reglas escritas para Centinela.
*/

rule RAT_NanoCore
{
    meta:
        author = "Centinela"
        description = "Troyano de acceso remoto NanoCore: permite al atacante controlar la computadora, activar la cámara y robar contraseñas."
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nanocore"
        date = "2026-10-03"
        family = "NanoCore"
        category = "rat"
        severity = "critical"
        score = 95

    strings:
        $ns_host = "NanoCore.ClientPluginHost" ascii
        $ns_plugin = "NanoCore.ClientPlugin" ascii
        $ns_client = "NanoCore Client" ascii wide

        $b_builder = "get_BuilderSettings" ascii fullword
        $b_loaderform = "ClientLoaderForm.resources" ascii fullword
        $b_plugincmd = "PluginCommand" ascii fullword
        $b_apphost = "IClientAppHost" ascii fullword
        $b_blockhash = "GetBlockHash" ascii fullword
        $b_hostentry = "AddHostEntry" ascii fullword
        $b_logexc = "LogClientException" ascii fullword
        $b_pipe = "PipeExists" ascii fullword
        $b_loghost = "IClientLoggingHost" ascii fullword

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 15MB and
        (
            1 of ($ns_*) or
            6 of ($b_*)
        )
}
