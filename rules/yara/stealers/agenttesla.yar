/*
    Centinela - Agent Tesla
    Licencia: Apache-2.0. Indicadores públicos (ver `reference`); reglas escritas para Centinela.
*/

rule Stealer_AgentTesla
{
    meta:
        author = "Centinela"
        description = "Agent Tesla: programa espía que roba las contraseñas guardadas (navegadores, correo, FTP, VPN) y las envía al atacante por mail, FTP o Telegram. Es de los más vistos en mails de falsas cotizaciones y facturas."
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.agent_tesla"
        date = "2026-10-03"
        family = "AgentTesla"
        category = "stealer"
        severity = "critical"
        score = 95

    strings:
        $t_mozlogins = "GetMozillaFromLogins" ascii fullword
        $t_mozsqlite = "GetMozillaFromSQLite" ascii fullword
        $t_acctuser = "AccountConfiguration+username" wide
        $t_mailacct = "MailAccountConfiguration" ascii fullword
        $t_smtpacct = "SmtpAccountConfiguration" ascii fullword
        $t_killtor = "KillTorProcess" ascii fullword
        $t_proxyagent = "Proxy-Agent: HToS5x" wide
        $t_binding = "set_BindingAccountConfiguration" ascii fullword
        $t_userpass = "doUsernamePasswordAuth" ascii fullword
        $t_safari = "SafariDecryptor" ascii fullword
        $t_cliphook = "get_ClipboardHook" ascii fullword
        $t_tglog = "TelegramLog" ascii fullword
        $t_keyv75 = "generateKeyV75" ascii fullword
        $t_guidmk = "set_GuidMasterKey" ascii fullword
        $t_mozlist = "MozillaBrowserList" ascii fullword
        $t_screenlog = "EnableScreenLogger" ascii fullword
        $t_vault7 = "VaultGetItem_WIN7" ascii fullword
        $t_pubip = "PublicIpAddressGrab" ascii fullword
        $t_torpanel = "EnableTorPanel" ascii fullword

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 15MB and
        5 of ($t_*)
}
