/*
    Centinela - ejecutables con canales de exfiltración por Telegram o Discord
    Licencia: Apache-2.0. Reglas escritas para Centinela.
    Muchos stealers y keyloggers (Snake, AgentTesla, XWorm, stealers en Python/.NET) mandan lo robado a
    un bot de Telegram o a un webhook de Discord.
*/

rule Technique_Telegram_Bot_Exfil
{
    meta:
        author = "Centinela"
        title = "Programa que envía datos a un bot de Telegram"
        description = "El ejecutable tiene incorporada la dirección de un bot de Telegram para mandar archivos o mensajes. Los ladrones de contraseñas lo usan para enviarle al atacante lo que roban."
        reference = "https://attack.mitre.org/techniques/T1567/"
        date = "2026-10-03"
        category = "technique"
        severity = "high"
        score = 65

    strings:
        $tg_api = "api.telegram.org/bot" ascii wide nocase

        $m_doc = "sendDocument" ascii wide
        $m_msg = "sendMessage" ascii wide
        $m_photo = "sendPhoto" ascii wide
        $m_chat = "chat_id" ascii wide

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 30MB and
        $tg_api and 1 of ($m_*)
}

rule Technique_Discord_Webhook_Exfil
{
    meta:
        author = "Centinela"
        title = "Programa que envía datos a un webhook de Discord"
        description = "El ejecutable tiene incorporada la dirección de un 'webhook' de Discord para subir información. Es un canal muy usado por ladrones de contraseñas y cookies."
        reference = "https://attack.mitre.org/techniques/T1567/"
        date = "2026-10-03"
        category = "technique"
        severity = "high"
        score = 60

    strings:
        $dw = /discord(app)?\.com\/api\/webhooks\/\d{6,24}\// nocase ascii wide

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 30MB and
        $dw
}
