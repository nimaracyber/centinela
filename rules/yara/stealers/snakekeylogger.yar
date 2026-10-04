/*
    Centinela - Snake Keylogger (derivado de 404 Keylogger)
    Licencia: Apache-2.0. Indicadores públicos (ver `reference`); reglas escritas para Centinela.
*/

rule Stealer_SnakeKeylogger
{
    meta:
        author = "Centinela"
        description = "Snake Keylogger (404 Keylogger): registra todo lo que se teclea, roba contraseñas del navegador y del correo y captura el portapapeles; envía los datos por mail, FTP o Telegram."
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.404keylogger"
        date = "2026-10-03"
        family = "Snake Keylogger"
        category = "stealer"
        severity = "critical"
        score = 95

    strings:
        $banner = "----------------S--------N--------A--------K--------E----------------" ascii wide
        $name = "SNAKE-KEYLOGGER" ascii wide fullword

        $a_encpw = "get_encryptedPassword" ascii fullword
        $a_encuser = "get_encryptedUsername" ascii fullword
        $a_pwchanged = "get_timePasswordChanged" ascii fullword
        $a_pwfield = "get_passwordField" ascii fullword
        $a_setencpw = "set_encryptedPassword" ascii fullword
        $a_passwords = "get_passwords" ascii fullword
        $a_logins = "get_logins" ascii fullword
        $a_outlook = "GetOutlookPasswords" ascii fullword
        $a_startkl = "StartKeylogger" ascii fullword
        $a_klargs = "KeyLoggerEventArgs" ascii fullword
        $a_klhandler = "KeyLoggerEventArgsEventHandler" ascii fullword
        $a_datapw = "GetDataPassword" ascii fullword
        $a_field = "_encryptedPassword" ascii fullword

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 15MB and
        (
            ($banner and $name) or
            #banner > 3 or
            #name > 3 or
            8 of ($a_*)
        )
}
