/*
    Centinela - ejecutable con el combo típico de robo de credenciales de navegadores
    Licencia: Apache-2.0. Reglas escritas para Centinela.
    Detecta comportamiento de "stealer" genérico (familias nuevas o sin regla propia) cuando las
    cadenas están en claro.
*/

rule Technique_Browser_Credential_Theft
{
    meta:
        author = "Centinela"
        title = "Programa preparado para robar contraseñas del navegador"
        description = "El ejecutable sabe dónde guardan Chrome, Edge, Firefox y otros navegadores las contraseñas y cómo descifrarlas. Es el comportamiento típico de un 'stealer' (ladrón de contraseñas)."
        reference = "https://attack.mitre.org/techniques/T1555/003/"
        date = "2026-10-03"
        category = "technique"
        severity = "high"
        score = 65

    strings:
        $q_pwvalue = "password_value" ascii wide nocase
        $q_logins = "FROM logins" ascii wide nocase

        $k_enckey = "encrypted_key" ascii wide
        $k_dpapi = "CryptUnprotectData" ascii wide
        $k_oscrypt = "os_crypt" ascii wide

        $b_chrome = "\\Google\\Chrome\\User Data" ascii wide nocase
        $b_edge = "\\Microsoft\\Edge\\User Data" ascii wide nocase
        $b_brave = "\\BraveSoftware\\Brave-Browser\\User Data" ascii wide nocase
        $b_opera = "\\Opera Software\\Opera Stable" ascii wide nocase
        $b_firefox = "\\Mozilla\\Firefox\\Profiles" ascii wide nocase
        $b_yandex = "\\Yandex\\YandexBrowser\\User Data" ascii wide nocase
        $b_vivaldi = "\\Vivaldi\\User Data" ascii wide nocase
        $b_chromium = "\\Chromium\\User Data" ascii wide nocase

        $f_logindata = "Login Data" ascii wide
        $f_loginsjson = "logins.json" ascii wide
        $f_key4 = "key4.db" ascii wide
        $f_webdata = "Web Data" ascii wide
        $f_localstate = "Local State" ascii wide

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 25MB and
        $q_pwvalue and $q_logins and
        1 of ($k_*) and 3 of ($b_*) and 2 of ($f_*)
}
