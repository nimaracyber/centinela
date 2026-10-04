/*
    Centinela - FormBook / XLoader
    Licencia: Apache-2.0. Secuencias de código documentadas públicamente (ver `reference`).

    FormBook cifra todas sus cadenas, por eso la regla busca secuencias de instrucciones propias de su
    payload (descifrado de strings, armado de hooks, parseo de pedidos POST). Se exigen al menos dos
    secuencias distintas para evitar falsos positivos. Casi siempre llega "empaquetado" dentro de otro
    ejecutable (.NET, AutoIt...): en ese caso esta regla no ve el payload y la detección depende de
    las reglas de loaders/técnicas, ClamAV y la reputación del hash.
*/

rule Stealer_FormBook
{
    meta:
        author = "Centinela"
        description = "FormBook / XLoader: roba lo que se escribe en formularios web y navegadores (usuarios, contraseñas, datos bancarios) y captura pantallas. Se distribuye en mails de falsos pedidos y facturas."
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.formbook"
        date = "2026-10-03"
        family = "FormBook"
        category = "stealer"
        severity = "critical"
        score = 95

    strings:
        $c_post = { 3C 30 50 4F 53 54 74 09 40 }
        $c_strlen = { 74 0A 4E 0F B6 08 8D 44 08 01 75 F6 8D 70 01 0F B6 00 8D 55 }
        $c_decode = { 1A D2 80 E2 AF 80 C2 7E EB 2A 80 FA 2F 75 11 8A D0 80 E2 01 }
        $c_epilogue = { 04 83 C4 0C 83 06 07 5B 5F 5E 8B E5 5D C3 8B 17 03 55 0C 6A 01 83 }
        $c_getpc = { E9 C5 9C FF FF C3 E8 00 00 00 00 58 C3 68 }
        $c_sub = { 8D 44 37 FE 8D 4E FF 8A 50 01 28 10 48 49 75 ?? 83 FE 01 76 ?? 8B C7 8D 4E FF 8D 9B 00 00 00 00 8A 50 01 28 10 40 49 }
        $c_hook = { B8 90 90 90 90 89 07 66 89 47 04 8D 5F 06 BF 04 00 00 00 39 7D FC 76 }
        $c_scan = { B2 88 81 3C 31 40 41 49 48 75 ?? 80 7C 31 04 B8 75 ?? 38 54 31 05 }
        $c_tramp = { 8D 57 FD 52 C7 45 14 90 90 90 90 C7 45 F8 55 8B EC 00 C7 45 FC 00 00 00 00 }

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 10MB and
        2 of ($c_*)
}
