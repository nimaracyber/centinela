"""Neutraliza la evidencia antes de guardarla, mostrarla o enviarla.

Centinela guarda fragmentos de lo que encontró (comandos decodificados, strings de un ejecutable,
pedazos de un script). Si esos fragmentos quedan literales, el antivirus del cliente marca como
amenaza la propia base de datos de Centinela, las páginas del dashboard o los mails de alerta
(pasó durante el desarrollo: Windows Defender detectó un archivo de log que contenía un comando
de descarga de prueba). Por eso toda evidencia pasa por `neutralize()`:

- inserta un separador visible («·») dentro de palabras clave de ataque: una persona lo sigue
  leyendo igual, pero deja de ser un comando ejecutable y deja de coincidir con firmas de antivirus;
- recorta bloques largos de base64/hex (payloads codificados) dejando solo el comienzo.

Los links NO se tocan acá: la evidencia también lleva links legítimos de referencia (MalwareBazaar,
Malpedia) que tienen que seguir sirviendo, y el dashboard y las alertas ya desactivan los links del
mail al mostrarlos (hxxp, [.]).

Es idempotente: aplicarlo dos veces da el mismo resultado.
"""

from __future__ import annotations

import re
from typing import Any

SEP = "·"  # U+00B7: visible, no rompe la lectura, rompe la coincidencia byte a byte

# Palabras clave que, juntas, forman comandos de ataque reconocibles. Se parten al medio.
_KEYWORDS = (
    "powershell",
    "pwsh",
    "invoke-expression",
    "invoke-webrequest",
    "invoke-restmethod",
    "downloadstring",
    "downloadfile",
    "downloaddata",
    "webclient",
    "start-process",
    "start-bitstransfer",
    "frombase64string",
    "encodedcommand",
    "reflection.assembly",
    "wscript.shell",
    "shell.application",
    "activexobject",
    "createobject",
    "urldownloadtofile",
    "xmlhttp",
    "adodb.stream",
    "mshta",
    "rundll32",
    "regsvr32",
    "certutil",
    "bitsadmin",
    "cscript",
    "wscript",
    "amsiutils",
    "amsiinitfailed",
    "add-mppreference",
    "set-mppreference",
    "eicar-standard-antivirus-test-file",
)
_KEYWORD_RE = re.compile(
    "|".join(re.escape(k) for k in sorted(_KEYWORDS, key=len, reverse=True)), re.IGNORECASE
)
# alias cortos de PowerShell: solo como palabra completa
_SHORT_RE = re.compile(r"(?<![\w·])(iex|iwr|irm)(?![\w·])", re.IGNORECASE)
# bloques codificados largos (base64 o hex): payloads, no información útil para una persona
_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")
_BLOB_KEEP = 40
MAX_DEPTH = 12


def _split(word: str) -> str:
    mid = max(1, len(word) // 2)
    return word[:mid] + SEP + word[mid:]


def _blob(m: re.Match[str]) -> str:
    s = m.group(0)
    return f"{s[:_BLOB_KEEP]}…[{len(s) - _BLOB_KEEP} caracteres codificados omitidos]"


def neutralize_text(text: str) -> str:
    if not text:
        return text
    text = _BLOB_RE.sub(_blob, text)
    text = _KEYWORD_RE.sub(lambda m: _split(m.group(0)), text)
    return _SHORT_RE.sub(lambda m: _split(m.group(0)), text)


def neutralize(value: Any, _depth: int = 0) -> Any:
    """Aplica `neutralize_text` a todos los strings (valores, no claves) de una estructura JSON-like."""
    if _depth > MAX_DEPTH:
        return value
    if isinstance(value, str):
        return neutralize_text(value)
    if isinstance(value, dict):
        return {k: neutralize(v, _depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        return [neutralize(v, _depth + 1) for v in value]
    if isinstance(value, tuple):
        return tuple(neutralize(v, _depth + 1) for v in value)
    return value
