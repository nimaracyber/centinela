"""Mails más grandes que `limits.max_message_bytes`: se analizan SOLO los encabezados.

Descartar en silencio un mail enorme sería una evasión trivial (el atacante infla el adjunto y nadie lo
revisa). En su lugar cada conector emite un `RawMessage` con la sección de headers, `truncated=True` y
`original_size`; el pipeline agrega el hallazgo POLICY `policy.message_too_large` y el remitente, el
asunto y la autenticación (SPF/DKIM/DMARC) se analizan igual.

Helpers puros y acotados (nunca leen más de `MAX_HEADER_BYTES`):
- `header_section(data)`: headers de un mail crudo (IMAP `BODY[HEADER]`, archivo, copia SMTP...).
- `headers_from_api(items)`: arma un bloque RFC 5322 con los pares nombre/valor que devuelven las APIs
  (Gmail `payload.headers`, Graph `internetMessageHeaders`).
- `oversize_raw(...)`: el `RawMessage` truncado.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

from centinela.core.models import RawMessage

if TYPE_CHECKING:
    from datetime import datetime

    from centinela.core.models import MessageRef

__all__ = [
    "MAX_HEADER_BYTES",
    "MAX_HEADER_FIELDS",
    "header_cap",
    "header_section",
    "headers_from_api",
    "oversize_raw",
]

#: Tope de la sección de headers que se conserva. Un mail real tiene pocos KB de headers; una cadena larga
#: de Received/ARC rara vez pasa de 100 KB.
MAX_HEADER_BYTES = 256 * 1024
#: Tope de headers armados a partir de una API (defensa ante respuestas hostiles o gigantes).
MAX_HEADER_FIELDS = 2000

_BLANK_LINE_RE = re.compile(rb"\r?\n\r?\n")
_NEWLINES_RE = re.compile(r"[\r\n\0]+")


def header_cap(limit: int) -> int:
    """Tope de headers para un límite de mensaje dado (nunca más que el propio límite)."""
    return max(64, min(MAX_HEADER_BYTES, int(limit)))


def header_section(data: bytes, max_bytes: int = MAX_HEADER_BYTES) -> bytes:
    """Encabezados de un mail crudo (hasta la primera línea en blanco), siempre terminados en línea en blanco.

    El resultado nunca supera `max_bytes`: si la línea en blanco no aparece antes, se corta en el último
    fin de línea completo (una línea de header gigante sin fin se descarta).
    """
    max_bytes = max(64, int(max_bytes))
    if not data or data.startswith((b"\r\n", b"\n")):
        return b"\r\n"
    m = _BLANK_LINE_RE.search(data, 0, max_bytes)
    if m is not None:
        return data[: m.end()]
    if len(data) <= max_bytes - 4:  # solo headers, sin cuerpo (ej. un .eml sin línea en blanco final)
        head = data if data.endswith(b"\n") else data + b"\r\n"
        return head + b"\r\n"
    head = data[: max_bytes - 2]
    cut = head.rfind(b"\n")
    return (head[: cut + 1] if cut >= 0 else b"") + b"\r\n"


def _clean_name(name: str) -> str:
    """Nombre de header válido según RFC 5322 (ASCII imprimible sin ':')."""
    return "".join(ch for ch in name[:200] if "!" <= ch <= "~" and ch != ":")


def headers_from_api(
    items: Iterable[Any] | None,
    *,
    max_bytes: int = MAX_HEADER_BYTES,
    max_fields: int = MAX_HEADER_FIELDS,
) -> bytes:
    """Bloque de headers RFC 5322 (CRLF, terminado en línea en blanco) desde `[{"name": .., "value": ..}]`.

    Saltos de línea dentro de un valor se reemplazan por espacios: un valor hostil no puede inyectar
    headers nuevos. Los valores no ASCII van en UTF-8 crudo (RFC 6532), que el parser acepta.
    """
    out = bytearray()
    count = 0
    for item in items or ():
        if count >= max_fields:
            break
        if not isinstance(item, dict):
            continue
        name, value = item.get("name"), item.get("value")
        if not isinstance(name, str) or not isinstance(value, str):
            continue
        clean = _clean_name(name)
        if not clean:
            continue
        line = f"{clean}: {_NEWLINES_RE.sub(' ', value).strip()}\r\n".encode("utf-8", "replace")
        if len(out) + len(line) + 2 > max_bytes:
            break
        out += line
        count += 1
    out += b"\r\n"
    return bytes(out)


def oversize_raw(
    ref: MessageRef,
    headers: bytes,
    *,
    original_size: int | None,
    limit: int,
    received_at: datetime | None = None,
) -> RawMessage:
    """`RawMessage` con solo los headers de un mail que supera `limit`.

    `original_size` es el tamaño informado por el origen; si no se conoce (o el origen mintió y dijo
    algo menor al límite) se usa la cota inferior `limit + 1`.
    """
    size = original_size if original_size is not None and original_size > limit else limit + 1
    if received_at is None:
        return RawMessage(ref=ref, raw=headers, truncated=True, original_size=size)
    return RawMessage(ref=ref, raw=headers, received_at=received_at, truncated=True, original_size=size)
