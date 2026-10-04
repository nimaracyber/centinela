"""Helpers compartidos para tests. Los tests NUNCA usan malware real ni red real:
- muestras sintéticas construidas en el test (strings inertes que disparan heurísticas),
- EICAR armado en runtime (ver `eicar()`), nunca guardado literal en un archivo del repo,
- HTTP mockeado con respx, Redis con fakeredis.

Uso: `from tests.helpers import make_artifact, build_eml, make_raw, eicar`
"""

from __future__ import annotations

import hashlib
from email.message import EmailMessage

from centinela.core.models import Artifact, MessageRef, RawMessage


def eicar() -> bytes:
    """String de test estándar antivirus, armado en runtime."""
    return b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def make_artifact(
    data: bytes,
    filename: str | None = "file.bin",
    detected_type: str = "unknown",
    *,
    id: str = "att0",
    depth: int = 0,
    parent_id: str | None = None,
    declared_content_type: str | None = None,
) -> Artifact:
    return Artifact(
        id=id,
        filename=filename,
        declared_content_type=declared_content_type,
        detected_type=detected_type,
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        sha1=hashlib.sha1(data).hexdigest(),  # noqa: S324
        md5=hashlib.md5(data).hexdigest(),  # noqa: S324
        depth=depth,
        parent_id=parent_id,
        data=data,
    )


def make_ref(remote_id: str = "1") -> MessageRef:
    return MessageRef(connector="test", mailbox="ventas@empresa.com", remote_id=remote_id)


def build_eml(
    *,
    subject: str = "Hola",
    from_: str = "Juan <juan@proveedor.com>",
    to: str = "ventas@empresa.com",
    text: str = "Texto",
    html: str | None = None,
    attachments: list[tuple[str, bytes, str]] | None = None,  # (filename, data, "maintype/subtype")
    headers: dict[str, str] | None = None,
) -> bytes:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_
    msg["To"] = to
    msg["Message-ID"] = "<test-1@proveedor.com>"
    for k, v in (headers or {}).items():
        msg[k] = v
    msg.set_content(text)
    if html is not None:
        msg.add_alternative(html, subtype="html")
    for filename, data, mime in attachments or []:
        maintype, subtype = mime.split("/", 1)
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
    return msg.as_bytes()


def make_raw(eml: bytes, remote_id: str = "1") -> RawMessage:
    return RawMessage(ref=make_ref(remote_id), raw=eml)
