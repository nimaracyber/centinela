"""Constructores de muestras sintéticas e INERTES para los tests de documentos.

Nada de esto es malware: son estructuras mínimas (OLE/CFB, OOXML, RTF, PDF, OneNote) con las marcas que
disparan las heurísticas (CLSIDs, relaciones, palabras clave). Los "ejecutables" son solo `MZ` + relleno.
"""

from __future__ import annotations

import io
import struct
import uuid
import zipfile
from dataclasses import dataclass, field

# --------------------------------------------------------------------------- OLE / CFB mínimo

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_ENDOFCHAIN = 0xFFFFFFFE
_FREESECT = 0xFFFFFFFF
_FATSECT = 0xFFFFFFFD
_NOSTREAM = 0xFFFFFFFF
_SECTOR = 512

EQUATION3_CLSID = "0002CE02-0000-0000-C000-000000000046"
URL_MONIKER_CLSID = "79EAC9E0-BAF9-11CE-8C82-00AA004BA90B"


@dataclass
class Node:
    name: str
    data: bytes | None = None  # None => storage
    clsid: str | None = None
    children: list[Node] = field(default_factory=list)


def build_cfb(children: list[Node], root_clsid: str | None = None) -> bytes:
    """Escribe un Compound File v3 mínimo (sectores de 512, una sola sector FAT, sin mini stream).

    Los streams deben medir 0 o >= 4096 bytes (se rellenan automáticamente) para no usar el mini stream.
    """
    entries: list[dict] = [{"name": "Root Entry", "type": 5, "clsid": root_clsid, "node": None}]

    def add(nodes: list[Node]) -> list[int]:
        ids = []
        for n in nodes:
            entries.append({"name": n.name, "type": 1 if n.data is None else 2, "clsid": n.clsid, "node": n})
            ids.append(len(entries) - 1)
        return ids

    # BFS para asignar ids y armar el árbol (hijos encadenados por el puntero derecho)
    queue: list[tuple[int, list[Node]]] = [(0, children)]
    while queue:
        parent, kids = queue.pop(0)
        ids = add(kids)
        entries[parent]["child"] = ids[0] if ids else _NOSTREAM
        for i, eid in enumerate(ids):
            entries[eid]["right"] = ids[i + 1] if i + 1 < len(ids) else _NOSTREAM
            node = entries[eid]["node"]
            if node.data is None:
                queue.append((eid, node.children))

    n_dir_sectors = (len(entries) * 128 + _SECTOR - 1) // _SECTOR
    next_sector = 1 + n_dir_sectors
    fat = [_FREESECT] * 128
    fat[0] = _FATSECT
    for s in range(1, 1 + n_dir_sectors):
        fat[s] = s + 1 if s < n_dir_sectors else _ENDOFCHAIN
    stream_blobs: list[bytes] = []
    for e in entries:
        node = e["node"]
        if node is None or node.data is None or len(node.data) == 0:
            e["start"], e["size"] = (_ENDOFCHAIN if e["type"] != 1 else 0), 0
            continue
        data = node.data if len(node.data) >= 4096 else node.data + b"\x00" * (4096 - len(node.data))
        nsec = (len(data) + _SECTOR - 1) // _SECTOR
        e["start"], e["size"] = next_sector, len(data)
        for k in range(nsec):
            fat[next_sector + k] = next_sector + k + 1 if k + 1 < nsec else _ENDOFCHAIN
        next_sector += nsec
        stream_blobs.append(data + b"\x00" * ((-len(data)) % _SECTOR))
    assert next_sector <= 128, "muestra demasiado grande para el CFB mínimo"

    def dir_entry(e: dict) -> bytes:
        name = (e["name"] + "\x00").encode("utf-16-le")
        clsid = uuid.UUID(e["clsid"]).bytes_le if e.get("clsid") else b"\x00" * 16
        return struct.pack(
            "<64sHBBIII16sIQQIQ",
            name.ljust(64, b"\x00"),
            len(name),
            e["type"],
            1,
            _NOSTREAM,
            e.get("right", _NOSTREAM),
            e.get("child", _NOSTREAM),
            clsid,
            0,
            0,
            0,
            e.get("start", _ENDOFCHAIN),
            e.get("size", 0),
        )

    empty = struct.pack(
        "<64sHBBIII16sIQQIQ",
        b"\x00" * 64,
        0,
        0,
        0,
        _NOSTREAM,
        _NOSTREAM,
        _NOSTREAM,
        b"\x00" * 16,
        0,
        0,
        0,
        0,
        0,
    )
    directory = b"".join(dir_entry(e) for e in entries)
    directory += empty * ((n_dir_sectors * _SECTOR - len(directory)) // 128)
    header = struct.pack(
        "<8s16sHHHHH6sIIIIIIIII",
        OLE_MAGIC,
        b"\x00" * 16,
        0x3E,
        3,
        0xFFFE,
        9,
        6,
        b"\x00" * 6,
        0,
        1,
        1,
        0,
        4096,
        _ENDOFCHAIN,
        0,
        _ENDOFCHAIN,
        0,
    )
    header += struct.pack("<I", 0) + struct.pack("<I", _FREESECT) * 108
    assert len(header) == 512
    fat_sector = struct.pack("<128I", *fat)
    return header + fat_sector + directory + b"".join(stream_blobs)


def ole10native(filename: str, src: str, tmp: str, payload: bytes, *, with_size: bool = True) -> bytes:
    """Stream \\x01Ole10Native / datos nativos de un objeto 'Package' (MS-OLEDS 2.3.6)."""
    body = (
        struct.pack("<H", 2)
        + filename.encode("latin-1")
        + b"\x00"
        + src.encode("latin-1")
        + b"\x00"
        + struct.pack("<II", 0x00030000, len(tmp) + 1)
        + tmp.encode("latin-1")
        + b"\x00"
        + struct.pack("<I", len(payload))
        + payload
    )
    return struct.pack("<I", len(body)) + body if with_size else body


def ole1_object(class_name: bytes, data: bytes) -> bytes:
    """Objeto OLE 1.0 (MS-OLEDS 2.2), como el que va hex-codificado en \\objdata de un RTF."""

    def lp(s: bytes) -> bytes:
        return struct.pack("<I", len(s)) + s

    return struct.pack("<II", 0x00000501, 2) + lp(class_name + b"\x00") + lp(b"") + lp(b"") + lp(data)


def url_moniker_stream(url: str) -> bytes:
    body = struct.pack("<IIII", 0x02000001, 9, 1, 0) + uuid.UUID(URL_MONIKER_CLSID).bytes_le
    wide = url.encode("utf-16-le") + b"\x00\x00"
    return body + struct.pack("<I", len(wide)) + wide


def ovba_compress_literal(source: bytes) -> bytes:
    """Contenedor comprimido MS-OVBA 2.4.1 válido usando solo tokens literales (sin compresión real).

    Alcanza para que olevba encuentre y descomprima el código de un módulo VBA."""
    out = bytearray(b"\x01")
    for i in range(0, len(source), 3500):
        chunk = source[i : i + 3500]
        tokens = bytearray()
        for j in range(0, len(chunk), 8):
            tokens += b"\x00" + chunk[j : j + 8]
        header = ((2 + len(tokens) - 3) & 0x0FFF) | (0b011 << 12) | 0x8000
        out += struct.pack("<H", header) + tokens
    return bytes(out)


def fake_pe() -> bytes:
    """No es un ejecutable real: solo la cabecera MZ y relleno inerte."""
    return (
        b"MZ\x90\x00"
        + b"\x00" * 60
        + b"This program cannot be run in DOS mode (muestra de test)"
        + b"\x00" * 64
    )


# --------------------------------------------------------------------------- OOXML

CT_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Override PartName="/word/document.xml" '
    'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
    "</Types>"
)
REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
REL_TYPE = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/"
W_NS = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'


def ooxml(parts: dict[str, bytes | str], content_types: str = CT_XML) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr(
            "_rels/.rels",
            f'<?xml version="1.0"?><Relationships xmlns="{REL_NS}"><Relationship Id="rId1" '
            f'Type="{REL_TYPE}officeDocument" Target="word/document.xml"/></Relationships>',
        )
        for name, data in parts.items():
            z.writestr(name, data)
    return buf.getvalue()


def rels(*items: tuple[str, str, str | None]) -> str:
    """items: (tipo, destino, targetmode|None)."""
    body = ""
    for i, (rtype, target, mode) in enumerate(items, start=1):
        tm = f' TargetMode="{mode}"' if mode else ""
        body += f'<Relationship Id="rId{i}" Type="{REL_TYPE}{rtype}" Target="{target}"{tm}/>'
    return f'<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="{REL_NS}">{body}</Relationships>'


def word_document(body_xml: str) -> str:
    return (
        f'<?xml version="1.0" encoding="UTF-8"?><w:document {W_NS}><w:body>{body_xml}</w:body></w:document>'
    )


def paragraph(text: str) -> str:
    return f"<w:p><w:r><w:t>{text}</w:t></w:r></w:p>"


# --------------------------------------------------------------------------- PDF


def pdf_stream(data: bytes, extra: bytes = b"") -> bytes:
    return b"<< /Length " + str(len(data)).encode() + b" " + extra + b">>\nstream\n" + data + b"\nendstream"


def build_pdf(
    objs: dict[int, bytes], *, root: int = 1, trailer_extra: bytes = b"", version: bytes = b"1.7"
) -> bytes:
    out = bytearray(b"%PDF-" + version + b"\n%\xe2\xe3\xcf\xd3\n")
    offsets: dict[int, int] = {}
    for num in sorted(objs):
        offsets[num] = len(out)
        out += f"{num} 0 obj\n".encode() + objs[num] + b"\nendobj\n"
    xref = len(out)
    size = max(objs) + 1
    out += f"xref\n0 {size}\n".encode() + b"0000000000 65535 f \n"
    for i in range(1, size):
        out += (f"{offsets[i]:010d} 00000 n \n" if i in offsets else "0000000000 65535 f \n").encode()
    out += f"trailer\n<< /Size {size} /Root {root} 0 R ".encode() + trailer_extra + b">>\n"
    out += f"startxref\n{xref}\n".encode() + b"%%EOF\n"
    return bytes(out)


def build_pdf_objstm(objs: dict[int, bytes], hidden: dict[int, bytes], *, root: int = 1) -> bytes:
    """PDF 1.5 con tabla de referencias en stream (/XRef) y los objetos `hidden` dentro de un /ObjStm
    comprimido: sus palabras clave NO aparecen en los bytes crudos."""
    import zlib

    objstm_num = max(list(objs) + list(hidden)) + 1
    xref_num = objstm_num + 1
    bodies = list(hidden.values())
    offsets_in = []
    pos = 0
    for b in bodies:
        offsets_in.append(pos)
        pos += len(b) + 1
    header = b" ".join(f"{n} {off}".encode() for n, off in zip(hidden, offsets_in, strict=True)) + b" "
    content = header + b" ".join(bodies)
    objs = dict(objs)
    objs[objstm_num] = pdf_stream(
        zlib.compress(content),
        f"/Type /ObjStm /N {len(hidden)} /First {len(header)} /Filter /FlateDecode ".encode(),
    )
    out = bytearray(b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n")
    offsets: dict[int, int] = {}
    for num in sorted(objs):
        offsets[num] = len(out)
        out += f"{num} 0 obj\n".encode() + objs[num] + b"\nendobj\n"
    offsets[xref_num] = len(out)
    size = xref_num + 1
    rows = b""
    for i in range(size):
        if i in offsets:
            rows += struct.pack(">BIH", 1, offsets[i], 0)
        elif i in hidden:
            rows += struct.pack(">BIH", 2, objstm_num, list(hidden).index(i))
        else:
            rows += struct.pack(">BIH", 0, 0, 0xFFFF)
    xref = pdf_stream(rows, f"/Type /XRef /Size {size} /W [1 4 2] /Root {root} 0 R ".encode())
    out += f"{xref_num} 0 obj\n".encode() + xref + b"\nendobj\n"
    out += f"startxref\n{offsets[xref_num]}\n".encode() + b"%%EOF\n"
    return bytes(out)


def simple_pdf(
    text: str = "Hola, adjunto el presupuesto solicitado.",
    *,
    catalog_extra: bytes = b"",
    page_extra: bytes = b"",
    extra_objs: dict[int, bytes] | None = None,
) -> bytes:
    """PDF de una página con texto real (Helvetica) y objetos extra opcionales (ids >= 10)."""
    content = f"BT /F1 12 Tf 72 712 Td ({text}) Tj ET".encode("latin-1")
    objs = {
        1: b"<< /Type /Catalog /Pages 2 0 R " + catalog_extra + b">>",
        2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> "
        b"/Contents 5 0 R " + page_extra + b">>",
        4: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        5: pdf_stream(content),
    }
    objs.update(extra_objs or {})
    return build_pdf(objs)


# --------------------------------------------------------------------------- OneNote

ONENOTE_HEADER = uuid.UUID("7B5C52E4-D88C-4DA7-AEB1-5378D02996D3").bytes_le
FDSO_HEADER = uuid.UUID("BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC").bytes_le
FDSO_FOOTER = uuid.UUID("71FBA722-0F79-4A0B-BB13-899256426B24").bytes_le


def onenote_blob(payloads: list[bytes], names: tuple[str, ...] = (), lure: str | None = None) -> bytes:
    out = bytearray(ONENOTE_HEADER + b"\x00" * 1008)
    for name in names:
        out += b"\x00\x00" + name.encode("utf-16-le") + b"\x00\x00"
    if lure:
        out += lure.encode("utf-16-le") + b"\x00\x00"
    for p in payloads:
        out += FDSO_HEADER + struct.pack("<QIQ", len(p), 0, 0) + p
        out += b"\x00" * ((-len(p)) % 8) + FDSO_FOOTER
    out += b"\x00" * 64
    return bytes(out)
