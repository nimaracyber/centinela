"""Constructores de muestras SINTÉTICAS e inertes para los tests de parsing.

Nada de esto es malware: son contenedores armados en memoria con contenido de juguete
("MZ" + cabecera PE mínima, textos, etc.) para ejercitar el parser y los límites.
Los vectores RAR/AES fueron generados una única vez con WinRAR / 7-Zip a partir de un .txt de prueba
(contenido: "factura de prueba centinela ..."), para validar contra implementaciones reales.
"""

from __future__ import annotations

import base64
import io
import os
import struct
import tarfile
import zipfile
import zlib

# --------------------------------------------------------------------------- binarios de juguete


def minimal_pe() -> bytes:
    """Cabecera DOS + 'PE\\0\\0' + padding. No es ejecutable útil."""
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 64)
    return bytes(dos) + b"PE\x00\x00" + struct.pack("<HH", 0x14C, 1) + b"\x00" * 300


def ole_bytes(root_clsid: bytes = b"\x00" * 16) -> bytes:
    """OLE2/CFB mínimo: header + 1 sector de directorio con el root entry (CLSID configurable)."""
    header = bytearray(512)
    header[0:8] = bytes.fromhex("D0CF11E0A1B11AE1")
    struct.pack_into("<HHHHH", header, 0x18, 0x3E, 3, 0xFFFE, 9, 6)
    struct.pack_into("<I", header, 0x2C, 1)  # sectores FAT
    struct.pack_into("<I", header, 0x30, 1)  # primer sector de directorio
    fat = bytearray(b"\xff" * 512)
    dir_sector = bytearray(512)
    name = "Root Entry".encode("utf-16-le") + b"\x00\x00"
    dir_sector[0 : len(name)] = name
    struct.pack_into("<H", dir_sector, 0x40, len(name))
    dir_sector[0x42] = 5
    dir_sector[0x50:0x60] = root_clsid
    return bytes(header) + bytes(fat) + bytes(dir_sector)


MSI_CLSID = bytes.fromhex("84100C0000000000C000000000000046")
LNK_HEADER = bytes.fromhex("4C0000000114020000000000C000000000000046")
ONENOTE_GUID = bytes.fromhex("E4525C7B8CD8A74DAEB15378D02996D3")
FDSO_HEADER = bytes.fromhex("E716E3BD65261145A4C48D4D0B7A9EAC")
FDSO_FOOTER = bytes.fromhex("22A7FB71790F0B4ABB13899256426B24")


# --------------------------------------------------------------------------- ZIP


def zip_bytes(
    entries: list[tuple[str, bytes]] | dict[str, bytes], method: int = zipfile.ZIP_DEFLATED
) -> bytes:
    items = list(entries.items()) if isinstance(entries, dict) else list(entries)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", method) as zf:
        for name, data in items:
            zf.writestr(name, data)
    return buf.getvalue()


def _crc_table() -> list[int]:
    table = []
    for n in range(256):
        c = n
        for _ in range(8):
            c = (c >> 1) ^ 0xEDB88320 if c & 1 else c >> 1
        table.append(c)
    return table


_CRC = _crc_table()


class _ZipCryptoKeys:
    """Cifrado "tradicional" PKWARE (APPNOTE 6.1), solo para armar muestras de test."""

    def __init__(self, password: bytes) -> None:
        self.k0, self.k1, self.k2 = 0x12345678, 0x23456789, 0x34567890
        for b in password:
            self._update(b)

    def _update(self, b: int) -> None:
        self.k0 = (self.k0 >> 8) ^ _CRC[(self.k0 ^ b) & 0xFF]
        self.k1 = (self.k1 + (self.k0 & 0xFF)) & 0xFFFFFFFF
        self.k1 = (self.k1 * 134775813 + 1) & 0xFFFFFFFF
        self.k2 = (self.k2 >> 8) ^ _CRC[(self.k2 ^ ((self.k1 >> 24) & 0xFF)) & 0xFF]

    def encrypt(self, data: bytes) -> bytes:
        out = bytearray()
        for b in data:
            t = (self.k2 | 2) & 0xFFFF
            out.append(b ^ (((t * (t ^ 1)) >> 8) & 0xFF))
            self._update(b)
        return bytes(out)


def raw_zip(entries: list[dict]) -> bytes:
    """Zip armado a mano. Cada entrada: name, data, [method=8], [password], [declared_size],
    [external_attr], [create_system=0]. Permite mentir en tamaños, cifrar con ZipCrypto, symlinks..."""
    local = bytearray()
    central = bytearray()
    for e in entries:
        name = e["name"].encode("utf-8")
        data = e["data"]
        method = e.get("method", 8)
        crc = zlib.crc32(data)
        if method == 8:
            c = zlib.compressobj(9, zlib.DEFLATED, -15)
            payload = c.compress(data) + c.flush()
        else:
            payload = data
        flag = 0x800
        if e.get("password"):
            flag |= 0x1
            keys = _ZipCryptoKeys(e["password"].encode())
            header = os.urandom(11) + bytes([(crc >> 24) & 0xFF])
            payload = keys.encrypt(header + payload)
        usize = e.get("declared_size", len(data))
        offset = len(local)
        local += struct.pack(
            "<4sHHHHHIIIHH", b"PK\x03\x04", 20, flag, method, 0, 0x21, crc, len(payload), usize, len(name), 0
        )
        local += name + payload
        central += struct.pack(
            "<4sBBHHHHHIIIHHHHHII",
            b"PK\x01\x02",
            20,
            e.get("create_system", 0),
            20,
            flag,
            method,
            0,
            0x21,
            crc,
            len(payload),
            usize,
            len(name),
            0,
            0,
            0,
            0,
            e.get("external_attr", 0),
            offset,
        )
        central += name
    eocd = struct.pack(
        "<4sHHHHIIH", b"PK\x05\x06", 0, 0, len(entries), len(entries), len(central), len(local), 0
    )
    return bytes(local + central + eocd)


# Generados con 7-Zip a partir de "factura.txt" (560 bytes de texto de prueba), contraseña "4455".
AES256_ZIP = base64.b64decode(
    "UEsDBDMAAQBjAFcARF0AAAAARgAAADACAAALAAsAZmFjdHVyYS50eHQBmQcAAgBBRQMIAAuLYjzk1opkn/s8ti2f5SfDiBc9roHmPfxkJPuX"
    "bJWOjyTL8/W6XC6IfEWLT7LHE29W8MJA2WTvDQhfClNSB0RbSmtXkVhQSwECPwAzAAEAYwBXAERdAAAAAEYAAAAwAgAACwAvAAAAAAAAACAA"
    "AAAAAAAAZmFjdHVyYS50eHQKACAAAAAAAAEAGAA+JzHUrFPdAQAAAAAAAAAAAAAAAAAAAAABmQcAAgBBRQMIAFBLBQYAAAAAAQABAGgAAAB6"
    "AAAAAAA="
)
AES128_STORED_ZIP = base64.b64decode(
    "UEsDBDMAAQBjAFcARF0AAAAARAIAADACAAALAAsAZmFjdHVyYS50eHQBmQcAAgBBRQEAAL9PEhRu0YuSt9axnEQVlDx24V9tqJ+aVc+MVpBy"
    "G1hbhStSnOwKqama6SgsqSeOjAXlrxX8O0ttV+UHypfN4DFYbbrQ6lmpeO3cQmt4O0GybfUL6OTn+5/JHjUOc610HOW1aPzigJNKIyn/7x12"
    "EGwmwOkSatg5CzktvkZo3y1VqCvU3QR8bp8xD56uRjuZNQhqA0o78Rd3B89xwxisP/GIlkyQQBi1SkXFK0mztU9yZGWHI1zY6b2nA+tjSReD"
    "eq5teApB6Ttf6W5/bSDgDshGs42+EZolJtcbr5mOM0EOUe8CMI7CH0h2Kd5bHA0t4YbMoHfK0/a7uU0IdYdaSRp+a8yiZ/L8apQ6iGuK+ppI"
    "/E6zNQilBu0VLqy26Alft1+SBlK+pOAKllTOK6wZcQPXju0FhjvtqerRPZnpfdXIyscF832tWzGj47xkcT1nFanlCwwtsSB69eXxzBfoGrSE"
    "gRELeFtf63acO5jgn99xNWM8o45cDR3u0Wtu3UsL6yfB0PER+J6ihZvKQrpy802pFhMeaOFqDOXcraiaBq44O5wZXzFpQ6uRDaMUT72EnIgc"
    "qlbpd3PgVHBEbAQ8dd7tvLbI9gMMgVZi759Iqdiw4gsTcfSWLjjeeAOWknKBOt8y0NyKTbGxOBUEPOmUwfKzafLDe56L4HIIi+2HKCzujJ9u"
    "uCF0RmwVMMOqOVGS3xp5YfOuuFlVm28qcz84EznzXCvhf1MIl0uLkEvpQn+3gW+H+X/0OoxsE3qo/TwwIPOBLqJQSwECPwAzAAEAYwBXAERd"
    "AAAAAEQCAAAwAgAACwAvAAAAAAAAACAAAAAAAAAAZmFjdHVyYS50eHQKACAAAAAAAAEAGAA+JzHUrFPdAQAAAAAAAAAAAAAAAAAAAAABmQcA"
    "AgBBRQEAAFBLBQYAAAAAAQABAGgAAAB4AgAAAAA="
)
ZIPCRYPTO_7Z_ZIP = base64.b64decode(
    "UEsDBBQAAQAIAFcARF2LUB3YNgAAADACAAALAAAAZmFjdHVyYS50eHTs5slMuJxjz4XF10ftComQjRt4YV7LRWMSsATf+OlEwrpXuQRUYO6r"
    "kYZP7kDOjQ9on9VbDwFQSwECPwAUAAEACABXAERdi1Ad2DYAAAAwAgAACwAkAAAAAAAAACAAAAAAAAAAZmFjdHVyYS50eHQKACAAAAAAAAEA"
    "GAA+JzHUrFPdAQAAAAAAAAAAAAAAAAAAAABQSwUGAAAAAAEAAQBdAAAAXwAAAAAA"
)
AES_PLAINTEXT = b"factura de prueba centinela " * 20

# Generados con WinRAR (RAR5) a partir de textos de prueba.
RAR_STORED = base64.b64decode(
    "UmFyIRoHAQAzkrXlCgEFBgAFAQGAgAC1lNfRJwIDC6AABKAAIIXnApqAAAALZmFjdHVyYS50eHQKAwIA4YEaqVPdAWhvbGEgZmFjdHVyYSBk"
    "ZSBwcnVlYmEgY2VudGluZWxhHXdWUQMFBAA="
)
RAR_STORED_CONTENT = b"hola factura de prueba centinela"
RAR_COMPRESSED = base64.b64decode(
    "UmFyIRoHAQDz4YLrCwEFBwAGAQGAgIAAwWkAeCMCAwudAAS4FyCsuyobgAUAB2JpZy50eHQKAwIZgo8xqVPdAcSEGiQCT7Mor818RwQRyb/I"
    "XPsutQMqhf9tC7aoHXdWUQMFBAA="
)
RAR_ENCRYPTED = base64.b64decode(
    "UmFyIRoHAQAzkrXlCgEFBgAFAQGAgAAF0e5XWAIDPKAABKAAICJhgfSAAAALZmFjdHVyYS50eHQwAQADD5FBM6GL70d92WLl/vEuX7DaB8lZ"
    "pyNoI3IFpngL2h37/Qvxnfcbo6KRiY11CgMCAOGBGqlT3QEsGOJPn1D/IRi/0dU7cEF8REDrUi6XYgeRMlcxzCS5lh13VlEDBQQA"
)


# --------------------------------------------------------------------------- otros contenedores


def seven_zip(
    entries: dict[str, bytes], password: str | None = None, header_encryption: bool = False
) -> bytes:
    import py7zr

    buf = io.BytesIO()
    with py7zr.SevenZipFile(buf, "w", password=password, header_encryption=header_encryption) as z:
        for name, data in entries.items():
            z.writestr(data, name)
    return buf.getvalue()


def tar_bytes(entries: dict[str, bytes], symlinks: dict[str, str] | None = None) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        for name, target in (symlinks or {}).items():
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            tf.addfile(info)
    return buf.getvalue()


def iso_bytes(files: dict[str, bytes], *, joliet: bool = True, udf: bool = False) -> bytes:
    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, joliet=3 if joliet else None, udf="2.60" if udf else None)
    for i, (name, data) in enumerate(files.items()):
        kwargs = {}
        if joliet:
            kwargs["joliet_path"] = "/" + name
        if udf:
            kwargs["udf_path"] = "/" + name
        iso.add_fp(io.BytesIO(data), len(data), f"/FILE{i}.BIN;1", **kwargs)
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    return out.getvalue()


def onenote_bytes(payloads: list[bytes]) -> bytes:
    out = bytearray(ONENOTE_GUID + b"\x00" * (1024 - 16))
    for p in payloads:
        out += FDSO_HEADER + struct.pack("<Q", len(p)) + b"\x00" * 12 + p + b"\x00" * ((-len(p)) % 8)
        out += FDSO_FOOTER + b"\x00" * 64
    return bytes(out)


def _tnef_attr(level: int, attr_id: int, data: bytes) -> bytes:
    return (
        bytes([level]) + struct.pack("<II", attr_id, len(data)) + data + struct.pack("<H", sum(data) & 0xFFFF)
    )


def tnef_bytes(attachments: list[tuple[str, bytes, str | None]]) -> bytes:
    """winmail.dat mínimo: (título 8.3, datos, nombre largo opcional vía MAPI PR_ATTACH_LONG_FILENAME)."""
    out = b"\x78\x9f\x3e\x22" + struct.pack("<H", 1)
    out += _tnef_attr(1, 0x00089006, struct.pack("<I", 0x00010000))
    out += _tnef_attr(1, 0x00069007, struct.pack("<II", 1252, 0))
    for title, data, long_name in attachments:
        out += _tnef_attr(2, 0x00069002, struct.pack("<HIIH", 1, 0xFFFFFFFF, 0, 0) + b"\x00" * 4)
        out += _tnef_attr(2, 0x00018010, title.encode("cp1252") + b"\x00")
        out += _tnef_attr(2, 0x0006800F, data)
        if long_name:
            value = long_name.encode("utf-16-le") + b"\x00\x00"
            prop = struct.pack("<HH", 0x001F, 0x3707) + struct.pack("<II", 1, len(value)) + value
            prop += b"\x00" * ((-len(value)) % 4)
            out += _tnef_attr(2, 0x00069005, struct.pack("<I", 1) + prop)
    return out


def cab_bytes(files: list[tuple[str, bytes]], *, compress: bool = True, lzx: bool = False) -> bytes:
    """CAB de un folder (MSZIP o sin compresión). `lzx=True` solo marca el tipo (para probar el no soporte)."""
    stream = b"".join(d for _, d in files)
    blocks: list[tuple[bytes, int]] = []
    prev = b""
    chunks = [stream[i : i + 32768] for i in range(0, len(stream), 32768)] or [b""]
    for chunk in chunks:
        if compress:
            c = (
                zlib.compressobj(9, zlib.DEFLATED, -15, zdict=prev)
                if prev
                else zlib.compressobj(9, zlib.DEFLATED, -15)
            )
            comp = b"CK" + c.compress(chunk) + c.flush(zlib.Z_FINISH)
        else:
            comp = chunk
        blocks.append((comp, len(chunk)))
        prev = chunk
    file_entries = b""
    off = 0
    for name, data in files:
        file_entries += (
            struct.pack("<IIHHHH", len(data), off, 0, 0, 0, 0x20) + name.encode("cp1252") + b"\x00"
        )
        off += len(data)
    coff_files = 36 + 8
    data_start = coff_files + len(file_entries)
    ctype = 3 if lzx else (1 if compress else 0)
    folder = struct.pack("<IHH", data_start, len(blocks), ctype)
    cfdata = b"".join(struct.pack("<IHH", 0, len(comp), ulen) + comp for comp, ulen in blocks)
    total = data_start + len(cfdata)
    header = b"MSCF" + struct.pack("<IIIII", 0, total, 0, coff_files, 0) + bytes([3, 1])
    header += struct.pack("<HHHHH", 1, len(files), 0, 0, 0)
    return header + folder + file_entries + cfdata


def pdf_with_attachment(name: str, data: bytes) -> bytes:
    from pypdf import PdfWriter

    w = PdfWriter()
    w.add_blank_page(width=200, height=200)
    w.add_attachment(name, data)
    out = io.BytesIO()
    w.write(out)
    return out.getvalue()


def encrypted_pdf_with_attachment(name: str, data: bytes, user_password: str, owner_password: str) -> bytes:
    """PDF cifrado (RC4) con un adjunto. `user_password=""` = solo restringe permisos (abre sin clave)."""
    from pypdf import PdfWriter

    w = PdfWriter()
    w.add_blank_page(width=200, height=200)
    w.add_attachment(name, data)
    w.encrypt(user_password=user_password, owner_password=owner_password)
    out = io.BytesIO()
    w.write(out)
    return out.getvalue()


def plain_pdf() -> bytes:
    from pypdf import PdfWriter

    w = PdfWriter()
    w.add_blank_page(width=200, height=200)
    out = io.BytesIO()
    w.write(out)
    return out.getvalue()


# --------------------------------------------------------------------------- OLE2 / CFB (escritor mínimo)

_FREE, _END, _FATSECT = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD


def cfb_bytes(streams: dict[str, bytes], root_clsid: bytes = b"\x00" * 16) -> bytes:
    """Compound File Binary v3 mínimo (sectores de 512, mini stream para < 4096 bytes).

    `streams`: {"Storage/Sub/Stream": datos}. Los storages intermedios se crean solos. Los hermanos se
    encadenan por `right` (árbol degenerado; olefile lo acepta). Solo para tests."""
    nodes: dict[str, dict] = {"": {"name": "Root Entry", "type": 5, "children": [], "data": b""}}
    for path, data in streams.items():
        parts = path.split("/")
        for i in range(1, len(parts)):
            key = "/".join(parts[:i])
            if key not in nodes:
                nodes[key] = {"name": parts[i - 1], "type": 1, "children": [], "data": b""}
                nodes["/".join(parts[: i - 1])]["children"].append(key)
        nodes[path] = {"name": parts[-1], "type": 2, "children": [], "data": data}
        nodes["/".join(parts[:-1])]["children"].append(path)
    order = [""]
    for key in order:
        order.extend(nodes[key]["children"])
    ids = {k: i for i, k in enumerate(order)}

    big = [k for k in order if nodes[k]["type"] == 2 and len(nodes[k]["data"]) >= 4096]
    small = [k for k in order if nodes[k]["type"] == 2 and len(nodes[k]["data"]) < 4096]
    ministream = bytearray()
    minifat: list[int] = []
    for k in small:
        data = nodes[k]["data"]
        n = max(1, -(-len(data) // 64)) if data else 0
        nodes[k]["start"] = len(minifat) if n else _END
        for j in range(n):
            minifat.append(len(minifat) + 1 if j < n - 1 else _END)
        ministream += data + b"\x00" * (n * 64 - len(data))

    def nsect(nbytes: int) -> int:
        return -(-nbytes // 512)

    n_dir = nsect(len(order) * 128)
    n_minifat = nsect(len(minifat) * 4)
    n_mini = nsect(len(ministream))
    n_big = sum(nsect(len(nodes[k]["data"])) for k in big)
    n_other = n_dir + n_minifat + n_mini + n_big
    n_fat = 1
    while n_fat * 128 < n_other + n_fat:
        n_fat += 1
    fat = [_FREE] * (n_fat * 128)
    cursor = 0
    for i in range(n_fat):
        fat[cursor + i] = _FATSECT
    cursor += n_fat

    def chain(count: int) -> int:
        nonlocal cursor
        if count == 0:
            return _END
        start = cursor
        for j in range(count):
            fat[cursor + j] = cursor + j + 1 if j < count - 1 else _END
        cursor += count
        return start

    dir_start = chain(n_dir)
    minifat_start = chain(n_minifat)
    mini_start = chain(n_mini)
    for k in big:
        nodes[k]["start"] = chain(nsect(len(nodes[k]["data"])))

    entries = bytearray()
    for k in order:
        node = nodes[k]
        e = bytearray(128)
        name = node["name"].encode("utf-16-le")[:62] + b"\x00\x00"
        e[0 : len(name)] = name
        struct.pack_into("<HBB", e, 0x40, len(name), node["type"], 1)
        siblings = nodes[k.rsplit("/", 1)[0] if "/" in k else ""]["children"] if k else []
        right = _FREE
        if k and siblings.index(k) + 1 < len(siblings):
            right = ids[siblings[siblings.index(k) + 1]]
        child = ids[node["children"][0]] if node["children"] else _FREE
        struct.pack_into("<III", e, 0x44, _FREE, right, child)
        if node["type"] == 5:
            e[0x50:0x60] = root_clsid
            struct.pack_into("<II", e, 0x74, mini_start if ministream else _END, len(ministream))
        elif node["type"] == 2:
            struct.pack_into("<II", e, 0x74, node.get("start", _END), len(node["data"]))
        else:
            struct.pack_into("<II", e, 0x74, 0, 0)
        entries += e
    entries += b"\x00" * (n_dir * 512 - len(entries))

    header = bytearray(512)
    header[0:8] = bytes.fromhex("D0CF11E0A1B11AE1")
    struct.pack_into("<HHHHH", header, 0x18, 0x3E, 3, 0xFFFE, 9, 6)
    struct.pack_into(
        "<IIIIIIII",
        header,
        0x2C,
        n_fat,
        dir_start,
        0,
        4096,
        minifat_start if minifat else _END,
        n_minifat,
        _END,
        0,
    )
    difat = [i for i in range(n_fat)] + [_FREE] * (109 - n_fat)
    struct.pack_into("<109I", header, 0x4C, *difat)

    body = bytearray()
    body += struct.pack(f"<{len(fat)}I", *fat)
    body += entries
    mf = minifat + [_FREE] * (n_minifat * 128 - len(minifat))
    body += struct.pack(f"<{len(mf)}I", *mf) if mf else b""
    body += ministream + b"\x00" * (n_mini * 512 - len(ministream))
    for k in big:
        data = nodes[k]["data"]
        body += data + b"\x00" * (nsect(len(data)) * 512 - len(data))
    return bytes(header + body)


def ole10native(filename: str, data: bytes) -> bytes:
    """Stream \\x01Ole10Native de un objeto Package (como el que arma Word al "insertar objeto")."""
    body = struct.pack("<H", 2) + filename.encode() + b"\x00" + f"C:\\Users\\x\\{filename}".encode() + b"\x00"
    body += struct.pack("<II", 0x00030000, 0) + f"C:\\Temp\\{filename}".encode() + b"\x00"
    body += struct.pack("<I", len(data)) + data
    return struct.pack("<I", len(body)) + body


def msi_stream_name(name: str) -> str:
    """Codifica un nombre de stream como lo hace Windows Installer (inverso de la decodificación)."""
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._"
    out = []
    i = 0
    while i < len(name):
        a = alphabet.index(name[i])
        if i + 1 < len(name) and name[i + 1] in alphabet:
            b = alphabet.index(name[i + 1])
            out.append(chr(0x3800 + a + (b << 6)))
            i += 2
        else:
            out.append(chr(0x4800 + a))
            i += 1
    return "".join(out)


def outlook_msg(attachments: list[tuple[str, bytes]], body: str = "Hola") -> bytes:
    """.msg de Outlook mínimo con adjuntos (solo las propiedades que mira el parser)."""
    streams: dict[str, bytes] = {
        "__properties_version1.0": b"\x00" * 32,
        "__substg1.0_1000001F": body.encode("utf-16-le"),
    }
    for i, (name, data) in enumerate(attachments):
        prefix = f"__attach_version1.0_#{i:08X}/"
        streams[prefix + "__substg1.0_3707001F"] = name.encode("utf-16-le")
        streams[prefix + "__substg1.0_37010102"] = data
    return cfb_bytes(streams)
