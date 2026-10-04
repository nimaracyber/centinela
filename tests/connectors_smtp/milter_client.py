"""Cliente milter mínimo para tests: se comporta como un MTA (Postfix) que respeta lo negociado."""

from __future__ import annotations

import asyncio
import struct

from centinela.connectors import milter as m

ALL_ACTIONS = 0x1FF  # SMFI_CURR_ACTS
ALL_PROTOCOL = 0x1FFFFF  # SMFI_CURR_PROT: todo lo que Postfix 3.x ofrece
V2_ACTIONS = 0x3F
V2_PROTOCOL = 0x7F


class MilterClient:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader = reader
        self.writer = writer
        self.version = 0
        self.actions = 0
        self.pflags = 0

    @classmethod
    async def connect(cls, port: int) -> MilterClient:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        return cls(reader, writer)

    async def send(self, cmd: bytes, data: bytes = b"") -> None:
        self.writer.write(struct.pack("!I", len(data) + 1) + cmd + data)
        await self.writer.drain()

    async def send_raw(self, data: bytes) -> None:
        self.writer.write(data)
        await self.writer.drain()

    async def recv(self, wait_s: float = 5.0) -> tuple[bytes, bytes]:
        head = await asyncio.wait_for(self.reader.readexactly(4), wait_s)
        (n,) = struct.unpack("!I", head)
        payload = await asyncio.wait_for(self.reader.readexactly(n), wait_s)
        return payload[:1], payload[1:]

    async def closed_by_server(self, wait_s: float = 5.0) -> bool:
        """True si el servidor cerró la conexión (EOF / reset) sin mandar nada más.
        False si mandó datos o si no cerró dentro de `wait_s`."""
        try:
            data = await asyncio.wait_for(self.reader.read(1), wait_s)
        except TimeoutError:  # ojo: TimeoutError es subclase de OSError
            return False
        except (ConnectionError, OSError):
            return True
        return data == b""

    async def wait_eof(self, wait_s: float = 5.0) -> None:
        """Lee (y descarta) hasta que el servidor cierre. Lanza TimeoutError si no cierra."""

        async def _drain() -> None:
            try:
                while await self.reader.read(65536):
                    pass
            except ConnectionError:
                pass

        await asyncio.wait_for(_drain(), wait_s)

    async def negotiate(
        self, version: int = 6, actions: int = ALL_ACTIONS, pflags: int = ALL_PROTOCOL
    ) -> tuple[int, int, int]:
        await self.send(m.SMFIC_OPTNEG, struct.pack("!III", version, actions, pflags))
        cmd, data = await self.recv()
        assert cmd == m.SMFIC_OPTNEG
        self.version, self.actions, self.pflags = struct.unpack("!III", data[:12])
        # un MTA real verifica que el milter pida un subconjunto de lo ofrecido
        assert self.actions & ~actions == 0
        assert self.pflags & ~pflags == 0
        return self.version, self.actions, self.pflags

    async def command(self, cmd: bytes, data: bytes, *, skip_flag: int = 0, nr_flag: int = 0) -> None:
        """Manda un comando como lo haría el MTA: lo omite si el milter pidió no recibirlo y espera
        SMFIR_CONTINUE salvo que el milter haya pedido no responder."""
        if skip_flag and self.pflags & skip_flag:
            return
        await self.send(cmd, data)
        if nr_flag and self.pflags & nr_flag:
            return
        reply = await self.recv()
        assert reply == (m.SMFIR_CONTINUE, b""), reply

    async def macro(self, stage: bytes, **macros: str) -> None:
        payload = stage + b"".join(k.encode() + b"\0" + v.encode() + b"\0" for k, v in macros.items())
        await self.send(m.SMFIC_MACRO, payload)

    async def message(
        self,
        *,
        rcpts: list[str],
        headers: list[tuple[str, str]] | list[tuple[bytes, bytes]],
        body_chunks: list[bytes],
        queue_id: str | None = None,
        eob: bool = True,
    ) -> list[tuple[bytes, bytes]]:
        await self.macro(b"M", mail_addr="juan@proveedor.com")
        await self.command(
            m.SMFIC_MAIL, b"<juan@proveedor.com>\0", skip_flag=m.SMFIP_NOMAIL, nr_flag=m.SMFIP_NR_MAIL
        )
        for rcpt in rcpts:
            await self.macro(b"R", **{"{rcpt_addr}": rcpt})
            await self.command(
                m.SMFIC_RCPT, f"<{rcpt}>\0".encode(), skip_flag=m.SMFIP_NORCPT, nr_flag=m.SMFIP_NR_RCPT
            )
        await self.command(m.SMFIC_DATA, b"", skip_flag=m.SMFIP_NODATA, nr_flag=m.SMFIP_NR_DATA)
        for name, value in headers:
            nb = name if isinstance(name, bytes) else name.encode()
            vb = value if isinstance(value, bytes) else value.encode()
            await self.command(
                m.SMFIC_HEADER, nb + b"\0" + vb + b"\0", skip_flag=m.SMFIP_NOHDRS, nr_flag=m.SMFIP_NR_HDR
            )
        await self.command(m.SMFIC_EOH, b"", skip_flag=m.SMFIP_NOEOH, nr_flag=m.SMFIP_NR_EOH)
        for chunk in body_chunks:
            await self.command(m.SMFIC_BODY, chunk, skip_flag=m.SMFIP_NOBODY, nr_flag=m.SMFIP_NR_BODY)
        if not eob:
            return []
        if queue_id:
            await self.macro(b"E", i=queue_id)
        return await self.eob()

    async def eob(self, wait_s: float = 10.0) -> list[tuple[bytes, bytes]]:
        await self.send(m.SMFIC_BODYEOB)
        replies: list[tuple[bytes, bytes]] = []
        while True:
            cmd, data = await self.recv(wait_s)
            replies.append((cmd, data))
            if cmd in (m.SMFIR_ACCEPT, m.SMFIR_CONTINUE) or len(replies) > 50:
                return replies

    async def quit(self) -> None:
        await self.send(m.SMFIC_QUIT)
        self.writer.close()

    def close(self) -> None:
        self.writer.close()


def decode_reply(cmd: bytes, data: bytes) -> tuple:
    """Respuesta -> tupla legible: ("chg", índice, nombre, valor) / ("add", nombre, valor) / ("a",)."""
    if cmd == m.SMFIR_CHGHEADER:
        (index,) = struct.unpack("!I", data[:4])
        name, value, *_ = data[4:].split(b"\0")
        return ("chg", index, name.decode(), value.decode())
    if cmd == m.SMFIR_ADDHEADER:
        name, value, *_ = data.split(b"\0")
        return ("add", name.decode(), value.decode())
    return (cmd.decode(),)
