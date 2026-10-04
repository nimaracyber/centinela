"""Alertas para SIEM (Wazuh, Graylog, ELK, ArcSight...): CEF sobre syslog RFC 5424, por UDP o TCP.

Formato de cada mensaje (uno por resultado):

    <PRI>1 2026-10-03T17:32:01.123Z <host> centinela <pid> <nivel> - CEF:0|Centinela|Centinela|<ver>|...

- PRI = facility 4 (security/authorization) * 8 + severidad syslog (malicioso=2 crit, sospechoso=4
  warning, error=3, limpio=6 info).
- El MSG va en UTF-8 sin BOM (MSG-ANY de RFC 5424): muchos parsers de CEF no toleran el BOM.
- UDP (RFC 5426): un datagrama por mensaje, acotado a `max_udp_bytes` (si no entra, los campos largos
  del CEF se achican; nunca se parte un mensaje).
- TCP (RFC 6587, non-transparent framing): cada mensaje termina en LF; el CEF escapa los saltos de
  línea, así que un mensaje nunca contiene LF interno. Conexión nueva por alerta (volumen bajo).
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from centinela.actions.alerts import AlertDeliveryError, describe_exception
from centinela.actions.alerts.base import AlertChannel
from centinela.actions.alerts.format import Alert, build_alert

if TYPE_CHECKING:
    import httpx

    from centinela.core.config import Settings, SyslogAlertConfig
    from centinela.core.models import AnalysisResult

log = logging.getLogger(__name__)

FACILITY_SECURITY = 4
_SYSLOG_SEVERITY = {"malicious": 2, "error": 3, "suspicious": 4, "clean": 6}
MAX_UDP_BYTES = 8192  # rsyslog acepta 8 KB por defecto; evita fragmentación grande
MAX_TCP_BYTES = 64 * 1024


def _header_field(value: str | None, max_len: int) -> str:
    """Campo del header RFC 5424: ASCII imprimible sin espacios (33..126), o "-"."""
    if not value:
        return "-"
    s = "".join(ch for ch in value if 33 <= ord(ch) <= 126)[:max_len]
    return s or "-"


def build_syslog_message(
    alert: Alert,
    *,
    hostname: str | None = None,
    pid: int | None = None,
    now: datetime | None = None,
    max_bytes: int = MAX_UDP_BYTES,
) -> bytes:
    """Mensaje RFC 5424 con el CEF como MSG, sin LF final (el framing lo agrega el transporte)."""
    now = now or datetime.now(UTC)
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    now = now.astimezone(UTC)
    pri = FACILITY_SECURITY * 8 + _SYSLOG_SEVERITY.get(alert.level, 5)
    ts = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
    host = _header_field(hostname if hostname is not None else socket.gethostname(), 255)
    procid = _header_field(str(pid if pid is not None else os.getpid()), 128)
    msgid = _header_field(alert.level, 32)
    header = f"<{pri}>1 {ts} {host} centinela {procid} {msgid} -"
    data = b""
    for scale in (1.0, 0.5, 0.25, 0.1):
        data = f"{header} {alert.to_cef(scale=scale)}".encode()
        if len(data) <= max_bytes:
            return data
    # último recurso: recorte crudo en límite de carácter UTF-8, sin dejar un escape "\" colgando
    text = data[:max_bytes].decode("utf-8", "ignore")
    stripped = text.rstrip("\\")
    if (len(text) - len(stripped)) % 2:
        text = text[:-1]
    return text.encode("utf-8")


class SyslogChannel(AlertChannel):
    type = "syslog"
    timeout_s = 10.0

    def __init__(self, config: SyslogAlertConfig, settings: Settings, http: httpx.AsyncClient) -> None:
        super().__init__(config, settings, http)
        if not config.host or any(ch.isspace() for ch in config.host):
            raise ValueError(f"canal {config.name!r}: host de syslog inválido")
        if not 0 < int(config.port) < 65536:
            raise ValueError(f"canal {config.name!r}: puerto de syslog inválido")

    def build_message(self, result: AnalysisResult) -> bytes:
        limit = MAX_UDP_BYTES if self.config.protocol == "udp" else MAX_TCP_BYTES
        return build_syslog_message(build_alert(result, self.settings), max_bytes=limit)

    async def send(self, result: AnalysisResult) -> None:
        data = self.build_message(result)
        where = f"{self.config.host}:{self.config.port}/{self.config.protocol}"
        try:
            if self.config.protocol == "udp":
                await self._send_udp(data)
            else:
                await self._send_tcp(data + b"\n")
        except TimeoutError:
            raise AlertDeliveryError(f"syslog {where}: tiempo de espera agotado", channel=self.name) from None
        except OSError as exc:
            raise AlertDeliveryError(
                f"syslog {where}: {describe_exception(exc)}", channel=self.name
            ) from None

    async def _send_udp(self, data: bytes) -> None:
        """Un datagrama por mensaje, con un socket propio que se cierra siempre (sin depender del
        `connection_lost` de los transports de datagramas, que en Windows/Proactor no llega si se cierra
        con un envío en curso)."""
        loop = asyncio.get_running_loop()
        infos = await asyncio.wait_for(
            loop.getaddrinfo(self.config.host, int(self.config.port), type=socket.SOCK_DGRAM),
            timeout=self.timeout_s,
        )
        if not infos:
            raise OSError(f"no se pudo resolver {self.config.host}")
        family, sock_type, proto, _canon, addr = infos[0]
        with socket.socket(family, sock_type, proto) as sock:
            sock.setblocking(False)
            await asyncio.wait_for(loop.sock_sendto(sock, data, addr), timeout=self.timeout_s)

    async def _send_tcp(self, data: bytes) -> None:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(self.config.host, int(self.config.port)), timeout=self.timeout_s
        )
        try:
            writer.write(data)
            await asyncio.wait_for(writer.drain(), timeout=self.timeout_s)
        finally:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=self.timeout_s)
            except (TimeoutError, OSError):
                pass
