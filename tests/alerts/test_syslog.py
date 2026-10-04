"""SyslogChannel contra listeners UDP/TCP locales (127.0.0.1, puertos efímeros)."""

from __future__ import annotations

import asyncio
import re
import socket
from datetime import UTC, datetime

import pytest

from centinela.actions.alerts import AlertDeliveryError
from centinela.actions.alerts.format import build_alert
from centinela.actions.alerts.syslog import MAX_UDP_BYTES, SyslogChannel, build_syslog_message
from centinela.core.config import SyslogAlertConfig
from centinela.core.models import Finding, FindingCategory, Severity
from tests.alerts.conftest import BODY_SECRET, SHA_EXE, bec_result, make_result, stealer_result
from tests.alerts.test_format import hostile_result

HEADER_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>1 (?P<ts>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z) (?P<host>\S+) centinela "
    r"(?P<pid>\S+) (?P<msgid>\S+) - (?P<cef>CEF:0\|.*)$",
    re.S,
)


def make_channel(settings, http, port: int, protocol: str = "udp") -> SyslogChannel:
    cfg = SyslogAlertConfig(type="syslog", name="siem", host="127.0.0.1", port=port, protocol=protocol)
    return SyslogChannel(cfg, settings, http)


class UdpCollector(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.queue: asyncio.Queue[bytes] = asyncio.Queue()

    def datagram_received(self, data, addr):
        self.queue.put_nowait(data)


async def udp_listener():
    loop = asyncio.get_running_loop()
    transport, proto = await loop.create_datagram_endpoint(UdpCollector, local_addr=("127.0.0.1", 0))
    return transport, proto, transport.get_extra_info("sockname")[1]


def extension_fields(cef: str) -> dict[str, str]:
    """Parser mínimo de extensiones CEF (respeta \\= y \\\\)."""
    ext = cef.split("|", 7)[7]
    out: dict[str, str] = {}
    for m in re.finditer(r"(\w+)=((?:\\.|[^\\])*?)(?= \w+=|$)", ext):
        out[m.group(1)] = m.group(2)
    return out


async def test_udp_rfc5424_with_cef(alert_settings, http):
    transport, proto, port = await udp_listener()
    try:
        await make_channel(alert_settings, http, port).send(stealer_result())
        data = await asyncio.wait_for(proto.queue.get(), 5)
    finally:
        transport.close()
    text = data.decode("utf-8")
    assert not text.startswith("\ufeff")  # sin BOM
    assert "\n" not in text
    m = HEADER_RE.match(text)
    assert m, text[:200]
    assert m["pri"] == str(4 * 8 + 2)  # security/auth + crit
    assert m["msgid"] == "malicious"
    cef = m["cef"]
    assert cef.startswith("CEF:0|Centinela|Centinela|")
    assert cef.split("|")[4] == "yara.AgentTesla"
    assert cef.split("|")[6] == "10"
    fields = extension_fields(cef)
    assert fields["fileHash"] == SHA_EXE
    assert fields["suser"] == "cobranzas@pagos-afip.com"
    assert fields["cs6"] == "ventas@empresa.com"
    assert BODY_SECRET not in text


async def test_suspicious_priority(alert_settings, http):
    transport, proto, port = await udp_listener()
    try:
        await make_channel(alert_settings, http, port).send(bec_result())
        data = await asyncio.wait_for(proto.queue.get(), 5)
    finally:
        transport.close()
    m = HEADER_RE.match(data.decode())
    assert m["pri"] == str(4 * 8 + 4) and m["msgid"] == "suspicious"


async def test_tcp_newline_framing_and_escaping(alert_settings, http):
    received: asyncio.Queue[bytes] = asyncio.Queue()

    async def handle(reader, writer):
        received.put_nowait(await reader.read())  # hasta que el cliente cierre
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    hostile_finding = Finding(
        analyzer="x",
        rule="regla|con=raros\\chars",
        title="t",
        category=FindingCategory.MALWARE,
        severity=Severity.CRITICAL,
        score=99,
    )
    try:
        r = make_result(subject="a=b\\c|d\nBcc: x", findings=[hostile_finding])
        await make_channel(alert_settings, http, port, "tcp").send(r)
        data = await asyncio.wait_for(received.get(), 5)
    finally:
        server.close()
        await server.wait_closed()
    assert data.endswith(b"\n") and data.count(b"\n") == 1  # un mensaje, LF de framing
    text = data[:-1].decode("utf-8")
    m = HEADER_RE.match(text)
    assert m
    cef = m["cef"]
    assert cef.split("|")[0:4] == ["CEF:0", "Centinela", "Centinela", cef.split("|")[3]]
    assert "|regla\\|con=raros\\\\chars|" in cef  # signature id del header: pipe y barra escapados
    assert "cs1=a\\=b\\\\c|d Bcc: x" in cef  # extensión: = y barra escapados; el pipe no
    assert "cs5=regla|con\\=raros\\\\chars" in cef


async def test_udp_size_is_bounded_for_hostile_input(alert_settings, http):
    transport, proto, port = await udp_listener()
    try:
        await make_channel(alert_settings, http, port).send(hostile_result())
        data = await asyncio.wait_for(proto.queue.get(), 5)
    finally:
        transport.close()
    assert len(data) <= MAX_UDP_BYTES
    assert HEADER_RE.match(data.decode("utf-8"))


def test_build_message_deterministic_and_hard_limit(alert_settings):
    alert = build_alert(stealer_result(), alert_settings)
    now = datetime(2026, 10, 3, 17, 32, 1, 123456, tzinfo=UTC)
    msg = build_syslog_message(alert, hostname="srv mail\u00f1", pid=42, now=now).decode()
    assert msg.startswith("<34>1 2026-10-03T17:32:01.123Z srvmail centinela 42 malicious - CEF:0|")
    tiny = build_syslog_message(alert, hostname="h", pid=1, now=now, max_bytes=300)
    assert len(tiny) <= 300
    tiny.decode("utf-8")  # sigue siendo UTF-8 válido
    assert not re.search(rb"(?<!\\)(\\\\)*\\$", tiny)  # sin escape colgando al final


async def test_tcp_connection_refused(alert_settings, http):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    with pytest.raises(AlertDeliveryError) as ei:
        await make_channel(alert_settings, http, port, "tcp").send(stealer_result())
    assert "syslog 127.0.0.1" in str(ei.value)


@pytest.mark.parametrize("host", ["", "dos hosts", " "])
def test_invalid_host_rejected(settings, http, host):
    cfg = SyslogAlertConfig(type="syslog", name="siem", host=host, port=514)
    with pytest.raises(ValueError):
        SyslogChannel(cfg, settings, http)
