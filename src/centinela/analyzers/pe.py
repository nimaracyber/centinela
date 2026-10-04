"""Analizador de ejecutables de Windows (PE: .exe, .dll, .scr, .cpl...).

Un ejecutable adjunto ya es sospechoso por sí mismo (MEDIUM 40; HIGH 60 si venía escondido dentro de
un ZIP/ISO). Además se extraen, con pefile (en un thread y con topes), los rasgos que delatan las
familias que más golpean a las PyMEs:

- stealers (RedLine, Lumma, Vidar, AgentTesla...): descifrado DPAPI/AES + rutas de almacenes de
  contraseñas de navegadores, billeteras cripto, Telegram, Discord, FileZilla => HIGH 75 (MALWARE);
- canales de exfiltración (bot de Telegram, webhooks de Discord, SMTP/FTP con credenciales, dead-drops);
- keylogger (SetWindowsHookEx + GetAsyncKeyState + GetForegroundWindow), inyección de procesos y
  process hollowing;
- rasgos de RAT .NET (AsyncRAT/DcRat/XWorm/Quasar...): Pastebin + Socket + Plugin + anti-análisis
  (consulta WMI a AntiVirusProduct, SbieDll.dll);
- ransomware (borrado de shadow copies, notas de rescate + APIs de cifrado y recorrido de archivos);
- empaquetadores/protectores (UPX, Themida, VMProtect, Enigma...), entropía alta, tabla de imports mínima;
- .NET: cabecera CLR (directorio 14) + heaps #Strings/#US del metadata (parseo propio, acotado);
- overlay, PE embebido en recursos/overlay, timestamp en el futuro, firma digital (presencia y firmante,
  sin validar la cadena) y suplantación de fabricante en la info de versión.

Nunca se ejecuta nada ni se escribe el archivo a disco (pefile trabaja sobre bytes en memoria).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import struct
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, ClassVar

from centinela.analyzers import _indicators as ind
from centinela.analyzers.base import ArtifactAnalyzer
from centinela.core.models import Finding, FindingCategory, Severity

if TYPE_CHECKING:
    from centinela.analyzers.base import AnalysisContext
    from centinela.core.models import Artifact

log = logging.getLogger(__name__)

try:  # dependencia declarada, pero el analizador se apaga solo si falta
    import pefile
except ImportError:  # pragma: no cover - entorno sin pefile
    pefile = None  # type: ignore[assignment]

MAX_PE_BYTES = 64 * 1024 * 1024
MAX_STRINGS_SCAN_BYTES = 32 * 1024 * 1024
MAX_STRING_CHARS_TOTAL = 8 * 1024 * 1024
MAX_STRINGS = 200_000
MAX_STRING_LEN = 1024
MAX_IMPORTS = 10_000
MAX_SECTIONS = 96
MAX_RESOURCES = 4096
MAX_ENTROPY_BYTES = 8 * 1024 * 1024
# presupuesto TOTAL de bytes para entropía (secciones + recursos + overlay): un PE hostil puede declarar
# decenas de secciones o miles de recursos apuntando a la misma región grande (~50 ms por MB cada pasada)
MAX_ENTROPY_TOTAL = 48 * 1024 * 1024
ENTROPY_SAMPLE_BYTES = 4096  # muestra que se usa una vez agotado el presupuesto
MAX_METADATA_BYTES = 32 * 1024 * 1024
MAX_DOTNET_STRINGS = 100_000
MAX_US_ENTRIES = 4 * MAX_DOTNET_STRINGS  # entradas del heap #US recorridas (incluye las vacías)
MAX_CERT_BYTES = 1024 * 1024
CMD_SCAN_CHARS = 2 * 1024 * 1024

IMAGE_SCN_CNT_CODE = 0x20
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_FILE_DLL = 0x2000
DIR_IMPORT, DIR_RESOURCE, DIR_SECURITY, DIR_DELAY_IMPORT, DIR_CLR = 1, 2, 4, 13, 14
RT_NAMES = {
    1: "RT_CURSOR",
    2: "RT_BITMAP",
    3: "RT_ICON",
    10: "RT_RCDATA",
    14: "RT_GROUP_ICON",
    16: "RT_VERSION",
    24: "RT_MANIFEST",
}
IMAGE_RES_TYPES = frozenset({1, 2, 3, 12, 14})

_ASCII_RE = re.compile(rb"[\x20-\x7e]{5,}")
_UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")
_DOS_STUBS = (b"This program cannot be run in DOS mode", b"This program must be run under Win32")

# --------------------------------------------------------------------------- catálogos de indicadores

PACKER_SECTIONS: dict[str, str] = {
    "upx0": "UPX",
    "upx1": "UPX",
    "upx2": "UPX",
    "upx!": "UPX",
    ".themida": "Themida",
    ".winlice": "Themida/WinLicense",
    "themida": "Themida",
    ".vmp0": "VMProtect",
    ".vmp1": "VMProtect",
    ".vmp2": "VMProtect",
    ".enigma1": "Enigma Protector",
    ".enigma2": "Enigma Protector",
    ".mpress1": "MPRESS",
    ".mpress2": "MPRESS",
    ".aspack": "ASPack",
    ".adata": "ASPack",
    "pec2": "PECompact",
    "pecompact2": "PECompact",
    "pec1": "PECompact",
    ".nsp0": "NsPack",
    ".nsp1": "NsPack",
    ".nsp2": "NsPack",
    "nsp0": "NsPack",
    "nsp1": "NsPack",
    ".petite": "Petite",
    "mew": "MEW",
    ".kkrunchy": "kkrunchy",
    "kkrunchy": "kkrunchy",
    ".y0da": "yoda's Crypter",
    ".yp": "yoda's Protector",
    ".perplex": "Perplex",
    ".obsidium": "Obsidium",
}
PROTECTORS = frozenset(
    {
        "Themida",
        "Themida/WinLicense",
        "VMProtect",
        "Enigma Protector",
        "Obsidium",
        "yoda's Protector",
        "yoda's Crypter",
    }
)
DOTNET_OBFUSCATORS: dict[str, str] = {
    "confusedbyattribute": "ConfuserEx",
    "dotfuscatorattribute": "Dotfuscator",
    "smartassembly.attributes": "SmartAssembly",
    "poweredbyattribute": "SmartAssembly",
    "babelobfuscatorattribute": "Babel",
    "babelattribute": "Babel",
    "yanoattribute": "Yano",
    "cryptoobfuscator": "Crypto Obfuscator",
    "obfuscatedbygoliath": "Goliath",
    "eazfuscator": "Eazfuscator",
    "secureteam.attributes": "Agile.NET",
    "netguard": "NetGuard",
    "dnguard": "DNGuard",
}

CRYPT_APIS = frozenset({"cryptunprotectdata", "bcryptdecrypt", "protecteddata", "unprotect"})
CRED_STORES: dict[str, tuple[str, ...]] = {
    "navegadores": (
        "\\google\\chrome\\user data",
        "\\chrome\\user data",
        "\\microsoft\\edge\\user data",
        "\\bravesoftware\\brave-browser",
        "\\opera software\\opera",
        "\\yandex\\yandexbrowser",
        "\\vivaldi\\user data",
        "login data",
        "web data",
        "local state",
        "\\network\\cookies",
        "mozilla\\firefox\\profiles",
        "logins.json",
        "key4.db",
        "key3.db",
        "signons.sqlite",
        "cookies.sqlite",
        "formhistory.sqlite",
        "encrypted_key",
        "password_value",
        "encrypted_value",
        "username_value",
        "moz_cookies",
    ),
    "billeteras cripto": (
        "wallet.dat",
        "\\exodus\\exodus.wallet",
        "exodus.wallet",
        "\\electrum\\wallets",
        "\\ethereum\\keystore",
        "\\atomic\\local storage",
        "\\coinomi",
        "\\armory",
        "\\jaxx",
        "\\guarda",
        "\\zcash",
        "\\bitcoin\\wallets",
        "\\monero\\wallets",
        "metamask",
    ),
    "mensajería": (
        "telegram desktop\\tdata",
        "\\tdata\\",
        "discord\\local storage",
        "discordcanary",
        "discordptb",
        "\\.purple\\accounts.xml",
        "\\signal\\config.json",
    ),
    "FTP/VPN/correo": (
        "filezilla\\recentservers.xml",
        "filezilla\\sitemanager.xml",
        "\\winscp",
        "\\nordvpn",
        "\\openvpn connect\\profiles",
        "\\protonvpn",
        "\\foxmail",
        "\\thunderbird\\profiles",
        "\\outlook\\profiles",
        "\\steam\\config\\loginusers.vdf",
    ),
}
# IDs de extensiones de billeteras cripto de Chrome que buscan los stealers
WALLET_EXTENSION_IDS: dict[str, str] = {
    "nkbihfbeogaeaoehlefnkodbefgpgknn": "MetaMask",
    "bfnaelmomeimhlpmgjnjophhpkkoljpa": "Phantom",
    "hnfanknocfeofbddgcijnmhnfnkdnaad": "Coinbase Wallet",
    "fhbohimaelbohpjbbldcngcnapndodjp": "Binance Wallet",
    "ibnejdfjmmkpcnlpebklmnkoeoihofec": "TronLink",
    "fnjhmkhhmkbjkkabndcnnogagogbneec": "Ronin",
    "egjidjbpglichdcondbcbdnbeeppgdph": "Trust Wallet",
    "bhghoamapcdpbohphigoooaddinpkbai": "Authenticator (2FA)",
    "dmkamcknogkgcdfhhbddcghachkejeap": "Keplr",
    "aeachknmefphepccionboohckonoeemg": "Coin98",
    "afbcbjpbpfadlkmhmclhkeeodmamcflc": "Math Wallet",
    "aholpfdialjgjfhomihkjbmgjidlcdno": "Exodus Web3",
    "acmacodkjbdgmoleebolmdjonilkdbch": "Rabby",
    "mcohilncbfahbmgdjkbpemcciiolgcge": "OKX Wallet",
    "ffnbelfdoeiohenkjibnmadjiehjhajb": "Yoroi",
    "lpfcbjknijpeeillifnkikgncikgfhdo": "Nami",
    "hpglfhgfnhbgpjdenjgmdgoeiappafln": "Guarda",
    "aiifbnbfobpmeekipheeijimdpnlpgpp": "Terra Station",
}
_SQL_STEALER_RE = re.compile(
    r"select\s+(?:origin_url|action_url|host_key|name)\s*,[^\n]{0,80}(?:password_value|encrypted_value)"
)

EXFIL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("bot de Telegram", re.compile(r"api\.telegram\.org/bot")),
    ("webhook de Discord", re.compile(r"discord(?:app)?\.com/api/webhooks")),
    (
        "dead-drop (Pastebin/Steam/Telegram/Rentry)",
        re.compile(
            r"pastebin\.com/raw|steamcommunity\.com/profiles/|(?<![\w.])t\.me/|rentry\.co/|paste\.ee/r/|telegra\.ph/"
        ),
    ),
    (
        "subida de archivos",
        re.compile(r"transfer\.sh|gofile\.io|anonfiles\.|(?<![\w.])file\.io|bashupload\.com"),
    ),
    (
        "geolocalización de la víctima",
        re.compile(
            r"ip-api\.com|api\.ipify\.org|checkip\.dyndns\.org|icanhazip\.com|ipinfo\.io|wtfismyip\.com|freegeoip|myexternalip\.com"
        ),
    ),
)

API_FAMILIES = {
    "hook": ("setwindowshookexa", "setwindowshookexw", "setwindowshookex"),
    "keystate": ("getasynckeystate", "getkeystate", "getkeyboardstate"),
    "foreground": ("getforegroundwindow",),
    "wintext": ("getwindowtexta", "getwindowtextw", "getwindowtext"),
    "alloc_remote": ("virtualallocex", "virtualalloc2", "ntallocatevirtualmemory", "zwallocatevirtualmemory"),
    "write_remote": ("writeprocessmemory", "ntwritevirtualmemory", "zwwritevirtualmemory"),
    "remote_thread": (
        "createremotethread",
        "createremotethreadex",
        "ntcreatethreadex",
        "zwcreatethreadex",
        "rtlcreateuserthread",
        "queueuserapc",
        "ntqueueapcthread",
        "zwqueueapcthread",
        "ntqueueapcthreadex",
    ),
    "unmap": ("ntunmapviewofsection", "zwunmapviewofsection"),
    "set_context": ("setthreadcontext", "wow64setthreadcontext", "ntsetcontextthread"),
    "encrypt": (
        "cryptencrypt",
        "bcryptencrypt",
        "cryptgenkey",
        "cryptimportkey",
        "bcryptgeneratesymmetrickey",
    ),
    "find_files": ("findfirstfilew", "findfirstfileexw", "findfirstfilea", "findnextfilew", "findnextfilea"),
}

# (categoría, modo, aguja): modo "id" = identificador/string exacto; "sub" = substring de las strings
RAT_TRAITS: tuple[tuple[str, str, str], ...] = (
    ("c2", "sub", "pastebin"),
    ("c2", "id", "keepaliveping"),
    ("c2", "id", "clientsocket"),
    ("c2", "id", "serversignature"),
    ("c2", "id", "server_signature"),
    ("c2", "id", "msgpack"),
    ("c2", "sub", "asyncclient"),
    ("c2", "sub", "pac_ket"),
    ("c2", "sub", "[endof]"),
    ("sockets", "id", "socket"),
    ("sockets", "id", "tcpclient"),
    ("sockets", "id", "sslstream"),
    ("plugins", "id", "plugin"),
    ("plugins", "id", "plugins"),
    ("plugins", "id", "saveplugin"),
    ("plugins", "id", "sendplugin"),
    ("plugins", "id", "loadplugin"),
    ("anti_analysis", "id", "anti_analysis"),
    ("anti_analysis", "id", "antianalysis"),
    ("anti_analysis", "id", "antivirus"),
    ("anti_analysis", "id", "detectsandboxie"),
    ("anti_analysis", "id", "detectdebugger"),
    ("anti_analysis", "id", "detectmanufacturer"),
    ("anti_analysis", "sub", "sbiedll.dll"),
    ("anti_analysis", "sub", "select * from antivirusproduct"),
    ("anti_analysis", "sub", "root\\securitycenter2"),
    ("anti_analysis", "sub", "select * from win32_computersystem"),
    ("anti_analysis", "sub", "vboxservice"),
    ("anti_analysis", "sub", "wine_get_unix_file_name"),
    ("persistence", "sub", "\\software\\microsoft\\windows\\currentversion\\run"),
    ("persistence", "sub", "\\nur\\noisrevtnerruc\\swodniw\\tfosorcim\\erawtfos"),
    ("persistence", "sub", "/sc onlogon"),
    ("persistence", "sub", "\\start menu\\programs\\startup"),
    ("surveillance", "sub", "keylogger"),
    ("surveillance", "sub", "capcreatecapturewindow"),
    ("surveillance", "id", "copyfromscreen"),
    ("surveillance", "sub", "hvnc"),
    ("surveillance", "id", "remotedesktop"),
)
RAT_CATEGORY_LABELS = {
    "c2": "comunicación con el atacante",
    "sockets": "conexiones de red propias",
    "plugins": "sistema de plugins",
    "anti_analysis": "detección de antivirus/sandbox/máquinas virtuales",
    "persistence": "arranque automático con Windows",
    "surveillance": "espionaje (teclas, pantalla, cámara)",
}
FAMILY_HINTS: dict[str, str] = {
    "asyncrat": "AsyncRAT",
    "dcrat": "DcRat",
    "xworm": "XWorm",
    "quasar.client": "Quasar RAT",
    "quasar.common": "Quasar RAT",
    "njrat": "njRAT",
    "remcos": "Remcos",
    "breaking-security.net": "Remcos",
    "nanocore": "NanoCore",
    "venomrat": "VenomRAT",
    "venom rat": "VenomRAT",
    "warzone160": "Warzone RAT",
    "ave_maria": "Warzone RAT",
    "dc_mutex": "DarkComet",
    "agenttesla": "Agent Tesla",
    "redline": "RedLine",
    "lumma": "Lumma Stealer",
    "stealc": "StealC",
    "formbook": "FormBook",
}
RANSOM_SHADOW = (
    "vssadmin delete shadows",
    "vssadmin.exe delete shadows",
    "delete shadows /all",
    "shadowcopy delete",
    "win32_shadowcopy",
    "recoveryenabled no",
    "bootstatuspolicy ignoreallfailures",
    "wbadmin delete catalog",
    "wbadmin delete systemstatebackup",
)
RANSOM_NOTE = (
    "your files have been encrypted",
    "your files are encrypted",
    "all your files",
    "tus archivos han sido",
    "sus archivos han sido",
    "decrypt your files",
    "how to decrypt",
    "how_to_decrypt",
    "readme_for_decrypt",
    "restore your files",
    ".onion",
    "tor browser",
    "bitcoin",
)
VENDORS = (
    "microsoft",
    "adobe",
    "google",
    "mozilla",
    "oracle",
    "apple",
    "intel",
    "nvidia",
    "cisco",
    "zoom",
    "docusign",
    "dropbox",
    "autodesk",
    "vmware",
    "realtek",
    "dell",
    "lenovo",
    "avast",
    "eset",
    "kaspersky",
    "symantec",
    "mcafee",
    "sophos",
    "anydesk",
    "teamviewer",
    "logmein",
    "citrix",
)
_VENDOR_RE = re.compile(r"\b(" + "|".join(VENDORS) + r")\b", re.IGNORECASE)
# marcadores largos: uno de 3 bytes ("WiX") aparece por azar en ~1 de cada 5 overlays cifrados de 4 MB y
# bajaría la severidad del overlay. Los bootstrappers de WiX (Burn) tienen la sección ".wixburn".
INSTALLER_MARKERS = {
    b"Nullsoft": "NSIS",
    b"Inno Setup": "Inno Setup",
    b"InstallShield": "InstallShield",
    b".wixburn": "WiX Burn",
}
# AMSI/ETW IMPORTADAS = uso legítimo (motores de scripts, antivirus); el bypass las resuelve por nombre
AMSI_ETW_IMPORTS = frozenset(
    {"amsiscanbuffer", "amsiscanstring", "amsiopensession", "amsiinitialize", "etweventwrite"}
)
AMSI_BYPASS_MARKERS = ("amsiutils", "amsiinitfailed", "amsicontext")
EMBEDDED_CMD_STRONG = frozenset(
    {"amsi_bypass", "defender_tamper", "credential_theft", "powershell_encoded", "privilege_escalation"}
)
EMBEDDED_CMD_GROUPS = EMBEDDED_CMD_STRONG | {"lolbin", "powershell_stealth", "persistence"}


# --------------------------------------------------------------------------- hechos extraídos


@dataclass
class SectionInfo:
    name: str
    raw_size: int
    virtual_size: int
    entropy: float
    characteristics: int

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE))

    @property
    def writable(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_MEM_WRITE)


@dataclass
class PeFacts:
    parse_error: str | None = None
    machine: int = 0
    is_dll: bool = False
    is_64: bool = False
    subsystem: int = 0
    timestamp: int = 0
    entrypoint: int = 0
    ep_section: str | None = None
    ep_section_index: int = -1
    sections: list[SectionInfo] = field(default_factory=list)
    imports: dict[str, list[str]] = field(default_factory=dict)
    import_count: int = 0
    imphash: str | None = None
    api_names: set[str] = field(default_factory=set)  # imports (minúsculas)
    dotnet: bool = False
    dotnet_version: str | None = None
    dotnet_ids: set[str] = field(default_factory=set)  # #Strings en minúsculas
    dotnet_us: list[str] = field(default_factory=list)
    strings_lower: str = ""
    string_set: set[str] = field(default_factory=set)  # strings exactas cortas, en minúsculas
    strings_text: str = ""  # strings originales (para el motor de indicadores), acotado
    signed: bool = False
    signer: str | None = None
    signer_issuer: str | None = None
    self_signed: bool | None = None
    cert_offset: int = 0
    cert_size: int = 0
    version_info: dict[str, str] = field(default_factory=dict)
    overlay_offset: int | None = None
    overlay_size: int = 0
    overlay_kind: str | None = None
    overlay_entropy: float | None = None
    installer: str | None = None
    embedded: list[str] = field(default_factory=list)
    encrypted_resources: list[str] = field(default_factory=list)
    upx_magic: bool = False

    def has_api(self, *names: str) -> bool:
        return any(n in self.api_names or n in self.dotnet_ids or n in self.string_set for n in names)

    def family(self, key: str) -> list[str]:
        return [
            n
            for n in API_FAMILIES[key]
            if n in self.api_names or n in self.dotnet_ids or n in self.string_set
        ]


class _Entropy:
    """Entropía de regiones de `data` con caché por (offset, tamaño) y presupuesto total acotado."""

    def __init__(self, data: bytes, budget: int = MAX_ENTROPY_TOTAL) -> None:
        self.data = data
        self.budget = budget
        self.cache: dict[tuple[int, int], float] = {}

    def __call__(self, off: int, size: int) -> float:
        off = max(off, 0)
        size = max(0, min(size, len(self.data) - off))
        key = (off, size)
        cached = self.cache.get(key)
        if cached is not None:
            return cached
        n = size if size <= self.budget else min(size, ENTROPY_SAMPLE_BYTES)
        self.budget = max(0, self.budget - n)
        value = ind.shannon_entropy(self.data[off : off + n]) if n else 0.0
        self.cache[key] = value
        return value


def _u16(b: bytes, off: int) -> int:
    return struct.unpack_from("<H", b, off)[0]


def _u32(b: bytes, off: int) -> int:
    return struct.unpack_from("<I", b, off)[0]


def _compressed_uint(buf: bytes, pos: int) -> tuple[int, int] | None:
    """Entero comprimido de ECMA-335 II.23.2: (valor, bytes usados)."""
    if pos >= len(buf):
        return None
    b0 = buf[pos]
    if b0 & 0x80 == 0:
        return b0, 1
    if b0 & 0xC0 == 0x80 and pos + 1 < len(buf):
        return ((b0 & 0x3F) << 8) | buf[pos + 1], 2
    if b0 & 0xE0 == 0xC0 and pos + 3 < len(buf):
        return ((b0 & 0x1F) << 24) | (buf[pos + 1] << 16) | (buf[pos + 2] << 8) | buf[pos + 3], 4
    return None


def _parse_dotnet(pe, data: bytes, facts: PeFacts) -> None:
    """Cabecera CLR + streams #Strings/#US del metadata (parseo propio, todo acotado)."""
    d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[DIR_CLR]
    off = pe.get_offset_from_rva(d.VirtualAddress)
    if off is None or off + 24 > len(data):
        return
    md_rva, md_size = struct.unpack_from("<II", data, off + 8)
    md_off = pe.get_offset_from_rva(md_rva)
    if md_off is None or md_off >= len(data):
        return
    md = data[md_off : md_off + min(md_size, MAX_METADATA_BYTES)]
    if len(md) < 20 or md[:4] != b"BSJB":
        return
    ver_len = _u32(md, 12)
    if ver_len > 256:
        return
    facts.dotnet_version = md[16 : 16 + ver_len].split(b"\x00", 1)[0].decode("ascii", "replace") or None
    p = 16 + ((ver_len + 3) & ~3)
    if p + 4 > len(md):
        return
    n_streams = min(_u16(md, p + 2), 16)
    p += 4
    streams: dict[str, bytes] = {}
    for _ in range(n_streams):
        if p + 8 > len(md):
            break
        s_off, s_size = struct.unpack_from("<II", md, p)
        name_end = md.find(b"\x00", p + 8, p + 8 + 32)
        if name_end < 0:
            break
        name = md[p + 8 : name_end].decode("ascii", "replace")
        p = p + 8 + ((name_end - (p + 8) + 1 + 3) & ~3)
        if s_off < len(md):
            streams[name] = md[s_off : s_off + min(s_size, MAX_METADATA_BYTES)]
    heap = streams.get("#Strings", b"")
    for raw in heap.split(b"\x00")[:MAX_DOTNET_STRINGS]:
        if len(raw) >= 2:
            facts.dotnet_ids.add(raw[:MAX_STRING_LEN].decode("utf-8", "replace").lower())
    us = streams.get("#US", b"")
    pos = 1
    entries = 0
    # tope de entradas recorridas: un heap de 32 MB de entradas de 1 byte serían 16M vueltas de Python
    while pos < len(us) and len(facts.dotnet_us) < MAX_DOTNET_STRINGS and entries < MAX_US_ENTRIES:
        entries += 1
        cu = _compressed_uint(us, pos)
        if cu is None:
            break
        length, used = cu
        blob = us[pos + used : pos + used + length]
        pos += used + max(length, 1) if length else used
        if length > 1:
            facts.dotnet_us.append(blob[: length - 1][: MAX_STRING_LEN * 2].decode("utf-16-le", "replace"))


def _der_total_len(blob: bytes) -> int | None:
    if len(blob) < 2 or blob[0] != 0x30:
        return None
    b1 = blob[1]
    if b1 < 0x80:
        return 2 + b1
    n = b1 & 0x7F
    if n == 0 or n > 4 or len(blob) < 2 + n:
        return None
    return 2 + n + int.from_bytes(blob[2 : 2 + n], "big")


def _parse_signature(data: bytes, facts: PeFacts) -> None:
    off, size = facts.cert_offset, facts.cert_size
    if size < 8 or off + 8 > len(data):
        return
    length = _u32(data, off)
    cert_type = _u16(data, off + 6)
    if cert_type != 0x0002 or length < 8:
        return
    blob = data[off + 8 : off + min(length, size, MAX_CERT_BYTES)]
    total = _der_total_len(blob)
    if total:
        blob = blob[:total]
    try:
        from cryptography.hazmat.primitives.serialization import pkcs7
        from cryptography.x509.oid import NameOID

        certs = pkcs7.load_der_pkcs7_certificates(blob)
    except Exception as exc:  # noqa: BLE001 - firma rota/hostil: solo se registra
        log.debug("no se pudo leer la firma Authenticode: %s", type(exc).__name__)
        return
    if not certs:
        return
    issuers = {c.issuer.rfc4514_string() for c in certs}
    leaf = next((c for c in certs if c.subject.rfc4514_string() not in issuers), certs[0])

    def name_of(n) -> str:
        for oid in (NameOID.COMMON_NAME, NameOID.ORGANIZATION_NAME):
            attrs = n.get_attributes_for_oid(oid)
            if attrs:
                return str(attrs[0].value)[:200]
        return n.rfc4514_string()[:200]

    facts.signer = name_of(leaf.subject)
    facts.signer_issuer = name_of(leaf.issuer)
    facts.self_signed = leaf.subject == leaf.issuer


def _extract_strings(data: bytes, facts: PeFacts) -> None:
    region = data[:MAX_STRINGS_SCAN_BYTES]
    out: list[str] = []
    total = 0
    for rx, enc in ((_ASCII_RE, "ascii"), (_UTF16_RE, "utf-16-le")):
        for m in rx.finditer(region):
            s = m.group(0)[: MAX_STRING_LEN * (2 if enc == "utf-16-le" else 1)].decode(enc, "replace")
            out.append(s)
            total += len(s)
            if len(out) >= MAX_STRINGS or total >= MAX_STRING_CHARS_TOTAL:
                break
    out.extend(facts.dotnet_us[:MAX_DOTNET_STRINGS])
    text = "\n".join(out)
    facts.strings_text = text[:CMD_SCAN_CHARS]
    facts.strings_lower = text.lower()
    facts.string_set = {s.lower() for s in out if len(s) <= 128}


def _walk_resources(pe, data: bytes, facts: PeFacts, entropy: _Entropy) -> None:
    root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if root is None:
        return
    seen = 0
    for type_entry in getattr(root, "entries", [])[:256]:
        type_id = getattr(type_entry, "id", None)
        type_name = RT_NAMES.get(type_id) if type_id is not None else None
        if type_name is None:
            raw_name = getattr(type_entry, "name", None)
            type_name = str(raw_name)[:40] if raw_name is not None else f"tipo {type_id}"
        stack = [type_entry]
        while stack and seen < MAX_RESOURCES:
            node = stack.pop()
            sub = getattr(node, "directory", None)
            if sub is not None:
                stack.extend(getattr(sub, "entries", [])[:512])
                continue
            dstruct = getattr(getattr(node, "data", None), "struct", None)
            if dstruct is None:
                continue
            seen += 1
            off = None
            with contextlib.suppress(Exception):  # RVA fuera del archivo (PEFormatError)
                off = pe.get_offset_from_rva(dstruct.OffsetToData)
            size = dstruct.Size
            if off is None or off >= len(data) or size <= 0:
                continue
            chunk = data[off : off + min(size, 4096)]
            if ind.looks_like_pe(chunk) or (chunk[:2] == b"MZ" and b"PE\x00\x00" in chunk[:1024]):
                facts.embedded.append(f"recurso {type_name}")
            elif size >= 100 * 1024 and type_id not in IMAGE_RES_TYPES:
                head = data[off : off + 16]
                if (
                    ind.sniff_magic(head) is None
                    and head[:4] not in (b"\x89PNG", b"GIF8")
                    and head[:3] != b"\xff\xd8\xff"
                ):
                    ent = entropy(off, min(size, 1024 * 1024))
                    if ent >= 7.5:
                        facts.encrypted_resources.append(
                            f"{type_name} ({size // 1024} KB, entropía {ent:.2f})"
                        )


def _version_info(pe, facts: PeFacts) -> None:
    for finfo in getattr(pe, "FileInfo", None) or []:
        for entry in finfo or []:
            for st in getattr(entry, "StringTable", None) or []:
                for k, v in list(getattr(st, "entries", {}).items())[:64]:
                    key = k.decode("utf-8", "replace") if isinstance(k, bytes) else str(k)
                    val = v.decode("utf-8", "replace") if isinstance(v, bytes) else str(v)
                    if key and val and key not in facts.version_info:
                        facts.version_info[key[:64]] = ind.clean_snippet(val, 200)


def extract_facts(data: bytes) -> PeFacts:
    """Parsea el PE con pefile (fast_load + directorios puntuales) y junta los rasgos. Síncrono, acotado."""
    facts = PeFacts()
    data = data[:MAX_PE_BYTES]
    if pefile is None:
        facts.parse_error = "pefile no está instalado"
        return facts
    try:
        pe = pefile.PE(data=data, fast_load=True)
    except Exception as exc:  # noqa: BLE001 - PEFormatError u otros errores ante PE hostiles
        facts.parse_error = f"{type(exc).__name__}: {str(exc)[:200]}"
        _extract_strings(data, facts)
        return facts
    try:
        with contextlib.suppress(Exception):
            pe.parse_data_directories(directories=[DIR_IMPORT, DIR_RESOURCE, DIR_DELAY_IMPORT])
        fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
        facts.machine = fh.Machine
        facts.is_dll = bool(fh.Characteristics & IMAGE_FILE_DLL)
        facts.is_64 = oh.Magic == 0x20B
        facts.subsystem = oh.Subsystem
        facts.timestamp = fh.TimeDateStamp
        facts.entrypoint = oh.AddressOfEntryPoint
        entropy = _Entropy(data)

        for idx, s in enumerate(pe.sections[:MAX_SECTIONS]):
            name = s.Name.rstrip(b"\x00").decode("latin-1", "replace")
            facts.sections.append(
                SectionInfo(
                    name=name,
                    raw_size=s.SizeOfRawData,
                    virtual_size=s.Misc_VirtualSize,
                    entropy=entropy(s.PointerToRawData, min(s.SizeOfRawData, MAX_ENTROPY_BYTES)),
                    characteristics=s.Characteristics,
                )
            )
            if facts.entrypoint and s.VirtualAddress <= facts.entrypoint < s.VirtualAddress + max(
                s.Misc_VirtualSize, s.SizeOfRawData
            ):
                facts.ep_section = name
                facts.ep_section_index = idx
        facts.upx_magic = b"UPX!" in data[:0x1000]

        for attr in ("DIRECTORY_ENTRY_IMPORT", "DIRECTORY_ENTRY_DELAY_IMPORT"):
            for entry in getattr(pe, attr, None) or []:
                dll = (entry.dll or b"").decode("latin-1", "replace").lower()
                funcs = facts.imports.setdefault(dll, [])
                for imp in entry.imports or []:
                    if facts.import_count >= MAX_IMPORTS:
                        break
                    facts.import_count += 1
                    if imp.name:
                        fname = imp.name.decode("latin-1", "replace")
                        funcs.append(fname)
                        facts.api_names.add(fname.lower())
        if facts.import_count:
            with contextlib.suppress(Exception):
                facts.imphash = pe.get_imphash() or None

        clr = oh.DATA_DIRECTORY[DIR_CLR] if len(oh.DATA_DIRECTORY) > DIR_CLR else None
        if clr is not None and clr.VirtualAddress and clr.Size:
            facts.dotnet = True
            with contextlib.suppress(Exception):
                _parse_dotnet(pe, data, facts)

        sec = oh.DATA_DIRECTORY[DIR_SECURITY] if len(oh.DATA_DIRECTORY) > DIR_SECURITY else None
        if sec is not None and sec.VirtualAddress and sec.Size and sec.VirtualAddress + 8 <= len(data):
            facts.signed = True
            facts.cert_offset, facts.cert_size = sec.VirtualAddress, sec.Size
            # una firma hostil no puede cortar el resto del análisis (recursos, overlay, instalador)
            with contextlib.suppress(Exception):
                _parse_signature(data, facts)

        with contextlib.suppress(Exception):
            _version_info(pe, facts)
        with contextlib.suppress(Exception):
            _walk_resources(pe, data, facts, entropy)

        ov = None
        with contextlib.suppress(Exception):
            ov = pe.get_overlay_data_start_offset()
        if ov is not None and ov < len(data):
            start, end = ov, len(data)
            size = end - start
            if facts.signed and facts.cert_offset >= start:
                size -= min(facts.cert_size, end - facts.cert_offset)
                if facts.cert_offset == start:
                    start = facts.cert_offset + facts.cert_size
            facts.overlay_offset, facts.overlay_size = ov, max(size, 0)
            if facts.overlay_size > 0 and start < end:
                head = data[start : start + ind.ISO_PROBE_BYTES]
                facts.overlay_kind = ind.sniff_magic(head)
                facts.overlay_entropy = round(entropy(start, min(end - start, 1024 * 1024)), 2)
                if facts.overlay_kind == "pe":
                    facts.embedded.append("datos pegados al final (overlay)")
        for marker, inst in INSTALLER_MARKERS.items():
            if marker in data[: 4 * 1024 * 1024]:
                facts.installer = inst
                break
        stubs = sum(data.count(s) for s in _DOS_STUBS)
        if stubs > 1 and not any("recurso" in e or "overlay" in e for e in facts.embedded):
            facts.embedded.append(f"{stubs - 1} cabecera(s) de ejecutable extra dentro del archivo")
    except Exception as exc:  # noqa: BLE001 - nunca romper por un PE raro: lo que se juntó sirve
        log.debug("error parcial analizando PE: %s", type(exc).__name__)
        facts.parse_error = facts.parse_error or f"{type(exc).__name__}"
    # Nota: no se llama pe.close(): con data= no hay mmap que cerrar y close() fuerza un gc.collect() completo.
    _extract_strings(data, facts)
    return facts


# --------------------------------------------------------------------------- evaluación


def _matched(haystack: str, needles: tuple[str, ...]) -> list[str]:
    return [n for n in needles if n in haystack]


class PeAnalyzer(ArtifactAnalyzer):
    name: ClassVar[str] = "pe"

    @classmethod
    def available(cls) -> bool:
        return pefile is not None

    def accepts(self, artifact: Artifact) -> bool:
        return artifact.detected_type == "pe"

    async def analyze(self, ctx: AnalysisContext, artifact: Artifact) -> list[Finding]:
        return await asyncio.to_thread(self._analyze_sync, artifact)

    def _analyze_sync(self, artifact: Artifact) -> list[Finding]:
        data = artifact.data or b""
        if not data:
            return [
                self._baseline(
                    artifact, None, note="no se pudo leer el contenido (posiblemente excede los límites)"
                )
            ]
        facts = extract_facts(data)
        return self.evaluate(artifact, facts)

    # ------------------------------------------------------------------ reglas
    def _f(
        self,
        artifact: Artifact,
        rule: str,
        title: str,
        description: str,
        severity: Severity,
        score: int,
        evidence: dict,
        category: FindingCategory = FindingCategory.SUSPICIOUS_FILE,
    ) -> Finding:
        return Finding(
            analyzer=self.name,
            rule=rule,
            title=title,
            description=description,
            category=category,
            severity=severity,
            score=score,
            artifact_id=artifact.id,
            evidence=evidence,
        )

    def evaluate(self, artifact: Artifact, facts: PeFacts) -> list[Finding]:
        out: list[Finding] = [self._baseline(artifact, facts)]
        if facts.parse_error and not facts.sections:
            out.append(
                self._f(
                    artifact,
                    "pe.malformed",
                    "Ejecutable dañado o armado para confundir a los antivirus",
                    "El archivo dice ser un programa de Windows pero su estructura está rota o manipulada. Los "
                    "programas legítimos no vienen así; suele hacerse para esquivar el análisis.",
                    Severity.MEDIUM,
                    25,
                    {"error": facts.parse_error},
                    FindingCategory.POLICY,
                )
            )
        exfil = self._exfil(artifact, facts)
        stealer = self._stealer(artifact, facts, exfil_found=exfil is not None)
        out.extend(f for f in (stealer, exfil) if f)
        for rule in (
            self._keylogger,
            self._injection,
            self._rat,
            self._ransomware,
            self._packed,
            self._embedded,
            self._overlay,
            self._embedded_commands,
            self._version_impersonation,
        ):
            f = rule(artifact, facts)
            if f:
                out.append(f)
        if not any(f.rule == "pe.rat_traits" for f in out):
            anti = self._anti_analysis(artifact, facts)
            if anti:
                out.append(anti)
        if facts.timestamp and facts.timestamp > time.time() + 2 * 86400:
            when = datetime.fromtimestamp(min(facts.timestamp, 32503680000), UTC).date().isoformat()
            out.append(
                self._f(
                    artifact,
                    "pe.timestamp_future",
                    "Fecha de compilación en el futuro",
                    "La fecha interna de creación del programa está en el futuro. Puede ser una compilación "
                    "reproducible, pero también una fecha falsificada para confundir el análisis.",
                    Severity.LOW,
                    10,
                    {"fecha_declarada": when},
                )
            )
        if not facts.signed and not facts.parse_error:
            out.append(
                self._f(
                    artifact,
                    "pe.unsigned",
                    "Programa sin firma digital",
                    "El programa no tiene firma digital, así que no hay forma de saber quién lo fabricó. Los "
                    "programas de empresas conocidas casi siempre vienen firmados.",
                    Severity.INFO,
                    0,
                    {},
                )
            )
        elif facts.signed and facts.self_signed:
            out.append(
                self._f(
                    artifact,
                    "pe.self_signed",
                    "Firma digital no confiable (autofirmada)",
                    "El programa está firmado con un certificado que se emitió a sí mismo: cualquiera puede hacerlo, "
                    "no prueba quién lo fabricó.",
                    Severity.LOW,
                    10,
                    {"firmante": facts.signer},
                )
            )
        return out

    def _baseline(self, artifact: Artifact, facts: PeFacts | None, *, note: str | None = None) -> Finding:
        nested = artifact.depth > 0
        evidence: dict = {"archivo": ind.clean_snippet(artifact.filename or "", 120)}
        if facts is not None:
            kind = "DLL" if facts.is_dll else "programa (.exe)"
            evidence["tipo"] = f"{kind} {'64' if facts.is_64 else '32'} bits" + (
                " .NET" if facts.dotnet else ""
            )
            if facts.dotnet_version:
                evidence["runtime_dotnet"] = facts.dotnet_version
            if facts.timestamp:
                evidence["compilado"] = (
                    datetime.fromtimestamp(min(facts.timestamp, 32503680000), UTC).date().isoformat()
                )
            if facts.sections:
                evidence["secciones"] = ind.cap_list(
                    (ind.clean_snippet(x.name, 16) or "(sin nombre)" for x in facts.sections), 10
                )
            evidence["firma"] = (
                (f"firmado por {facts.signer} (no verificado)" if facts.signer else "firmado (no verificado)")
                if facts.signed
                else "sin firma"
            )
            vi = {
                k: v
                for k, v in facts.version_info.items()
                if k in ("CompanyName", "ProductName", "FileDescription", "OriginalFilename")
            }
            if vi:
                evidence["info_version"] = vi
            if facts.imphash:
                evidence["imphash"] = facts.imphash
            if facts.installer:
                evidence["instalador"] = facts.installer
        if nested:
            evidence["dentro_de"] = artifact.parent_id
        if note:
            evidence["nota"] = note
        if nested:
            title = "Programa de Windows escondido dentro de un archivo comprimido"
            desc = (
                "Dentro del adjunto (un ZIP, RAR, ISO o similar) hay un programa ejecutable de Windows. Meter el "
                "programa en un comprimido o imagen de disco es el truco más común para que el filtro del correo "
                "no lo detecte. No lo abras."
            )
            sev, score = Severity.HIGH, 60
        else:
            title = "Programa ejecutable de Windows adjunto"
            desc = (
                "El adjunto es un programa de Windows (no un documento). Al abrirlo se ejecuta con tus permisos. "
                "Salvo que estés esperando exactamente este programa de alguien de confianza, no lo abras."
            )
            sev, score = Severity.MEDIUM, 40
        return self._f(artifact, "pe.executable_attachment", title, desc, sev, score, evidence)

    def _stealer(self, artifact: Artifact, facts: PeFacts, *, exfil_found: bool) -> Finding | None:
        s = facts.strings_lower
        if not s:
            return None
        crypto = sorted(
            n for n in CRYPT_APIS if n in facts.api_names or n in facts.dotnet_ids or n in facts.string_set
        )
        if "unprotect" in crypto and "protecteddata" not in crypto:
            crypto.remove("unprotect")  # "Unprotect" suelto es demasiado genérico
        stores = {cat: _matched(s, needles) for cat, needles in CRED_STORES.items()}
        stores = {cat: m for cat, m in stores.items() if m}
        wallets = [name for wid, name in WALLET_EXTENSION_IDS.items() if wid in s]
        sql = bool(_SQL_STEALER_RE.search(s))
        total = sum(len(m) for m in stores.values())
        hit = (
            (crypto and total >= 2 and "navegadores" in stores)
            or (total >= 4 and len(stores) >= 2)
            or len(wallets) >= 2
            or (sql and bool(crypto))
        )
        if not hit:
            return None
        score = 85 if exfil_found else 75
        evidence: dict = {
            "almacenes_buscados": {cat: ind.cap_list(m, 5) for cat, m in stores.items()},
        }
        if crypto:
            evidence["descifrado_de_contrasenas"] = crypto
        if wallets:
            evidence["extensiones_de_billeteras"] = ind.cap_list(wallets, 6)
        if sql:
            evidence["consulta_sql_de_contrasenas"] = True
        return self._f(
            artifact,
            "pe.stealer_behavior",
            "Comportamiento de robo de credenciales (stealer)",
            "Este programa busca y descifra las contraseñas guardadas en los navegadores, las cookies de sesión, "
            "billeteras cripto y cuentas de Telegram/Discord/FTP. Es el comportamiento de un 'infostealer': si se "
            "ejecutó, hay que cambiar todas las contraseñas guardadas en esa computadora y cerrar sesiones abiertas.",
            Severity.HIGH,
            score,
            evidence,
            FindingCategory.MALWARE,
        )

    def _exfil(self, artifact: Artifact, facts: PeFacts) -> Finding | None:
        s = facts.strings_lower
        channels = [label for label, rx in EXFIL_PATTERNS if rx.search(s)]
        ids = facts.dotnet_ids
        if ("smtpclient" in ids and ("networkcredential" in ids or "credentials" in ids)) or (
            "mail from:" in s and "rcpt to:" in s and "auth login" in s
        ):
            channels.append("envío por mail (SMTP con usuario y contraseña)")
        if ("ftpwebrequest" in ids and "networkcredential" in ids) or ("ftp://" in s and "stor " in s):
            channels.append("subida por FTP con credenciales")
        strong = [c for c in channels if c != "geolocalización de la víctima"]
        if not strong:
            return None
        sev, score = (Severity.HIGH, 60) if len(strong) >= 2 else (Severity.MEDIUM, 45)
        return self._f(
            artifact,
            "pe.exfil_channel",
            "Puede enviar datos robados al atacante",
            "El programa contiene canales típicos para sacar información de la computadora: bots de Telegram, "
            "webhooks de Discord, envío por mail o FTP con credenciales escritas adentro, o páginas usadas como "
            "buzón por los atacantes.",
            sev,
            score,
            {"canales": ind.cap_list(channels)},
        )

    def _keylogger(self, artifact: Artifact, facts: PeFacts) -> Finding | None:
        hook, keys, fg, wt = (facts.family(k) for k in ("hook", "keystate", "foreground", "wintext"))
        if hook and keys and fg:
            sev, score, variant = Severity.HIGH, 60, "gancho de teclado"
        elif "getasynckeystate" in keys and fg and wt:
            sev, score, variant = Severity.MEDIUM, 40, "lectura periódica del teclado"
        else:
            return None
        return self._f(
            artifact,
            "pe.keylogger",
            "Puede registrar lo que se escribe en el teclado (keylogger)",
            "El programa usa funciones de Windows para capturar las teclas que se presionan y saber en qué ventana "
            "se escriben: así se roban contraseñas y datos bancarios mientras se tipean.",
            sev,
            score,
            {"tecnica": variant, "funciones": ind.cap_list(hook + keys + fg + wt)},
            FindingCategory.MALWARE,
        )

    def _injection(self, artifact: Artifact, facts: PeFacts) -> Finding | None:
        alloc, write, thread, unmap, ctx = (
            facts.family(k) for k in ("alloc_remote", "write_remote", "remote_thread", "unmap", "set_context")
        )
        if unmap and write:
            technique, score = "process hollowing (vacía un programa legítimo y lo reemplaza)", 75
        elif alloc and write and thread:
            technique, score = "inyección en otro proceso", 70
        else:
            return None
        return self._f(
            artifact,
            "pe.process_injection",
            "Se mete dentro de otros programas (inyección de código)",
            "El programa tiene la capacidad de escribir código dentro de otros procesos de Windows para esconderse "
            "detrás de programas legítimos. Es una técnica clásica de loaders y troyanos.",
            Severity.HIGH,
            score,
            {"tecnica": technique, "funciones": ind.cap_list(alloc + write + thread + unmap + ctx)},
        )

    def _rat_matches(self, facts: PeFacts) -> dict[str, list[str]]:
        s, ids = facts.strings_lower, facts.dotnet_ids
        out: dict[str, list[str]] = {}
        for cat, mode, needle in RAT_TRAITS:
            ok = (needle in ids or needle in facts.string_set) if mode == "id" else needle in s
            if ok:
                out.setdefault(cat, []).append(needle)
        return out

    def _rat(self, artifact: Artifact, facts: PeFacts) -> Finding | None:
        m = self._rat_matches(facts)
        total = sum(len(v) for v in m.values())
        if not (
            len(m) >= 3
            and total >= 4
            and ("c2" in m or "sockets" in m)
            and ("anti_analysis" in m or "plugins" in m)
        ):
            return None
        hay = facts.strings_lower
        families = ind.cap_list(
            name for key, name in FAMILY_HINTS.items() if key in hay or key in facts.dotnet_ids
        )
        evidence: dict = {
            "rasgos": {RAT_CATEGORY_LABELS[c]: ind.cap_list(v, 5) for c, v in m.items()},
        }
        if families:
            evidence["posible_familia"] = families
        return self._f(
            artifact,
            "pe.rat_traits",
            "Rasgos de troyano de acceso remoto (RAT)",
            "El programa combina conexión con un servidor del atacante, plugins descargables y trucos para detectar "
            "antivirus y entornos de análisis: el perfil de un troyano de control remoto (como AsyncRAT o XWorm) que "
            "permite espiar y manejar la computadora a distancia.",
            Severity.HIGH,
            75,
            evidence,
            FindingCategory.MALWARE,
        )

    def _anti_analysis(self, artifact: Artifact, facts: PeFacts) -> Finding | None:
        traits = self._rat_matches(facts).get("anti_analysis", [])
        if len(traits) < 2:
            return None
        return self._f(
            artifact,
            "pe.anti_analysis",
            "Intenta detectar antivirus o entornos de análisis",
            "El programa revisa qué antivirus hay instalado o si corre en una máquina virtual/sandbox, algo que hace "
            "el malware para esconderse de los analistas.",
            Severity.MEDIUM,
            35,
            {"rasgos": ind.cap_list(traits)},
        )

    def _ransomware(self, artifact: Artifact, facts: PeFacts) -> Finding | None:
        s = facts.strings_lower
        shadow = _matched(s, RANSOM_SHADOW)
        note = _matched(s, RANSOM_NOTE)
        crypto = facts.family("encrypt") and facts.family("find_files")
        if shadow:
            score = 85 if note else 80
        elif len(note) >= 2 and crypto:
            score = 80
        elif len(note) >= 3:
            score = 70
        else:
            return None
        evidence: dict = {}
        if shadow:
            evidence["borra_copias_de_seguridad"] = ind.cap_list(shadow, 4)
        if note:
            evidence["textos_de_rescate"] = ind.cap_list(note, 5)
        if crypto:
            evidence["cifra_archivos"] = True
        return self._f(
            artifact,
            "pe.ransomware_traits",
            "Rasgos de ransomware (secuestro de archivos)",
            "El programa borra las copias de seguridad de Windows y/o contiene textos de pedido de rescate: es el "
            "comportamiento de un ransomware, que cifra todos los archivos de la empresa y pide plata para liberarlos.",
            Severity.HIGH,
            score,
            evidence,
            FindingCategory.MALWARE,
        )

    def _packed(self, artifact: Artifact, facts: PeFacts) -> Finding | None:
        signals: list[str] = []
        packers = sorted(
            {PACKER_SECTIONS[x.name.lower()] for x in facts.sections if x.name.lower() in PACKER_SECTIONS}
        )
        if facts.upx_magic and "UPX" not in packers:
            packers.append("UPX")
        if packers:
            signals.append("empaquetador/protector: " + ", ".join(packers))
        high = [x for x in facts.sections if x.executable and x.raw_size >= 4096 and x.entropy > 7.2]
        if high:
            signals.append(
                "código cifrado/comprimido (entropía "
                + ", ".join(f"{x.name or '?'}={x.entropy:.2f}" for x in high[:3])
                + ")"
            )
        if not facts.dotnet and facts.sections and not (facts.is_dll and not facts.entrypoint):
            loaders = facts.has_api(
                "loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw"
            ) and facts.has_api("getprocaddress")
            if facts.import_count == 0:
                signals.append("no importa ninguna función (las resuelve en tiempo de ejecución)")
            elif facts.import_count <= 5 or (facts.import_count <= 10 and loaders):
                signals.append(f"tabla de imports mínima ({facts.import_count} funciones)")
        rwx = [x.name for x in facts.sections if x.executable and x.writable]
        if rwx:
            signals.append(
                "sección de código modificable: " + ", ".join(ind.clean_snippet(n, 16) for n in rwx[:3])
            )
        if facts.entrypoint and facts.sections and facts.ep_section is None:
            signals.append("el punto de entrada está fuera de las secciones")
        elif (
            facts.ep_section_index > 0
            and facts.ep_section_index == len(facts.sections) - 1
            and len(facts.sections) > 2
        ):
            signals.append(
                f"el punto de entrada está en la última sección ({ind.clean_snippet(facts.ep_section or '', 16)})"
            )
        obf = sorted(
            {
                name
                for key, name in DOTNET_OBFUSCATORS.items()
                if any(key in i for i in facts.dotnet_ids) or key in facts.strings_lower
            }
        )
        if obf:
            signals.append("ofuscador .NET: " + ", ".join(obf))
        if facts.encrypted_resources:
            signals.append("recurso grande cifrado: " + facts.encrypted_resources[0])
        if not signals:
            return None
        base = 40 if any(p in PROTECTORS for p in packers) or obf else 30
        score = min(45, base + 5 * (len(signals) - 1))
        return self._f(
            artifact,
            "pe.packed",
            "Programa empaquetado u ofuscado",
            "El programa está comprimido, cifrado u ofuscado para que no se pueda ver qué hace. Algunos programas "
            "legítimos lo usan para protegerse de copias, pero es la norma en el malware para esquivar antivirus.",
            Severity.MEDIUM,
            score,
            {"senales": signals},
        )

    def _embedded(self, artifact: Artifact, facts: PeFacts) -> Finding | None:
        if not facts.embedded:
            return None
        strong = any("recurso" in e or "overlay" in e for e in facts.embedded)
        return self._f(
            artifact,
            "pe.embedded_pe",
            "Lleva otro programa escondido adentro (dropper)",
            "Dentro de este programa hay otro ejecutable guardado. Es el funcionamiento de un 'dropper': al abrirse, "
            "suelta e instala el verdadero virus.",
            Severity.HIGH if strong else Severity.MEDIUM,
            60 if strong else 40,
            {"ubicacion": ind.cap_list(facts.embedded, 5)},
        )

    def _overlay(self, artifact: Artifact, facts: PeFacts) -> Finding | None:
        size = facts.overlay_size
        if size < 64 * 1024:
            return None
        ratio = size / max(artifact.size or 1, 1)
        if size < 512 * 1024 and ratio < 0.5:
            return None
        evidence: dict = {"tamano": size, "porcentaje_del_archivo": round(min(ratio, 1.0) * 100)}
        if facts.overlay_kind:
            evidence["contenido"] = ind.PAYLOAD_LABELS.get(facts.overlay_kind, facts.overlay_kind)
        if facts.overlay_entropy is not None:
            evidence["entropia"] = facts.overlay_entropy
        if facts.installer:
            evidence["instalador"] = facts.installer
        if facts.signed and facts.installer:
            sev, score = Severity.LOW, 5
        elif facts.installer:
            sev, score = Severity.LOW, 10
        elif (facts.overlay_entropy or 0) >= 7.5 or facts.overlay_kind:
            sev, score = Severity.MEDIUM, 30
        else:
            sev, score = Severity.MEDIUM, 25
        return self._f(
            artifact,
            "pe.overlay",
            "Datos extra pegados al final del programa",
            "El programa tiene una gran cantidad de datos agregados después del final normal del ejecutable. Los "
            "instaladores lo hacen, pero también el malware para esconder su carga real.",
            sev,
            score,
            evidence,
        )

    def _embedded_commands(self, artifact: Artifact, facts: PeFacts) -> Finding | None:
        if not facts.strings_text:
            return None
        result = ind.scan_text(facts.strings_text, profile="pe", max_depth=1)
        groups = {g: hits for g, hits in result.groups().items() if g in EMBEDDED_CMD_GROUPS}
        if (
            "amsi_bypass" in groups
            and facts.api_names & AMSI_ETW_IMPORTS
            and not any(m in facts.strings_lower for m in AMSI_BYPASS_MARKERS)
        ):
            del groups["amsi_bypass"]  # el programa USA AMSI/ETW (las importa), no las desactiva
        if not groups:
            return None
        if groups.keys() & EMBEDDED_CMD_STRONG:
            sev, score = Severity.HIGH, 70
        elif "lolbin" in groups or "powershell_stealth" in groups:
            sev, score = Severity.MEDIUM, 45
        else:
            sev, score = Severity.MEDIUM, 25
        hits = [h for hs in groups.values() for h in hs]
        return self._f(
            artifact,
            "pe.embedded_commands",
            "Contiene comandos para desactivar defensas o ejecutar código",
            "Dentro del programa hay comandos de Windows/PowerShell para cosas como desactivar Windows Defender, "
            "ejecutar código oculto o instalarse para arrancar solo.",
            sev,
            score,
            {
                "indicadores": ind.cap_list(h.label for h in hits),
                "fragmentos": ind.cap_list((h.snippet for h in hits if h.snippet), 3),
            },
        )

    def _version_impersonation(self, artifact: Artifact, facts: PeFacts) -> Finding | None:
        vi = facts.version_info
        # la empresa declarada manda: "Exportador para Microsoft Excel" de "Estudio Pérez" no se hace pasar por
        # Microsoft; solo sin CompanyName se mira el copyright y el nombre de producto
        company = vi.get("CompanyName", "").strip()
        claimed_src = company or " ".join(vi.get(k, "") for k in ("LegalCopyright", "ProductName"))
        m = _VENDOR_RE.search(claimed_src)
        if not m:
            return None
        vendor = m.group(1).lower()
        signer = (facts.signer or "").lower()
        if facts.signed and facts.signer and not facts.self_signed:
            if vendor in signer or "microsoft windows hardware compatibility" in signer:
                return None
            reason = f"dice ser de {m.group(1)} pero está firmado por '{ind.clean_snippet(facts.signer, 80)}'"
            score = 40
        elif facts.signed and facts.self_signed:
            reason = f"dice ser de {m.group(1)} pero su firma es autofirmada"
            score = 45
        elif facts.signed:
            reason = f"dice ser de {m.group(1)} pero su firma digital está dañada o no se puede leer"
            score = 45
        else:
            reason = f"dice ser de {m.group(1)} pero no tiene firma digital"
            score = 45
        return self._f(
            artifact,
            "pe.version_impersonation",
            f"Se hace pasar por un programa de {m.group(1)}",
            f"Los datos internos del programa {reason}. Las empresas grandes siempre firman sus programas: esto es "
            "una suplantación típica para parecer confiable.",
            Severity.MEDIUM,
            score,
            {"info_version": {k: vi[k] for k in ("CompanyName", "ProductName", "LegalCopyright") if k in vi}},
        )
