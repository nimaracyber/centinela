"""Indicadores compartidos por los analizadores de scripts, accesos directos (.lnk), HTML y ejecutables.

Es un motor de detección sobre TEXTO, consciente de la ofuscación:

- normaliza trucos comunes antes de buscar: backticks de PowerShell (``I`E`X``), ``^`` de cmd
  (``p^o^w^e^r^s^h^e^l^l``), concatenaciones ``'Down'+'loadString'`` / ``"a" & "b"`` y comillas vacías;
- decodifica capas y las vuelve a revisar (con profundidad y tamaño acotados): PowerShell
  ``-EncodedCommand`` (base64 UTF-16LE), ``FromBase64String``/``atob``/``b64decode``, blobs base64
  grandes, gzip/deflate, arreglos de códigos de carácter (``[char]73``, ``Chr(73)``,
  ``String.fromCharCode``), escapes ``%XX``/``\\xNN``, texto invertido y variables de ``set`` en .bat;
- detecta programas embebidos: base64 / base64 invertido / hex / arreglos de bytes que empiezan con ``MZ``.

Reglas de seguridad: nada se ejecuta (solo regex y decodificación en memoria); todas las regex
evitan cuantificadores anidados ambiguos y las corridas largas llevan lookbehind para que el costo
sea lineal; cada capa, decodificación y lista de evidencia tiene un tope.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import math
import re
import urllib.parse
import zlib
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field

from centinela.core.models import Finding, FindingCategory, Severity

# --------------------------------------------------------------------------- límites

MAX_TEXT_BYTES = 8 * 1024 * 1024  # bytes de un archivo de texto que se decodifican
MAX_SCAN_CHARS = 4 * 1024 * 1024  # caracteres por capa que se revisan con regex
MAX_TOTAL_DECODED_CHARS = 6 * 1024 * 1024  # presupuesto total de capas decodificadas
MAX_LAYERS = 24
MAX_DEPTH = 3
MAX_MATCHES_PER_INDICATOR = 3
MAX_BLOB_CANDIDATES = 32
MAX_DECODED_BLOB_BYTES = 2 * 1024 * 1024
MAX_DECOMPRESSED_BYTES = 4 * 1024 * 1024
SNIPPET_CHARS = 160
MAX_EVIDENCE_ITEMS = 8

# --------------------------------------------------------------------------- utilidades de texto


def decode_text(data: bytes, max_bytes: int = MAX_TEXT_BYTES) -> tuple[str, bool]:
    """Decodifica bytes de un archivo de texto (BOM, UTF-16 sin BOM, UTF-8, latin-1). Devuelve (texto, truncado)."""
    truncated = len(data) > max_bytes
    raw = data[:max_bytes]
    if raw.startswith(codecs.BOM_UTF8):
        return raw[3:].decode("utf-8", "replace"), truncated
    if raw.startswith(codecs.BOM_UTF16_LE):
        return raw[2:].decode("utf-16-le", "replace"), truncated
    if raw.startswith(codecs.BOM_UTF16_BE):
        return raw[2:].decode("utf-16-be", "replace"), truncated
    sample = raw[:4096]
    if len(sample) >= 16:
        odd_nuls = sample[1::2].count(0)
        even_nuls = sample[0::2].count(0)
        half = len(sample) // 2
        if odd_nuls > half * 0.6 and even_nuls < half * 0.2:
            return raw.decode("utf-16-le", "replace"), truncated
        if even_nuls > half * 0.6 and odd_nuls < half * 0.2:
            return raw.decode("utf-16-be", "replace"), truncated
    try:
        return raw.decode("utf-8"), truncated
    except UnicodeDecodeError as exc:
        if exc.start >= len(raw) - 4:  # corte a mitad de un carácter multibyte por el truncado
            return raw.decode("utf-8", "replace"), truncated
        return raw.decode("latin-1"), truncated


def shannon_entropy(data: bytes | str) -> float:
    """Entropía de Shannon en bits por símbolo (0..8 para bytes)."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# incluye surrogates sueltos (\uD800-\uDFFF): salen de `\uD800` o fromCharCode(55296) en texto hostil y
# rompen la serializaci\u00f3n JSON/UTF-8 de la evidencia (alertas, API)
_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ud800-\udfff]")
_WS_RE = re.compile(r"\s+")
_HTTP_RE = re.compile(r"(?i)\bhttp(s?)://")


def defang(text: str) -> str:
    """Neutraliza URLs para mostrarlas sin que sean clickeables (http -> hxxp)."""
    return _HTTP_RE.sub(r"hxxp\1://", text)


def clean_snippet(text: str, limit: int = SNIPPET_CHARS) -> str:
    """Fragmento apto para evidencia: sin caracteres de control, espacios colapsados, URLs neutralizadas."""
    text = _CTRL_RE.sub("", text[: limit * 4])
    text = _WS_RE.sub(" ", text).strip()
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return defang(text)


def snippet_around(text: str, start: int, end: int, limit: int = SNIPPET_CHARS) -> str:
    lo = max(0, start - 30)
    hi = min(len(text), max(end, start) + limit)
    return clean_snippet(text[lo:hi], limit)


def cap_list(items: Iterable[str], limit: int = MAX_EVIDENCE_ITEMS) -> list[str]:
    """Lista sin duplicados (orden estable) y con tope; agrega '(+N más)' si se recortó."""
    seen: dict[str, None] = {}
    for it in items:
        if it and it not in seen:
            seen[it] = None
    out = list(seen)
    if len(out) > limit:
        extra = len(out) - limit
        out = out[:limit] + [f"(+{extra} más)"]
    return out


def printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    ok = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    return ok / len(text)


# --------------------------------------------------------------------------- tipos de archivo embebidos

# (tipo, descripción para humanos)
PAYLOAD_LABELS: dict[str, str] = {
    "pe": "un programa ejecutable de Windows (.exe/.dll)",
    "zip": "un archivo comprimido ZIP",
    "7z": "un archivo comprimido 7-Zip",
    "rar": "un archivo comprimido RAR",
    "iso": "una imagen de disco ISO",
    "ole": "un documento Office antiguo / instalador MSI",
    "cab": "un archivo comprimido CAB",
    "lnk": "un acceso directo de Windows (.lnk)",
    "gzip": "un archivo comprimido GZIP",
    "vhd": "un disco virtual (VHD/VHDX)",
    "elf": "un programa ejecutable de Linux",
}
DANGEROUS_PAYLOADS = frozenset(PAYLOAD_LABELS)
ISO_PROBE_BYTES = 0x8006  # "CD001" vive en el offset 0x8001


def sniff_magic(head: bytes) -> str | None:
    """Tipo de un payload por sus primeros bytes (solo los tipos que importan para entrega de malware)."""
    if len(head) < 2:
        return None
    if head[:2] == b"MZ":
        return "pe"
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return "zip"
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if head[:6] == b"Rar!\x1a\x07":
        return "rar"
    if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole"
    if head[:4] == b"MSCF":
        return "cab"
    if head[:8] == b"L\x00\x00\x00\x01\x14\x02\x00":
        return "lnk"
    if head[:2] == b"\x1f\x8b":
        return "gzip"
    if head[:8] in (b"conectix", b"vhdxfile"):
        return "vhd"
    if head[:4] == b"\x7fELF":
        return "elf"
    if len(head) >= 0x8006 and head[0x8001:0x8006] in (b"CD001", b"BEA01"):
        return "iso"
    return None


def looks_like_pe(data: bytes) -> bool:
    """MZ + cabecera PE válida (evita falsos positivos con cualquier texto que empiece con 'MZ')."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return False
    e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
    return 0x40 <= e_lfanew <= len(data) - 4 and data[e_lfanew : e_lfanew + 4] == b"PE\x00\x00"


# --------------------------------------------------------------------------- base64 / hex


def b64_decode(s: str, max_bytes: int) -> bytes | None:
    """Decodifica (como mucho `max_bytes`) un string base64; tolera url-safe, espacios y padding faltante."""
    if "-" in s or "_" in s:
        s = s.replace("-", "+").replace("_", "/")
    if any(c.isspace() for c in s[:200_000]):
        s = _WS_RE.sub("", s)
    s = s.rstrip("=")
    n = min(len(s), (max_bytes // 3 + 1) * 4)
    chunk = s[:n]
    if len(chunk) % 4 == 1:
        chunk = chunk[:-1]
    chunk += "=" * (-len(chunk) % 4)
    if not chunk:
        return None
    try:
        return base64.b64decode(chunk, validate=True)[:max_bytes]
    except (binascii.Error, ValueError):
        return None


_B64_RUN_CACHE: dict[int, re.Pattern[str]] = {}


def iter_base64_runs(text: str, min_len: int, limit: int = MAX_BLOB_CANDIDATES) -> Iterator[re.Match[str]]:
    """Corridas base64 de al menos `min_len` caracteres (lineal: el lookbehind evita reintentos dentro de una corrida)."""
    rx = _B64_RUN_CACHE.get(min_len)
    if rx is None:
        rx = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{" + str(int(min_len)) + r",}={0,2}")
        _B64_RUN_CACHE[min_len] = rx
    for count, m in enumerate(rx.finditer(text)):
        if count >= limit:
            return
        yield m


HEX_RUN_RE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){64,}")
BYTE_ARRAY_RE = re.compile(
    r"(?<![\w.,])(?:0x[0-9a-fA-F]{1,2}|\d{1,3})(?:\s*,\s*(?:0x[0-9a-fA-F]{1,2}|\d{1,3})){7,}"
)


def parse_int_list(s: str, max_items: int) -> list[int]:
    out: list[int] = []
    for part in s.split(",", max_items):
        part = part.strip()
        if not part:
            continue
        try:
            out.append(int(part, 16) if part[:2].lower() == "0x" else int(part))
        except ValueError:
            break
        if len(out) >= max_items:
            break
    return out


# --------------------------------------------------------------------------- definición de indicadores

_DASH = "[-/\u2013\u2014\u2015]"  # PowerShell acepta - / – — ― como prefijo de parámetro
_TOK = r"(?<![\w-])"
# separador parámetro/valor ("-w:hidden", "-w hidden", "-w : hidden"). Sin dos `\s*` contiguos alrededor
# de un opcional: esa forma es cuadrática ante corridas largas de espacios.
_SEP = r"(?:\s*:\s*|\s+)"


def _prefix_re(word: str, min_len: int) -> str:
    """Regex de todos los prefijos de `word` de largo >= min_len (PowerShell acepta abreviaturas)."""
    head, tail = word[:min_len], word[min_len:]
    rx = ""
    for ch in reversed(tail):
        rx = f"(?:{re.escape(ch)}{rx})?"
    return re.escape(head) + rx


_ENC_PARAM = f"(?:ec|{_prefix_re('encodedcommand', 1)})"
PS_ENCODED_RE = re.compile(
    _TOK + _DASH + _ENC_PARAM + r"\s+[\"']?(?P<b64>[A-Za-z0-9+/]{16,}={0,2})", re.IGNORECASE
)


@dataclass(frozen=True, slots=True)
class _Ind:
    key: str
    group: str | None  # grupo de hallazgo; None = solo aporta roles/contexto
    label: str  # descripción corta (español)
    rx: re.Pattern[str]
    roles: frozenset[str] = frozenset()
    profiles: frozenset[str] = frozenset({"script", "html", "pe"})
    requires: str | None = None  # bandera de contexto necesaria ("ps", "wsh")


def _i(
    key: str,
    group: str | None,
    label: str,
    pattern: str,
    roles: str = "",
    profiles: str = "script html pe",
    requires: str | None = None,
) -> _Ind:
    return _Ind(
        key=key,
        group=group,
        label=label,
        rx=re.compile(pattern, re.IGNORECASE),
        roles=frozenset(roles.split()),
        profiles=frozenset(profiles.split()),
        requires=requires,
    )


_EXE_EXT = r"(?:exe|dll|scr|ps1|bat|cmd|vbs|vbe|js|jse|hta|msi|lnk|zip|wsf|cpl)"

INDICATORS: tuple[_Ind, ...] = (
    # ---------------- PowerShell
    _i(
        "ps_encoded",
        "powershell_encoded",
        "PowerShell con comando codificado (-EncodedCommand)",
        PS_ENCODED_RE.pattern,
        "exec",
        requires="ps",
    ),
    _i(
        "ps_hidden",
        "powershell_stealth",
        "ventana oculta (-WindowStyle Hidden)",
        _TOK
        + _DASH
        + _prefix_re("windowstyle", 1)
        + _SEP
        + r"[\"']?(?:"
        + _prefix_re("hidden", 1)
        + r"|1)\b",
        requires="ps",
    ),
    _i(
        "ps_noprofile",
        "powershell_stealth",
        "sin perfil (-NoProfile)",
        _TOK + _DASH + _prefix_re("noprofile", 3) + r"\b",
        requires="ps",
    ),
    _i(
        "ps_noninteractive",
        "powershell_stealth",
        "no interactivo (-NonInteractive)",
        _TOK + _DASH + _prefix_re("noninteractive", 4) + r"\b",
        requires="ps",
    ),
    _i(
        "ps_bypass",
        "powershell_stealth",
        "saltea la política de ejecución (-ExecutionPolicy Bypass)",
        _TOK
        + _DASH
        + r"(?:ep|"
        + _prefix_re("executionpolicy", 2)
        + r")"
        + _SEP
        + r"[\"']?(?:bypass|unrestricted)\b|\bset-executionpolicy\s+(?:-\w+\s+)?[\"']?(?:bypass|unrestricted)\b",
    ),
    _i(
        "ps_iex",
        "dynamic_exec",
        "Invoke-Expression (ejecuta texto como código)",
        r"(?<![\w-])(?:iex|invoke-expression)\b",
        "exec",
        requires="ps",
    ),
    _i(
        "ps_iex_obf",
        "dynamic_exec",
        "Invoke-Expression escondido ($pshome/$shellid/$env:comspec)",
        r"\$(?:pshome|shellid|env:comspec|verbosepreference(?:\.tostring\(\))?)\s*\[\s*\d+\s*\]",
        "exec obf",
    ),
    _i(
        "ps_downloadstring",
        None,
        "descarga con WebClient (DownloadString)",
        r"\.download(?:string|data)(?:async|taskasync)?\b",
        "fetch",
    ),
    _i(
        "ps_downloadfile",
        None,
        "descarga a disco (DownloadFile)",
        r"\.downloadfile(?:async|taskasync)?\b",
        "fetch write",
    ),
    _i("ps_webclient", None, "cliente web (Net.WebClient)", r"\bnet\.webclient\b", "fetch"),
    _i(
        "ps_iwr",
        None,
        "descarga web (Invoke-WebRequest / iwr / irm / BITS)",
        r"(?<![\w-])(?:invoke-webrequest|invoke-restmethod|iwr|irm|start-bitstransfer)\b",
        "fetch",
    ),
    _i(
        "ps_httpclient",
        None,
        "cliente HTTP (.NET HttpClient)",
        r"\bsystem\.net\.http\.httpclient\b|\bnet\.httpwebrequest\b",
        "fetch",
    ),
    _i(
        "write_file",
        None,
        "escribe archivos en disco",
        r"(?<![\w-])-outfile\b|\bout-file\b|\bset-content\b|\[(?:system\.)?io\.file\]::write(?:allbytes|alltext|alllines)\b|\.savetofile\b|\bcreatetextfile\b|\.copyhere\b",
        "write",
    ),
    _i(
        "ps_start_process",
        None,
        "inicia procesos (Start-Process)",
        r"(?<![\w-])(?:start-process|saps|invoke-item)\b",
        "exec",
    ),
    _i(
        "ps_reflection",
        "reflective_load",
        "carga de código en memoria ([Reflection.Assembly]::Load)",
        r"\[(?:system\.)?reflection\.assembly\]\s*::\s*(?:load|loadfrom|loadfile|unsafeloadfrom)\b|\[appdomain\]::currentdomain\.load\b|\.entrypoint\.invoke\b",
        "exec",
    ),
    _i(
        "ps_delegate",
        "reflective_load",
        "ejecuta código binario en memoria (GetDelegateForFunctionPointer)",
        r"\bgetdelegateforfunctionpointer\b",
        "exec",
    ),
    _i(
        "api_virtualalloc",
        None,
        "reserva memoria ejecutable (VirtualAlloc)",
        r"\bvirtualalloc(?:ex)?\b",
        "alloc",
        "script html",
    ),
    _i(
        "api_thread",
        None,
        "crea hilos (CreateThread)",
        r"\b(?:createthread|createremotethread)\b",
        "thread",
        "script html",
    ),
    _i("ps_frombase64", None, "decodifica base64 (FromBase64String)", r"\bfrombase64string\b", "decode"),
    _i(
        "ps_compression",
        None,
        "descomprime datos (GzipStream/DeflateStream)",
        r"\bio\.compression\.(?:gzipstream|deflatestream)\b",
        "decode",
    ),
    _i("ps_tcpclient", None, "conexión de red directa (TCPClient)", r"\bnet\.sockets\.tcpclient\b", "socket"),
    # ---------------- evasión de defensas / ransomware / credenciales
    _i(
        "amsi",
        "amsi_bypass",
        "intenta desactivar AMSI (revisión antimalware de Windows)",
        r"\bamsi(?:utils|initfailed|scanbuffer|opensession|context)\b",
    ),
    _i("etw", "amsi_bypass", "intenta silenciar el registro de eventos (ETW)", r"\betweventwrite\b"),
    _i(
        "defender_exclusion",
        "defender_tamper",
        "agrega exclusiones a Windows Defender",
        r"\badd-mppreference\b[^\n]{0,200}?-exclusion(?:path|process|extension|ipaddress)\b",
    ),
    _i(
        "defender_disable",
        "defender_tamper",
        "apaga protecciones de Windows Defender",
        r"\bset-mppreference\b[^\n]{0,200}?-disable(?:realtimemonitoring|behaviormonitoring|ioavprotection|scriptscanning|blockatfirstseen|intrusionpreventionsystem|archivescanning)\b"
        r"|\bsc(?:\.exe)?\s+(?:stop|delete|config)\s+windefend\b|\bdisableantispyware\b",
    ),
    _i(
        "shadow_delete",
        "shadow_delete",
        "borra copias de seguridad de Windows (shadow copies)",
        r"\bvssadmin(?:\.exe)?\s+delete\s+shadows\b|\bwmic(?:\.exe)?\s+shadowcopy\s+delete\b"
        r"|\bwbadmin(?:\.exe)?\s+delete\s+(?:catalog|systemstatebackup|backup)\b"
        r"|\bbcdedit(?:\.exe)?\s[^\n]{0,60}?recoveryenabled\s+no\b|\bwin32_shadowcopy\b[^\n]{0,200}?\.delete\s*\(",
    ),
    _i(
        "mimikatz",
        "credential_theft",
        "herramienta de robo de credenciales (Mimikatz)",
        r"\b(?:invoke-mimikatz|mimikatz|sekurlsa::|lsadump::)",
    ),
    _i(
        "uac_bypass",
        "privilege_escalation",
        "evade el control de cuentas de usuario (UAC)",
        r"\\(?:ms-settings|mscfile|exefile|folder)\\shell\\open\\command\b",
    ),
    # ---------------- objetos COM / Windows Script Host
    _i(
        "com_wscript_shell",
        "com_objects",
        "WScript.Shell (ejecuta programas)",
        r"\bwscript\.shell\b",
        "exec wsh",
    ),
    _i(
        "com_shell_app",
        "com_objects",
        "Shell.Application (ejecuta programas)",
        r"\bshell\.application\b",
        "exec wsh",
    ),
    _i(
        "com_activex",
        "com_objects",
        "crea objetos ActiveX/COM",
        r"\bnew\s+activexobject\b|\b(?:wscript\.)?createobject\s*\(|\bgetobject\s*\(",
        "wsh",
    ),
    _i(
        "com_xmlhttp",
        "com_objects",
        "descarga con MSXML2.XMLHTTP / WinHttp",
        r"\b(?:msxml2\.(?:server)?xmlhttp(?:\.\d\.\d)?|microsoft\.xmlhttp|winhttp\.winhttprequest(?:\.5\.1)?)\b",
        "fetch",
    ),
    _i("com_adodb", "com_objects", "guarda binarios con ADODB.Stream", r"\badodb\.stream\b", "write"),
    _i(
        "com_fso",
        "com_objects",
        "manipula archivos (Scripting.FileSystemObject)",
        r"\bscripting\.filesystemobject\b",
        "write",
    ),
    _i(
        "wmi_process",
        None,
        "crea procesos vía WMI (Win32_Process)",
        r"(?<!from )\bwin32_process\b(?!startup)|\bwmic(?:\.exe)?\b[^\n]{0,100}?\bprocess\s+call\s+create\b",
        "exec",
    ),
    _i(
        "shell_run",
        None,
        "ejecuta comandos (.Run / .Exec / ShellExecute)",
        r"\.(?:run|exec)\s*(?:\(\s*)?[\"'(%\w]|\.shellexecute\b",
        "exec",
        requires="wsh",
    ),
    _i(
        "cmd_exec",
        None,
        "abre la consola (cmd /c)",
        r"\b(?:cmd(?:\.exe)?|%comspec%)[\"']?\s+/[ckr]\b",
        "exec",
    ),
    _i(
        "ps_invoke",
        None,
        "invoca PowerShell",
        r"\b(?:powershell|pwsh)\.exe\b|\b(?:powershell|pwsh)[\"']?\s+(?:[-/\u2013\u2014]\w|[\"'{&$])",
        "exec ps",
    ),
    _i("js_eval", "dynamic_exec", "eval() (ejecuta texto como código)", r"\beval\s*\(", "exec", "script"),
    _i(
        "vbs_execute",
        "dynamic_exec",
        "Execute/ExecuteGlobal (ejecuta texto como código)",
        r"\bexecute(?:global)?\s*[(\"]|\bexecuteglobal\b",
        "exec",
        "script",
    ),
    _i(
        "js_function_ctor",
        "dynamic_exec",
        "new Function() (ejecuta texto como código)",
        r"\bnew\s+function\s*\(",
        "exec",
        "script",
    ),
    _i(
        "bat_start",
        None,
        "lanza un programa (start)",
        r"(?m)^[ \t@]*start\s+(?:\"[^\"\n]{0,80}\"\s+)?(?:/\w+\s+){0,4}[^\s\n]{1,200}\." + _EXE_EXT + r"\b",
        "exec",
        "script",
    ),
    _i(
        "py_exec",
        None,
        "ejecuta código/comandos (Python)",
        r"(?<![.\w])exec\s*\(|\bos\.(?:system|popen)\s*\(|\bsubprocess\.(?:popen|call|run|check_output)\b",
        "exec",
        "script",
    ),
    _i(
        "py_fetch",
        None,
        "descarga web (Python)",
        r"\burllib\d?\.(?:request\.)?urlopen\b|\brequests\.get\s*\(|\burlretrieve\s*\(",
        "fetch",
        "script",
    ),
    _i(
        "sh_pipe",
        None,
        "descarga y ejecuta en una línea (curl | sh)",
        r"\b(?:curl|wget)\b[^\n|]{0,300}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b",
        "fetch exec",
        "script",
    ),
    _i(
        "curl_url",
        None,
        "descarga web (curl/wget)",
        r"\b(?:curl|wget)(?:\.exe)?\s[^\n]{0,300}?https?://",
        "fetch",
    ),
    _i(
        "curl_out_exe",
        "lolbin",
        "curl/wget guarda un ejecutable o script",
        r"\b(?:curl|wget)(?:\.exe)?\s[^\n]{0,300}?(?:-o|--output|--output-document)\s*[\"']?[^\s\"']{0,200}\."
        + _EXE_EXT
        + r"\b",
        "fetch write",
    ),
    # ---------------- LOLBins (herramientas legítimas de Windows abusadas)
    _i(
        "certutil_download",
        "lolbin",
        "certutil descarga archivos (-urlcache)",
        r"\bcertutil(?:\.exe)?\b[^\n]{0,200}?[-/](?:urlcache|verifyctl)\b",
        "fetch write",
    ),
    _i(
        "certutil_decode",
        "lolbin",
        "certutil decodifica archivos (-decode)",
        r"\bcertutil(?:\.exe)?\b[^\n]{0,200}?[-/]decode(?:hex)?\b",
        "decode write",
    ),
    _i(
        "bitsadmin",
        "lolbin",
        "bitsadmin descarga archivos (/transfer)",
        r"\bbitsadmin(?:\.exe)?\b[^\n]{0,200}?/(?:transfer|addfile|setnotifycmdline)\b",
        "fetch write",
    ),
    _i(
        "mshta_remote",
        "lolbin",
        "mshta ejecuta código remoto",
        r"\bmshta(?:\.exe)?[\"']?\s+[\"']?(?:https?:|vbscript:|javascript:|about:|\\\\)",
        "fetch exec",
    ),
    _i(
        "rundll32_abuse",
        "lolbin",
        "rundll32 ejecuta código (javascript:/url.dll/UNC)",
        r"\brundll32(?:\.exe)?\b[^\n]{0,300}?(?:javascript:|vbscript:|url\.dll\s*,\s*(?:fileprotocolhandler|openurl)"
        r"|shell32(?:\.dll)?\s*,\s*shellexec_rundll|advpack(?:\.dll)?\s*,\s*(?:launchinfsection|registerocx)"
        r"|zipfldr(?:\.dll)?\s*,\s*routethecall|mshtml(?:\.dll)?\s*,\s*runhtmlapplication|\\\\[^\s\\]{1,200}\\)",
        "exec",
    ),
    _i(
        "regsvr32_squiblydoo",
        "lolbin",
        "regsvr32 ejecuta un script remoto (squiblydoo)",
        r"\bregsvr32(?:\.exe)?\b[^\n]{0,200}?(?:/i:\s*[\"']?(?:https?:|\\\\)|\bscrobj(?:\.dll)?\b)",
        "fetch exec",
    ),
    _i(
        "msiexec_remote",
        "lolbin",
        "msiexec instala un paquete desde Internet",
        r"\bmsiexec(?:\.exe)?\b[^\n]{0,200}?(?:https?://|\\\\\w)",
        "fetch exec",
    ),
    _i(
        "forfiles",
        "lolbin",
        "forfiles ejecuta comandos (/c)",
        r"\bforfiles(?:\.exe)?\b[^\n]{0,300}?/c\b",
        "exec",
    ),
    _i(
        "wmic_xsl",
        "lolbin",
        "wmic ejecuta un script remoto (/format)",
        r"\bwmic(?:\.exe)?\b[^\n]{0,200}?/format:\s*[\"']?(?:https?:|\\\\)",
        "fetch exec",
    ),
    _i("hh_remote", "lolbin", "hh.exe abre ayuda remota", r"\bhh(?:\.exe)?\s+[\"']?https?://", "fetch exec"),
    _i(
        "cmstp",
        "lolbin",
        "cmstp instala un perfil malicioso",
        r"\bcmstp(?:\.exe)?\b[^\n]{0,100}?/(?:s|ni|au)\b",
        "exec",
    ),
    _i(
        "msbuild_temp",
        "lolbin",
        "compila y ejecuta código con MSBuild/InstallUtil",
        r"\b(?:msbuild|installutil|regasm|regsvcs)(?:\.exe)?\b[^\n]{0,200}?(?:%(?:temp|tmp|appdata|public|programdata)%|\\temp\\|\\appdata\\|\\users\\public\\|\\programdata\\|/u\b)",
        "exec",
    ),
    _i(
        "odbcconf",
        "lolbin",
        "odbcconf registra una DLL",
        r"\bodbcconf(?:\.exe)?\b[^\n]{0,100}?(?:/a\s*\{?\s*regsvr|\s-f\s)",
        "exec",
    ),
    _i("pcalua", "lolbin", "pcalua lanza programas", r"\bpcalua(?:\.exe)?\s+-a\b", "exec"),
    _i(
        "finger",
        "lolbin",
        "finger.exe descarga comandos (variante ClickFix)",
        r"\bfinger(?:\.exe)?\s+[\w.\-]{1,64}@[\w.\-]{2,253}",
        "fetch",
    ),
    _i(
        "conhost_headless",
        "lolbin",
        "conhost --headless (consola invisible)",
        r"\bconhost(?:\.exe)?\b[^\n]{0,30}?--headless\b",
        "exec",
    ),
    _i(
        "syncappv",
        "lolbin",
        "SyncAppvPublishingServer ejecuta PowerShell",
        r"\bsyncappvpublishingserver(?:\.vbs|\.exe)?\b",
        "exec",
    ),
    # ---------------- persistencia
    _i(
        "schtasks",
        "persistence",
        "crea una tarea programada (schtasks /create)",
        r"\bschtasks(?:\.exe)?\b[^\n]{0,60}?/create\b",
        "persist",
    ),
    _i(
        "run_key",
        "persistence",
        "se agrega al inicio de Windows (clave Run del registro)",
        r"\b(?:reg(?:\.exe)?\s+add|new-itemproperty|set-itemproperty|regwrite)\b[^\n]{0,300}?\\currentversion\\(?:run|runonce|runservices|policies\\explorer\\run)\b",
        "persist",
    ),
    _i(
        "ps_schtask",
        "persistence",
        "registra una tarea programada (PowerShell)",
        r"\b(?:register-scheduledtask|new-scheduledtaskaction)\b",
        "persist",
    ),
    _i(
        "startup_folder",
        "persistence",
        "se copia a la carpeta Inicio",
        r"\\programs\\startup\b|\bshell:startup\b",
        "persist",
    ),
    _i(
        "service_create",
        "persistence",
        "crea un servicio de Windows",
        r"\bnew-service\b|\bsc(?:\.exe)?\s+create\b",
        "persist",
    ),
    _i(
        "wmi_subscription",
        "persistence",
        "suscripción WMI permanente",
        r"\b(?:__eventfilter|commandlineeventconsumer|activescripteventconsumer)\b",
        "persist",
    ),
    # ---------------- scripts codificados
    _i(
        "jse_encoded",
        "encoded_script",
        "script codificado con Script Encoder (#@~^)",
        r"#@~\^[A-Za-z0-9+/]{6}==",
    ),
)

_CTX_PS_RE = re.compile(
    r"\b(?:powershell|pwsh)\b|\$(?:env|psversiontable)\b|-(?:nop|enc|ep|exec)\b|\bnew-object\b"
    r"|\[(?:system\.)?convert\]::|\bwrite-(?:host|output)\b|\bget-(?:childitem|item|content|process|wmiobject|ciminstance)\b",
    re.IGNORECASE,
)
_CTX_WSH_RE = re.compile(
    r"\b(?:wscript\.shell|shell\.application|activexobject|createobject|getobject|wscript\.)", re.IGNORECASE
)
# En una página web (perfil "html", no .hta) ActiveXObject/CreateObject solos no implican Windows Script
# Host: jQuery 1.x usa `new ActiveXObject("Microsoft.XMLHTTP")` y `regex.exec(...)` es JS de todos los días.
_CTX_WSH_STRICT_RE = re.compile(r"\b(?:wscript\.shell|shell\.application|wscript\.)", re.IGNORECASE)

# --------------------------------------------------------------------------- normalización / ofuscación

_CONCAT_RE = re.compile(r"'\s*\+\s*'" + "|" + r'"\s*[+&]\s*"')  # 'a'+'b'  "a"+"b"  "a" & "b"
_EMPTY_QUOTES_RE = re.compile(r"(?<=\w)(?:" + '""' + "|" + "''" + r")(?=\w)")  # po""wer''shell


def normalize(text: str) -> str:
    """Deshace trucos de ofuscación baratos para que las regex vean el comando real."""
    t = text.replace("\x00", "")
    if "`" in t:
        t = t.replace("`", "")
    if "^" in t:
        t = t.replace("^", "")
    t = _CONCAT_RE.sub("", t)
    return _EMPTY_QUOTES_RE.sub("", t)


# el grupo ya admite espacios: un `\s*` delante sería ambiguo con él (costo cuadrático)
_CHARCODE_CALL_RE = re.compile(r"\bfromcharcode\s*\(([0-9a-fx,\s]{3,200000}?)\)", re.IGNORECASE)
_CHARCODE_TOKEN_RE = re.compile(
    r"\[char\]\s*(?:\(\s*)?(0x[0-9a-f]{1,4}|\d{1,5})|\bchr[wb]?\s*\(\s*(\d{1,5})\s*\)", re.IGNORECASE
)
_CMD_SUBSTR_RE = re.compile(r"%(\w{1,30}):~-?\d{1,4}(?:,-?\d{1,4})?%")
# recortes de %DATE%/%TIME% son lo normal en un .bat de backup ("backup_%DATE:~6,4%...") y no ofuscan nada
_PLAIN_SUBSTR_VARS = frozenset({"date", "time"})
_OBFIO_RE = re.compile(r"\b_0x[0-9a-f]{4,6}\b", re.IGNORECASE)
_PERCENT_RE = re.compile(r"%[0-9a-fA-F]{2}")
JS_ESCAPE_RE = re.compile(r"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}")
_REVERSE_PRIMITIVE_RE = re.compile(
    r"\[array\]::reverse\b|\.split\(\s*[\"']{2}\s*\)\s*\.reverse\(\s*\)|\bstrreverse\s*\(|\[\s*-1\s*\.\.\s*-|\[::-1\]|\|\s*rev\b",
    re.IGNORECASE,
)
_REPLACE_RE = re.compile(r"\.replace\s*\(|-replace\b", re.IGNORECASE)
_EXPLICIT_B64_RE = re.compile(
    r"(?:frombase64string|atob|b64decode|base64decode|decodebase64)\s*\(\s*b?[\"']([A-Za-z0-9+/=_\-\s]{16,2800000})[\"']",
    re.IGNORECASE,
)
_SET_VAR_RE = re.compile(r"(?im)^[ \t@]*set\s+\"?(\w{1,30})=([^\r\n&\"]{0,300})")
_VAR_USE_RE = re.compile(r"%(\w{1,30})(?::~(-?\d{1,4})(?:,(-?\d{1,4}))?)?%")
_REVERSED_MZ_B64 = "AAAAEAAAAMAAQqVT"  # "TVqQAAMAAAAEAAAA" (cabecera MZ estándar en base64) invertido


def obfuscation_metrics(text: str) -> list[tuple[str, str]]:
    """Métricas de ofuscación sobre el texto original. Devuelve [(clave, descripción)]."""
    out: list[tuple[str, str]] = []
    t = text[:MAX_SCAN_CHARS]
    n = len(t)
    if n == 0:
        return out
    longest = max((len(line) for line in t.splitlines()), default=0)
    if longest >= 4000:
        out.append(("long_line", f"línea de {longest} caracteres"))
    if n >= 2000:
        ent = shannon_entropy(t)
        if ent >= 5.3:
            out.append(("entropy", f"entropía alta ({ent:.2f} bits/carácter)"))
    charcodes = sum(len(m.group(1).split(",")) for m in _CHARCODE_CALL_RE.finditer(t)) + sum(
        1 for _ in _CHARCODE_TOKEN_RE.finditer(t)
    )
    if charcodes >= 20:
        out.append(("charcodes", f"{charcodes} códigos de carácter sueltos (texto armado letra por letra)"))
    concat = len(_CONCAT_RE.findall(t))
    if concat >= 30 and concat * 200 >= n:
        out.append(("concat", f"{concat} concatenaciones de strings"))
    for m in iter_base64_runs(t, 1000, limit=4):
        head = b64_decode(m.group(0)[:64], 48) or b""
        if head[:4] in (b"\x89PNG", b"GIF8") or head[:3] == b"\xff\xd8\xff":
            continue  # imagen embebida: no es ofuscación
        out.append(("base64_blob", f"bloque base64 de {len(m.group(0))} caracteres"))
        break
    carets = t.count("^")
    if carets >= 30 and carets * 50 >= n:
        out.append(("carets", f"{carets} símbolos ^ intercalados (ofuscación de cmd)"))
    backticks = t.count("`")
    if backticks >= 30 and backticks * 50 >= n:
        out.append(("backticks", f"{backticks} backticks intercalados (ofuscación de PowerShell)"))
    substr = sum(1 for name in _CMD_SUBSTR_RE.findall(t) if name.lower() not in _PLAIN_SUBSTR_VARS)
    if substr >= 5:
        out.append(("cmd_substring", f"{substr} recortes de variables %VAR:~x,y% (ofuscación de cmd)"))
    obfio = len(set(_OBFIO_RE.findall(t)))
    if obfio >= 20:
        out.append(("obfuscator_io", f"{obfio} identificadores _0x… (javascript-obfuscator)"))
    replaces = len(_REPLACE_RE.findall(t))
    if replaces >= 15:
        out.append(("replace_chain", f"{replaces} reemplazos de texto encadenados"))
    if _REVERSE_PRIMITIVE_RE.search(t):
        out.append(("reversed", "invierte texto antes de usarlo"))
    if len(_PERCENT_RE.findall(t[:200_000])) >= 300:
        out.append(("percent", "texto codificado con %XX"))
    if len(JS_ESCAPE_RE.findall(t[:200_000])) >= 200:
        out.append(("js_escapes", "texto codificado con \\xNN/\\uNNNN"))
    return out


# --------------------------------------------------------------------------- resultado del escaneo


@dataclass(slots=True)
class IndicatorHit:
    key: str
    group: str | None
    label: str
    snippet: str
    layer: int
    how: str
    count: int = 1


@dataclass(slots=True)
class EmbeddedPayload:
    kind: str  # "pe", "zip"...
    how: str  # "base64", "base64 invertido", "hex", "arreglo de bytes", "gzip+base64"...
    size: int


@dataclass(slots=True)
class ScanResult:
    hits: dict[str, IndicatorHit] = field(default_factory=dict)
    roles: set[str] = field(default_factory=set)
    payloads: list[EmbeddedPayload] = field(default_factory=list)
    obfuscation: list[tuple[str, str]] = field(default_factory=list)
    layers: list[tuple[str, int, str]] = field(default_factory=list)  # (cómo, profundidad, vista previa)
    truncated: bool = False

    def groups(self) -> dict[str, list[IndicatorHit]]:
        out: dict[str, list[IndicatorHit]] = {}
        for h in self.hits.values():
            if h.group:
                out.setdefault(h.group, []).append(h)
        return out

    def has(self, *keys: str) -> bool:
        return any(k in self.hits for k in keys)


@dataclass(slots=True)
class _Layer:
    text: str
    depth: int
    how: str


class _Scanner:
    def __init__(self, profile: str, max_depth: int, assume: frozenset[str]) -> None:
        self.profile = profile
        self.max_depth = max_depth
        self.assume = assume
        self.result = ScanResult()
        self.queue: list[_Layer] = []
        self.decoded_chars = 0
        self.layers_done = 0
        self._seen_layers: set[int] = set()
        self._payload_keys: set[tuple[str, str]] = set()
        self.indicators = tuple(i for i in INDICATORS if profile in i.profiles)
        self._wsh_ctx_re = _CTX_WSH_STRICT_RE if profile == "html" else _CTX_WSH_RE

    # ---------------------------------------------------------------- capas
    def push(self, text: str, depth: int, how: str) -> None:
        if depth > self.max_depth or len(self.queue) + self.layers_done >= MAX_LAYERS:
            return
        text = text[:MAX_SCAN_CHARS]
        # capas decodificadas muy cortas son ruido; el texto original se revisa siempre ("iex $a")
        if not text or (depth > 0 and len(text) < 8):
            return
        h = hash(text)
        if h in self._seen_layers:
            return
        if depth > 0:
            if self.decoded_chars + len(text) > MAX_TOTAL_DECODED_CHARS:
                self.result.truncated = True
                return
            self.decoded_chars += len(text)
            self.result.layers.append((how, depth, clean_snippet(text, 200)))
        self._seen_layers.add(h)
        self.queue.append(_Layer(text, depth, how))

    def add_payload(self, kind: str, how: str, size: int) -> None:
        if (kind, how) in self._payload_keys or len(self.result.payloads) >= 8:
            return
        self._payload_keys.add((kind, how))
        self.result.payloads.append(EmbeddedPayload(kind=kind, how=how, size=size))

    def run(self, text: str) -> ScanResult:
        if len(text) > MAX_SCAN_CHARS:
            self.result.truncated = True
        if self.profile != "pe":  # las strings de un binario no son "código ofuscado"
            self.result.obfuscation = obfuscation_metrics(text)
        self.push(text, 0, "original")
        while self.queue:
            layer = self.queue.pop(0)
            self.layers_done += 1
            self._scan_layer(layer)
        self._combos()
        return self.result

    # ---------------------------------------------------------------- indicadores
    def _scan_layer(self, layer: _Layer) -> None:
        norm = normalize(layer.text)
        ctx = {
            "ps": "ps" in self.assume or layer.how.startswith("PowerShell") or bool(_CTX_PS_RE.search(norm)),
            "wsh": "wsh" in self.assume or bool(self._wsh_ctx_re.search(norm)),
        }
        for ind in self.indicators:
            if ind.requires and not ctx.get(ind.requires):
                continue
            hits = 0
            for m in ind.rx.finditer(norm):
                hits += 1
                prev = self.result.hits.get(ind.key)
                if prev is None:
                    self.result.hits[ind.key] = IndicatorHit(
                        key=ind.key,
                        group=ind.group,
                        label=ind.label,
                        snippet=snippet_around(norm, m.start(), m.end()),
                        layer=layer.depth,
                        how=layer.how,
                    )
                else:
                    prev.count += 1
                if hits >= MAX_MATCHES_PER_INDICATOR:
                    break
            if hits:
                self.result.roles.update(ind.roles)
        if layer.depth < self.max_depth:
            self._decode(norm, layer)
        self._embedded(norm, layer)

    def _combos(self) -> None:
        r = self.result
        if "alloc" in r.roles and "thread" in r.roles and "ps_shellcode" not in r.hits:
            r.hits["ps_shellcode"] = IndicatorHit(
                key="ps_shellcode",
                group="reflective_load",
                label="reserva memoria y la ejecuta (VirtualAlloc + CreateThread)",
                snippet="",
                layer=0,
                how="original",
            )
        if "socket" in r.roles and "exec" in r.roles:
            r.hits.setdefault(
                "reverse_shell",
                IndicatorHit(
                    key="reverse_shell",
                    group="reverse_shell",
                    label="conexión TCP que ejecuta lo que recibe",
                    snippet=r.hits["ps_tcpclient"].snippet if "ps_tcpclient" in r.hits else "",
                    layer=0,
                    how="original",
                ),
            )

    # ---------------------------------------------------------------- decodificación
    def _decode(self, norm: str, layer: _Layer) -> None:
        depth = layer.depth + 1
        # PowerShell -EncodedCommand (base64 de UTF-16LE)
        for count, m in enumerate(PS_ENCODED_RE.finditer(norm)):
            if count >= 8:
                break
            raw = b64_decode(m.group("b64"), MAX_DECODED_BLOB_BYTES)
            txt = bytes_to_text(raw) if raw else None
            if txt:
                self.push(txt, depth, "PowerShell -EncodedCommand")
        # funciones de decodificación explícitas
        for count, m in enumerate(_EXPLICIT_B64_RE.finditer(norm)):
            if count >= MAX_BLOB_CANDIDATES:
                break
            self._try_blob(m.group(1), depth, "base64 (decodificado explícito)", min_text=8)
        # blobs base64 grandes sueltos
        for m in iter_base64_runs(norm, 200):
            blob = m.group(0)
            self._try_blob(blob, depth, "base64", min_text=40)
            self._probe_payload(blob[::-1].lstrip("="), "base64 invertido")
        # arreglos de códigos de carácter
        for txt in charcode_texts(norm):
            self.push(txt, depth, "códigos de carácter")
        for m in BYTE_ARRAY_RE.finditer(norm[:MAX_SCAN_CHARS]):
            vals = parse_int_list(m.group(0), 4096)
            if vals and all(9 <= v <= 126 for v in vals[:4096]) and len(vals) >= 8:
                self.push("".join(chr(v) for v in vals), depth, "arreglo de códigos de carácter")
        # %XX y \xNN
        if len(_PERCENT_RE.findall(norm[:200_000])) >= 30:
            self.push(urllib.parse.unquote(norm[:MAX_SCAN_CHARS]), depth, "texto %XX decodificado")
        if len(JS_ESCAPE_RE.findall(norm[:200_000])) >= 30:
            self.push(unescape_js(norm[:MAX_SCAN_CHARS]), depth, "escapes \\xNN decodificados")
        # texto invertido
        if layer.depth == 0 and _REVERSE_PRIMITIVE_RE.search(norm):
            self.push(norm[::-1], depth, "texto invertido")
        # variables de cmd (DOSfuscation)
        expanded = _expand_cmd_vars(norm)
        if expanded:
            self.push(expanded, depth, "variables de cmd expandidas")

    def _try_blob(self, blob: str, depth: int, how: str, *, min_text: int) -> None:
        raw = b64_decode(blob, MAX_DECODED_BLOB_BYTES)
        if not raw:
            return
        self._check_payload(raw, how)
        if raw[:2] == b"\x1f\x8b":
            inflated = inflate(raw, gzip=True)
            if inflated:
                self._check_payload(inflated, f"gzip+{how}")
                txt = bytes_to_text(inflated)
                if txt and len(txt) >= min_text:
                    self.push(txt, depth, f"gzip+{how}")
            return
        txt = bytes_to_text(raw)
        if txt and len(txt) >= min_text:
            self.push(txt, depth, how)
            return
        inflated = inflate(raw, gzip=False)  # DeflateStream (raw deflate)
        if inflated:
            self._check_payload(inflated, f"deflate+{how}")
            txt = bytes_to_text(inflated)
            if txt and len(txt) >= min_text:
                self.push(txt, depth, f"deflate+{how}")

    def _probe_payload(self, blob: str, how: str) -> None:
        head = b64_decode(blob[: ISO_PROBE_BYTES // 3 * 4 + 8], ISO_PROBE_BYTES)
        if head:
            self._check_payload(head, how)

    def _check_payload(self, data: bytes, how: str) -> None:
        # Un blob base64/hex que decodifica a "MZ" ya es suficiente: que un texto inocente produzca
        # exactamente esa cabecera es astronómicamente improbable (y el payload real puede estar truncado).
        kind = sniff_magic(data)
        if kind in DANGEROUS_PAYLOADS and kind != "gzip":
            self.add_payload(kind, how, len(data))

    def _embedded(self, norm: str, layer: _Layer) -> None:
        if _REVERSED_MZ_B64 in norm:
            self.add_payload("pe", "base64 invertido", 0)
        for count, m in enumerate(HEX_RUN_RE.finditer(norm[:MAX_SCAN_CHARS])):
            if count >= MAX_BLOB_CANDIDATES:
                break
            try:
                head = bytes.fromhex(m.group(0)[: 2 * 4096])
            except ValueError:
                continue
            self._check_payload(head, "hex")
        for count, m in enumerate(BYTE_ARRAY_RE.finditer(norm[:MAX_SCAN_CHARS])):
            if count >= MAX_BLOB_CANDIDATES:
                break
            vals = parse_int_list(m.group(0), 4096)
            if len(vals) >= 64 and vals[0] == 0x4D and vals[1] == 0x5A and all(0 <= v <= 255 for v in vals):
                self._check_payload(bytes(vals), "arreglo de bytes")


def bytes_to_text(raw: bytes) -> str | None:
    """Interpreta bytes decodificados como texto si lo parecen (UTF-16LE o UTF-8/latin-1 imprimible)."""
    if not raw:
        return None
    sample = raw[:4096]
    if len(sample) >= 8 and sample[1::2].count(0) >= len(sample) // 2 * 0.8:
        txt = raw[: len(raw) // 2 * 2].decode("utf-16-le", "replace")
    else:
        try:
            txt = raw.decode("utf-8")
        except UnicodeDecodeError:
            txt = raw.decode("latin-1")
    return txt if printable_ratio(txt[:4096]) >= 0.9 else None


def inflate(raw: bytes, *, gzip: bool) -> bytes | None:
    try:
        d = zlib.decompressobj(16 + zlib.MAX_WBITS if gzip else -zlib.MAX_WBITS)
        out = d.decompress(raw, MAX_DECOMPRESSED_BYTES)
    except zlib.error:
        return None
    return out or None


def unescape_js(text: str) -> str:
    return JS_ESCAPE_RE.sub(lambda m: chr(int(m.group(0)[2:], 16)), text)


def charcode_texts(norm: str) -> Iterator[str]:
    """Textos armados con fromCharCode / [char]N / Chr(N) (solo códigos imprimibles)."""
    for count, m in enumerate(_CHARCODE_CALL_RE.finditer(norm)):
        if count >= MAX_BLOB_CANDIDATES:
            break
        vals = parse_int_list(m.group(1), 100_000)
        if len(vals) >= 4 and all(9 <= v <= 0xFFFF for v in vals):
            yield "".join(chr(v) for v in vals)
    # tokens [char]N / Chr(N) consecutivos (separados por + & , espacios o comillas)
    run: list[int] = []
    last_end = -1
    produced = 0
    for m in _CHARCODE_TOKEN_RE.finditer(norm[:MAX_SCAN_CHARS]):
        tok = m.group(1) or m.group(2)
        try:
            val = int(tok, 16) if tok.lower().startswith("0x") else int(tok)
        except ValueError:
            continue
        if last_end >= 0 and m.start() - last_end > 12:
            if len(run) >= 4:
                yield "".join(chr(v) for v in run if 9 <= v <= 0xFFFF)
                produced += 1
                if produced >= MAX_BLOB_CANDIDATES:
                    return
            run = []
        run.append(val)
        last_end = m.end()
    if len(run) >= 4:
        yield "".join(chr(v) for v in run if 9 <= v <= 0xFFFF)


def _expand_cmd_vars(norm: str) -> str | None:
    """Expande `set x=...` + `%x%` / `%x:~a,b%` de archivos .bat ofuscados (solo variables definidas en el archivo)."""
    sets = _SET_VAR_RE.findall(norm[:MAX_SCAN_CHARS])
    if len(sets) < 3:
        return None
    env: dict[str, str] = {}
    for name, value in sets[:500]:
        env[name.lower()] = value
    uses = 0

    def repl(m: re.Match[str]) -> str:
        nonlocal uses
        val = env.get(m.group(1).lower())
        if val is None:
            return m.group(0)
        uses += 1
        if m.group(2) is None:
            return val
        start = int(m.group(2))
        if m.group(3) is None:
            return val[start:]
        length = int(m.group(3))
        begin = start if start >= 0 else max(0, len(val) + start)
        return val[begin : begin + length] if length >= 0 else val[begin:length]

    expanded = _VAR_USE_RE.sub(repl, norm[:MAX_SCAN_CHARS])
    return expanded if uses >= 3 else None


def scan_text(
    text: str,
    *,
    profile: str = "script",
    max_depth: int = MAX_DEPTH,
    assume: Iterable[str] = (),
) -> ScanResult:
    """Escanea `text` con los indicadores del perfil ("script", "html" o "pe"), decodificando capas.

    `assume` fija banderas de contexto conocidas de antemano: "ps" (es PowerShell, ej. un .ps1) o
    "wsh" (corre en Windows Script Host, ej. .js/.vbs/.hta).
    """
    return _Scanner(profile, max_depth, frozenset(assume)).run(text)


# --------------------------------------------------------------------------- hallazgos


@dataclass(frozen=True, slots=True)
class GroupSpec:
    title: str
    description: str  # admite {where}
    severity: Severity
    score: int
    category: FindingCategory = FindingCategory.SUSPICIOUS_FILE


_H, _M = Severity.HIGH, Severity.MEDIUM

GROUPS: dict[str, GroupSpec] = {
    "downloader": GroupSpec(
        "Descarga y ejecuta programas desde Internet",
        "El {where} tiene instrucciones para bajar algo de Internet y ejecutarlo o guardarlo en la computadora. "
        "Así entra la mayoría de los virus: el archivo parece inofensivo, pero al abrirlo descarga el programa malicioso.",
        _H,
        80,
    ),
    "amsi_bypass": GroupSpec(
        "Intenta apagar la protección antivirus de Windows",
        "El {where} intenta desactivar AMSI o el registro de eventos de Windows, los mecanismos que permiten al antivirus "
        "revisar scripts antes de ejecutarlos. Ningún programa legítimo hace esto.",
        _H,
        85,
    ),
    "defender_tamper": GroupSpec(
        "Intenta desactivar Windows Defender",
        "El {where} intenta agregar exclusiones o apagar la protección en tiempo real de Windows Defender para que "
        "el virus no sea detectado.",
        _H,
        80,
    ),
    "shadow_delete": GroupSpec(
        "Borra las copias de seguridad de Windows (típico de ransomware)",
        "El {where} borra las copias de respaldo internas de Windows. Es lo primero que hace un ransomware antes de "
        "cifrar los archivos, para que no se puedan recuperar.",
        _H,
        85,
        FindingCategory.MALWARE,
    ),
    "credential_theft": GroupSpec(
        "Herramienta de robo de contraseñas",
        "El {where} usa Mimikatz o técnicas equivalentes para sacar contraseñas de la memoria de Windows.",
        _H,
        85,
        FindingCategory.MALWARE,
    ),
    "reverse_shell": GroupSpec(
        "Abre una puerta de control remoto",
        "El {where} abre una conexión de red y ejecuta los comandos que recibe: le da a un atacante control remoto "
        "de la computadora.",
        _H,
        80,
        FindingCategory.MALWARE,
    ),
    "reflective_load": GroupSpec(
        "Carga programas directamente en la memoria",
        "El {where} carga código ejecutable directamente en memoria, sin guardarlo como archivo, una técnica usada "
        "para esquivar al antivirus.",
        _H,
        70,
    ),
    "lolbin": GroupSpec(
        "Usa herramientas de Windows para bajar o ejecutar programas",
        "El {where} usa programas propios de Windows (como certutil, mshta, bitsadmin, rundll32 o regsvr32) de forma "
        "abusiva para descargar o ejecutar código sin levantar sospechas.",
        _H,
        70,
    ),
    "privilege_escalation": GroupSpec(
        "Intenta obtener permisos de administrador sin avisar",
        "El {where} modifica el registro para saltear el aviso de control de cuentas (UAC) de Windows.",
        _H,
        70,
    ),
    "powershell_encoded": GroupSpec(
        "Comando de PowerShell oculto (codificado)",
        "El {where} contiene un comando de PowerShell codificado para que no se pueda leer a simple vista. "
        "Centinela lo decodificó y revisó su contenido.",
        _H,
        65,
    ),
    "powershell_stealth": GroupSpec(
        "PowerShell en modo oculto",
        "El {where} ejecuta PowerShell escondido (sin ventana, sin perfil o salteando las políticas de seguridad), "
        "algo típico de los programas maliciosos.",
        _M,
        45,
    ),
    "encoded_script": GroupSpec(
        "Script codificado para ocultar su contenido",
        "El {where} está codificado con 'Script Encoder' para que no se pueda leer. No hay motivo legítimo para "
        "mandar un script así por mail.",
        _H,
        75,
    ),
    "embedded_pe": GroupSpec(
        "Contiene un programa o archivo comprimido escondido",
        "El {where} tiene un archivo peligroso escondido adentro, codificado como texto. Es la técnica de los "
        "'droppers': al abrirse, sueltan el virus en la computadora.",
        _H,
        85,
    ),
    "persistence": GroupSpec(
        "Se configura para arrancar solo con Windows",
        "El {where} crea tareas programadas, servicios o entradas de inicio para volver a ejecutarse cada vez que se "
        "prende la computadora.",
        _M,
        45,
    ),
    "dynamic_exec": GroupSpec(
        "Ejecuta código armado en el momento",
        "El {where} arma texto y lo ejecuta como código (por ejemplo con Invoke-Expression o eval), una forma común "
        "de esconder lo que realmente hace.",
        _M,
        35,
    ),
    "com_objects": GroupSpec(
        "Usa componentes de Windows para ejecutar programas o manejar archivos",
        "El {where} usa objetos de Windows (WScript.Shell, Shell.Application, XMLHTTP, ADODB.Stream, FileSystemObject) "
        "que permiten ejecutar programas, bajar archivos o escribir en el disco.",
        _M,
        30,
    ),
    "obfuscation": GroupSpec(
        "Código ofuscado (escrito para que no se entienda)",
        "El {where} está escrito de forma deliberadamente ilegible (texto partido, codificado o invertido). Los "
        "programas legítimos no necesitan esconderse así.",
        _M,
        30,
    ),
}

# grupos que, si aparecen solos, describen la técnica de entrega (para el "resumen" en la evidencia)
STRONG_GROUPS = frozenset(
    {
        "downloader",
        "amsi_bypass",
        "defender_tamper",
        "shadow_delete",
        "credential_theft",
        "reverse_shell",
        "reflective_load",
        "lolbin",
        "privilege_escalation",
        "powershell_encoded",
        "encoded_script",
        "embedded_pe",
    }
)


def _layer_note(hits: list[IndicatorHit]) -> str | None:
    deep = [h for h in hits if h.layer > 0]
    if not deep:
        return None
    return f"encontrado después de decodificar: {deep[0].how}"


def findings_from_scan(
    result: ScanResult,
    *,
    analyzer: str,
    prefix: str,
    artifact_id: str | None,
    where: str,
    allowed_groups: frozenset[str] | None = None,
) -> list[Finding]:
    """Convierte un ScanResult en hallazgos agrupados (un hallazgo por técnica, con evidencia acotada)."""
    findings: list[Finding] = []
    groups = result.groups()

    def add(
        group: str, evidence: dict, *, score: int | None = None, severity: Severity | None = None
    ) -> None:
        if allowed_groups is not None and group not in allowed_groups:
            return
        spec = GROUPS[group]
        findings.append(
            Finding(
                analyzer=analyzer,
                rule=f"{prefix}.{group}",
                title=spec.title,
                description=spec.description.format(where=where),
                category=spec.category,
                severity=severity if severity is not None else spec.severity,
                score=score if score is not None else spec.score,
                artifact_id=artifact_id,
                evidence=evidence,
            )
        )

    def ev(hits: list[IndicatorHit]) -> dict:
        out: dict = {
            "indicadores": cap_list(h.label for h in hits),
            "fragmentos": cap_list((h.snippet for h in hits if h.snippet), 4),
        }
        note = _layer_note(hits)
        if note:
            out["capa"] = note
        return out

    # descarga + ejecución / escritura
    fetch, exec_, write = "fetch" in result.roles, "exec" in result.roles, "write" in result.roles
    if fetch and (exec_ or write):
        role_hits = [h for h in result.hits.values() if _roles_of(h.key) & {"fetch", "exec", "write"}]
        e = ev(role_hits)
        e["acciones"] = [
            r for r, ok in (("descarga", fetch), ("guarda en disco", write), ("ejecuta", exec_)) if ok
        ]
        add("downloader", e, score=80 if exec_ else 65)

    for group, hits in groups.items():
        if group in ("obfuscation",):
            continue
        e = ev(hits)
        if group == "powershell_encoded":
            previews = [p for how, _d, p in result.layers if how == "PowerShell -EncodedCommand"]
            if previews:
                e["comando_decodificado"] = previews[0]
        if group == "powershell_stealth":
            distinct = len({h.key for h in hits})
            add(
                group,
                e,
                score=60 if distinct >= 2 else 45,
                severity=Severity.HIGH if distinct >= 2 else Severity.MEDIUM,
            )
            continue
        add(group, e)

    if result.payloads:
        add(
            "embedded_pe",
            {
                "contenido": cap_list(PAYLOAD_LABELS.get(p.kind, p.kind) for p in result.payloads),
                "codificacion": cap_list(p.how for p in result.payloads),
            },
        )

    obf = list(result.obfuscation)
    obf_hits = [h for h in result.hits.values() if "obf" in _roles_of(h.key)]
    if obf_hits:
        obf.append(("iex_obf", obf_hits[0].label))
    if len(result.layers) >= 2 or any(depth >= 2 for _how, depth, _p in result.layers):
        obf.append(("layers", f"{len(result.layers)} capas de codificación"))
    if obf:
        n = len(obf)
        score, sev = (
            (30, Severity.MEDIUM) if n == 1 else (45, Severity.MEDIUM) if n == 2 else (60, Severity.HIGH)
        )
        add("obfuscation", {"senales": cap_list(label for _k, label in obf)}, score=score, severity=sev)
    return findings


_ROLES_BY_KEY: dict[str, frozenset[str]] = {i.key: i.roles for i in INDICATORS}


def _roles_of(key: str) -> frozenset[str]:
    return _ROLES_BY_KEY.get(key, frozenset())


def hit_summary(result: ScanResult, limit: int = MAX_EVIDENCE_ITEMS) -> list[str]:
    """Lista corta de indicadores encontrados (para la evidencia de hallazgos base)."""
    return cap_list((h.label for h in result.hits.values()), limit)
