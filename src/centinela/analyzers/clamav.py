"""Analizador ClamAV: escanea cada archivo con clamd por TCP usando el protocolo INSTREAM.

Protocolo (docs.clamav.net/manual/Usage/ClamdProtocol.html):
    -> "zINSTREAM\\0"
    -> [longitud de 4 bytes big-endian][datos] ... repetido por cada bloque
    -> 00 00 00 00                                   (fin del stream)
    <- "stream: OK\\0" | "stream: <Firma> FOUND\\0" | "INSTREAM size limit exceeded. ERROR\\0"
Para comandos sin sesión clamd cierra la conexión después de responder: se leen respuestas hasta EOF.

- Una conexión por escaneo (clamd no mantiene estado entre escaneos y así un error no contamina otros).
- Tope local `analyzers.clamav.max_stream_bytes` (igual o menor que StreamMaxLength de clamd): lo que lo
  supera no se manda y queda un INFO "clamav.too_large". Las entradas "solo listadas" (sin bytes) se saltean.
- Si clamd no responde, `analyze` levanta ConnectionError: el pipeline lo registra en `errors` y el
  veredicto no se presenta como "limpio con confianza".
- `setup()` NUNCA falla si clamd está caído (en Docker suele tardar en cargar las firmas): solo avisa.
- Los archivos viajan solo a clamd (contenedor propio de la empresa), nunca a terceros.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING

from centinela.analyzers.base import ArtifactAnalyzer
from centinela.analyzers.reputation import canonical_family, known_family
from centinela.core.models import Finding, FindingCategory, Severity

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from centinela.analyzers.base import AnalysisContext
    from centinela.core.config import Settings
    from centinela.core.models import Artifact

log = logging.getLogger(__name__)

DEFAULT_MAX_STREAM_BYTES = 25 * 1024 * 1024  # StreamMaxLength histórico de clamd (las versiones nuevas: 100M)
_CHUNK_BYTES = 256 * 1024
_MAX_REPLY_BYTES = 64 * 1024
_REPLY_IDLE_S = 0.5  # tras una respuesta completa, cuánto esperar por más (modo AllMatch) antes de cortar
_FOUND_RE = re.compile(r"^(?:stream:\s*)?(?P<sig>.+?)\s+FOUND$")
_OFFICIAL_RE = re.compile(
    r"^(?P<platform>[A-Za-z0-9]+)\.(?P<cat>[A-Za-z0-9]+)\.(?P<name>.+?)-(?P<sid>\d+)-(?P<rev>\d+)$"
)
_RULE_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")


class ClamdError(RuntimeError):
    """clamd respondió con un error o algo que no entendemos."""


class ClamdUnavailableError(ConnectionError):
    """No se pudo hablar con clamd (caído, rechazó la conexión o no respondió a tiempo)."""


# --------------------------------------------------------------------------- clasificación de firmas


@dataclass(frozen=True)
class SignatureInfo:
    signature: str
    kind: str  # malware | test | heuristic | pua | phishing | spam | policy
    category: FindingCategory
    severity: Severity
    score: int
    family: str | None
    official: bool


def _tokens(name: str) -> list[str]:
    return [t for t in re.split(r"[.\-_:/ ]+", name) if t]


def classify_signature(signature: str) -> SignatureInfo:
    """Mapea un nombre de firma de ClamAV (oficial o de terceros) a severidad/categoría/familia.

    Oficiales: <Plataforma>.<Categoría>.<Nombre>-<id>-<rev> (ej: Win.Trojan.AgentTesla-9876543-0).
    clamd agrega ".UNOFFICIAL" a toda firma que no viene de las bases oficiales (Sanesecurity,
    SecuriteInfo, URLhaus, reglas YARA cargadas en clamd...).
    """
    sig = signature.strip()[:300]
    unofficial = sig.upper().endswith(".UNOFFICIAL")
    base = sig[: -len(".UNOFFICIAL")] if unofficial else sig
    lower = base.lower()
    toks = [t.lower() for t in _tokens(base)]
    official = not unofficial

    def mk(
        kind: str, cat: FindingCategory, sev: Severity, score: int, family: str | None = None
    ) -> SignatureInfo:
        return SignatureInfo(sig, kind, cat, sev, score, family, official)

    # --- heurísticas del motor
    if lower.startswith("heuristics."):
        if lower.startswith(("heuristics.limits.exceeded", "heuristics.exceeds")):
            return mk("policy", FindingCategory.POLICY, Severity.INFO, 0)
        if lower.startswith("heuristics.encrypted"):
            return mk("policy", FindingCategory.POLICY, Severity.INFO, 0)
        if lower.startswith("heuristics.structured"):  # DLP: números de tarjeta, etc.
            return mk("policy", FindingCategory.POLICY, Severity.INFO, 0)
        if lower.startswith("heuristics.phishing"):
            return mk("phishing", FindingCategory.PHISHING, Severity.MEDIUM, 35)
        if lower.startswith(("heuristics.broken", "heuristics.ole2.containsmacros")):
            return mk("heuristic", FindingCategory.SUSPICIOUS_FILE, Severity.LOW, 10)
        return mk("heuristic", FindingCategory.SUSPICIOUS_FILE, Severity.MEDIUM, 30)

    # --- programas potencialmente no deseados
    if lower.startswith("pua."):
        return mk("pua", FindingCategory.SUSPICIOUS_FILE, Severity.LOW, 15)

    # --- archivos de prueba (EICAR): se tratan como malware para poder probar las alertas de punta a punta
    if "eicar" in lower or "test" in toks[1:2] or lower.startswith("clamav.test"):
        return mk("test", FindingCategory.MALWARE, Severity.CRITICAL, 95, "EICAR-Test-File")

    # --- phishing
    if lower.startswith("phishing.") or any(t.startswith("phish") for t in toks):
        return mk("phishing", FindingCategory.PHISHING, Severity.MEDIUM, 45)

    # --- spam / estafas / listas de URLs basura (Sanesecurity y similares)
    if any(t in ("scam", "jurlbl", "lott", "lotto", "419") for t in toks):
        return mk("spam", FindingCategory.PHISHING, Severity.LOW, 15)
    if any(t in ("spam", "junk", "hdr", "img", "spamimg") for t in toks):
        return mk("spam", FindingCategory.PHISHING, Severity.LOW, 5)

    # --- heurísticas de terceros sobre tipos de archivo riesgosos / macros
    if "foxhole" in toks:
        return mk("heuristic", FindingCategory.SUSPICIOUS_FILE, Severity.MEDIUM, 35)
    if "badmacro" in toks:
        return mk("heuristic", FindingCategory.SUSPICIOUS_FILE, Severity.HIGH, 70)

    # --- firmas oficiales con formato moderno
    m = _OFFICIAL_RE.match(base)
    if m and official:
        cat = m.group("cat").lower()
        family = canonical_family(m.group("name"))
        if cat == "revoked":
            return mk("policy", FindingCategory.POLICY, Severity.INFO, 0)
        if cat in ("adware", "joke"):  # no son familias de malware: sin malware_family
            return mk("pua", FindingCategory.SUSPICIOUS_FILE, Severity.LOW, 15)
        if cat in ("tool", "countermeasure", "proxy"):
            return mk("heuristic", FindingCategory.SUSPICIOUS_FILE, Severity.HIGH, 65, family)
        if cat == "phishing":
            return mk("phishing", FindingCategory.PHISHING, Severity.MEDIUM, 45)
        return mk("malware", FindingCategory.MALWARE, Severity.CRITICAL, 95, family)

    if official:
        # firma oficial con nombre "viejo" (ej: "Trojan.Agent-12345", "Worm.Mydoom.M")
        family = next((f for f in (known_family(t) for t in toks) if f), None)
        return mk("malware", FindingCategory.MALWARE, Severity.CRITICAL, 95, family)

    # --- firmas de terceros: más falsos positivos que las oficiales => HIGH, no CRITICAL
    family = next((f for f in (known_family(t) for t in toks) if f), None)
    return mk("malware", FindingCategory.MALWARE, Severity.HIGH, 80, family)


_KIND_TEXT: dict[str, tuple[str, str]] = {
    "malware": (
        "El antivirus detectó malware",
        "El antivirus ClamAV (que corre dentro de la empresa) identificó este archivo como malicioso. "
        "No lo abras ni lo reenvíes; si alguien ya lo abrió, avisá a quien maneje la seguridad.",
    ),
    "test": (
        "El antivirus detectó el archivo de prueba EICAR",
        "Es el archivo de prueba estándar de antivirus (no es dañino): sirve para comprobar que la "
        "detección y las alertas funcionan.",
    ),
    "heuristic": (
        "El antivirus marcó el archivo como sospechoso",
        "ClamAV encontró características típicas de archivos maliciosos, aunque no una firma exacta. "
        "Tratalo con cuidado y confirmá con el remitente por otro medio antes de abrirlo.",
    ),
    "pua": (
        "El antivirus detectó un programa potencialmente no deseado",
        "ClamAV identificó una herramienta o programa que no es necesariamente un virus, pero que no "
        "debería llegar por mail (adware, herramientas de hacking, empaquetadores).",
    ),
    "phishing": (
        "El antivirus detectó contenido de phishing",
        "ClamAV identificó contenido usado para robar contraseñas o datos (phishing). No ingreses tus "
        "datos ni hagas clic en los links.",
    ),
    "spam": (
        "El antivirus detectó contenido de spam o estafa",
        "ClamAV identificó contenido asociado a spam o estafas conocidas.",
    ),
    "policy": (
        "El antivirus no pudo revisar el archivo por completo",
        "ClamAV no pudo analizar todo el contenido (archivo cifrado, demasiado grande o con límites "
        "superados). Otros analizadores sí lo revisaron.",
    ),
}


def _human_size(n: int) -> str:
    if n >= 1024 * 1024:
        return f"{n / (1024 * 1024):.0f} MB"
    if n >= 1024:
        return f"{n / 1024:.0f} KB"
    return f"{n} bytes"


def _rule_id(signature: str) -> str:
    safe = _RULE_SAFE_RE.sub("_", signature).strip("._-")[:120]
    return f"clamav.{safe or 'unknown'}"


def finding_for_signature(
    signature: str, artifact_id: str | None, engine_version: str | None = None
) -> Finding:
    info = classify_signature(signature)
    title, description = _KIND_TEXT[info.kind]
    if info.kind == "malware" and info.family:
        title = f"El antivirus detectó malware: {info.family}"
    evidence: dict[str, object] = {
        "engine": "clamav",
        "signature": info.signature,
        "official": info.official,
        "kind": info.kind,
    }
    if engine_version:
        evidence["engine_version"] = engine_version
    return Finding(
        analyzer="clamav",
        rule=_rule_id(info.signature),
        title=title,
        description=description,
        category=info.category,
        severity=info.severity,
        score=info.score,
        artifact_id=artifact_id,
        malware_family=info.family,
        evidence=evidence,
    )


# --------------------------------------------------------------------------- analizador


async def _read_replies(reader: asyncio.StreamReader) -> list[str]:
    """Lee respuestas terminadas en NUL hasta EOF (o hasta que no llegue nada más tras una completa)."""
    buf = bytearray()
    while len(buf) < _MAX_REPLY_BYTES:
        try:
            if b"\0" in buf:
                try:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=_REPLY_IDLE_S)
                except TimeoutError:
                    break
            else:
                chunk = await reader.read(4096)
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            if buf:  # clamd ya respondió y cortó (p.ej. al superar StreamMaxLength)
                break
            raise
        if not chunk:
            break
        buf += chunk
    text = bytes(buf[:_MAX_REPLY_BYTES]).decode("utf-8", "replace")
    return [p.strip() for p in re.split(r"[\0\n]", text) if p.strip()]


class ClamAVAnalyzer(ArtifactAnalyzer):
    name = "clamav"
    max_stream_bytes: int = DEFAULT_MAX_STREAM_BYTES
    max_concurrent_scans: int = 4  # clamd atiende pocos hilos (MaxThreads=10 por defecto)

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self._sem = asyncio.Semaphore(self.max_concurrent_scans)
        self.engine_version: str | None = None
        # analyzers.clamav.max_stream_bytes (igual o menor que StreamMaxLength de clamd)
        configured = int(settings.analyzers.clamav.max_stream_bytes or 0)
        self.max_stream_bytes = configured if configured > 0 else DEFAULT_MAX_STREAM_BYTES

    @classmethod
    def enabled(cls, settings: Settings) -> bool:
        return super().enabled(settings) and settings.analyzers.clamav.enabled

    @property
    def _addr(self) -> str:
        cfg = self.settings.analyzers.clamav
        return f"{cfg.host}:{cfg.port}"

    async def setup(self) -> None:
        if await self.ping():
            self.engine_version = await self.version()
            log.info("clamd disponible en %s (%s)", self._addr, self.engine_version or "versión desconocida")
        else:
            log.warning(
                "clamd no responde en %s: los archivos se analizarán sin antivirus hasta que vuelva",
                self._addr,
            )

    def accepts(self, artifact: Artifact) -> bool:
        # entradas solo listadas (zip cifrado, demasiado grandes...): no hay bytes que escanear
        return bool(artifact.data) and not artifact.listing_only

    # ----------------------------------------------------------------- protocolo

    async def _session(self, payload_writer: Callable[[asyncio.StreamWriter], Awaitable[None]]) -> list[str]:
        cfg = self.settings.analyzers.clamav
        try:
            async with asyncio.timeout(cfg.timeout_s):
                reader, writer = await asyncio.open_connection(cfg.host, cfg.port)
                try:
                    write_error: BaseException | None = None
                    try:
                        await payload_writer(writer)
                    except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError) as exc:
                        # clamd corta la conexión al superar StreamMaxLength, pero antes manda la respuesta
                        write_error = exc
                    replies = await _read_replies(reader)
                    if not replies and write_error is not None:
                        raise ClamdUnavailableError(
                            f"clamd ({self._addr}) cortó la conexión: {type(write_error).__name__}"
                        ) from write_error
                    return replies
                finally:
                    writer.close()
                    with contextlib.suppress(Exception):
                        await writer.wait_closed()
        except ClamdUnavailableError:
            raise
        except TimeoutError as exc:
            raise ClamdUnavailableError(f"clamd ({self._addr}) no respondió en {cfg.timeout_s:g}s") from exc
        except OSError as exc:
            raise ClamdUnavailableError(f"no se pudo conectar a clamd en {self._addr}: {exc}") from exc

    async def _command(self, command: bytes) -> list[str]:
        async def send(writer: asyncio.StreamWriter) -> None:
            writer.write(command)
            await writer.drain()

        return await self._session(send)

    async def ping(self) -> bool:
        """True si clamd responde PONG. Nunca levanta excepciones (lo usa el health check)."""
        try:
            replies = await self._command(b"zPING\0")
        except (ConnectionError, ClamdError, OSError):
            return False
        return bool(replies) and replies[0] == "PONG"

    async def version(self) -> str | None:
        try:
            replies = await self._command(b"zVERSION\0")
        except (ConnectionError, ClamdError, OSError):
            return None
        return replies[0][:120] if replies else None

    async def scan_bytes(self, data: bytes) -> list[str]:
        """Manda `data` por INSTREAM y devuelve las líneas de respuesta de clamd."""

        async def send(writer: asyncio.StreamWriter) -> None:
            writer.write(b"zINSTREAM\0")
            view = memoryview(data)
            for off in range(0, len(view), _CHUNK_BYTES):
                chunk = view[off : off + _CHUNK_BYTES]
                writer.write(struct.pack(">I", len(chunk)))
                writer.write(chunk)
                await writer.drain()
            writer.write(b"\0\0\0\0")
            await writer.drain()

        async with self._sem:
            return await self._session(send)

    # ----------------------------------------------------------------- análisis

    async def analyze(self, ctx: AnalysisContext, artifact: Artifact) -> list[Finding]:
        data = artifact.data
        if not data or artifact.listing_only:
            return []
        if len(data) > self.max_stream_bytes:
            return [self._too_large(artifact, len(data))]
        replies = await self.scan_bytes(data)
        return self._parse_replies(replies, artifact)

    def _parse_replies(self, replies: list[str], artifact: Artifact) -> list[Finding]:
        if not replies:
            raise ClamdError("clamd cerró la conexión sin responder")
        findings: list[Finding] = []
        seen: set[str] = set()
        clean = False
        for line in replies[:20]:
            if line in ("stream: OK", "OK"):
                clean = True
                continue
            if line.endswith("ERROR"):
                if "size limit exceeded" in line.lower():
                    return [self._too_large(artifact, len(artifact.data), clamd_limit=True)]
                raise ClamdError(f"clamd devolvió un error: {line[:200]}")
            m = _FOUND_RE.match(line)
            if m:
                sig = m.group("sig").strip()
                if sig and sig not in seen:
                    seen.add(sig)
                    findings.append(finding_for_signature(sig, artifact.id, self.engine_version))
                continue
            raise ClamdError(f"respuesta inesperada de clamd: {line[:120]!r}")
        if not findings and not clean:
            raise ClamdError("clamd no informó resultado")
        return findings

    def _too_large(self, artifact: Artifact, size: int, *, clamd_limit: bool = False) -> Finding:
        if clamd_limit:
            detail = "supera el tamaño máximo que acepta el antivirus (StreamMaxLength de clamd)"
        else:
            detail = f"supera el límite de {_human_size(self.max_stream_bytes)} para el antivirus"
        return Finding(
            analyzer=self.name,
            rule="clamav.too_large",
            title="El antivirus no revisó el archivo por su tamaño",
            description=(
                f"El archivo {detail}, así que ClamAV no lo analizó. Los demás analizadores (reglas YARA, "
                "estructura del archivo, reputación del hash) sí lo revisaron."
            ),
            category=FindingCategory.POLICY,
            severity=Severity.INFO,
            score=0,
            artifact_id=artifact.id,
            evidence={"size": size, "limit": self.max_stream_bytes, "clamd_limit": clamd_limit},
        )


__all__ = [
    "ClamAVAnalyzer",
    "ClamdError",
    "ClamdUnavailableError",
    "SignatureInfo",
    "classify_signature",
    "finding_for_signature",
]
