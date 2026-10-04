"""Analizador de scripts adjuntos (.js, .vbs, .ps1, .bat/.cmd, .wsf, Python, shell...).

Un script adjunto no es un documento: con doble clic, Windows lo ejecuta. Por eso cualquier script
recibe una señal base (MEDIUM) y además se buscan técnicas concretas con el motor compartido de
`_indicators` (descarga + ejecución, PowerShell codificado, LOLBins, evasión de Defender/AMSI,
persistencia, payloads embebidos, ofuscación), que decodifica capas antes de buscar.

Los .hta los analiza `HtmlAnalyzer` (son HTML con permisos completos); acá se excluyen para no
duplicar hallazgos.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, ClassVar

from centinela.analyzers import _indicators as ind
from centinela.analyzers.base import ArtifactAnalyzer
from centinela.core.models import Finding, FindingCategory, Severity

if TYPE_CHECKING:
    from centinela.analyzers.base import AnalysisContext
    from centinela.core.models import Artifact

log = logging.getLogger(__name__)

# subtipo -> (descripción para humanos, contexto asumido para el motor de indicadores)
_KINDS: dict[str, tuple[str, tuple[str, ...]]] = {
    "js": ("JavaScript", ("wsh",)),
    "vbs": ("VBScript", ("wsh",)),
    "wsf": ("Windows Script File", ("wsh",)),
    "ps1": ("PowerShell", ("ps",)),
    "bat": ("archivo de comandos .bat/.cmd", ()),
    "vba": ("macro VBA", ("wsh",)),
    "python": ("Python", ()),
    "sh": ("script de Linux/macOS", ()),
}
_WINDOWS_DOUBLE_CLICK = frozenset({"js", "vbs", "wsf", "bat", "ps1"})


class ScriptAnalyzer(ArtifactAnalyzer):
    name: ClassVar[str] = "scripts"

    def accepts(self, artifact: Artifact) -> bool:
        t = artifact.detected_type or ""
        return t.startswith("script/") and t != "script/hta"

    async def analyze(self, ctx: AnalysisContext, artifact: Artifact) -> list[Finding]:
        return await asyncio.to_thread(self._analyze_sync, artifact)

    # ------------------------------------------------------------------ síncrono (en thread)
    def _analyze_sync(self, artifact: Artifact) -> list[Finding]:
        kind = (artifact.detected_type or "").partition("/")[2] or "desconocido"
        label, assume = _KINDS.get(kind, (kind, ()))
        findings: list[Finding] = []

        data = artifact.data or b""
        text, truncated = ind.decode_text(data, ind.MAX_TEXT_BYTES)
        result = ind.scan_text(text, profile="script", assume=assume) if text else None

        # VBA extraída de un documento Office (depth > 0): la señal base la pone el analizador de Office.
        if not (kind == "vba" and artifact.depth > 0):
            findings.append(self._baseline(artifact, kind, label, result, truncated, empty=not data))

        if result is not None:
            where = f"script adjunto ({label})"
            findings.extend(
                ind.findings_from_scan(
                    result, analyzer=self.name, prefix="script", artifact_id=artifact.id, where=where
                )
            )
        return findings

    def _baseline(
        self,
        artifact: Artifact,
        kind: str,
        label: str,
        result: ind.ScanResult | None,
        truncated: bool,
        *,
        empty: bool,
    ) -> Finding:
        nested = artifact.depth > 0
        if kind in _WINDOWS_DOUBLE_CLICK:
            how = "Con doble clic, Windows lo ejecuta directamente: no es un documento."
        else:
            how = "Es código que puede ejecutar comandos en la computadora: no es un documento."
        where = "dentro de un archivo comprimido o imagen de disco" if nested else "como adjunto"
        evidence: dict = {"tipo": label, "archivo": ind.clean_snippet(artifact.filename or "", 120)}
        if nested:
            evidence["dentro_de"] = artifact.parent_id
        if result is not None and result.hits:
            evidence["indicadores"] = ind.hit_summary(result)
        if truncated or (result is not None and result.truncated):
            evidence["nota"] = "archivo muy grande: se revisó solo una parte"
        if empty:
            evidence["nota"] = "no se pudo leer el contenido (posiblemente excede los límites de tamaño)"
        return Finding(
            analyzer=self.name,
            rule="script.attachment",
            title=f"Script adjunto ({label})",
            description=(
                f"Llegó un archivo de script ({label}) {where}. {how} Proveedores y clientes casi nunca mandan "
                "scripts por mail: no lo abras salvo que lo estés esperando y sepas quién lo armó."
            ),
            category=FindingCategory.SUSPICIOUS_FILE,
            severity=Severity.MEDIUM,
            score=40,
            artifact_id=artifact.id,
            evidence=evidence,
        )
