"""Pipeline de análisis: RawMessage -> AnalysisResult.

parse (MIME + desempaquetado recursivo) -> analizadores en paralelo (con timeout c/u) -> scoring -> resultado.
No etiqueta ni alerta: eso lo hace centinela.actions.dispatcher con el resultado.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING

from centinela.analyzers.base import AnalysisContext, Analyzer, ArtifactAnalyzer, MessageAnalyzer
from centinela.core.models import (
    AnalysisResult,
    ArtifactSummary,
    Finding,
    FindingCategory,
    ParsedMessage,
    RawMessage,
    Severity,
    Verdict,
    VerdictLevel,
)
from centinela.core.scoring import score_findings
from centinela.parsing.mime import parse_message

if TYPE_CHECKING:
    import httpx

    from centinela.core.cache import Cache
    from centinela.core.config import Settings
    from centinela.core.models import Artifact

log = logging.getLogger(__name__)


class Pipeline:
    def __init__(
        self,
        settings: Settings,
        analyzers: list[Analyzer],
        http: httpx.AsyncClient,
        cache: Cache,
        *,
        concurrency: int = 8,
    ) -> None:
        self.settings = settings
        self.analyzers = analyzers
        self.http = http
        self.cache = cache
        self._sem = asyncio.Semaphore(concurrency)
        self._ready = False

    async def setup(self) -> None:
        if self._ready:
            return
        ok: list[Analyzer] = []
        for a in self.analyzers:
            try:
                await a.setup()
                ok.append(a)
            except Exception:
                log.exception("no se pudo inicializar el analizador %s; se omite", a.name)
        self.analyzers = ok
        self._ready = True

    async def close(self) -> None:
        for a in self.analyzers:
            try:
                await a.close()
            except Exception:  # noqa: BLE001
                log.debug("error cerrando %s", a.name, exc_info=True)

    async def _run(self, label: str, coro, errors: list[str]) -> list[Finding]:
        async with self._sem:
            try:
                return list(
                    await asyncio.wait_for(coro, timeout=self.settings.limits.analyzer_timeout_s) or []
                )
            except TimeoutError:
                errors.append(f"{label}: timeout")
            except Exception as exc:
                log.exception("analizador falló: %s", label)
                errors.append(f"{label}: {type(exc).__name__}: {exc}"[:500])
            return []

    async def analyze(self, raw: RawMessage) -> AnalysisResult:
        await self.setup()
        t0 = time.perf_counter()
        errors: list[str] = []
        try:
            parsed: ParsedMessage = await asyncio.to_thread(parse_message, raw, self.settings.limits)
        except Exception as exc:
            log.exception("no se pudo parsear el mensaje %s", raw.ref)
            return AnalysisResult(
                ref=raw.ref,
                received_at=raw.received_at,
                size=len(raw.raw),
                verdict=Verdict(level=VerdictLevel.ERROR, score=0, summary="No se pudo leer el mensaje."),
                errors=[f"parse: {type(exc).__name__}: {exc}"[:500]],
                duration_ms=int((time.perf_counter() - t0) * 1000),
            )
        errors.extend(f"parse: {e}" for e in parsed.parse_errors)

        ctx = AnalysisContext(settings=self.settings, message=parsed, http=self.http, cache=self.cache)
        tasks = []
        for a in self.analyzers:
            if isinstance(a, MessageAnalyzer):
                tasks.append(self._run(a.name, a.analyze(ctx), errors))
            elif isinstance(a, ArtifactAnalyzer):
                for art in parsed.artifacts:
                    if self._accepts(a, art, errors):
                        tasks.append(self._run(f"{a.name}[{art.id}]", a.analyze(ctx, art), errors))

        try:
            results = await asyncio.wait_for(
                asyncio.gather(*tasks), timeout=self.settings.limits.message_timeout_s
            )
        except TimeoutError:
            results = []
            errors.append("pipeline: timeout global del mensaje")

        findings = _dedupe([f for group in results for f in group])
        if raw.truncated:
            findings.append(_truncated_finding(raw, self.settings.limits.max_message_bytes))
        verdict = score_findings(findings, self.settings.scoring, parsed)
        if errors and not findings and verdict.level == VerdictLevel.CLEAN and len(parsed.artifacts) > 0:
            # hubo adjuntos y algún analizador falló: no afirmar "limpio" con confianza
            verdict = verdict.model_copy(
                update={"summary": verdict.summary + " (análisis parcial: ver errores)"}
            )

        return AnalysisResult(
            ref=raw.ref,
            message_id=parsed.message_id,
            subject=parsed.subject,
            from_addr=parsed.from_addr,
            from_display=parsed.from_display,
            to=parsed.to,
            received_at=raw.received_at,
            size=parsed.size or len(raw.raw),
            artifacts=[ArtifactSummary.from_artifact(a) for a in parsed.artifacts],
            urls=parsed.urls,
            findings=sorted(findings, key=lambda f: (-int(f.severity), -f.score)),
            verdict=verdict,
            errors=errors,
            truncated=raw.truncated,
            duration_ms=int((time.perf_counter() - t0) * 1000),
        )

    @staticmethod
    def _accepts(a: ArtifactAnalyzer, art: Artifact, errors: list[str]) -> bool:
        try:
            return a.accepts(art)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{a.name}.accepts[{art.id}]: {exc}"[:300])
            return False


def _truncated_finding(raw: RawMessage, limit: int) -> Finding:
    size = raw.original_size or 0
    return Finding(
        analyzer="pipeline",
        rule="policy.message_too_large",
        title="Mail demasiado grande: no se pudo analizar completo",
        description=(
            f"El mail pesa {size / 1_048_576:.0f} MB y supera el límite de análisis ({limit / 1_048_576:.0f} MB), "
            "así que solo se revisaron el remitente y los encabezados, no los adjuntos. Mandar archivos enormes es "
            "un truco conocido para esquivar los antivirus: tratalo con cuidado."
        ),
        category=FindingCategory.POLICY,
        severity=Severity.MEDIUM,
        score=35,
        evidence={"tamano_bytes": size, "limite_bytes": limit},
    )


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str | None, str | None]] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.rule, f.artifact_id, f.dedupe_key)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out
