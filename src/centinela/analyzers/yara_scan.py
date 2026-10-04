"""Analizador YARA: aplica las reglas de `rules/yara/**` (y carpetas extra) a cada archivo.

Motor: YARA-X (`yara_x`), con `yara-python` como alternativa si YARA-X no está instalado.

- Se compilan todos los *.yar / *.yara de cada carpeta de `analyzers.yara.rules_dirs`, recursivamente.
  Rutas relativas: primero contra el directorio de trabajo, después contra la raíz del proyecto.
- Cada archivo va en su propio namespace. Primero se compila cada archivo por separado para encontrar
  los rotos (se saltean con un warning) y después se compila el conjunto sano.
- Variables externas disponibles para reglas de la comunidad (signature-base las usa):
  filename, filepath, extension, filetype, owner.
- El escaneo (CPU) corre en `asyncio.to_thread`. Los `yara_x.Scanner` NO se pueden compartir entre
  hilos (pyo3 "unsendable"): hay un Scanner por hilo (threading.local), regenerado si se recargan reglas.
- La evidencia incluye ids de patrones y offsets, y como mucho 64 caracteres imprimibles por patrón.
- Se saltean los artifacts sin bytes: vacíos y entradas "solo listadas" (`listing_only`).
"""

from __future__ import annotations

import asyncio
import importlib
import itertools
import logging
import re
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from centinela.analyzers.base import ArtifactAnalyzer
from centinela.analyzers.reputation import canonical_family
from centinela.core.models import Finding, FindingCategory, Severity

if TYPE_CHECKING:
    from centinela.analyzers.base import AnalysisContext
    from centinela.core.config import Settings
    from centinela.core.models import Artifact

log = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[3]
_ENGINE_MODULES: tuple[str, ...] = ("yara_x", "yara")
_RULE_SUFFIXES = frozenset({".yar", ".yara"})
_MAX_RULE_FILES = 5000
_MAX_RULE_FILE_BYTES = 5 * 1024 * 1024
_MAX_MATCHES_PER_PATTERN = 100
_MAX_PATTERNS_IN_EVIDENCE = 20
_MAX_OFFSETS = 5
_SNIPPET_CHARS = 64
_EXTERNALS: dict[str, str] = {"filename": "", "filepath": "", "extension": "", "filetype": "", "owner": ""}
_MAX_SCANNERS_PER_THREAD = 4

# Estado por hilo a nivel de módulo (nunca se destruye): los yara_x.Scanner son "unsendable" y deben
# liberarse en el hilo que los creó. Un threading.local por instancia se liberaría desde el hilo que
# suelta la instancia (normalmente el principal), rompiendo esa regla.
_THREAD_STATE = threading.local()
# generación global de conjuntos de reglas compilados (única en todo el proceso)
_GENERATIONS = itertools.count(1)

_FAMILY_CATEGORIES = frozenset(
    {
        "rat",
        "stealer",
        "infostealer",
        "loader",
        "ransomware",
        "backdoor",
        "trojan",
        "keylogger",
        "worm",
        "miner",
    }
)
_SUSPICIOUS_CATEGORIES = frozenset({"technique", "generic", "exploit", "hacktool", "suspicious", "pua"})
_SEVERITY_NAMES = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}
_DEFAULT_SCORE = {
    Severity.CRITICAL: 95,
    Severity.HIGH: 75,
    Severity.MEDIUM: 40,
    Severity.LOW: 10,
    Severity.INFO: 0,
}
_CATEGORY_TITLES = {
    "rat": "Troyano de acceso remoto (RAT)",
    "stealer": "Programa ladrón de contraseñas (stealer)",
    "infostealer": "Programa ladrón de contraseñas (stealer)",
    "keylogger": "Programa que registra lo que se teclea (keylogger)",
    "loader": "Descargador de malware (loader)",
    "ransomware": "Ransomware (secuestro de archivos)",
    "backdoor": "Puerta trasera (backdoor)",
    "trojan": "Troyano",
    "worm": "Gusano",
    "miner": "Minero de criptomonedas",
}


class ScanTimeoutError(Exception):
    """El escaneo superó `analyzers.yara.timeout_s`."""


# --------------------------------------------------------------------------- modelo interno


@dataclass(frozen=True)
class RuleFile:
    path: Path
    namespace: str
    display: str  # ruta relativa legible (para logs y evidencia)
    source: str


@dataclass
class PatternHit:
    identifier: str
    offsets: list[int]
    count: int
    sample: str


@dataclass
class RuleHit:
    rule: str
    namespace: str
    meta: dict[str, Any]
    tags: list[str]
    patterns: list[PatternHit] = field(default_factory=list)


@dataclass
class CompiledRuleset:
    rules: Any
    engine: str
    loaded_files: list[str]
    skipped_files: dict[str, str]
    rule_count: int
    namespaces: dict[str, str]  # namespace -> archivo


def _snippet(data: bytes, offset: int, length: int) -> str:
    """Hasta 64 caracteres imprimibles del texto que coincidió (UTF-16LE se decodifica)."""
    if offset < 0 or offset >= len(data):
        return ""
    raw = data[offset : offset + max(0, min(length, _SNIPPET_CHARS * 2))]
    if len(raw) >= 4 and all(b == 0 for b in raw[1::2]) and any(raw[0::2]):
        text = raw.decode("utf-16-le", "replace")
    else:
        text = raw.decode("latin-1")
    return "".join(ch if ch.isprintable() and ch != "�" else "." for ch in text)[:_SNIPPET_CHARS]


def _plain(value: Any) -> Any:
    """Valor de meta -> tipo JSON (bytes -> texto imprimible)."""
    if isinstance(value, bool | int | float):
        return value
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    text = str(value)
    return "".join(ch if ch.isprintable() else " " for ch in text)[:2000]


def _meta_dict(items: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    pairs = items.items() if isinstance(items, dict) else items or ()
    for pair in pairs:
        try:
            key, value = pair
        except (TypeError, ValueError):
            continue
        key = str(key)
        if key not in out:  # si se repite, gana la primera
            out[key] = _plain(value)
    return out


# --------------------------------------------------------------------------- motores


class _Engine(Protocol):
    name: str

    def check(self, f: RuleFile) -> str | None: ...
    def build(self, files: list[RuleFile]) -> Any: ...
    def count(self, rules: Any) -> int: ...
    def scan(
        self, rules: Any, generation: int, data: bytes, timeout_s: int, externals: dict[str, str]
    ) -> list[RuleHit]: ...


class YaraXEngine:
    name = "yara-x"

    def __init__(self, module: Any) -> None:
        self._yx = module

    def _compiler(self, files: list[RuleFile]) -> Any:
        c = self._yx.Compiler(relaxed_re_syntax=True)
        for key, value in _EXTERNALS.items():
            c.define_global(key, value)
        for d in sorted({str(f.path.parent) for f in files}):
            try:
                c.add_include_dir(d)
            except Exception:  # noqa: BLE001 - versiones viejas sin includes
                log.debug("yara-x: no se pudo agregar include dir %s", d, exc_info=True)
        return c

    def check(self, f: RuleFile) -> str | None:
        c = self._compiler([f])
        try:
            c.new_namespace(f.namespace)
            c.add_source(f.source, origin=f.display)
            c.build()
        except self._yx.CompileError as exc:
            return str(exc)
        return None

    def build(self, files: list[RuleFile]) -> Any:
        c = self._compiler(files)
        for f in files:
            c.new_namespace(f.namespace)
            c.add_source(f.source, origin=f.display)
        return c.build()

    def count(self, rules: Any) -> int:
        try:
            return sum(1 for _ in rules)
        except TypeError:
            return -1

    def _scanner(self, rules: Any, generation: int, timeout_s: int) -> Any:
        """Scanner de ESTE hilo para este conjunto de reglas (se crea, usa y destruye en el mismo hilo)."""
        cache: OrderedDict[int, tuple[Any, Any]] | None = getattr(_THREAD_STATE, "scanners", None)
        if cache is None:
            cache = _THREAD_STATE.scanners = OrderedDict()
        entry = cache.get(generation)
        if entry is None or entry[0] is not rules:
            scanner = self._yx.Scanner(rules)
            scanner.set_timeout(max(1, int(timeout_s)))
            scanner.max_matches_per_pattern(_MAX_MATCHES_PER_PATTERN)
            entry = cache[generation] = (rules, scanner)
            while len(cache) > _MAX_SCANNERS_PER_THREAD:
                cache.popitem(last=False)  # se libera en este mismo hilo
        else:
            cache.move_to_end(generation)
        return entry[1]

    def scan(
        self, rules: Any, generation: int, data: bytes, timeout_s: int, externals: dict[str, str]
    ) -> list[RuleHit]:
        scanner = self._scanner(rules, generation, timeout_s)
        for key, value in externals.items():
            scanner.set_global(key, value)
        try:
            results = scanner.scan(data)
        except self._yx.TimeoutError as exc:
            raise ScanTimeoutError(str(exc)) from exc
        hits: list[RuleHit] = []
        for m in results.matching_rules:
            patterns: list[PatternHit] = []
            for p in m.patterns:
                matches = list(p.matches)
                if not matches:
                    continue
                first = matches[0]
                patterns.append(
                    PatternHit(
                        identifier=p.identifier,
                        offsets=[x.offset for x in matches[:_MAX_OFFSETS]],
                        count=len(matches),
                        sample=_snippet(data, first.offset, first.length),
                    )
                )
            hits.append(
                RuleHit(
                    rule=m.identifier,
                    namespace=m.namespace,
                    meta=_meta_dict(m.metadata),
                    tags=[str(t) for t in m.tags],
                    patterns=patterns,
                )
            )
        return hits


class YaraPythonEngine:
    """Alternativa con yara-python (libyara). Las reglas compiladas son thread-safe."""

    name = "yara-python"

    def __init__(self, module: Any) -> None:
        self._y = module

    def check(self, f: RuleFile) -> str | None:
        try:
            self._y.compile(filepaths={f.namespace: str(f.path)}, externals=dict(_EXTERNALS))
        except Exception as exc:  # noqa: BLE001 - yara.SyntaxError / yara.Error
            return str(exc)
        return None

    def build(self, files: list[RuleFile]) -> Any:
        return self._y.compile(
            filepaths={f.namespace: str(f.path) for f in files}, externals=dict(_EXTERNALS)
        )

    def count(self, rules: Any) -> int:
        try:
            return sum(1 for _ in rules)
        except TypeError:
            return -1

    def scan(
        self, rules: Any, generation: int, data: bytes, timeout_s: int, externals: dict[str, str]
    ) -> list[RuleHit]:
        timeout_exc = getattr(self._y, "TimeoutError", None)
        try:
            matches = rules.match(data=data, timeout=max(1, int(timeout_s)), externals=dict(externals))
        except Exception as exc:
            if (timeout_exc is not None and isinstance(exc, timeout_exc)) or "timeout" in str(exc).lower():
                raise ScanTimeoutError(str(exc)) from exc
            raise
        hits: list[RuleHit] = []
        for m in matches:
            grouped: dict[str, PatternHit] = {}
            for s in getattr(m, "strings", []) or []:
                if isinstance(s, tuple):  # yara-python < 4.3: (offset, identifier, data)
                    offset, ident, matched = s[0], str(s[1]), s[2]
                    instances = [(offset, matched)]
                else:  # >= 4.3: StringMatch(identifier, instances[offset, matched_data])
                    ident = str(s.identifier)
                    instances = [(i.offset, i.matched_data) for i in s.instances]
                for offset, matched in instances:
                    hit = grouped.get(ident)
                    if hit is None:
                        sample = _snippet(bytes(matched), 0, len(matched))
                        hit = grouped[ident] = PatternHit(ident, [], 0, sample)
                    hit.count += 1
                    if len(hit.offsets) < _MAX_OFFSETS:
                        hit.offsets.append(int(offset))
            hits.append(
                RuleHit(
                    rule=str(m.rule),
                    namespace=str(getattr(m, "namespace", "")),
                    meta=_meta_dict(getattr(m, "meta", {}) or {}),
                    tags=[str(t) for t in getattr(m, "tags", []) or []],
                    patterns=list(grouped.values()),
                )
            )
        return hits


def load_engine() -> _Engine | None:
    """Primer motor importable de `_ENGINE_MODULES`, o None."""
    for mod_name in _ENGINE_MODULES:
        try:
            module = importlib.import_module(mod_name)
        except Exception as exc:  # noqa: BLE001 - ImportError o binarios rotos
            log.debug("yara: motor %s no disponible: %s", mod_name, exc)
            continue
        if mod_name == "yara_x" and hasattr(module, "Compiler") and hasattr(module, "Scanner"):
            return YaraXEngine(module)
        if mod_name == "yara" and hasattr(module, "compile"):
            return YaraPythonEngine(module)
    return None


# --------------------------------------------------------------------------- descubrimiento y compilación


def resolve_rules_dir(path: Path, *, cwd: Path | None = None, repo_root: Path = REPO_ROOT) -> Path | None:
    """Ruta absoluta existente para una entrada de `rules_dirs` (relativas: CWD y después el repo)."""
    path = Path(path)
    if path.is_absolute():
        return path if path.exists() else None
    for base in (cwd or Path.cwd(), repo_root):
        candidate = base / path
        if candidate.exists():
            return candidate
    return None


def _read_rule_source(path: Path) -> str | None:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        log.warning("yara: no se pudo leer %s: %s", path, exc)
        return None
    for encoding in ("utf-8-sig", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return None  # pragma: no cover - latin-1 decodifica cualquier cosa


def discover_rule_files(
    rules_dirs: list[Path], *, cwd: Path | None = None
) -> tuple[list[RuleFile], dict[str, str]]:
    """Lista los archivos de reglas. Devuelve (archivos, salteados{archivo: motivo})."""
    files: list[RuleFile] = []
    skipped: dict[str, str] = {}
    seen: set[Path] = set()
    for idx, entry in enumerate(rules_dirs):
        base = resolve_rules_dir(Path(entry), cwd=cwd)
        if base is None:
            log.warning("yara: la carpeta de reglas %s no existe", entry)
            continue
        if base.is_file():
            root, candidates = base.parent, [base]
        else:
            root = base
            candidates = sorted(
                p
                for p in base.rglob("*")
                if p.suffix.lower() in _RULE_SUFFIXES
                and not any(part.startswith(".") for part in p.relative_to(base).parts)
            )
        for p in candidates:
            if len(files) >= _MAX_RULE_FILES:
                log.warning("yara: se alcanzó el máximo de %d archivos de reglas", _MAX_RULE_FILES)
                return files, skipped
            try:
                if not p.is_file():
                    continue
                resolved = p.resolve()
                size = p.stat().st_size
            except OSError:
                continue
            if resolved in seen:
                continue
            seen.add(resolved)
            rel = p.relative_to(root).as_posix()
            display = rel if idx == 0 else f"{entry}/{rel}"
            if size > _MAX_RULE_FILE_BYTES:
                skipped[display] = "archivo demasiado grande"
                log.warning("yara: se saltea %s (más de %d bytes)", display, _MAX_RULE_FILE_BYTES)
                continue
            source = _read_rule_source(p)
            if source is None:
                skipped[display] = "no se pudo leer"
                continue
            namespace = rel if idx == 0 else f"{idx}:{rel}"
            files.append(RuleFile(path=p, namespace=namespace, display=display, source=source))
    return files, skipped


def compile_ruleset(engine: _Engine, rules_dirs: list[Path], *, cwd: Path | None = None) -> CompiledRuleset:
    """Compila las reglas salteando archivos rotos (CPU: llamar desde un hilo)."""
    files, skipped = discover_rule_files(rules_dirs, cwd=cwd)
    good: list[RuleFile] = []
    for f in files:
        error = engine.check(f)
        if error is None:
            good.append(f)
            continue
        first_line = next((ln.strip() for ln in error.splitlines() if ln.strip()), "error de compilación")
        skipped[f.display] = first_line[:300]
        log.warning("yara: se saltea el archivo de reglas %s: %s", f.display, first_line[:300])
    if not good:
        return CompiledRuleset(None, engine.name, [], skipped, 0, {})
    try:
        rules = engine.build(good)
    except Exception as exc:  # noqa: BLE001 - p.ej. conflicto entre archivos: no tumbar el analizador
        log.error("yara: falló la compilación del conjunto de reglas: %s", str(exc).splitlines()[0][:300])
        return CompiledRuleset(
            None, engine.name, [], {**skipped, "*": "falló la compilación conjunta"}, 0, {}
        )
    return CompiledRuleset(
        rules=rules,
        engine=engine.name,
        loaded_files=[f.display for f in good],
        skipped_files=skipped,
        rule_count=engine.count(rules),
        namespaces={f.namespace: f.display for f in good},
    )


# --------------------------------------------------------------------------- mapeo a Finding


def _to_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return int(value)
    if isinstance(value, str) and re.fullmatch(r"\s*\d{1,3}\s*", value):
        return int(value)
    return None


def _family_from_meta(meta: dict[str, Any]) -> str | None:
    for key in ("family", "malware_family", "malware"):
        value = meta.get(key)
        if isinstance(value, str) and value.strip():
            return canonical_family(value)
    threat = meta.get("threat_name")  # Elastic: "Windows.Trojan.AgentTesla"
    if isinstance(threat, str) and threat.strip():
        return canonical_family(threat.strip().split(".")[-1])
    return None


def finding_from_hit(hit: RuleHit, artifact: Artifact, *, engine: str, source_file: str | None) -> Finding:
    meta = hit.meta
    family = _family_from_meta(meta)
    category_raw = str(meta.get("category", "")).strip().lower()

    if category_raw == "phishing":
        category = FindingCategory.PHISHING
    elif category_raw in _FAMILY_CATEGORIES:
        category = FindingCategory.MALWARE
    elif category_raw in _SUSPICIOUS_CATEGORIES:
        category = FindingCategory.SUSPICIOUS_FILE
    else:
        category = FindingCategory.MALWARE if family else FindingCategory.SUSPICIOUS_FILE

    score = _to_int(meta.get("score"))
    severity = _SEVERITY_NAMES.get(str(meta.get("severity", "")).strip().lower())
    if score is not None:
        score = max(0, min(100, score))
    if severity is None:
        if score is None:
            severity = (
                Severity.CRITICAL if category == FindingCategory.MALWARE and family else Severity.MEDIUM
            )
        elif score >= 90:
            severity = Severity.CRITICAL
        elif score >= 60:
            severity = Severity.HIGH
        elif score >= 25:
            severity = Severity.MEDIUM
        elif score > 0:
            severity = Severity.LOW
        else:
            severity = Severity.INFO
    if score is None:
        score = 90 if severity == Severity.CRITICAL and family else _DEFAULT_SCORE[severity]

    title = meta.get("title") if isinstance(meta.get("title"), str) and meta.get("title").strip() else None
    if not title:
        base = _CATEGORY_TITLES.get(category_raw)
        if base and family:
            title = f"{base}: {family}"
        elif family:
            title = f"Malware detectado: {family}"
        elif base:
            title = f"{base} detectado"
        else:
            title = f"Archivo sospechoso (regla YARA {hit.rule})"
    title = str(title)[:200]

    description = meta.get("description")
    if not isinstance(description, str) or not description.strip():
        description = (
            f"El archivo coincide con la regla YARA '{hit.rule}', que identifica contenido malicioso o "
            "sospechoso. No lo abras sin confirmarlo con el remitente por otro medio."
        )

    evidence: dict[str, Any] = {
        "engine": engine,
        "rule": hit.rule,
        "namespace": hit.namespace,
        "matches": [
            {"id": p.identifier, "offsets": p.offsets, "count": p.count, "sample": p.sample}
            for p in hit.patterns[:_MAX_PATTERNS_IN_EVIDENCE]
        ],
    }
    if source_file:
        evidence["source_file"] = source_file
    if category_raw:
        evidence["category"] = category_raw[:40]
    if hit.tags:
        evidence["tags"] = hit.tags[:10]
    reference = meta.get("reference")
    if isinstance(reference, str) and reference.strip():
        evidence["reference"] = reference.strip()[:300]

    return Finding(
        analyzer="yara",
        rule=f"yara.{hit.rule}",
        title=title,
        description=description.strip()[:1500],
        category=category,
        severity=severity,
        score=score,
        artifact_id=artifact.id,
        malware_family=family,
        evidence=evidence,
    )


# --------------------------------------------------------------------------- analizador


class YaraAnalyzer(ArtifactAnalyzer):
    name = "yara"

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self._engine: _Engine | None = None
        self._ruleset: CompiledRuleset | None = None
        self._generation = 0
        self._loaded = False
        self._load_lock = asyncio.Lock()

    @classmethod
    def available(cls) -> bool:
        return load_engine() is not None

    @classmethod
    def enabled(cls, settings: Settings) -> bool:
        return super().enabled(settings) and settings.analyzers.yara.enabled

    # ----------------------------------------------------------------- estado (para health / dashboard)

    @property
    def engine_name(self) -> str | None:
        return self._engine.name if self._engine else None

    @property
    def rule_count(self) -> int:
        return self._ruleset.rule_count if self._ruleset else 0

    @property
    def loaded_files(self) -> list[str]:
        return list(self._ruleset.loaded_files) if self._ruleset else []

    @property
    def skipped_files(self) -> dict[str, str]:
        return dict(self._ruleset.skipped_files) if self._ruleset else {}

    # ----------------------------------------------------------------- carga

    async def setup(self) -> None:
        await self.reload()

    async def reload(self) -> None:
        """(Re)compila las reglas. Si falla, se mantienen las reglas anteriores."""
        async with self._load_lock:
            engine = self._engine or load_engine()
            if engine is None:
                log.warning("yara: no hay motor disponible (instalá yara-x)")
                self._loaded = True
                return
            dirs = list(self.settings.analyzers.yara.rules_dirs)
            ruleset = await asyncio.to_thread(compile_ruleset, engine, dirs)
            self._engine = engine
            self._loaded = True
            if ruleset.rules is None:
                if self._ruleset is None:
                    self._ruleset = ruleset
                log.warning("yara: no se cargó ninguna regla desde %s", [str(d) for d in dirs])
                return
            self._ruleset = ruleset
            self._generation = next(_GENERATIONS)
            log.info(
                "yara: %d reglas cargadas de %d archivos con %s (%d archivos salteados)",
                ruleset.rule_count,
                len(ruleset.loaded_files),
                engine.name,
                len(ruleset.skipped_files),
            )

    def accepts(self, artifact: Artifact) -> bool:
        # los .eml adjuntos se abren en el parser y se escanean sus partes ya decodificadas; las entradas
        # solo listadas (zip cifrado, demasiado grandes) no tienen bytes
        return bool(artifact.data) and not artifact.listing_only and artifact.detected_type != "eml"

    async def analyze(self, ctx: AnalysisContext, artifact: Artifact) -> list[Finding]:
        if not self._loaded:
            await self.setup()
        ruleset, engine = self._ruleset, self._engine
        if ruleset is None or ruleset.rules is None or engine is None or not artifact.data:
            return []
        if artifact.listing_only:
            return []
        timeout_s = int(self.settings.analyzers.yara.timeout_s)
        externals = {
            "filename": (artifact.filename or "")[:255],
            "filepath": artifact.id[:1024],
            "extension": artifact.extension[:32],
            "filetype": (artifact.detected_type or "")[:64],
            "owner": "",
        }
        try:
            hits = await asyncio.to_thread(
                engine.scan, ruleset.rules, self._generation, artifact.data, timeout_s, externals
            )
        except ScanTimeoutError:
            log.warning("yara: timeout escaneando %s (%d bytes)", artifact.id, len(artifact.data))
            return [
                Finding(
                    analyzer=self.name,
                    rule="yara.scan_timeout",
                    title="El análisis con reglas YARA no terminó a tiempo",
                    description=(
                        "El archivo tardó demasiado en analizarse con las reglas YARA y el análisis se "
                        "cortó. Puede ser un archivo muy grande o armado a propósito para evadir controles."
                    ),
                    category=FindingCategory.POLICY,
                    severity=Severity.INFO,
                    score=0,
                    artifact_id=artifact.id,
                    evidence={"timeout_s": timeout_s, "size": len(artifact.data)},
                )
            ]
        return [
            finding_from_hit(h, artifact, engine=engine.name, source_file=ruleset.namespaces.get(h.namespace))
            for h in hits
        ]


__all__ = [
    "REPO_ROOT",
    "CompiledRuleset",
    "RuleHit",
    "ScanTimeoutError",
    "YaraAnalyzer",
    "YaraPythonEngine",
    "YaraXEngine",
    "compile_ruleset",
    "discover_rule_files",
    "finding_from_hit",
    "load_engine",
    "resolve_rules_dir",
]
