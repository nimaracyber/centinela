"""Calidad del ruleset rules/yara/**: compila en YARA-X estricto, meta completa, cada regla dispara con
su muestra sintética y ninguna dispara con el corpus benigno."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

yara_x = pytest.importorskip("yara_x")

from centinela.analyzers.yara_scan import REPO_ROOT, YaraXEngine, compile_ruleset  # noqa: E402
from tests.analyzers_engines.samples import BENIGN_SAMPLES, RULE_SAMPLES  # noqa: E402

RULES_DIR = REPO_ROOT / "rules" / "yara"
RULE_FILES = sorted(p for p in RULES_DIR.rglob("*") if p.suffix.lower() in (".yar", ".yara"))

ALLOWED_CATEGORIES = {"rat", "stealer", "loader", "ransomware", "backdoor", "technique", "generic"}
FAMILY_CATEGORIES = {"rat", "stealer", "loader", "ransomware", "backdoor"}
SEVERITY_SCORE = {"critical": (90, 100), "high": (60, 89), "medium": (25, 59), "low": (1, 24), "info": (0, 0)}


def _rel(p: Path) -> str:
    return p.relative_to(RULES_DIR).as_posix()


@pytest.fixture(scope="module")
def ruleset():
    engine = YaraXEngine(yara_x)
    compiled = compile_ruleset(engine, [RULES_DIR])
    assert compiled.rules is not None
    return engine, compiled


def _matches(ruleset, data: bytes) -> set[str]:
    engine, compiled = ruleset
    externals = {"filename": "", "filepath": "", "extension": "", "filetype": "", "owner": ""}
    return {h.rule for h in engine.scan(compiled.rules, 1, data, 10, externals)}


def _all_rules() -> list[tuple[str, str, dict]]:
    """(archivo, regla, meta) de todo el ruleset."""
    out = []
    for path in RULE_FILES:
        c = yara_x.Compiler()
        c.add_source(path.read_text(encoding="utf-8"), origin=_rel(path))
        for rule in c.build():
            out.append((_rel(path), rule.identifier, dict(rule.metadata)))
    return out


def test_ruleset_layout():
    folders = {p.relative_to(RULES_DIR).parts[0] for p in RULE_FILES}
    assert {"rats", "stealers", "loaders", "techniques"} <= folders
    assert (RULES_DIR / "README.md").is_file()
    assert len(RULE_FILES) >= 25


@pytest.mark.parametrize("path", RULE_FILES, ids=_rel)
def test_rule_file_compiles_strict_without_warnings(path: Path):
    """Cada archivo compila solo, en YARA-X estricto (sin relaxed_re_syntax) y sin 'slow patterns'."""
    c = yara_x.Compiler()
    c.add_source(path.read_text(encoding="utf-8"), origin=_rel(path))
    rules = c.build()
    assert c.warnings() == []
    assert sum(1 for _ in rules) >= 1


def test_whole_ruleset_compiles_with_engine_and_names_are_unique(ruleset):
    _, compiled = ruleset
    assert compiled.skipped_files == {}
    assert len(compiled.loaded_files) == len(RULE_FILES)
    names = [name for _, name, _ in _all_rules()]
    assert len(names) == len(set(names)), "nombres de regla repetidos entre archivos"
    assert compiled.rule_count == len(names)


@pytest.mark.parametrize("file,rule,meta", _all_rules(), ids=lambda v: v if isinstance(v, str) else "")
def test_rule_meta_conventions(file: str, rule: str, meta: dict):
    assert meta.get("author") == "Centinela"
    desc = meta.get("description", "")
    assert isinstance(desc, str) and len(desc) >= 40
    # texto para humanos en español
    assert re.search(r"[áéíóúñ¿¡]|\b(el|la|los|que|para|con)\b", desc, re.IGNORECASE)
    assert str(meta.get("reference", "")).startswith("https://")
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(meta.get("date", "")))
    category = meta.get("category")
    assert category in ALLOWED_CATEGORIES
    severity = meta.get("severity")
    assert severity in SEVERITY_SCORE
    score = meta.get("score")
    assert isinstance(score, int) and not isinstance(score, bool)
    lo, hi = SEVERITY_SCORE[severity]
    assert lo <= score <= hi, f"{rule}: score {score} no corresponde a severidad {severity}"
    folder = file.split("/")[0]
    if folder in ("rats", "stealers"):
        assert category in FAMILY_CATEGORIES and meta.get("family"), f"{rule}: regla de familia sin 'family'"
        assert rule.startswith(("RAT_", "Stealer_"))
    if folder == "techniques":
        assert category in ("technique", "generic")
        assert "family" not in meta
        assert meta.get("title"), "las técnicas llevan un título corto para la alerta"


def test_every_rule_has_a_positive_sample():
    names = {name for _, name, _ in _all_rules()}
    assert names == set(RULE_SAMPLES), (
        f"sin muestra: {sorted(names - set(RULE_SAMPLES))}; muestra sin regla: {sorted(set(RULE_SAMPLES) - names)}"
    )


@pytest.mark.parametrize(
    "rule,idx",
    [(rule, i) for rule, samples in RULE_SAMPLES.items() for i in range(len(samples))],
    ids=lambda v: str(v),
)
def test_rule_fires_on_its_synthetic_sample(ruleset, rule: str, idx: int):
    assert rule in _matches(ruleset, RULE_SAMPLES[rule][idx])


@pytest.mark.parametrize("name", sorted(BENIGN_SAMPLES))
def test_benign_corpus_triggers_nothing(ruleset, name: str):
    assert _matches(ruleset, BENIGN_SAMPLES[name]) == set()


def test_family_samples_do_not_cross_fire_between_families(ruleset):
    """La muestra de una familia no debe atribuirse a OTRA familia (salvo forks documentados)."""
    family_rules = {name for _, name, meta in _all_rules() if meta.get("family")}
    allowed_overlap = {("RAT_VenomRAT", "RAT_AsyncRAT"), ("RAT_DCRat", "RAT_AsyncRAT")}
    for rule, samples in RULE_SAMPLES.items():
        if rule not in family_rules:
            continue
        for sample in samples:
            others = (_matches(ruleset, sample) & family_rules) - {rule}
            assert all((rule, o) in allowed_overlap for o in others), f"{rule} también dispara {others}"


def test_generic_smuggling_yields_to_payload_rule(ruleset):
    hits = _matches(ruleset, RULE_SAMPLES["Technique_HTML_Smuggling_Payload"][0])
    assert "Technique_HTML_Smuggling_Payload" in hits
    assert "Technique_HTML_Smuggling_Generic" not in hits


def test_pe_only_rules_ignore_same_strings_in_plain_text(ruleset):
    """Las reglas de familia exigen cabecera PE: el mismo texto en un .txt (p.ej. un informe) no dispara."""
    text = b"\n".join(
        [
            b"Informe: AsyncRAT usa Stub.exe, get_ActivatePong, get_SslClient y vmware.",
            '/c schtasks /create /f /sc onlogon /rl highest /tn "'.encode("utf-16-le"),
            b"Remcos restarted by watchdog! Mutex_RemWatchdog",
            b"TeslaBrowser/5.5 /c2sock RedLine.Logic.SQLite NanoCore.ClientPluginHost",
        ]
    )
    hits = _matches(ruleset, text)
    assert not {h for h in hits if h.startswith(("RAT_", "Stealer_"))}
