"""YaraAnalyzer: carga de reglas, mapeo a Finding, evidencia acotada, hilos, timeouts y fallback."""

from __future__ import annotations

import asyncio
import logging
import types
from pathlib import Path

import pytest

from centinela.analyzers import yara_scan
from centinela.analyzers.yara_scan import (
    REPO_ROOT,
    RuleHit,
    ScanTimeoutError,
    YaraAnalyzer,
    YaraPythonEngine,
    resolve_rules_dir,
)
from centinela.core.models import Artifact, FindingCategory, Severity
from tests.analyzers_engines.samples import BENIGN_SAMPLES, RULE_SAMPLES, a, fake_pe
from tests.helpers import make_artifact

pytest.importorskip("yara_x")


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
async def analyzer(settings):
    an = YaraAnalyzer(settings)
    await an.setup()
    return an


async def test_setup_loads_repo_rules_from_default_relative_dir(settings, tmp_path, monkeypatch):
    # CWD sin rules/: la ruta relativa por defecto se resuelve contra la raíz del repo
    monkeypatch.chdir(tmp_path)
    an = YaraAnalyzer(settings)
    await an.setup()
    assert an.engine_name == "yara-x"
    assert an.rule_count >= 30
    assert "rats/asyncrat.yar" in an.loaded_files
    assert "techniques/html_smuggling.yar" in an.loaded_files
    assert an.skipped_files == {}


async def test_family_rule_maps_to_critical_malware_finding(analyzer, make_ctx):
    art = make_artifact(RULE_SAMPLES["RAT_AsyncRAT"][0], "Stub.exe", "pe", id="att0/pedido.zip/Stub.exe")
    findings = await analyzer.analyze(make_ctx(), art)
    by_rule = {f.rule: f for f in findings}
    f = by_rule["yara.RAT_AsyncRAT"]
    assert f.analyzer == "yara"
    assert f.category == FindingCategory.MALWARE
    assert f.severity == Severity.CRITICAL
    assert f.score == 95
    assert f.malware_family == "AsyncRAT"
    assert f.artifact_id == "att0/pedido.zip/Stub.exe"
    assert "AsyncRAT" in f.title and "acceso remoto" in f.title
    ev = f.evidence
    assert ev["engine"] == "yara-x"
    assert ev["source_file"] == "rats/asyncrat.yar"
    assert ev["reference"].startswith("https://")
    ids = {m["id"] for m in ev["matches"]}
    assert {"$s_stub", "$s_pong"} <= ids
    stub = next(m for m in ev["matches"] if m["id"] == "$s_stub")
    assert stub["sample"] == "Stub.exe"  # UTF-16 decodificado
    assert all(isinstance(o, int) for o in stub["offsets"])


async def test_technique_rule_maps_to_suspicious_file(analyzer, make_ctx):
    art = make_artifact(RULE_SAMPLES["Technique_Encoded_PE_In_Text"][0], "script.js", "script/js")
    findings = await analyzer.analyze(make_ctx(), art)
    f = next(x for x in findings if x.rule == "yara.Technique_Encoded_PE_In_Text")
    assert f.category == FindingCategory.SUSPICIOUS_FILE
    assert f.severity == Severity.HIGH
    assert f.score == 70
    assert f.malware_family is None
    assert f.title == "Ejecutable escondido como texto codificado"


async def test_loader_without_family_is_malware_without_family(analyzer, make_ctx):
    art = make_artifact(RULE_SAMPLES["Loader_DotNet_Encoded_PE"][0], "factura.exe", "pe")
    findings = await analyzer.analyze(make_ctx(), art)
    f = next(x for x in findings if x.rule == "yara.Loader_DotNet_Encoded_PE")
    assert f.category == FindingCategory.MALWARE
    assert f.malware_family is None
    assert f.severity == Severity.HIGH


@pytest.mark.parametrize("name", ["lorem", "minimal_pdf", "ps_admin_script", "html_newsletter", "benign_pe"])
async def test_benign_artifacts_produce_no_findings(analyzer, make_ctx, name):
    art = make_artifact(BENIGN_SAMPLES[name], f"{name}.bin", "text")
    assert await analyzer.analyze(make_ctx(), art) == []


async def test_accepts_skips_empty_and_attached_eml(analyzer):
    assert analyzer.accepts(make_artifact(b"hola", "a.txt", "text"))
    assert not analyzer.accepts(make_artifact(b"", "vacio.txt", "text"))
    assert not analyzer.accepts(make_artifact(b"From: x\r\n\r\nhola", "reenviado.eml", "eml"))


async def test_listing_only_artifacts_are_skipped(analyzer, make_ctx):
    listed = Artifact(
        id="att0/Stub.exe", filename="Stub.exe", size=9000, depth=1, parent_id="att0", listing_only=True
    )
    assert not analyzer.accepts(listed)
    assert await analyzer.analyze(make_ctx(), listed) == []
    # contrato roto (listado pero con bytes que matchean una regla): igual no se escanea
    weird = make_artifact(RULE_SAMPLES["RAT_AsyncRAT"][0], "Stub.exe", "pe").model_copy(
        update={"listing_only": True}
    )
    assert not analyzer.accepts(weird)
    assert await analyzer.analyze(make_ctx(), weird) == []


async def test_evidence_is_bounded_and_printable(settings, tmp_path, make_ctx):
    _write(
        tmp_path / "r" / "binario.yar",
        'rule Binario { meta: category = "generic" severity = "low" score = 5 '
        'strings: $b = { 00 01 02 03 04 05 06 07 FF FE 41 42 } $t = "token" condition: #t > 2 and $b }',
    )
    settings.analyzers.yara.rules_dirs = [tmp_path / "r"]
    an = YaraAnalyzer(settings)
    await an.setup()
    data = bytes(range(8)) + b"\xff\xfeAB" + b"x" * 200 + b"token " * 500
    findings = await an.analyze(make_ctx(), make_artifact(data, "x.bin", "unknown"))
    assert len(findings) == 1
    matches = {m["id"]: m for m in findings[0].evidence["matches"]}
    assert matches["$t"]["count"] >= 100  # hay muchas, pero...
    assert len(matches["$t"]["offsets"]) <= 5  # ...se guardan pocas
    sample = matches["$b"]["sample"]
    assert len(sample) <= 64 and sample.isprintable()
    assert "AB" in sample
    assert findings[0].severity == Severity.LOW and findings[0].category == FindingCategory.SUSPICIOUS_FILE


async def test_broken_rule_file_is_skipped_and_good_ones_still_work(settings, tmp_path, make_ctx, caplog):
    rules = tmp_path / "reglas"
    _write(rules / "buena.yar", 'rule Buena { strings: $a = "centinela-ok" condition: $a }')
    _write(rules / "sub" / "otra.yara", 'rule Otra { strings: $a = "otra-regla" condition: $a }')
    _write(rules / "rota.yar", "rule Rota { condition: variable_que_no_existe }")
    _write(rules / "rota2.yar", "rule { esto no es yara")
    _write(rules / ".oculta" / "ignorada.yar", 'rule Oculta { strings: $a = "centinela-ok" condition: $a }')
    _write(rules / "notas.txt", "no es una regla")
    settings.analyzers.yara.rules_dirs = [rules]
    an = YaraAnalyzer(settings)
    with caplog.at_level(logging.WARNING, logger="centinela.analyzers.yara_scan"):
        await an.setup()
    assert sorted(an.loaded_files) == ["buena.yar", "sub/otra.yara"]
    assert set(an.skipped_files) == {"rota.yar", "rota2.yar"}
    assert "rota.yar" in caplog.text
    findings = await an.analyze(
        make_ctx(), make_artifact(b"... centinela-ok ... otra-regla", "x.txt", "text")
    )
    assert {f.rule for f in findings} == {"yara.Buena", "yara.Otra"}


async def test_same_rule_name_in_two_files_does_not_collide(settings, tmp_path, make_ctx):
    _write(tmp_path / "r" / "a.yar", 'rule Dup { strings: $a = "uno" condition: $a }')
    _write(tmp_path / "r" / "b.yar", 'rule Dup { strings: $a = "dos" condition: $a }')
    settings.analyzers.yara.rules_dirs = [tmp_path / "r"]
    an = YaraAnalyzer(settings)
    await an.setup()
    assert an.skipped_files == {} and an.rule_count == 2
    findings = await an.analyze(make_ctx(), make_artifact(b"dos", "x.txt", "text"))
    assert [f.evidence["source_file"] for f in findings] == ["b.yar"]


async def test_community_rule_meta_is_inferred(settings, tmp_path, make_ctx):
    _write(
        tmp_path / "community" / "elastic_like.yar",
        """
        rule Windows_Trojan_Remcos_test {
            meta:
                author = "Elastic Security"
                description = "Detects Remcos (community rule)"
                threat_name = "Windows.Trojan.Remcos"
                score = 75
            strings: $a = "remcos-community-marker"
            condition: $a
        }
        rule Sin_Meta { strings: $a = "sin-meta-marker" condition: $a }
        """,
    )
    settings.analyzers.yara.rules_dirs = [tmp_path / "community"]
    an = YaraAnalyzer(settings)
    await an.setup()
    data = b"remcos-community-marker / sin-meta-marker"
    findings = {f.rule: f for f in await an.analyze(make_ctx(), make_artifact(data, "x.bin", "unknown"))}
    remcos = findings["yara.Windows_Trojan_Remcos_test"]
    assert remcos.malware_family == "Remcos"
    assert remcos.category == FindingCategory.MALWARE
    assert remcos.severity == Severity.HIGH and remcos.score == 75
    assert remcos.description == "Detects Remcos (community rule)"
    plain = findings["yara.Sin_Meta"]
    assert plain.category == FindingCategory.SUSPICIOUS_FILE
    assert plain.severity == Severity.MEDIUM and plain.score == 40
    assert "Sin_Meta" in plain.title and plain.description


async def test_external_variables_are_filled_per_artifact(settings, tmp_path, make_ctx):
    _write(
        tmp_path / "ext" / "ext.yar",
        'rule DobleExtension { condition: extension == "exe" and filename contains ".pdf." and filetype == "pe" }',
    )
    settings.analyzers.yara.rules_dirs = [tmp_path / "ext"]
    an = YaraAnalyzer(settings)
    await an.setup()
    hit = await an.analyze(make_ctx(), make_artifact(b"MZ..", "factura.pdf.exe", "pe"))
    miss = await an.analyze(make_ctx(), make_artifact(b"MZ..", "factura.exe", "pe"))
    assert [f.rule for f in hit] == ["yara.DobleExtension"]
    assert miss == []


async def test_concurrent_scans_use_one_scanner_per_thread(analyzer, make_ctx):
    """yara_x.Scanner no se puede compartir entre hilos: muchos escaneos en paralelo no deben romper."""
    ctx = make_ctx()
    samples = [
        (RULE_SAMPLES["RAT_Remcos"][0], "yara.RAT_Remcos"),
        (
            RULE_SAMPLES["Technique_PowerShell_Download_Cradle"][0],
            "yara.Technique_PowerShell_Download_Cradle",
        ),
        (BENIGN_SAMPLES["lorem"], None),
    ] * 15
    results = await asyncio.gather(
        *(
            analyzer.analyze(ctx, make_artifact(data, "x", "unknown", id=f"att{i}"))
            for i, (data, _) in enumerate(samples)
        )
    )
    for (_, expected), findings in zip(samples, results, strict=True):
        rules = {f.rule for f in findings}
        assert (expected in rules) if expected else rules == set()


async def test_reload_picks_up_new_rules(settings, tmp_path, make_ctx):
    rules = tmp_path / "r"
    _write(rules / "a.yar", 'rule Primera { strings: $a = "marcador" condition: $a }')
    settings.analyzers.yara.rules_dirs = [rules]
    an = YaraAnalyzer(settings)
    await an.setup()
    art = make_artifact(b"marcador nuevo-marcador", "x.txt", "text")
    assert {f.rule for f in await an.analyze(make_ctx(), art)} == {"yara.Primera"}
    _write(rules / "b.yar", 'rule Segunda { strings: $a = "nuevo-marcador" condition: $a }')
    await an.reload()
    assert {f.rule for f in await an.analyze(make_ctx(), art)} == {"yara.Primera", "yara.Segunda"}


async def test_scan_timeout_becomes_policy_finding(analyzer, make_ctx, monkeypatch):
    def boom(*args, **kwargs):
        raise ScanTimeoutError("timeout")

    monkeypatch.setattr(analyzer._engine, "scan", boom)
    findings = await analyzer.analyze(make_ctx(), make_artifact(b"x" * 100, "x.bin", "unknown"))
    assert len(findings) == 1
    f = findings[0]
    assert f.rule == "yara.scan_timeout"
    assert f.category == FindingCategory.POLICY and f.severity == Severity.INFO and f.score == 0


async def test_unexpected_scan_error_propagates_to_pipeline(analyzer, make_ctx, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("falla interna")

    monkeypatch.setattr(analyzer._engine, "scan", boom)
    with pytest.raises(RuntimeError):
        await analyzer.analyze(make_ctx(), make_artifact(b"x", "x.bin", "unknown"))


async def test_missing_rules_dir_does_not_crash(settings, tmp_path, make_ctx, caplog):
    settings.analyzers.yara.rules_dirs = [tmp_path / "no-existe"]
    an = YaraAnalyzer(settings)
    with caplog.at_level(logging.WARNING):
        await an.setup()
    assert an.rule_count == 0
    assert "no existe" in caplog.text
    assert await an.analyze(make_ctx(), make_artifact(RULE_SAMPLES["RAT_Remcos"][0], "x", "pe")) == []


async def test_without_engine_analyzer_is_unavailable(settings, make_ctx, monkeypatch):
    monkeypatch.setattr(yara_scan, "_ENGINE_MODULES", ("centinela_modulo_inexistente",))
    assert YaraAnalyzer.available() is False
    an = YaraAnalyzer(settings)
    await an.setup()
    assert await an.analyze(make_ctx(), make_artifact(b"x", "x", "text")) == []


def test_enabled_flags(settings):
    assert YaraAnalyzer.enabled(settings)
    settings.analyzers.yara.enabled = False
    assert not YaraAnalyzer.enabled(settings)
    settings.analyzers.yara.enabled = True
    settings.analyzers.disabled = ["yara"]
    assert not YaraAnalyzer.enabled(settings)


def test_resolve_rules_dir(tmp_path):
    (tmp_path / "rules" / "yara").mkdir(parents=True)
    # relativa: primero el CWD
    assert resolve_rules_dir(Path("rules/yara"), cwd=tmp_path) == tmp_path / "rules" / "yara"
    # si no está en el CWD, la raíz del repo
    other = tmp_path / "vacio"
    other.mkdir()
    assert resolve_rules_dir(Path("rules/yara"), cwd=other) == REPO_ROOT / "rules/yara"
    assert resolve_rules_dir(tmp_path / "nada") is None
    assert resolve_rules_dir(Path("tampoco/existe"), cwd=other) is None


async def test_hostile_inputs_do_not_break_the_scanner(analyzer, make_ctx):
    hostile = [
        b"\x00" * (2 * 1024 * 1024),
        b"MZ" + b"\xff" * 4096,  # e_lfanew apunta fuera del archivo
        b"MZ",
        ("A" * 100_000 + "<HTA:APPLICATION").encode(),
        b"\xff\xfe" + "texto UTF-16 con ‮ caracteres raros".encode("utf-16-le"),
    ]
    for i, data in enumerate(hostile):
        findings = await analyzer.analyze(make_ctx(), make_artifact(data, "h.bin", "unknown", id=f"att{i}"))
        assert all(f.rule.startswith("yara.") for f in findings)


# --------------------------------------------------------------------------- yara-python (fallback)


class _FakeYaraModule(types.SimpleNamespace):
    """Imita la API de yara-python lo justo para probar el adaptador."""


def _fake_yara(matches, *, raise_timeout: bool = False):
    class TimeoutErr(Exception):
        pass

    class Rules:
        def __iter__(self):
            return iter([object(), object()])

        def match(self, data, timeout, externals):
            assert isinstance(data, bytes) and timeout >= 1 and "filename" in externals
            if raise_timeout:
                raise TimeoutErr("scan timed out")
            return matches

    def compile(filepaths=None, externals=None):  # noqa: A001
        for p in (filepaths or {}).values():
            if "rota" in p:
                raise SyntaxError("regla rota")
        return Rules()

    return _FakeYaraModule(compile=compile, TimeoutError=TimeoutErr)


def test_yara_python_adapter_new_and_old_string_api(tmp_path):
    inst = types.SimpleNamespace(offset=10, matched_data=b"S\x00t\x00u\x00b\x00", matched_length=8)
    new_style = types.SimpleNamespace(
        rule="R1",
        namespace="ns",
        meta={"family": "AsyncRAT", "score": 95},
        tags=["t"],
        strings=[types.SimpleNamespace(identifier="$a", instances=[inst, inst])],
    )
    old_style = types.SimpleNamespace(
        rule="R2", namespace="ns", meta={}, tags=[], strings=[(5, "$b", b"hola"), (9, "$b", b"hola")]
    )
    engine = YaraPythonEngine(_fake_yara([new_style, old_style]))
    hits = engine.scan(engine.build([]), 1, b"data", 5, {"filename": "x"})
    assert [h.rule for h in hits] == ["R1", "R2"]
    assert hits[0].patterns[0].identifier == "$a" and hits[0].patterns[0].count == 2
    assert hits[0].patterns[0].sample == "Stub"
    assert hits[1].patterns[0].offsets == [5, 9] and hits[1].patterns[0].sample == "hola"
    assert hits[0].meta["family"] == "AsyncRAT"


def test_yara_python_adapter_maps_timeout_and_broken_files(tmp_path):
    engine = YaraPythonEngine(_fake_yara([], raise_timeout=True))
    with pytest.raises(ScanTimeoutError):
        engine.scan(engine.build([]), 1, b"x", 5, {"filename": ""})
    rule_file = yara_scan.RuleFile(
        path=tmp_path / "rota.yar", namespace="rota.yar", display="rota.yar", source=""
    )
    assert engine.check(rule_file) is not None


def test_finding_from_hit_clamps_scores_and_handles_odd_meta():
    art = make_artifact(b"x", "x.bin", "unknown")
    hit = RuleHit(
        rule="Rara",
        namespace="ns",
        meta={"score": "250", "severity": "HIGH", "category": "phishing", "description": "  "},
        tags=[],
    )
    f = yara_scan.finding_from_hit(hit, art, engine="yara-x", source_file=None)
    assert f.score == 100 and f.severity == Severity.HIGH
    assert f.category == FindingCategory.PHISHING
    assert f.description  # descripción por defecto en español
    hit2 = RuleHit(rule="Fam", namespace="ns", meta={"family": "Generic"}, tags=[])
    f2 = yara_scan.finding_from_hit(hit2, art, engine="yara-x", source_file=None)
    assert f2.malware_family is None  # "Generic" no es una familia


def test_sample_helpers_are_inert():
    pe = fake_pe(a("hola"))
    assert pe[:2] == b"MZ" and b".text" not in pe  # sin secciones ni código
