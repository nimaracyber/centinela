"""La evidencia que Centinela guarda/muestra/envía no debe contener comandos de ataque literales."""

from __future__ import annotations

from centinela.core.defang import SEP, neutralize, neutralize_text
from centinela.core.models import Finding, FindingCategory, Severity


def j(*parts: str) -> str:
    """Arma cadenas sensibles por partes para que el archivo de test no las contenga literales."""
    return "".join(parts)


def test_keywords_are_split_but_readable():
    cmd = j(
        "power", "shell -w hidden -nop ", "I", "EX (New-Object Net.Web", "Client).Download", "String('x')"
    )
    out = neutralize_text(cmd)
    assert j("power", "shell") not in out.lower()
    assert j("download", "string") not in out.lower()
    assert j("web", "client") not in out.lower()
    assert SEP in out
    # sigue siendo legible quitando el separador
    assert out.replace(SEP, "") == cmd


def test_short_aliases_only_as_whole_words():
    assert neutralize_text(j("i", "ex $x")).startswith("i" + SEP + "ex")
    assert neutralize_text("complex index") == "complex index"


def test_long_blobs_are_truncated():
    blob = "QUJD" * 100
    out = neutralize_text(f"payload {blob} fin")
    assert blob not in out and "caracteres codificados omitidos" in out and out.endswith(" fin")
    sha256 = "a" * 64
    assert neutralize_text(sha256) == sha256  # hashes cortos quedan intactos


def test_links_and_dots_are_untouched():
    url = "https://bazaar.abuse.ch/sample/abc/"
    assert neutralize_text(url) == url


def test_idempotent_and_nested():
    data = {"a": [j("msh", "ta http://x"), {"b": (j("cert", "util -decode"),)}], "n": 3, "none": None}
    once = neutralize(data)
    assert neutralize(once) == once
    assert once["n"] == 3 and once["none"] is None
    assert j("msh", "ta") not in once["a"][0]


def test_finding_evidence_is_neutralized_on_construction():
    f = Finding(
        analyzer="t",
        rule="t.x",
        title="PowerShell que descarga",  # los títulos (texto en español) no se tocan
        category=FindingCategory.SUSPICIOUS_FILE,
        severity=Severity.HIGH,
        score=80,
        evidence={"fragmento": j("power", "shell -enc AAAA")},
    )
    assert f.title == "PowerShell que descarga"
    assert j("power", "shell") not in f.evidence["fragmento"].lower()
    # al persistir y releer (JSON) no se pierde la neutralización
    again = Finding.model_validate_json(f.model_dump_json())
    assert again.evidence == f.evidence
