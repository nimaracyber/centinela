from __future__ import annotations

import pytest

from centinela.core.config import ScoringConfig
from centinela.core.models import (
    Finding,
    FindingCategory,
    ParsedMessage,
    RawMessage,
    Severity,
    VerdictLevel,
)
from centinela.core.pipeline import _truncated_finding
from centinela.core.scoring import describe_family, effective_findings, is_trusted_sender, score_findings
from tests.helpers import make_artifact, make_ref

C = FindingCategory
S = Severity


def F(  # noqa: N802 - helper corto para las tablas
    rule: str,
    score: int,
    severity: Severity = S.MEDIUM,
    category: FindingCategory = C.SUSPICIOUS_FILE,
    *,
    artifact_id: str | None = None,
    family: str | None = None,
    title: str | None = None,
) -> Finding:
    return Finding(
        analyzer=rule.split(".", 1)[0],
        rule=rule,
        title=title or f"Regla {rule}",
        category=category,
        severity=severity,
        score=score,
        artifact_id=artifact_id,
        malware_family=family,
    )


def msg(from_addr: str | None = "juan@proveedor.com", artifacts=None) -> ParsedMessage:
    return ParsedMessage(ref=make_ref(), from_addr=from_addr, artifacts=artifacts or [])


CFG = ScoringConfig()


# --------------------------------------------------------------------------- tabla principal

CASES = [
    # (id, findings, cfg, from, nivel esperado, score esperado)
    ("vacio", [], CFG, None, VerdictLevel.CLEAN, 0),
    ("info_no_suma", [F("headers.info", 0, S.INFO, C.POLICY)], CFG, None, VerdictLevel.CLEAN, 0),
    ("uno_low", [F("url.shortener", 10, S.LOW, C.PHISHING)], CFG, None, VerdictLevel.CLEAN, 10),
    ("uno_medium", [F("filetype.exe", 40)], CFG, None, VerdictLevel.SUSPICIOUS, 40),
    ("noisy_or_30_50", [F("a.x", 30), F("b.y", 50)], CFG, None, VerdictLevel.SUSPICIOUS, 65),
    ("noisy_or_3x40", [F("a.x", 40), F("b.y", 40), F("c.z", 40)], CFG, None, VerdictLevel.MALICIOUS, 78),
    ("umbral_exacto_susp", [F("a.x", 30)], CFG, None, VerdictLevel.SUSPICIOUS, 30),
    ("umbral_exacto_mal", [F("a.x", 70, S.HIGH)], CFG, None, VerdictLevel.MALICIOUS, 70),
    (
        "score_100",
        [F("yara.X", 100, S.CRITICAL, C.MALWARE), F("b.y", 50)],
        CFG,
        None,
        VerdictLevel.MALICIOUS,
        100,
    ),
    # escaladas
    (
        "critical_malware_escala",
        [F("clamav.sig", 50, S.CRITICAL, C.MALWARE)],
        CFG,
        None,
        VerdictLevel.MALICIOUS,
        70,
    ),
    (
        "critical_reputation_escala",
        [F("rep.malwarebazaar", 20, S.CRITICAL, C.REPUTATION)],
        CFG,
        None,
        VerdictLevel.MALICIOUS,
        70,
    ),
    (
        "critical_otra_categoria_no_escala",
        [F("office.x", 60, S.CRITICAL, C.SUSPICIOUS_FILE)],
        CFG,
        None,
        VerdictLevel.SUSPICIOUS,
        60,
    ),
    (
        "dos_high_distintas",
        [F("lnk.ps", 35, S.HIGH), F("office.auto", 35, S.HIGH)],
        CFG,
        None,
        VerdictLevel.MALICIOUS,
        70,
    ),
    (
        "dos_high_misma_regla",
        [F("lnk.ps", 35, S.HIGH, artifact_id="att0"), F("lnk.ps", 35, S.HIGH, artifact_id="att1")],
        CFG,
        None,
        VerdictLevel.SUSPICIOUS,
        58,
    ),
    (
        "high_y_critical_distintas",
        [F("a.x", 10, S.HIGH), F("b.y", 10, S.CRITICAL, C.SUSPICIOUS_FILE)],
        CFG,
        None,
        VerdictLevel.MALICIOUS,
        70,
    ),
    # overrides
    (
        "override_silencia",
        [F("url.shortener", 40, S.MEDIUM, C.PHISHING)],
        ScoringConfig(rule_overrides={"url.shortener": 0}),
        None,
        VerdictLevel.CLEAN,
        0,
    ),
    (
        "override_silencia_critical",
        [F("yara.FalsoPositivo", 95, S.CRITICAL, C.MALWARE)],
        ScoringConfig(rule_overrides={"yara.FalsoPositivo": 0}),
        None,
        VerdictLevel.CLEAN,
        0,
    ),
    (
        "override_sube",
        [F("content.lure", 10, S.LOW, C.PHISHING)],
        ScoringConfig(rule_overrides={"content.lure": 90}),
        None,
        VerdictLevel.MALICIOUS,
        90,
    ),
    (
        "override_comodin",
        [F("url.a", 40, S.MEDIUM, C.PHISHING), F("url.b", 40, S.MEDIUM, C.PHISHING)],
        ScoringConfig(rule_overrides={"url.*": 0}),
        None,
        VerdictLevel.CLEAN,
        0,
    ),
    (
        "override_exacto_gana_comodin",
        [F("url.a", 40, S.MEDIUM, C.PHISHING)],
        ScoringConfig(rule_overrides={"url.*": 0, "url.a": 50}),
        None,
        VerdictLevel.SUSPICIOUS,
        50,
    ),
    (
        "high_silenciado_no_escala",
        [F("a.x", 35, S.HIGH), F("b.y", 35, S.HIGH)],
        ScoringConfig(rule_overrides={"b.y": 0}),
        None,
        VerdictLevel.SUSPICIOUS,
        35,
    ),
    # remitentes de confianza
    (
        "trusted_halves_weak",
        [F("url.x", 40, S.MEDIUM, C.PHISHING)],
        ScoringConfig(trusted_senders=["juan@proveedor.com"]),
        "juan@proveedor.com",
        VerdictLevel.CLEAN,
        20,
    ),
    (
        "trusted_domain",
        [F("filetype.x", 40, S.MEDIUM, C.SUSPICIOUS_FILE)],
        ScoringConfig(trusted_senders=["@proveedor.com"]),
        "otro@proveedor.com",
        VerdictLevel.CLEAN,
        20,
    ),
    (
        "trusted_domain_sin_arroba",
        [F("filetype.x", 40)],
        ScoringConfig(trusted_senders=["proveedor.com"]),
        "x@PROVEEDOR.com",
        VerdictLevel.CLEAN,
        20,
    ),
    (
        "trusted_no_subdominio",
        [F("filetype.x", 40)],
        ScoringConfig(trusted_senders=["@proveedor.com"]),
        "x@mail.proveedor.com",
        VerdictLevel.SUSPICIOUS,
        40,
    ),
    (
        "trusted_no_toca_high",
        [F("lnk.x", 60, S.HIGH, C.SUSPICIOUS_FILE)],
        ScoringConfig(trusted_senders=["@proveedor.com"]),
        "a@proveedor.com",
        VerdictLevel.SUSPICIOUS,
        60,
    ),
    (
        "trusted_no_toca_malware",
        [F("yara.AgentTesla", 95, S.CRITICAL, C.MALWARE)],
        ScoringConfig(trusted_senders=["@proveedor.com"]),
        "a@proveedor.com",
        VerdictLevel.MALICIOUS,
        95,
    ),
    (
        "trusted_no_toca_reputation_medium",
        [F("rep.vt", 40, S.MEDIUM, C.REPUTATION)],
        ScoringConfig(trusted_senders=["@proveedor.com"]),
        "a@proveedor.com",
        VerdictLevel.SUSPICIOUS,
        40,
    ),
    (
        "trusted_no_toca_policy",
        [F("archive.encrypted", 40, S.MEDIUM, C.POLICY)],
        ScoringConfig(trusted_senders=["@proveedor.com"]),
        "a@proveedor.com",
        VerdictLevel.SUSPICIOUS,
        40,
    ),
    (
        "trusted_revocado_por_spoofing_high",
        [F("url.x", 40, S.MEDIUM, C.PHISHING), F("headers.from_spoof", 60, S.HIGH, C.SPOOFING)],
        ScoringConfig(trusted_senders=["@proveedor.com"]),
        "a@proveedor.com",
        VerdictLevel.MALICIOUS,
        76,  # sin la confianza revocada sería 1-(0.8*0.4)=68 -> sospechoso
    ),
    (
        "trusted_revocado_por_dmarc_fail",
        [F("filetype.x", 40), F("headers.dmarc_fail", 30, S.MEDIUM, C.SPOOFING)],
        ScoringConfig(trusted_senders=["@proveedor.com"]),
        "a@proveedor.com",
        VerdictLevel.SUSPICIOUS,
        58,
    ),
    (
        "no_trusted_si_no_coincide",
        [F("url.x", 40, S.MEDIUM, C.PHISHING)],
        ScoringConfig(trusted_senders=["@proveedor.com"]),
        "a@otro.com",
        VerdictLevel.SUSPICIOUS,
        40,
    ),
    # umbrales a medida
    (
        "umbrales_custom",
        [F("a.x", 50)],
        ScoringConfig(suspicious_threshold=60, malicious_threshold=90),
        None,
        VerdictLevel.CLEAN,
        50,
    ),
    (
        "umbrales_custom_escala",
        [F("clamav.x", 10, S.CRITICAL, C.MALWARE)],
        ScoringConfig(suspicious_threshold=20, malicious_threshold=95),
        None,
        VerdictLevel.MALICIOUS,
        95,
    ),
]


@pytest.mark.parametrize(
    ("findings", "cfg", "from_addr", "level", "score"), [c[1:] for c in CASES], ids=[c[0] for c in CASES]
)
def test_scoring_table(findings, cfg, from_addr, level, score):
    v = score_findings(findings, cfg, msg(from_addr))
    assert v.level == level
    assert v.score == score
    assert v.level != VerdictLevel.ERROR
    assert 0 <= v.score <= 100
    assert v.summary and len(v.summary) <= 480


def test_score_is_noisy_or_rounded():
    findings = [F("a.x", 25), F("b.y", 25), F("c.z", 10, S.LOW)]
    expected = round(100 * (1 - (0.75 * 0.75 * 0.9)))
    assert score_findings(findings, CFG, msg()).score == expected


def test_findings_are_not_mutated():
    f = F("url.x", 40, S.MEDIUM, C.PHISHING)
    score_findings(
        [f], ScoringConfig(trusted_senders=["juan@proveedor.com"], rule_overrides={"url.x": 10}), msg()
    )
    assert f.score == 40


# --------------------------------------------------------------------------- resumen y familias


def test_summary_mentions_attachment_and_family_in_plain_spanish():
    art = make_artifact(b"MZ", "factura.pdf.exe", "pe", id="att0")
    findings = [
        F(
            "filetype.double_extension",
            70,
            S.HIGH,
            C.SUSPICIOUS_FILE,
            artifact_id="att0",
            title="Ejecutable disfrazado de PDF",
        ),
        F(
            "yara.AgentTesla",
            95,
            S.CRITICAL,
            C.MALWARE,
            artifact_id="att0",
            family="AgentTesla",
            title="Firma de AgentTesla",
        ),
    ]
    v = score_findings(findings, CFG, msg(artifacts=[art]))
    assert v.level == VerdictLevel.MALICIOUS
    assert "«factura.pdf.exe»" in v.summary
    assert "AgentTesla" in v.summary
    assert "contraseñas" in v.summary
    assert v.malware_families == ["AgentTesla"]


def test_summary_for_nested_artifact_mentions_container():
    parent = make_artifact(b"PK", "factura.zip", "zip", id="att0")
    child = make_artifact(b"MZ", "factura.exe", "pe", id="att0/factura.exe", depth=1, parent_id="att0")
    v = score_findings(
        [F("pe.packer", 60, S.HIGH, artifact_id="att0/factura.exe", title="Ejecutable empaquetado")],
        CFG,
        msg(artifacts=[parent, child]),
    )
    assert "«factura.exe»" in v.summary and "«factura.zip»" in v.summary
    assert v.summary.startswith("El archivo")


def test_summary_message_level_finding():
    v = score_findings(
        [F("headers.dmarc_fail", 45, S.MEDIUM, C.SPOOFING, title="El remitente no pudo verificarse (DMARC)")],
        CFG,
        msg(),
    )
    assert v.summary.startswith("Este correo es sospechoso:")
    assert "remitente no pudo verificarse" in v.summary


def test_summary_second_reason_when_no_family():
    v = score_findings(
        [
            F("a.x", 50, S.HIGH, title="Macro que se ejecuta sola"),
            F("b.y", 40, title="Link a un dominio nuevo"),
        ],
        CFG,
        msg(),
    )
    assert "Además: link a un dominio nuevo." in v.summary


def test_clean_summaries():
    assert score_findings([], CFG, msg()).summary == "No se encontraron señales de peligro en este correo."
    v = score_findings(
        [F("url.shortener", 10, S.LOW, C.PHISHING, title="Usa un acortador de links")], CFG, msg()
    )
    assert v.level == VerdictLevel.CLEAN
    assert v.summary.startswith("No se detectaron amenazas claras")


def test_silenced_findings_do_not_appear_in_summary_or_families():
    v = score_findings(
        [F("yara.Ruidosa", 90, S.CRITICAL, C.MALWARE, family="Remcos", title="Regla ruidosa")],
        ScoringConfig(rule_overrides={"yara.Ruidosa": 0}),
        msg(),
    )
    assert v.malware_families == [] and "Remcos" not in v.summary and "ruidosa" not in v.summary.lower()


def test_families_unique_and_ordered_by_importance():
    findings = [
        F("yara.remcos", 50, S.MEDIUM, C.MALWARE, family="Remcos"),
        F("clamav.x", 95, S.CRITICAL, C.MALWARE, family="AgentTesla"),
        F("rep.mb", 90, S.CRITICAL, C.REPUTATION, family="Agent Tesla"),
        F("yara.lumma", 70, S.HIGH, C.MALWARE, family="Lumma Stealer"),
    ]
    v = score_findings(findings, CFG, msg())
    assert v.malware_families == ["AgentTesla", "Lumma Stealer", "Remcos"]
    assert "Coincide con malware conocido" in v.summary


@pytest.mark.parametrize(
    ("name", "fragment"),
    [
        ("AgentTesla", "roba contraseñas"),
        ("Win32/AgentTesla.A!MTB", "roba contraseñas"),
        ("AsyncRAT", "controlar la computadora"),
        ("SomethingRAT", "controlar la computadora"),
        ("Grandoreiro", "troyano bancario"),
        ("Mekotio", "troyano bancario"),
        ("LockBit 3.0", "secuestra"),
        ("GuLoader", "descarga"),
        ("Snake Keylogger", "teclado"),
    ],
)
def test_describe_family(name, fragment):
    assert fragment in describe_family(name)


def test_describe_unknown_family():
    assert describe_family("FamiliaInventada") is None
    v = score_findings([F("yara.x", 95, S.CRITICAL, C.MALWARE, family="FamiliaInventada")], CFG, msg())
    assert "FamiliaInventada, un malware conocido" in v.summary


# --------------------------------------------------------------------------- mail demasiado grande

MB = 1024 * 1024
TOO_LARGE_SUMMARY = (
    "Este correo es sospechoso: supera el tamaño máximo que se puede analizar, así que sus adjuntos no se "
    "revisaron. Mandar archivos enormes es un truco conocido para esquivar los antivirus: abrilo solo si lo "
    "esperabas."
)


def too_large() -> Finding:
    """El hallazgo REAL que agrega el pipeline (POLICY, MEDIUM, 35) cuando el conector truncó el mail."""
    raw = RawMessage(ref=make_ref(), raw=b"Subject: x\r\n\r\n", truncated=True, original_size=80 * MB)
    return _truncated_finding(raw, 60 * MB)


def test_message_too_large_finding_contract():
    f = too_large()
    assert (f.rule, f.category, f.severity, f.score) == (
        "policy.message_too_large",
        C.POLICY,
        S.MEDIUM,
        35,
    )


def test_message_too_large_alone_is_suspicious_with_readable_summary():
    v = score_findings([too_large()], CFG, msg())
    assert v.level == VerdictLevel.SUSPICIOUS and v.score == 35
    assert v.summary == TOO_LARGE_SUMMARY
    assert "demasiado grande:" not in v.summary  # no se pega el título ("Mail demasiado grande: no se...")
    assert v.summary.count(":") == 2 and v.malware_families == []


@pytest.mark.parametrize(
    ("cfg", "score"),
    [
        (
            ScoringConfig(suspicious_threshold=60, malicious_threshold=90),
            60,
        ),  # umbral subido: no queda limpio
        (ScoringConfig(rule_overrides={"policy.message_too_large": 10}), 30),  # bajarle el peso tampoco
        (ScoringConfig(trusted_senders=["@proveedor.com"]), 35),  # POLICY: la confianza no lo toca
    ],
    ids=["umbral_alto", "override_bajo", "remitente_confianza"],
)
def test_message_too_large_never_clean(cfg, score):
    v = score_findings([too_large()], cfg, msg("juan@proveedor.com"))
    assert v.level == VerdictLevel.SUSPICIOUS and v.score == score
    assert v.summary.startswith("Este correo es sospechoso: supera el tamaño máximo")


def test_message_too_large_silenced_with_zero_override():
    v = score_findings([too_large()], ScoringConfig(rule_overrides={"policy.message_too_large": 0}), msg())
    assert v.level == VerdictLevel.CLEAN and v.score == 0
    assert v.summary == "No se encontraron señales de peligro en este correo."


def test_message_too_large_mentioned_when_other_reason_leads():
    spoof = F("headers.from_spoof", 40, S.HIGH, C.SPOOFING, title="El remitente se hace pasar por tu empresa")
    shortener = F("url.shortener", 10, S.LOW, C.PHISHING, title="Usa un acortador de links")
    v = score_findings([shortener, too_large(), spoof], CFG, msg())
    assert v.level == VerdictLevel.SUSPICIOUS and v.score == 65
    assert v.summary.startswith("Este correo es sospechoso: el remitente se hace pasar por tu empresa.")
    # el análisis incompleto gana el segundo lugar frente a otras señales
    assert v.summary.endswith(
        "Además, supera el tamaño máximo que se puede analizar y sus adjuntos no se revisaron."
    )


def test_message_too_large_with_two_high_is_malicious():
    findings = [
        F("headers.from_spoof", 60, S.HIGH, C.SPOOFING, title="El remitente se hace pasar por tu empresa"),
        F("headers.lookalike", 60, S.HIGH, C.SPOOFING, title="Dominio parecido al de un banco"),
        too_large(),
    ]
    v = score_findings(findings, CFG, msg())
    assert v.level == VerdictLevel.MALICIOUS
    assert v.summary.startswith("Este correo es peligroso:")
    assert "sus adjuntos no se revisaron" in v.summary


def test_message_too_large_leading_with_weaker_second_reason():
    shortener = F("url.shortener", 10, S.LOW, C.PHISHING, title="Usa un acortador de links")
    v = score_findings([shortener, too_large()], CFG, msg())
    assert v.summary == (
        "Este correo es sospechoso: supera el tamaño máximo que se puede analizar, así que sus adjuntos no se "
        "revisaron. Además: usa un acortador de links."
    )


def test_is_trusted_sender_helper():
    assert is_trusted_sender("Juan@Proveedor.com", ["juan@proveedor.com"])
    assert is_trusted_sender("x@proveedor.com", ["@proveedor.com"])
    assert not is_trusted_sender("x@evilproveedor.com", ["@proveedor.com"])
    assert not is_trusted_sender(None, ["@proveedor.com"])
    assert not is_trusted_sender("x@proveedor.com", [])


def test_effective_findings_exposes_adjusted_scores():
    eff = effective_findings(
        [F("url.x", 40, S.MEDIUM, C.PHISHING), F("y.z", 30)],
        ScoringConfig(trusted_senders=["@proveedor.com"], rule_overrides={"y.z": 0}),
        msg("a@proveedor.com"),
    )
    assert [(f.rule, s) for f, s in eff] == [("url.x", 20.0)]
