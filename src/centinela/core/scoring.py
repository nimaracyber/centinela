"""Scoring: lista de Findings -> Verdict (nivel, score 0-100, resumen en español, familias).

Reglas:
1. `cfg.rule_overrides` (id de regla -> score) reemplaza el score del analizador; 0 SILENCIA la regla por
   completo (no suma, no escala, no aparece en el resumen). Se acepta también un comodín final
   ("url.*") como conveniencia; gana el id exacto y después el prefijo más largo.
2. Remitentes de confianza (`trusted_senders`: dirección exacta o "@dominio") reducen a la mitad el score
   de heurísticas débiles (severidad <= MEDIUM en PHISHING / SPOOFING / SUSPICIOUS_FILE). NUNCA tocan
   MALWARE ni REPUTATION. Como el From se puede falsificar, la confianza NO se aplica si hay evidencia de
   suplantación (un finding SPOOFING de severidad HIGH o más, o `headers.dmarc_fail`).
3. Combinación noisy-OR: score = round(100 * (1 - Π(1 - s/100))).
4. Escaladas: cualquier finding CRITICAL de MALWARE/REPUTATION => MALICIOUS; dos o más findings HIGH
   (o más) en reglas distintas => al menos MALICIOUS. En ambos casos el score sube al menos al umbral.
5. Si no, por umbrales (suspicious_threshold / malicious_threshold). ERROR nunca sale de acá.
6. Análisis incompleto (`policy.message_too_large`: el mail superaba el límite y solo se miraron los
   encabezados) => al menos SUSPICIOUS aunque los umbrales se hayan subido: mandar un adjunto enorme no
   puede alcanzar para que un mail quede "limpio". Solo un override 0 lo silencia (regla 1).
"""

from __future__ import annotations

import math
import re
from typing import TYPE_CHECKING, NamedTuple

from centinela.core.models import Finding, FindingCategory, Severity, Verdict, VerdictLevel

if TYPE_CHECKING:
    from centinela.core.config import ScoringConfig
    from centinela.core.models import Artifact, ParsedMessage

__all__ = ["describe_family", "effective_findings", "is_trusted_sender", "score_findings"]

_WEAK_CATEGORIES = {FindingCategory.PHISHING, FindingCategory.SPOOFING, FindingCategory.SUSPICIOUS_FILE}
_SIGNATURE_CATEGORIES = {FindingCategory.MALWARE, FindingCategory.REPUTATION}
_AUTH_FAIL_RULES = {"headers.dmarc_fail"}
# el mail no se pudo analizar completo: nunca "limpio" (regla 6)
_INCOMPLETE_RULES = frozenset({"policy.message_too_large"})
_MAX_TITLE = 140
_MAX_SUMMARY = 480


class _Phrasing(NamedTuple):
    """Cómo nombrar una regla en el resumen cuando su título no se lee bien dentro de una oración."""

    reason: str  # va después de "Este correo es sospechoso: ..."
    aside: str  # oración completa cuando la regla NO es el motivo principal
    followup: str  # segunda oración cuando es el único motivo


_PHRASINGS: dict[str, _Phrasing] = {
    "policy.message_too_large": _Phrasing(
        reason="supera el tamaño máximo que se puede analizar, así que sus adjuntos no se revisaron",
        aside="Además, supera el tamaño máximo que se puede analizar y sus adjuntos no se revisaron.",
        followup="Mandar archivos enormes es un truco conocido para esquivar los antivirus: abrilo solo si lo "
        "esperabas.",
    ),
}


# --------------------------------------------------------------------------- familias conocidas

_FAMILY_KIND = {
    # stealers
    "stealer": "un programa que roba contraseñas y datos guardados",
    # RATs
    "rat": "un programa que permite controlar la computadora a distancia",
    # loaders
    "loader": "un programa que descarga e instala otros virus",
    # troyanos bancarios
    "banker": "un troyano bancario que roba el acceso al home banking",
    # ransomware
    "ransomware": "un programa que secuestra (cifra) los archivos para pedir rescate",
    # keyloggers
    "keylogger": "un programa que registra todo lo que se escribe con el teclado",
    # botnets / backdoors genéricos
    "backdoor": "una puerta trasera que da acceso remoto a los atacantes",
}

_FAMILIES: dict[str, str] = {
    # stealers
    "agenttesla": "stealer", "lumma": "stealer", "lummastealer": "stealer", "lummac2": "stealer",
    "redline": "stealer", "redlinestealer": "stealer", "vidar": "stealer", "raccoon": "stealer",
    "raccoonstealer": "stealer", "stealc": "stealer", "formbook": "stealer", "xloader": "stealer",
    "lokibot": "stealer", "azorult": "stealer", "risepro": "stealer", "metastealer": "stealer",
    "rhadamanthys": "stealer", "atomic": "stealer", "amos": "stealer", "strelastealer": "stealer",
    "vipkeylogger": "keylogger", "snakekeylogger": "keylogger", "snake": "keylogger", "404keylogger": "keylogger",
    "hawkeye": "keylogger", "masslogger": "keylogger",
    # RATs
    "asyncrat": "rat", "remcos": "rat", "remcosrat": "rat", "njrat": "rat", "bladabindi": "rat",
    "nanocore": "rat", "quasarrat": "rat", "quasar": "rat", "dcrat": "rat", "darkcomet": "rat",
    "warzone": "rat", "avemaria": "rat", "netwire": "rat", "xworm": "rat", "venomrat": "rat",
    "orcusrat": "rat", "netsupport": "rat", "netsupportrat": "rat", "darkgate": "rat", "nanocorerat": "rat",
    "plugx": "rat", "gh0st": "rat", "gh0strat": "rat", "valleyrat": "rat", "sectoprat": "rat", "arechclient2": "rat",
    # loaders
    "guloader": "loader", "cloudeye": "loader", "smokeloader": "loader", "bumblebee": "loader",
    "icedid": "loader", "emotet": "loader", "qakbot": "loader", "qbot": "loader", "pikabot": "loader",
    "latrodectus": "loader", "socgholish": "loader", "privateloader": "loader", "hijackloader": "loader",
    "idatloader": "loader", "dbatloader": "loader", "modiloader": "loader", "bazarloader": "loader",
    "trickbot": "loader", "ssload": "loader", "matanbuchus": "loader", "gootloader": "loader",
    # troyanos bancarios (muy activos en Latinoamérica)
    "grandoreiro": "banker", "mekotio": "banker", "casbaneiro": "banker", "metamorfo": "banker",
    "ousaban": "banker", "javali": "banker", "amavaldo": "banker", "guildma": "banker", "astaroth": "banker",
    "bbtok": "banker", "mispadu": "banker", "ursa": "banker", "vadokrist": "banker", "zumanek": "banker",
    "lampion": "banker", "coyote": "banker", "kiron": "banker", "chaes": "banker", "numando": "banker",
    "banbra": "banker", "sombra": "banker", "toitoin": "banker", "bizarro": "banker", "melcoz": "banker",
    "janeleiro": "banker", "zloader": "banker", "dridex": "banker", "ursnif": "banker", "gozi": "banker",
    # ransomware
    "lockbit": "ransomware", "blackcat": "ransomware", "alphv": "ransomware", "conti": "ransomware",
    "akira": "ransomware", "phobos": "ransomware", "stop": "ransomware", "djvu": "ransomware",
    "medusa": "ransomware", "royal": "ransomware", "blacksuit": "ransomware", "play": "ransomware",
    "cl0p": "ransomware", "clop": "ransomware", "ryuk": "ransomware", "revil": "ransomware",
    "sodinokibi": "ransomware", "babuk": "ransomware", "mallox": "ransomware", "8base": "ransomware",
    "rhysida": "ransomware", "blackbasta": "ransomware", "hive": "ransomware", "wannacry": "ransomware",
    # backdoors
    "cobaltstrike": "backdoor", "sliver": "backdoor", "metasploit": "backdoor", "meterpreter": "backdoor",
    "bruteratel": "backdoor", "havoc": "backdoor",
}  # fmt: skip

_HINTS = (
    ("ransom", "ransomware"),
    ("stealer", "stealer"),
    ("keylog", "keylogger"),
    ("rat", "rat"),
    ("loader", "loader"),
    ("banker", "banker"),
    ("bank", "banker"),
    ("backdoor", "backdoor"),
)


def _family_key(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def describe_family(name: str) -> str | None:
    """Descripción para un no-técnico de una familia de malware ("un programa que roba contraseñas...")."""
    key = _family_key(name)
    kind = _FAMILIES.get(key)
    if kind is None:
        # "Win32.AgentTesla.Gen", "Lumma Stealer", "MSIL/Remcos.A"...
        for fam, k in _FAMILIES.items():
            if len(fam) >= 5 and fam in key:
                kind = k
                break
    if kind is None:
        low = name.lower()
        for hint, k in _HINTS:
            if hint == "rat":
                if re.search(r"(?:^|[^a-z])rat(?:$|[^a-z])|rat$", low):
                    kind = k
                    break
            elif hint in low:
                kind = k
                break
    return _FAMILY_KIND.get(kind) if kind else None


# --------------------------------------------------------------------------- reglas


def _override(rule: str, overrides: dict[str, int]) -> int | None:
    if not overrides:
        return None
    if rule in overrides:
        return overrides[rule]
    best: tuple[int, int] | None = None
    for pattern, score in overrides.items():
        if pattern.endswith("*") and rule.startswith(pattern[:-1]):
            if best is None or len(pattern) > best[0]:
                best = (len(pattern), score)
    return best[1] if best else None


def is_trusted_sender(address: str | None, trusted: list[str]) -> bool:
    """True si la dirección coincide exacto con una entrada o con un "@dominio" de la lista."""
    if not address or not trusted:
        return False
    addr = address.strip().lower()
    domain = addr.rsplit("@", 1)[-1] if "@" in addr else ""
    for entry in trusted:
        e = (entry or "").strip().lower()
        if not e:
            continue
        if e.startswith("@"):
            if domain and domain == e[1:]:
                return True
        elif "@" not in e:
            if domain and domain == e:  # "proveedor.com" sin @: se interpreta como dominio
                return True
        elif addr == e:
            return True
    return False


def effective_findings(
    findings: list[Finding], cfg: ScoringConfig, message: ParsedMessage | None = None
) -> list[tuple[Finding, float]]:
    """[(finding, score efectivo)] tras overrides y remitentes de confianza (sin los silenciados)."""
    staged: list[tuple[Finding, float]] = []
    for f in findings:
        ov = _override(f.rule, cfg.rule_overrides)
        score = float(f.score if ov is None else max(0, min(100, ov)))
        if ov is not None and ov <= 0:
            continue  # silenciado
        staged.append((f, score))

    trusted = message is not None and is_trusted_sender(message.from_addr, cfg.trusted_senders)
    if trusted:
        spoofed = any(
            f.category == FindingCategory.SPOOFING
            and (f.severity >= Severity.HIGH or f.rule in _AUTH_FAIL_RULES)
            for f, _ in staged
        )
        if not spoofed:
            staged = [
                (f, s / 2 if f.category in _WEAK_CATEGORIES and f.severity <= Severity.MEDIUM else s)
                for f, s in staged
            ]
    return staged


# --------------------------------------------------------------------------- resumen


def _short(text: str, limit: int = _MAX_TITLE) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _lower_first(text: str) -> str:
    if len(text) >= 2 and text[0].isupper() and text[1].islower():
        return text[0].lower() + text[1:]
    return text


def _artifact_index(message: ParsedMessage | None) -> dict[str, Artifact]:
    return {a.id: a for a in message.artifacts} if message is not None else {}


def _subject_for(f: Finding, arts: dict[str, Artifact]) -> str:
    if not f.artifact_id:
        return "Este correo"
    art = arts.get(f.artifact_id)
    if art is None:
        return "Un archivo adjunto"
    name = art.filename or "sin nombre"
    if art.depth == 0 or not art.parent_id:
        return f"El adjunto «{_short(name, 80)}»"
    root = art
    seen = 0
    while root.parent_id and root.parent_id in arts and seen < 32:
        root = arts[root.parent_id]
        seen += 1
    container = root.filename or root.id
    return f"El archivo «{_short(name, 80)}» (dentro de «{_short(container, 80)}»)"


def _families_sentence(families: list[str]) -> str:
    if not families:
        return ""
    if len(families) == 1:
        desc = describe_family(families[0])
        if desc:
            return f"Coincide con {families[0]}, {desc}."
        return f"Coincide con {families[0]}, un malware conocido."
    names = ", ".join(families[:3])
    return f"Coincide con malware conocido: {names}."


def _summary(
    level: VerdictLevel,
    ranked: list[tuple[Finding, float]],
    families: list[str],
    message: ParsedMessage | None,
) -> str:
    if not ranked:
        return "No se encontraron señales de peligro en este correo."
    arts = _artifact_index(message)
    top = ranked[0][0]
    phrasing = _PHRASINGS.get(top.rule)
    reason = phrasing.reason if phrasing else _lower_first(_short(top.title or top.rule))
    if level == VerdictLevel.CLEAN:
        return _short(f"No se detectaron amenazas claras. Señal menor: {reason}.", _MAX_SUMMARY)
    verb = "es peligroso" if level == VerdictLevel.MALICIOUS else "es sospechoso"
    subject = _subject_for(top, arts)
    first = f"{subject} {verb}: {reason}."
    second = _families_sentence(families)
    if not second:
        others = [f for f, _ in ranked[1:] if f.rule != top.rule]
        # un análisis incompleto se menciona siempre: cambia cómo hay que leer todo el veredicto
        pick = next((f for f in others if f.rule in _INCOMPLETE_RULES), None)
        if pick is None:
            pick = next((f for f in others if f.title and f.title != top.title), None)
        if pick is not None:
            other = _PHRASINGS.get(pick.rule)
            second = other.aside if other else f"Además: {_lower_first(_short(pick.title, 100))}."
        elif phrasing:
            second = phrasing.followup
    text = f"{first} {second}".strip()
    return _short(text, _MAX_SUMMARY)


# --------------------------------------------------------------------------- API


def score_findings(findings: list[Finding], cfg: ScoringConfig, message: ParsedMessage) -> Verdict:
    """Combina los hallazgos en un veredicto. Nunca devuelve ERROR."""
    staged = effective_findings(findings, cfg, message)
    contributing = [(f, s) for f, s in staged if s > 0]

    product = math.prod(1.0 - min(100.0, max(0.0, s)) / 100.0 for _, s in contributing)
    score = int(min(100, max(0, round(100.0 * (1.0 - product)))))

    critical_signature = any(
        f.severity >= Severity.CRITICAL and f.category in _SIGNATURE_CATEGORIES for f, _ in staged
    )
    high_rules = {f.rule for f, _ in staged if f.severity >= Severity.HIGH}
    incomplete = any(f.rule in _INCOMPLETE_RULES for f, _ in staged)

    if critical_signature or len(high_rules) >= 2:
        level = VerdictLevel.MALICIOUS
        score = max(score, cfg.malicious_threshold)
    elif score >= cfg.malicious_threshold:
        level = VerdictLevel.MALICIOUS
    elif score >= cfg.suspicious_threshold:
        level = VerdictLevel.SUSPICIOUS
    elif incomplete:  # regla 6: lo que no se pudo revisar no se declara limpio
        level = VerdictLevel.SUSPICIOUS
        score = max(score, cfg.suspicious_threshold)
    else:
        level = VerdictLevel.CLEAN

    ranked = sorted(staged, key=lambda fs: (-int(fs[0].severity), -fs[1]))
    families: list[str] = []
    seen: set[str] = set()
    for f, _ in ranked:
        fam = (f.malware_family or "").strip()
        if fam and _family_key(fam) not in seen:
            seen.add(_family_key(fam))
            families.append(fam)

    summary_findings = [(f, s) for f, s in ranked if s > 0 or f.severity >= Severity.HIGH] or ranked
    if level == VerdictLevel.CLEAN:
        summary_findings = [(f, s) for f, s in ranked if s > 0]
    summary = _summary(level, summary_findings, families, message)
    return Verdict(level=level, score=min(100, score), summary=summary, malware_families=families)
