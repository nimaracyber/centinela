"""Registro de analizadores. Para agregar uno: crear el módulo y sumarlo a ANALYZERS."""

from __future__ import annotations

import importlib
import logging
from typing import TYPE_CHECKING

from centinela.analyzers.base import Analyzer, ArtifactAnalyzer, MessageAnalyzer

if TYPE_CHECKING:
    from centinela.core.config import Settings

log = logging.getLogger(__name__)

# (módulo, clase). El orden no importa: el pipeline los corre en paralelo.
ANALYZERS: list[tuple[str, str]] = [
    # --- mensaje completo
    ("centinela.analyzers.headers", "HeaderAnalyzer"),  # SPF/DKIM/DMARC, suplantación, lookalikes
    ("centinela.analyzers.urls", "UrlAnalyzer"),  # links de descarga, punycode, IPs, acortadores
    ("centinela.analyzers.content", "ContentAnalyzer"),  # señuelos: "factura adjunta, clave 1234"
    # --- por archivo
    ("centinela.analyzers.filetype", "FileTypeAnalyzer"),  # extensiones peligrosas, doble extensión, RTLO
    ("centinela.analyzers.clamav", "ClamAVAnalyzer"),
    ("centinela.analyzers.yara_scan", "YaraAnalyzer"),
    ("centinela.analyzers.reputation", "ReputationAnalyzer"),  # SHA-256 en MalwareBazaar / VirusTotal
    ("centinela.analyzers.reputation", "UrlReputationAnalyzer"),  # URLhaus (solo si privacy.url_lookups)
    ("centinela.analyzers.office", "OfficeAnalyzer"),  # macros VBA/XLM, DDE, template injection, Follina
    ("centinela.analyzers.pdf", "PdfAnalyzer"),
    ("centinela.analyzers.pe", "PeAnalyzer"),  # ejecutables Windows: imports de stealer, packers, .NET RATs
    ("centinela.analyzers.scripts", "ScriptAnalyzer"),  # js/vbs/ps1/hta/bat/wsf/cmd
    ("centinela.analyzers.lnk", "LnkAnalyzer"),
    ("centinela.analyzers.html", "HtmlAnalyzer"),  # HTML smuggling, formularios de login locales
    ("centinela.analyzers.onenote", "OneNoteAnalyzer"),
]


def load_analyzer_classes() -> list[type[Analyzer]]:
    classes: list[type[Analyzer]] = []
    for module_name, class_name in ANALYZERS:
        try:
            module = importlib.import_module(module_name)
            cls = getattr(module, class_name)
        except Exception as exc:  # noqa: BLE001 - un analizador roto no debe tumbar el sistema
            log.warning("analizador %s.%s no disponible: %s", module_name, class_name, exc)
            continue
        classes.append(cls)
    return classes


def build_analyzers(settings: Settings) -> list[Analyzer]:
    out: list[Analyzer] = []
    for cls in load_analyzer_classes():
        if not cls.enabled(settings):
            continue
        if not cls.available():
            log.warning("analizador %s omitido: falta una dependencia opcional", cls.name)
            continue
        out.append(cls(settings))
    return out


__all__ = ["ANALYZERS", "Analyzer", "ArtifactAnalyzer", "MessageAnalyzer", "build_analyzers"]
