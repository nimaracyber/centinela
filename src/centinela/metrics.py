"""Métricas Prometheus (expuestas en /metrics por la API). Etiquetas de baja cardinalidad solamente."""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

REGISTRY = CollectorRegistry(auto_describe=True)

MESSAGES_ANALYZED = Counter(
    "centinela_messages_analyzed_total", "Mensajes analizados", ["connector", "verdict"], registry=REGISTRY
)
FINDINGS = Counter(
    "centinela_findings_total", "Hallazgos por categoría", ["category", "severity"], registry=REGISTRY
)
ANALYSIS_DURATION = Histogram(
    "centinela_analysis_duration_seconds",
    "Duración del análisis por mensaje",
    buckets=(0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60, 120, 300),
    registry=REGISTRY,
)
ANALYZER_ERRORS = Counter(
    "centinela_analyzer_errors_total", "Errores de analizadores", ["analyzer"], registry=REGISTRY
)
ALERTS_SENT = Counter("centinela_alerts_total", "Alertas enviadas", ["channel", "status"], registry=REGISTRY)
TAGS_APPLIED = Counter(
    "centinela_tags_total", "Etiquetas aplicadas", ["connector", "status"], registry=REGISTRY
)
QUEUE_DEPTH = Gauge("centinela_queue_depth", "Mensajes pendientes en la cola", registry=REGISTRY)
CONNECTOR_UP = Gauge(
    "centinela_connector_up", "1 si el conector está conectado", ["connector"], registry=REGISTRY
)
MESSAGES_INGESTED = Counter(
    "centinela_messages_ingested_total", "Mensajes recibidos de conectores", ["connector"], registry=REGISTRY
)
