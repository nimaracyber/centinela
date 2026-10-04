"""Páginas HTML del dashboard (Jinja2 con autoescape SIEMPRE activo, sin frameworks ni CDNs).

Todo lo que viene de un mail (asunto, remitente, nombres de archivo, evidencia, URLs) es hostil:
- se escapa siempre (autoescape) y nunca se marca como `|safe`;
- los caracteres invisibles, de control y de dirección bidi (U+202E "RLO", el truco de
  `factura<RLO>fdp.exe` que se ve como `factura exe.pdf`) se muestran como marcas visibles `[U+202E]`;
- las URLs se muestran "desactivadas" (`hxxps://dominio[.]com/...`) y nunca como links clicables;
- el HTML del mail nunca se renderiza.
Los únicos links externos son búsquedas por SHA-256 en VirusTotal / MalwareBazaar, que abre la persona
si quiere (el dashboard no consulta nada por su cuenta y el archivo nunca sale de la empresa).
"""

from __future__ import annotations

import json
import logging
import math
import re
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta, tzinfo
from datetime import time as dt_time
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode

import jinja2
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, Response

from centinela.api.auth import (
    CSRF_FIELD,
    LOGIN_COOKIE,
    MAX_PASSWORD_CHARS,
    MAX_USERNAME_CHARS,
    Session,
    clear_login_cookie,
    clear_session_cookie,
    pad_response_time,
    require_session,
    safe_next,
    session_from_request,
    set_login_cookie,
    set_session_cookie,
)
from centinela.core.models import (
    AnalysisResult,
    ArtifactSummary,
    Finding,
    FindingCategory,
    VerdictLevel,
    utcnow,
)
from centinela.storage.protocol import ResultFilter

if TYPE_CHECKING:
    from centinela.api.app import DashboardContext
    from centinela.storage.protocol import Stats

log = logging.getLogger(__name__)

router = APIRouter()

# --------------------------------------------------------------------------- límites de presentación

PAGE_SIZE = 50
MAX_PAGE = 2000
MAX_FINDINGS_SHOWN = 500
MAX_ARTIFACTS_SHOWN = 500
MAX_URLS_SHOWN = 300
MAX_EVIDENCE_CHARS = 6000
MAX_URL_CHARS = 2048
URL_DISPLAY_CHARS = 200
MAX_TREE_INDENT = 8
MAX_NOTE_CHARS = 500
CAMPAIGN_DAYS = (1, 7, 30, 90)

# --------------------------------------------------------------------------- vocabulario en español

LEVEL_LABELS = {
    "clean": "Limpio",
    "suspicious": "Sospechoso",
    "malicious": "Malicioso",
    "error": "Error de análisis",
}
LEVEL_PLURAL = {
    "clean": "limpios",
    "suspicious": "sospechosos",
    "malicious": "maliciosos",
    "error": "con error",
}
LEVEL_SINGULAR = {
    "clean": "limpio",
    "suspicious": "sospechoso",
    "malicious": "malicioso",
    "error": "con error",
}
LEVEL_ICONS = {"clean": "check", "suspicious": "alert", "malicious": "x", "error": "question"}
SEVERITY_LABELS = {4: "Crítico", 3: "Alto", 2: "Medio", 1: "Bajo", 0: "Informativo"}
SEVERITY_CLASSES = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}
CATEGORY_LABELS = {
    FindingCategory.MALWARE.value: "Malware",
    FindingCategory.SUSPICIOUS_FILE.value: "Archivo sospechoso",
    FindingCategory.PHISHING.value: "Phishing",
    FindingCategory.SPOOFING.value: "Suplantación de remitente",
    FindingCategory.REPUTATION.value: "Reputación (hash conocido)",
    FindingCategory.POLICY.value: "Política",
}
NIVEL_CHOICES = (
    ("", "Todos"),
    ("amenazas", "Sospechosos y maliciosos"),
    ("malicious", "Maliciosos"),
    ("suspicious", "Sospechosos"),
    ("clean", "Limpios"),
    ("error", "Con error de análisis"),
)
DIAS_SEMANA = ("lun", "mar", "mié", "jue", "vie", "sáb", "dom")
HEALTH_KEY_LABELS = {
    "ok": "Funciona",
    "backend": "Motor",
    "depth": "Mensajes en cola",
    "dead_letters": "Mensajes fallidos (dead letter)",
    "error": "Error",
    "enabled": "Habilitado",
    "last_error": "Último error",
    "last_error_at": "Fecha del último error",
    "last_sync": "Última sincronización",
    "last_connect": "Última conexión",
    "last_scan": "Último escaneo",
    "folders": "Carpetas",
    "mailboxes": "Buzones",
    "host": "Servidor",
    "mailbox": "Buzón",
    "type": "Tipo",
    "listen": "Escucha en",
    "running": "En marcha",
    "processed": "Procesados",
    "failed": "Fallidos",
    "path": "Carpeta",
    "pending": "Pendientes",
    "pending_analyses": "Análisis pendientes",
    "connections": "Conexiones",
    "connected": "Conectado",
    "realtime": "Tiempo real",
    "watch_expiration": "Vencimiento del aviso en tiempo real",
    "skipped_too_large": "Omitidos por tamaño",
    "truncated_too_large": "Muy grandes (solo encabezados)",
    "auth": "Autenticación",
    "idle": "IMAP IDLE",
}
FLASH_MESSAGES = {
    "marcado": "Listo: el mail quedó marcado como falso positivo.",
    "desmarcado": "Listo: se quitó la marca de falso positivo.",
}

# --------------------------------------------------------------------------- formato


_INVISIBLE_RE = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f​-‏‪-‮⁠-⁤⁦-⁩﻿]")
_CONTROL_RE = re.compile("[\x00-\x1f\x7f]")


def visible(value: Any) -> str:
    """Hace visibles los caracteres invisibles / de control / bidi: `[U+202E]` en lugar del carácter."""
    text = "" if value is None else str(value)
    return _INVISIBLE_RE.sub(lambda m: f"[U+{ord(m.group()):04X}]", text)


def level_value(level: Any) -> str:
    value = str(getattr(level, "value", level) or "").lower()
    return value if value in LEVEL_LABELS else "error"


def level_label(level: Any) -> str:
    return LEVEL_LABELS[level_value(level)]


def severity_value(severity: Any) -> int:
    try:
        value = int(severity)
    except (TypeError, ValueError):
        return 0
    return max(0, min(4, value))


def severity_label(severity: Any) -> str:
    return SEVERITY_LABELS[severity_value(severity)]


def severity_class(severity: Any) -> str:
    return SEVERITY_CLASSES[severity_value(severity)]


def category_label(category: Any) -> str:
    value = str(getattr(category, "value", category) or "")
    return CATEGORY_LABELS.get(value, value or "Otro")


def fmt_int(value: Any) -> str:
    try:
        return f"{int(value):,}".replace(",", ".")
    except (TypeError, ValueError):
        return "0"


def fmt_bytes(value: Any) -> str:
    try:
        n = max(0, int(value))
    except (TypeError, ValueError):
        return "—"
    if n < 1024:
        return f"{n} bytes" if n != 1 else "1 byte"
    size = float(n)
    for unit in ("KB", "MB", "GB", "TB"):
        size /= 1024
        if size < 1024 or unit == "TB":
            return f"{size:.1f} {unit}".replace(".", ",")
    return f"{n} bytes"  # pragma: no cover


def fmt_ms(value: Any) -> str:
    try:
        ms = max(0, int(value))
    except (TypeError, ValueError):
        return "—"
    if ms < 1000:
        return f"{ms} ms"
    return f"{ms / 1000:.1f} s".replace(".", ",")


def make_fmt_dt(tz: tzinfo) -> Callable[[Any], str]:
    def fmt_dt(value: Any, with_seconds: bool = False) -> str:
        if value is None or value == "":
            return "—"
        dt = value
        if isinstance(value, str):
            try:
                dt = datetime.fromisoformat(value)
            except ValueError:
                return visible(value)[:40]
        if not isinstance(dt, datetime):
            return visible(value)[:40]
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        dt = dt.astimezone(tz)
        return dt.strftime("%d/%m/%Y %H:%M:%S" if with_seconds else "%d/%m/%Y %H:%M")

    return fmt_dt


def short_hash(value: Any, n: int = 12) -> str:
    text = str(value or "")
    return text if len(text) <= n else text[:n] + "…"


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def is_sha256(value: Any) -> bool:
    return bool(_SHA256_RE.match(str(value or "").lower()))


def vt_url(sha256: Any) -> str:
    """Búsqueda del hash en VirusTotal (la abre la persona; no se sube ningún archivo)."""
    sha = str(sha256 or "").lower()
    return f"https://www.virustotal.com/gui/file/{sha}" if _SHA256_RE.match(sha) else ""


def mb_url(sha256: Any) -> str:
    """Búsqueda del hash en MalwareBazaar (abuse.ch)."""
    sha = str(sha256 or "").lower()
    return f"https://bazaar.abuse.ch/browse.php?search=sha256%3A{sha}" if _SHA256_RE.match(sha) else ""


_URL_PARTS_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]{0,30}):(//)?([^/?#]*)(.*)$", re.DOTALL)
_SCHEME_DEFANG = {"http": "hxxp", "https": "hxxps", "ftp": "fxp", "ftps": "fxps", "ws": "wxs", "wss": "wxss"}


def defang(url: Any) -> str:
    """`https://malo.com/x` -> `hxxps://malo[.]com/x`: se puede leer y copiar pero no abrir por error."""
    text = visible(url)[:MAX_URL_CHARS]
    m = _URL_PARTS_RE.match(text)
    if m:
        scheme, slashes, host, rest = m.groups()
        scheme = _SCHEME_DEFANG.get(scheme.lower(), scheme)
        return f"{scheme}:{slashes or ''}{host.replace('.', '[.]')}{rest}"
    head, sep, tail = text.partition("/")
    return head.replace(".", "[.]") + sep + tail


def action_label(action: Any) -> str:
    """Traduce las acciones registradas por el dispatcher ("alert:telegram:ok", "tag:...")."""
    text = visible(action)[:300]
    kind, _, rest = text.partition(":")
    if kind == "alert" and rest:
        name, _, status = rest.rpartition(":")
        name = name or rest
        if status == "ok":
            return f"Alerta enviada por «{name}»"
        if status == "dedup":
            return f"Alerta por «{name}» omitida: ya se avisó de esta misma campaña"
        if status == "error":
            return f"Falló el envío de la alerta por «{name}»"
        return f"Alerta: {rest}"
    if kind == "tag" and rest:
        name, _, status = rest.rpartition(":")
        if status == "error" and name:
            return f"No se pudo etiquetar el mail en «{name}»"
        return f"Mail etiquetado en el buzón ({rest})"
    return text


def source_label(source: Any, artifact_names: Mapping[str, str]) -> str:
    text = str(source or "")
    if text == "body_html":
        return "Cuerpo del mail (HTML)"
    if text == "body_text":
        return "Cuerpo del mail (texto)"
    if text.startswith("artifact:"):
        art_id = text.split(":", 1)[1]
        return "Adjunto: " + visible(artifact_names.get(art_id, art_id))[:200]
    return visible(text)[:200] or "—"


def evidence_text(evidence: Any) -> str:
    """Evidencia como JSON legible, acotada (se muestra escapada dentro de un <pre>)."""
    if not evidence:
        return ""
    try:
        text = json.dumps(evidence, indent=2, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError, RecursionError):
        text = str(evidence)
    if len(text) > MAX_EVIDENCE_CHARS:
        text = text[:MAX_EVIDENCE_CHARS] + "\n… (recortado)"
    return visible(text)


def key_label(key: Any) -> str:
    text = str(key)
    return HEALTH_KEY_LABELS.get(text, text.replace("_", " "))


_ISO_DT_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}")


def make_health_value(fmt_dt: Callable[[Any], str]) -> Callable[[Any], str]:
    def health_value(value: Any) -> str:
        if value is None:
            return "—"
        if isinstance(value, bool):
            return "Sí" if value else "No"
        if isinstance(value, int | float):
            return fmt_int(value) if isinstance(value, int) else f"{value:.1f}".replace(".", ",")
        text = str(value)
        if _ISO_DT_RE.match(text):
            return fmt_dt(text)
        return visible(text)

    return health_value


def bucket_label(value: Any, bucket: str, tz: tzinfo) -> str:
    try:
        dt = value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return visible(value)[:20]
    if dt.tzinfo is not None:
        dt = dt.astimezone(tz)
    if bucket == "day":
        return f"{DIAS_SEMANA[dt.weekday()]} {dt:%d/%m}"
    return f"{dt.hour:02d} h"


# --------------------------------------------------------------------------- gráfico (SVG del lado del servidor)

STACK_ORDER = (
    "malicious",
    "suspicious",
    "error",
    "clean",
)  # desde la base: las amenazas se leen contra el eje
LEGEND_ORDER = ("malicious", "suspicious", "error", "clean")
CHART_W, CHART_H = 720, 220
CHART_LEFT, CHART_RIGHT, CHART_TOP, CHART_BOTTOM = 44, 10, 12, 30
BAR_MAX_W = 24.0
SEG_GAP = 2.0
SEG_MIN_H = 4.0
BAR_RADIUS = 4.0
MAX_BARS = 200


_NICE_STEPS = (1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10)


def _nice_max(value: int) -> int:
    """Tope "redondo" del eje Y (entero) lo más ajustado posible al máximo real."""
    if value <= 1:
        return 1
    exp = 10 ** int(math.floor(math.log10(value)))
    for m in _NICE_STEPS:
        candidate = m * exp
        if candidate >= value and abs(candidate - round(candidate)) < 1e-9:
            return int(round(candidate))
    return 10 * exp  # pragma: no cover


def _bar_path(x: float, y: float, w: float, h: float, r: float) -> str:
    """Rectángulo con el extremo de datos (arriba) redondeado y la base recta."""
    r = max(0.0, min(r, w / 2, h))
    if r < 0.5:
        return f"M{x:.1f},{y:.1f}h{w:.1f}v{h:.1f}h{-w:.1f}Z"
    return (
        f"M{x:.1f},{y + h:.1f}V{y + r:.1f}Q{x:.1f},{y:.1f} {x + r:.1f},{y:.1f}"
        f"H{x + w - r:.1f}Q{x + w:.1f},{y:.1f} {x + w:.1f},{y + r:.1f}V{y + h:.1f}Z"
    )


def _count(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def build_chart(timeline: list[Any], *, bucket: str, tz: tzinfo, title: str) -> dict[str, Any]:
    """Geometría de barras apiladas (malicioso / sospechoso / error / limpio) para el template.

    Solo números y etiquetas: el SVG lo arma Jinja con autoescape. Cada segmento no vacío tiene una
    altura mínima visible (un solo malicioso entre mil limpios tiene que verse); el valor exacto está
    en el tooltip (<title>) y en la tabla accesible."""
    rows = [r for r in (timeline or []) if isinstance(r, Mapping)][-MAX_BARS:]
    counts = [{lv: _count(r.get(lv)) for lv in STACK_ORDER} for r in rows]
    totals = [sum(c.values()) for c in counts]
    ymax = _nice_max(max(totals, default=0))
    plot_w = CHART_W - CHART_LEFT - CHART_RIGHT
    plot_h = CHART_H - CHART_TOP - CHART_BOTTOM
    base_y = CHART_TOP + plot_h
    n = len(rows)
    slot = plot_w / n if n else plot_w
    bar_w = max(2.0, min(BAR_MAX_W, slot * 0.7))
    label_every = max(1, math.ceil(n / 8)) if n else 1
    bars: list[dict[str, Any]] = []
    for i, (row, c) in enumerate(zip(rows, counts, strict=True)):
        x = CHART_LEFT + i * slot + (slot - bar_w) / 2
        label = bucket_label(row.get("bucket"), bucket, tz)
        present = [lv for lv in STACK_ORDER if c[lv] > 0]
        segments: list[dict[str, str]] = []
        cursor = float(base_y)
        for j, lv in enumerate(present):
            h = max(c[lv] / ymax * plot_h, SEG_MIN_H)
            y_top = max(float(CHART_TOP), cursor - h)
            seg_bottom = cursor - (SEG_GAP if j > 0 else 0.0)
            seg_h = max(seg_bottom - y_top, 1.0)
            radius = BAR_RADIUS if j == len(present) - 1 else 0.0
            segments.append({"level": lv, "d": _bar_path(x, y_top, bar_w, seg_h, radius)})
            cursor = y_top
        detail = ", ".join(
            f"{fmt_int(c[lv])} {LEVEL_SINGULAR[lv] if c[lv] == 1 else LEVEL_PLURAL[lv]}"
            for lv in LEGEND_ORDER
        )
        bars.append(
            {
                "segments": segments,
                "title": f"{label}: {detail}",
                "hit_x": round(CHART_LEFT + i * slot, 1),
                "hit_w": round(slot, 1),
                "label": label if i % label_every == 0 else "",
                "label_x": round(x + bar_w / 2, 1),
                "full_label": label,
                "counts": c,
            }
        )
    tick_values = [0, ymax // 2, ymax] if ymax >= 2 and ymax % 2 == 0 else [0, ymax]
    ticks = [{"label": fmt_int(t), "y": round(base_y - t / ymax * plot_h, 1)} for t in tick_values]
    return {
        "title": title,
        "w": CHART_W,
        "h": CHART_H,
        "left": CHART_LEFT,
        "right": CHART_W - CHART_RIGHT,
        "top": CHART_TOP,
        "base_y": base_y,
        "label_y": CHART_H - 10,
        "bars": bars,
        "ticks": ticks,
        "empty": sum(totals) == 0,
        "totals": {lv: sum(c[lv] for c in counts) for lv in LEGEND_ORDER},
    }


def kpis(stats: Stats) -> dict[str, int]:
    by_level = stats.by_level or {}
    return {
        "total": _count(stats.total),
        "clean": _count(by_level.get("clean")),
        "suspicious": _count(by_level.get("suspicious")),
        "malicious": _count(by_level.get("malicious")),
        "error": _count(by_level.get("error")),
    }


# --------------------------------------------------------------------------- detalle de un mensaje


def artifact_tree(artifacts: list[ArtifactSummary]) -> list[tuple[ArtifactSummary, int]]:
    """Artifacts en orden de árbol (padre antes que hijos) con su profundidad visual (acotada)."""
    arts = list(artifacts[:MAX_ARTIFACTS_SHOWN])
    ids = {a.id for a in arts}
    children: dict[str, list[ArtifactSummary]] = {}
    roots: list[ArtifactSummary] = []
    for a in arts:
        if a.parent_id and a.parent_id in ids and a.parent_id != a.id:
            children.setdefault(a.parent_id, []).append(a)
        else:
            roots.append(a)
    out: list[tuple[ArtifactSummary, int]] = []
    seen: set[int] = set()
    stack = [(a, 0) for a in reversed(roots)]
    while stack:
        a, depth = stack.pop()
        if id(a) in seen:
            continue
        seen.add(id(a))
        out.append((a, min(depth, MAX_TREE_INDENT)))
        for child in reversed(children.get(a.id, [])):
            if id(child) not in seen:
                stack.append((child, depth + 1))
    for a in arts:  # ciclos o referencias raras: que igual aparezcan
        if id(a) not in seen:
            seen.add(id(a))
            out.append((a, min(max(0, a.depth), MAX_TREE_INDENT)))
    return out


def group_findings(findings: list[Finding], artifact_names: Mapping[str, str]) -> list[dict[str, Any]]:
    groups: dict[int, list[dict[str, Any]]] = {}
    for f in findings[:MAX_FINDINGS_SHOWN]:
        sev = severity_value(f.severity)
        groups.setdefault(sev, []).append(
            {
                "finding": f,
                "evidence": evidence_text(f.evidence),
                "artifact": artifact_names.get(f.artifact_id or "", f.artifact_id) if f.artifact_id else None,
            }
        )
    out = []
    for sev in sorted(groups, reverse=True):
        items = sorted(groups[sev], key=lambda it: -int(it["finding"].score))
        out.append(
            {"severity": sev, "label": SEVERITY_LABELS[sev], "cls": SEVERITY_CLASSES[sev], "items": items}
        )
    return out


def recommendations(result: AnalysisResult, *, false_positive: bool | None = None) -> list[str]:
    """ "Qué hacer", en lenguaje para alguien no técnico."""
    if false_positive is None:
        false_positive = bool(result.false_positive)
    level = level_value(result.verdict.level)
    cats = {
        str(getattr(f.category, "value", f.category))
        for f in result.findings
        if severity_value(f.severity) > 0
    }
    tips: list[str] = []
    if false_positive:
        tips.append("Este mail fue marcado como falso positivo: alguien lo revisó y lo consideró legítimo.")
    if result.truncated:
        tips.append(
            "Este mail era demasiado grande y Centinela solo revisó el remitente y los encabezados: los "
            "adjuntos NO se analizaron. No lo des por seguro; si no lo esperabas, confirmá con el remitente "
            "por otro canal antes de abrir nada."
        )
    if level == "malicious":
        tips += [
            "No abras los adjuntos ni hagas clic en los links de este mail, y no lo reenvíes.",
            "Si alguien ya abrió un adjunto o un link: desconectá esa computadora de la red (cable y Wi-Fi) "
            "y avisá enseguida a quien te da soporte informático. No la apagues: puede servir para investigar.",
        ]
        if cats & {FindingCategory.MALWARE.value, FindingCategory.REPUTATION.value}:
            tips.append(
                "Desde OTRA computadora, cambiá las contraseñas que se usan en ese equipo (correo, banco, "
                "sistemas de la empresa) y activá la verificación en dos pasos: este tipo de programas roba "
                "contraseñas guardadas en el navegador."
            )
        if FindingCategory.PHISHING.value in cats:
            tips.append(
                "Si alguien escribió su usuario y contraseña en un link de este mail, cambiá esa contraseña ya "
                "mismo y revisá que no se hayan creado reglas de reenvío en su correo."
            )
        tips.append(
            "Avisá al resto del equipo: estos ataques suelen llegar a varias personas a la vez (ver Campañas)."
        )
    elif level == "suspicious":
        tips += [
            "Tratalo con cuidado: no abras adjuntos ni links hasta confirmar que el mail es legítimo.",
            "Confirmá con el remitente por otro canal (teléfono o un contacto que ya tengas agendado), "
            "nunca respondiendo este mismo mail.",
        ]
        if FindingCategory.PHISHING.value in cats:
            tips.append(
                "Si un link te pide usuario y contraseña, no los ingreses: entrá al sitio escribiendo vos la dirección."
            )
        if FindingCategory.SPOOFING.value in cats:
            tips.append(
                "Desconfiá de pedidos de pago, cambios de CBU o cuenta bancaria y urgencias: es el engaño más "
                "común por mail."
            )
        if not false_positive:
            tips.append(
                "Si confirmás que es legítimo, marcalo como falso positivo para que quede registrado."
            )
    elif level == "error":
        tips += [
            "El análisis no se pudo completar, así que este mail NO debe considerarse seguro.",
            "Tratalo como sospechoso: no abras adjuntos ni links sin confirmar con el remitente.",
            "Revisá la página Estado por si algún componente (ClamAV, base de datos) tiene problemas.",
        ]
    else:
        tips += [
            "No se encontraron amenazas en este mail."
            if not result.truncated
            else "No se encontraron amenazas en los encabezados (el resto del mail no se pudo revisar).",
            "Igual, ante pedidos de pago, cambios de datos bancarios o urgencias inesperadas, confirmá por otro canal.",
        ]
    return tips


def false_positive_info(result: AnalysisResult) -> dict[str, Any] | None:
    """Quién marcó (o desmarcó) el falso positivo, cuándo y con qué nota (None si nunca se tocó)."""
    if not result.false_positive and result.false_positive_at is None:
        return None
    note = _CONTROL_RE.sub(" ", result.false_positive_note or "").strip()[:MAX_NOTE_CHARS]
    return {
        "active": bool(result.false_positive),
        "by": visible(result.false_positive_by or "")[:200] or None,
        "at": result.false_positive_at,
        "note": visible(note) or None,
    }


def build_detail_view(result: AnalysisResult, *, false_positive: bool | None = None) -> dict[str, Any]:
    if false_positive is None:
        false_positive = bool(result.false_positive)
    artifact_names = {a.id: (a.filename or a.id) for a in result.artifacts}
    per_artifact: dict[str, dict[str, int]] = {}
    for f in result.findings:
        if f.artifact_id:
            slot = per_artifact.setdefault(f.artifact_id, {"count": 0, "max": 0})
            slot["count"] += 1
            slot["max"] = max(slot["max"], severity_value(f.severity))
    urls = []
    for u in result.urls[:MAX_URLS_SHOWN]:
        full = defang(u.url)
        shown_text = visible(u.display_text).strip()[:200] if u.display_text else ""
        urls.append(
            {
                "full": full,
                "text": full if len(full) <= URL_DISPLAY_CHARS else full[:URL_DISPLAY_CHARS] + "…",
                "source": source_label(u.source, artifact_names),
                "display_text": shown_text if shown_text and shown_text != (u.url or "").strip() else "",
            }
        )
    families = list(result.verdict.malware_families) or sorted(
        {f.malware_family for f in result.findings if f.malware_family}
    )
    return {
        "result": result,
        "level": level_value(result.verdict.level),
        "false_positive": false_positive,
        "fp_info": false_positive_info(result),
        "truncated": bool(result.truncated),
        "listing_only_total": sum(1 for a in result.artifacts if a.listing_only),
        "recommendations": recommendations(result, false_positive=false_positive),
        "families": families[:20],
        "groups": group_findings(result.findings, artifact_names),
        "findings_total": len(result.findings),
        "findings_hidden": max(0, len(result.findings) - MAX_FINDINGS_SHOWN),
        "tree": artifact_tree(result.artifacts),
        "artifacts_total": len(result.artifacts),
        "artifacts_hidden": max(0, len(result.artifacts) - MAX_ARTIFACTS_SHOWN),
        "per_artifact": per_artifact,
        "urls": urls,
        "urls_total": len(result.urls),
        "urls_hidden": max(0, len(result.urls) - MAX_URLS_SHOWN),
        "actions": [action_label(a) for a in result.actions[:200]],
        "errors": [visible(e)[:1000] for e in result.errors[:200]],
    }


# --------------------------------------------------------------------------- estado del sistema

_SECRET_KEY_RE = re.compile(
    r"pass|secret|token|api[_-]?key|private|credential|cookie|authorization|bearer|session|signature|dsn",
    re.IGNORECASE,
)
_SECRET_VALUE_RES = (
    (re.compile(r"(?i)\b([a-z][a-z0-9+.\-]{1,20}://)[^/\s:@]{1,200}:[^/\s@]{1,200}@"), r"\1***@"),
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=\-]{4,}"), r"\1 ***"),
    (
        re.compile(
            r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)(\s*[=:]\s*)[^\s,;&]{1,500}"
        ),
        r"\1\2***",
    ),
)


def sanitize_health(value: Any, depth: int = 0) -> Any:
    """Copia acotada del dict de salud, sin claves con pinta de secreto y con credenciales enmascaradas."""
    if depth > 4:
        return "…"
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for i, (k, v) in enumerate(value.items()):
            if i >= 60:
                out["…"] = f"{len(value) - 60} más"
                break
            key = visible(k)[:80]
            if _SECRET_KEY_RE.search(key):
                continue
            out[key] = sanitize_health(v, depth + 1)
        return out
    if isinstance(value, list | tuple | set | frozenset):
        return [sanitize_health(v, depth + 1) for v in list(value)[:60]]
    if value is None or isinstance(value, bool | int | float):
        return value
    text = str(value)[:500]
    for rx, repl in _SECRET_VALUE_RES:
        text = rx.sub(repl, text)
    return visible(text)


def _dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def status_view(health: dict[str, Any]) -> dict[str, Any]:
    db = _dict(health.get("db"))
    redis = _dict(health.get("redis"))
    queue = _dict(health.get("queue"))
    components: list[dict[str, Any]] = [
        {
            "name": "Base de datos",
            "ok": bool(db.get("ok")),
            "details": {k: v for k, v in db.items() if k != "ok"},
        }
    ]
    if redis.get("enabled") is False:
        components.append(
            {
                "name": "Redis",
                "ok": True,
                "note": "No se usa: cola en memoria (modo todo-en-uno).",
                "details": {},
            }
        )
    elif redis:
        components.append(
            {
                "name": "Redis",
                "ok": bool(redis.get("ok")),
                "details": {k: v for k, v in redis.items() if k != "ok"},
            }
        )
    if queue:
        dead = queue.get("dead_letters")
        components.append(
            {
                "name": "Cola de análisis",
                "ok": not (isinstance(dead, int) and dead > 0),
                "warn_only": True,
                "details": queue,
            }
        )
    if "clamav" in health:
        clam = _dict(health.get("clamav"))
        components.append(
            {
                "name": "Antivirus ClamAV",
                "ok": bool(clam.get("ok")),
                "details": {k: v for k, v in clam.items() if k != "ok"},
            }
        )
    connectors = [
        {
            "name": name,
            "ok": bool(_dict(info).get("ok")),
            "details": {k: v for k, v in _dict(info).items() if k != "ok"},
        }
        for name, info in _dict(health.get("connectors")).items()
    ]
    status = str(health.get("status") or ("ok" if health.get("ok") else "error"))
    if status not in ("ok", "degraded", "error"):
        status = "error"
    analyzers = health.get("analyzers")
    channels = health.get("alert_channels")
    degraded = health.get("degraded")
    return {
        "status": status,
        "version": health.get("version"),
        "role": health.get("role"),
        "started_at": health.get("started_at"),
        "components": components,
        "connectors": connectors,
        "analyzers": [str(a) for a in analyzers] if isinstance(analyzers, list) else [],
        "alert_channels": [str(c) for c in channels] if isinstance(channels, list) else [],
        "degraded": [str(d) for d in degraded] if isinstance(degraded, list) else [],
    }


# --------------------------------------------------------------------------- filtros del listado


def _param(params: Mapping[str, str], name: str, limit: int) -> str:
    value = params.get(name) or ""
    return _CONTROL_RE.sub("", str(value)).strip()[:limit]


def _parse_date(value: str) -> date | None:
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


@dataclass
class MessageFilters:
    nivel: str = ""
    conector: str = ""
    buzon: str = ""
    q: str = ""
    desde: str = ""
    hasta: str = ""
    familia: str = ""
    fp: bool = False
    pagina: int = 1
    errors: list[str] = field(default_factory=list)

    @classmethod
    def from_query(cls, params: Mapping[str, str]) -> MessageFilters:
        nivel = _param(params, "nivel", 20)
        if nivel not in {value for value, _ in NIVEL_CHOICES}:
            nivel = ""
        try:
            pagina = int(_param(params, "pagina", 10) or "1")
        except ValueError:
            pagina = 1
        return cls(
            nivel=nivel,
            conector=_param(params, "conector", 64),
            buzon=_param(params, "buzon", 320),
            q=_param(params, "q", 200),
            desde=_param(params, "desde", 10),
            hasta=_param(params, "hasta", 10),
            familia=_param(params, "familia", 200),
            fp=_param(params, "fp", 5).lower() in {"1", "on", "true", "si", "sí"},
            pagina=max(1, min(pagina, MAX_PAGE)),
        )

    def to_filter(self, tz: tzinfo) -> ResultFilter:
        level: VerdictLevel | None = None
        min_level: VerdictLevel | None = None
        if self.nivel == "amenazas":
            min_level = VerdictLevel.SUSPICIOUS
        elif self.nivel:
            level = VerdictLevel(self.nivel)
        since = until = None
        if self.desde:
            d = _parse_date(self.desde)
            if d is None:
                self.errors.append("La fecha «desde» no es válida (usá el formato AAAA-MM-DD).")
                self.desde = ""
            else:
                since = datetime.combine(d, dt_time.min, tzinfo=tz).astimezone(UTC)
        if self.hasta:
            d = _parse_date(self.hasta)
            if d is None:
                self.errors.append("La fecha «hasta» no es válida (usá el formato AAAA-MM-DD).")
                self.hasta = ""
            else:
                until = (
                    datetime.combine(d, dt_time.min, tzinfo=tz) + timedelta(days=1, microseconds=-1)
                ).astimezone(UTC)
        if since and until and since > until:
            self.errors.append("La fecha «desde» es posterior a «hasta»: se ignoró el rango de fechas.")
            since = until = None
        return ResultFilter(
            level=level,
            min_level=min_level,
            connector=self.conector or None,
            mailbox=self.buzon or None,
            q=self.q or None,
            family=self.familia or None,
            since=since,
            until=until,
            include_false_positives=self.fp,
        )

    def params(self, **changes: Any) -> dict[str, str]:
        values: dict[str, Any] = {
            "nivel": self.nivel,
            "conector": self.conector,
            "buzon": self.buzon,
            "q": self.q,
            "desde": self.desde,
            "hasta": self.hasta,
            "familia": self.familia,
            "fp": "1" if self.fp else "",
            "pagina": self.pagina if self.pagina > 1 else "",
        }
        values.update(changes)
        out: dict[str, str] = {}
        for key, value in values.items():
            if value in ("", None):
                continue
            if key == "pagina" and (not isinstance(value, int) or value <= 1):
                continue
            out[key] = str(value)
        return out

    def query(self, **changes: Any) -> str:
        return urlencode(self.params(**changes))

    @property
    def active(self) -> bool:
        return any(
            (self.nivel, self.conector, self.buzon, self.q, self.desde, self.hasta, self.familia, self.fp)
        )


# --------------------------------------------------------------------------- entorno Jinja


def build_environment(
    templates_dir: Path,
    *,
    tz: tzinfo,
    static_url: Callable[[str], str],
) -> jinja2.Environment:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(templates_dir)),
        autoescape=True,  # SIEMPRE: todo lo que viene del mail es hostil
        trim_blocks=True,
        lstrip_blocks=True,
        auto_reload=False,
        enable_async=False,
    )
    fmt_dt = make_fmt_dt(tz)
    env.filters.update(
        {
            "visible": visible,
            "defang": defang,
            "level_value": level_value,
            "level_label": level_label,
            "severity_label": severity_label,
            "severity_class": severity_class,
            "category_label": category_label,
            "fmt_int": fmt_int,
            "fmt_bytes": fmt_bytes,
            "fmt_ms": fmt_ms,
            "fmt_dt": fmt_dt,
            "short_hash": short_hash,
            "key_label": key_label,
            "health_value": make_health_value(fmt_dt),
        }
    )
    env.globals.update(
        {
            "static_url": static_url,
            "vt_url": vt_url,
            "mb_url": mb_url,
            "is_sha256": is_sha256,
            "LEVEL_LABELS": LEVEL_LABELS,
            "LEVEL_ICONS": LEVEL_ICONS,
            "LEGEND_ORDER": LEGEND_ORDER,
            "NIVEL_CHOICES": NIVEL_CHOICES,
        }
    )
    return env


# --------------------------------------------------------------------------- utilidades de rutas


def _ctx(request: Request) -> DashboardContext:
    return request.app.state.centinela


def _parse_uuid(value: str) -> uuid.UUID | None:
    if not value or len(value) > 64:
        return None
    try:
        return uuid.UUID(value)
    except ValueError:
        return None


async def _read_form(request: Request) -> Mapping[str, Any]:
    try:
        return await request.form(max_files=0, max_fields=20, max_part_size=16 * 1024)
    except Exception as exc:  # noqa: BLE001 - multipart malformado, etc.
        raise HTTPException(status_code=400, detail="El formulario enviado no es válido.") from exc


def _form_str(form: Mapping[str, Any], name: str, limit: int) -> str:
    value = form.get(name)
    return value[:limit] if isinstance(value, str) else ""


def _not_found() -> HTTPException:
    return HTTPException(
        status_code=404, detail="No encontramos ese mensaje. Puede que se haya borrado por antigüedad."
    )


def _csrf_error() -> HTTPException:
    return HTTPException(
        status_code=403,
        detail="El formulario venció o no es válido (protección CSRF). Recargá la página e intentá de nuevo.",
    )


# --------------------------------------------------------------------------- login / logout


def _login_form(
    request: Request,
    *,
    status_code: int = 200,
    error: str | None = None,
    info: str | None = None,
    username: str = "",
    next_path: str = "/",
) -> Response:
    ctx = _ctx(request)
    assert ctx.sessions is not None
    cookie_value, token = ctx.sessions.new_login_token()
    response = ctx.render(
        request,
        "login.html",
        {
            "login_token": token,
            "next_path": next_path,
            "error": error,
            "info": info,
            "username": username,
            "nav": "",
        },
        status_code=status_code,
    )
    set_login_cookie(response, cookie_value, secure=ctx.proxies.is_secure(request))
    return response


@router.get("/login")
async def login_page(request: Request) -> Response:
    next_path = safe_next(request.query_params.get("next"))
    if session_from_request(request) is not None:
        return RedirectResponse(next_path, status_code=303)
    info = "Cerraste sesión." if request.query_params.get("salida") else None
    return _login_form(request, info=info, next_path=next_path)


@router.post("/login")
async def login_submit(request: Request) -> Response:
    ctx = _ctx(request)
    assert ctx.sessions is not None and ctx.verifier is not None
    started = time.perf_counter()
    form = await _read_form(request)
    username = _form_str(form, "username", MAX_USERNAME_CHARS + 1).strip()
    password = _form_str(form, "password", MAX_PASSWORD_CHARS + 1)
    next_path = safe_next(_form_str(form, "next", 2000))
    ip = ctx.proxies.client_ip(request)

    if not ctx.sessions.check_login_token(
        request.cookies.get(LOGIN_COOKIE), _form_str(form, CSRF_FIELD, 300)
    ):
        await pad_response_time(started, ctx.login_min_response_s)
        log.warning("login rechazado desde %s: formulario vencido o sin token", ip)
        return _login_form(
            request,
            status_code=400,
            error="El formulario venció o no es válido. Volvé a intentar.",
            next_path=next_path,
        )

    wait = ctx.limiter.retry_after(ip, username)
    if wait > 0:
        await pad_response_time(started, ctx.login_min_response_s)
        minutes = max(1, math.ceil(wait / 60))
        log.warning("login bloqueado temporalmente desde %s: demasiados intentos fallidos", ip)
        response = _login_form(
            request,
            status_code=429,
            error=(
                f"Demasiados intentos fallidos. Esperá {minutes} minuto{'s' if minutes != 1 else ''} "
                "y volvé a intentar."
            ),
            username=username,
            next_path=next_path,
        )
        response.headers["Retry-After"] = str(math.ceil(wait))
        return response

    if not await ctx.verifier.check(username, password):
        ctx.limiter.register_failure(ip, username)
        await pad_response_time(started, ctx.login_min_response_s)
        log.warning("login fallido desde %s", ip)
        return _login_form(
            request,
            status_code=401,
            error="Usuario o contraseña incorrectos.",
            username=username,
            next_path=next_path,
        )

    ctx.limiter.reset(ip, username)
    value, session = ctx.sessions.issue()
    await pad_response_time(started, ctx.login_min_response_s)
    secure = ctx.proxies.is_secure(request)
    response = RedirectResponse(next_path, status_code=303)
    set_session_cookie(response, value, secure=secure, max_age=ctx.sessions.max_age_s)
    clear_login_cookie(response, secure=secure)
    log.info("login exitoso de %s desde %s", session.user, ip)
    return response


@router.get("/logout")
async def logout_page(request: Request, session: Session = Depends(require_session)) -> Response:  # noqa: B008
    return _ctx(request).render(request, "logout.html", {"nav": ""})


@router.post("/logout")
async def logout_submit(request: Request) -> Response:
    ctx = _ctx(request)
    secure = ctx.proxies.is_secure(request)
    session = session_from_request(request)
    if session is None:
        response = RedirectResponse("/login", status_code=303)
        clear_session_cookie(response, secure=secure)
        return response
    request.state.session = session
    form = await _read_form(request)
    if not session.check_csrf(_form_str(form, CSRF_FIELD, 300)):
        raise _csrf_error()
    assert ctx.sessions is not None
    ctx.sessions.revoke(session)
    response = RedirectResponse("/login?salida=1", status_code=303)
    clear_session_cookie(response, secure=secure)
    log.info("logout de %s", session.user)
    return response


# --------------------------------------------------------------------------- páginas


@router.get("/")
async def overview(request: Request, session: Session = Depends(require_session)) -> Response:  # noqa: B008
    ctx = _ctx(request)
    now = utcnow()
    # consultas en serie: con SQLite en memoria comparten una única conexión
    s24 = await ctx.store.stats(now - timedelta(hours=24), bucket="hour")
    s7 = await ctx.store.stats(now - timedelta(days=7), bucket="day")
    recent, _ = await ctx.store.list_results(
        ResultFilter(min_level=VerdictLevel.SUSPICIOUS, include_false_positives=False), limit=10
    )
    return ctx.render(
        request,
        "overview.html",
        {
            "nav": "resumen",
            "k24": kpis(s24),
            "k7": kpis(s7),
            "chart24": build_chart(
                s24.timeline, bucket="hour", tz=ctx.tz, title="Mensajes por hora, últimas 24 horas"
            ),
            "chart7": build_chart(
                s7.timeline, bucket="day", tz=ctx.tz, title="Mensajes por día, últimos 7 días"
            ),
            "top_families": s7.top_families[:10],
            "top_senders": s7.top_senders[:10],
            "top_rules": s7.top_rules[:10],
            "avg_ms": s24.avg_duration_ms,
            "recent": recent,
            # para los links de los KPIs (el filtro de /messages es por día calendario)
            "desde24": (now - timedelta(hours=24)).astimezone(ctx.tz).date().isoformat(),
            "desde7": (now - timedelta(days=7)).astimezone(ctx.tz).date().isoformat(),
        },
    )


@router.get("/messages")
async def messages(request: Request, session: Session = Depends(require_session)) -> Response:  # noqa: B008
    ctx = _ctx(request)
    filters = MessageFilters.from_query(request.query_params)
    flt = filters.to_filter(ctx.tz)
    items, total = await ctx.store.list_results(flt, limit=PAGE_SIZE, offset=(filters.pagina - 1) * PAGE_SIZE)
    pages = max(1, math.ceil(total / PAGE_SIZE))
    connectors = [c.name for c in ctx.settings.connectors]
    if filters.conector and filters.conector not in connectors:
        connectors.append(filters.conector)
    return ctx.render(
        request,
        "messages.html",
        {
            "nav": "mensajes",
            "f": filters,
            "items": items,
            "total": total,
            "pages": pages,
            "page": filters.pagina,
            "first_index": (filters.pagina - 1) * PAGE_SIZE + 1,
            "connectors": connectors,
            "prev_query": filters.query(pagina=filters.pagina - 1) if filters.pagina > 1 else None,
            "next_query": filters.query(pagina=filters.pagina + 1) if filters.pagina < pages else None,
            "clear_family_query": filters.query(familia="", pagina=""),
        },
    )


@router.get("/messages/{result_id}")
async def message_detail(
    request: Request,
    result_id: str,
    session: Session = Depends(require_session),  # noqa: B008
) -> Response:
    ctx = _ctx(request)
    rid = _parse_uuid(result_id)
    if rid is None:
        raise _not_found()
    result = await ctx.store.get_result(rid)
    if result is None:
        raise _not_found()
    view = build_detail_view(result)  # la marca de falso positivo viene en el resultado (storage)
    view.update(
        {
            "nav": "mensajes",
            "flash": FLASH_MESSAGES.get(request.query_params.get("fp", "")),
            "note_max": MAX_NOTE_CHARS,
        }
    )
    return ctx.render(request, "message_detail.html", view)


@router.post("/messages/{result_id}/false-positive")
async def mark_false_positive(
    request: Request,
    result_id: str,
    session: Session = Depends(require_session),  # noqa: B008
) -> Response:
    ctx = _ctx(request)
    form = await _read_form(request)
    if not session.check_csrf(_form_str(form, CSRF_FIELD, 300)):
        raise _csrf_error()
    rid = _parse_uuid(result_id)
    if rid is None:
        raise _not_found()
    value = _form_str(form, "value", 5).strip() != "0"
    note = _CONTROL_RE.sub(" ", _form_str(form, "note", 4 * MAX_NOTE_CHARS)).strip()[:MAX_NOTE_CHARS]
    if not await ctx.store.set_false_positive(rid, value, user=session.user, note=note):
        raise _not_found()
    log.info(
        "resultado %s %s como falso positivo por %s", rid, "marcado" if value else "desmarcado", session.user
    )
    return RedirectResponse(f"/messages/{rid}?fp={'marcado' if value else 'desmarcado'}", status_code=303)


@router.get("/campaigns")
async def campaigns(request: Request, session: Session = Depends(require_session)) -> Response:  # noqa: B008
    ctx = _ctx(request)
    try:
        dias = int(request.query_params.get("dias", "30"))
    except ValueError:
        dias = 30
    if dias not in CAMPAIGN_DAYS:
        dias = 30
    items = await ctx.store.campaigns(utcnow() - timedelta(days=dias), min_messages=2, limit=100)
    return ctx.render(
        request,
        "campaigns.html",
        {"nav": "campanas", "items": items, "dias": dias, "dias_choices": CAMPAIGN_DAYS},
    )


@router.get("/status")
async def status(request: Request, session: Session = Depends(require_session)) -> Response:  # noqa: B008
    ctx = _ctx(request)
    error = None
    health: dict[str, Any] = {}
    try:
        health = await ctx.health()
    except TimeoutError:
        error = "El sistema no respondió a tiempo al pedido de estado. Puede estar sobrecargado."
    except Exception as exc:  # noqa: BLE001
        log.warning("no se pudo obtener el estado del runtime: %s", type(exc).__name__)
        error = f"No se pudo obtener el estado del sistema ({type(exc).__name__})."
    view = status_view(sanitize_health(health)) if not error else None
    return ctx.render(request, "status.html", {"nav": "estado", "error": error, "s": view})


__all__ = [
    "MessageFilters",
    "action_label",
    "artifact_tree",
    "build_chart",
    "build_detail_view",
    "build_environment",
    "defang",
    "false_positive_info",
    "mb_url",
    "recommendations",
    "router",
    "sanitize_health",
    "status_view",
    "visible",
    "vt_url",
]
