"""Unidades de presentación: defang, caracteres invisibles, gráfico, árbol, acciones, saneo de salud, filtros."""

from __future__ import annotations

import re
import time
from datetime import UTC, datetime, timedelta

import pytest

from centinela.api.views import (
    MessageFilters,
    action_label,
    artifact_tree,
    build_chart,
    defang,
    evidence_text,
    fmt_bytes,
    fmt_int,
    mb_url,
    sanitize_health,
    visible,
    vt_url,
)
from centinela.core.models import VerdictLevel
from centinela.storage.protocol import ResultStore
from tests.api.fakes import FakeResultStore, make_artifact, sha


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://evil.example.com/a.b?x=1", "hxxps://evil[.]example[.]com/a.b?x=1"),
        ("http://192.168.0.1:8080/x", "hxxp://192[.]168[.]0[.]1:8080/x"),
        ("HTTPS://Evil.COM", "hxxps://Evil[.]COM"),
        ("ftp://files.example.org/f", "fxp://files[.]example[.]org/f"),
        ("www.evil.com/login.php", "www[.]evil[.]com/login.php"),
        ("javascript:alert(1)", "javascript:alert(1)"),
        ("https://xn--bnco-nacin-x9a.com", "hxxps://xn--bnco-nacin-x9a[.]com"),
        ("https://evil.com/‮cod.exe", "hxxps://evil[.]com/[U+202E]cod.exe"),
    ],
)
def test_defang(url, expected):
    assert defang(url) == expected


def test_defang_bounded_and_fast_on_hostile_input():
    start = time.perf_counter()
    out = defang("https://" + "a." * 200_000 + "/" + "x" * 100_000)
    assert time.perf_counter() - start < 1.0
    assert len(out) < 2048 * 3


def test_visible_marks_invisible_and_bidi_chars():
    assert visible("factura‮fdp.exe") == "factura[U+202E]fdp.exe"
    assert visible("a​b\x00c\x1bd﻿") == "a[U+200B]b[U+0000]c[U+001B]d[U+FEFF]"
    assert visible("línea\ncon\ttab") == "línea\ncon\ttab"
    assert visible(None) == ""


def test_hash_links_only_for_valid_sha256():
    good = sha("x")
    assert vt_url(good) == f"https://www.virustotal.com/gui/file/{good}"
    assert mb_url(good.upper()).endswith(good)
    for bad in ("", "abc", good + "0", '"><script>', "g" * 64):
        assert vt_url(bad) == "" and mb_url(bad) == ""


@pytest.mark.parametrize(
    ("action", "expected"),
    [
        ("alert:telegram:ok", "Alerta enviada por «telegram»"),
        (
            "alert:email-soporte:dedup",
            "Alerta por «email-soporte» omitida: ya se avisó de esta misma campaña",
        ),
        ("alert:webhook:error", "Falló el envío de la alerta por «webhook»"),
        (
            "tag:gmail:label:Centinela/Malicioso",
            "Mail etiquetado en el buzón (gmail:label:Centinela/Malicioso)",
        ),
        ("tag:imap-ventas:error", "No se pudo etiquetar el mail en «imap-ventas»"),
        ("otra-cosa", "otra-cosa"),
    ],
)
def test_action_labels(action, expected):
    assert action_label(action) == expected


def test_fmt_helpers():
    assert fmt_int(1234567) == "1.234.567"
    assert fmt_int("x") == "0"
    assert fmt_bytes(1) == "1 byte"
    assert fmt_bytes(512) == "512 bytes"
    assert fmt_bytes(1536) == "1,5 KB"
    assert fmt_bytes(5 * 1024 * 1024) == "5,0 MB"
    assert fmt_bytes(-3) == "0 bytes"


def test_evidence_text_bounded():
    text = evidence_text({"big": "A" * 50_000, "nested": [[[[{"x": 1}]]]]})
    assert text.endswith("(recortado)") and len(text) < 7000
    assert evidence_text({}) == ""


def _timeline(counts: list[dict[str, int]]) -> list[dict]:
    base = datetime(2026, 10, 3, 0, 0, tzinfo=UTC)
    return [{"bucket": (base + timedelta(hours=i)).isoformat(), **c} for i, c in enumerate(counts)]


def test_chart_geometry_and_small_values_visible():
    rows = [{"clean": 1000, "malicious": 1}, {"clean": 0}, {"suspicious": 3, "error": 2}]
    chart = build_chart(_timeline(rows), bucket="hour", tz=UTC, title="t")
    assert chart["empty"] is False
    assert chart["totals"] == {"malicious": 1, "suspicious": 3, "error": 2, "clean": 1000}
    first = chart["bars"][0]
    assert [s["level"] for s in first["segments"]] == ["malicious", "clean"]  # amenazas contra el eje
    # el único malicioso entre mil limpios se ve (altura mínima)
    height = float(re.search(r"v(\d+(?:\.\d+)?)", first["segments"][0]["d"]).group(1))
    assert height >= 3.9
    # el de arriba tiene el extremo redondeado (curvas Q), la base es recta
    assert "Q" in first["segments"][-1]["d"] and "Q" not in first["segments"][0]["d"]
    # sólo números y comandos SVG en los paths (nada interpolado de afuera)
    for bar in chart["bars"]:
        for seg in bar["segments"]:
            assert re.fullmatch(r"[MVHQhvZ0-9., \-]+", seg["d"]), seg["d"]
    assert chart["bars"][1]["segments"] == []
    assert "1.000 limpios" in first["title"] and "1 malicioso," in first["title"]
    assert [t["label"] for t in chart["ticks"]] == ["0", "600", "1.200"]  # eje ajustado a 1.001
    assert first["full_label"] == "00 h"


@pytest.mark.parametrize(
    ("maximum", "ticks"),
    [
        (0, ["0", "1"]),
        (1, ["0", "1"]),
        (2, ["0", "1", "2"]),
        (7, ["0", "4", "8"]),
        (11, ["0", "6", "12"]),
        (95, ["0", "50", "100"]),
    ],
)
def test_chart_y_axis_is_round(maximum, ticks):
    chart = build_chart(_timeline([{"clean": maximum}]), bucket="hour", tz=UTC, title="t")
    assert [t["label"] for t in chart["ticks"]] == ticks


def test_chart_empty_and_malformed_rows():
    chart = build_chart([], bucket="day", tz=UTC, title="vacío")
    assert chart["empty"] is True and chart["bars"] == []
    chart = build_chart(
        [{"bucket": "no-fecha", "clean": "x", "malicious": -5}, "basura", None],
        bucket="day",
        tz=UTC,
        title="t",
    )
    assert len(chart["bars"]) == 1 and chart["empty"] is True
    days = build_chart(_timeline([{"clean": 1}] * 30), bucket="day", tz=UTC, title="t")
    labels = [b["label"] for b in days["bars"] if b["label"]]
    assert 0 < len(labels) <= 8  # etiquetas del eje X espaciadas
    assert days["bars"][0]["full_label"] == "sáb 03/10"


def test_chart_caps_number_of_bars():
    chart = build_chart(_timeline([{"clean": 1}] * 1000), bucket="hour", tz=UTC, title="t")
    assert len(chart["bars"]) == 200


def test_artifact_tree_orders_children_and_survives_cycles():
    arts = [
        make_artifact("hijo.exe", id="att0/hijo", parent_id="att0", depth=1),
        make_artifact("a.zip", id="att0"),
        make_artifact("nieto.js", id="att0/hijo/nieto", parent_id="att0/hijo", depth=2),
        make_artifact("b.pdf", id="att1"),
        make_artifact("ciclo1", id="c1", parent_id="c2"),
        make_artifact("ciclo2", id="c2", parent_id="c1"),
        make_artifact("huérfano", id="x", parent_id="no-existe", depth=3),
    ]
    tree = artifact_tree(arts)
    names = [(a.filename, d) for a, d in tree]
    assert names[:4] == [("a.zip", 0), ("hijo.exe", 1), ("nieto.js", 2), ("b.pdf", 0)]
    assert {n for n, _ in names} == {a.filename for a in arts}  # nadie se pierde (ni los ciclos)
    assert len(names) == len(arts)


def test_artifact_tree_depth_capped():
    arts = [make_artifact("root", id="n0")]
    for i in range(1, 30):
        arts.append(make_artifact(f"n{i}", id=f"n{i}", parent_id=f"n{i - 1}", depth=i))
    assert max(d for _, d in artifact_tree(arts)) == 8


def test_sanitize_health_drops_and_masks_secrets():
    raw = {
        "db": {"ok": False, "error": "connect failed postgresql://centinela:Sup3rS3creta@db:5432/centinela"},
        "connectors": {
            "imap": {
                "ok": True,
                "password": "hunter2",
                "client_secret": "xyz",
                "Authorization": "Bearer abc",
                "last_error": "AUTH failed: password=hunter3; token: tok123",
                "folders": {"INBOX": {"error": "Bearer eyJhbGciOi.payload.sig"}},
            }
        },
        "many": list(range(500)),
        "deep": {"a": {"b": {"c": {"d": {"e": {"f": 1}}}}}},
    }
    out = sanitize_health(raw)
    text = repr(out)
    for secret in ("Sup3rS3creta", "hunter2", "hunter3", "xyz", "tok123", "eyJhbGciOi"):
        assert secret not in text
    assert "postgresql://***@db:5432" in text
    assert "password" not in out["connectors"]["imap"]
    assert len(out["many"]) == 60
    assert "…" in text  # profundidad acotada


def test_message_filters_roundtrip_and_query():
    f = MessageFilters.from_query(
        {"nivel": "amenazas", "q": " factura ", "pagina": "3", "fp": "1", "buzon": "x\x00y"}
    )
    assert f.nivel == "amenazas" and f.q == "factura" and f.pagina == 3 and f.fp and f.buzon == "xy"
    flt = f.to_filter(UTC)
    assert flt.min_level == VerdictLevel.SUSPICIOUS and flt.level is None and flt.include_false_positives
    assert f.query(pagina=4) == "nivel=amenazas&buzon=xy&q=factura&fp=1&pagina=4"
    assert "pagina" not in f.query(pagina=1)
    f2 = MessageFilters.from_query({"nivel": "clean", "pagina": "999999"})
    assert f2.to_filter(UTC).level == VerdictLevel.CLEAN and f2.pagina == 2000
    assert not MessageFilters.from_query({}).active


def test_fake_store_implements_protocol():
    assert isinstance(FakeResultStore(), ResultStore)


def test_false_positive_info_and_recommendations():
    from centinela.api.views import false_positive_info, recommendations
    from tests.api.fakes import make_result

    r = make_result(level=VerdictLevel.SUSPICIOUS)
    assert false_positive_info(r) is None
    when = datetime(2026, 10, 3, 12, 0, tzinfo=UTC)
    marked = r.model_copy(
        update={
            "false_positive": True,
            "false_positive_by": "ana‮",
            "false_positive_note": "ok\x00" + "n" * 900,
            "false_positive_at": when,
        }
    )
    info = false_positive_info(marked)
    assert info["active"] is True and info["by"] == "ana[U+202E]" and info["at"] == when
    assert info["note"].startswith("ok ") and len(info["note"]) <= 500
    tips = recommendations(marked)
    assert tips[0].startswith("Este mail fue marcado como falso positivo")
    assert not any("marcalo como falso positivo" in t for t in tips)
    unmarked = marked.model_copy(update={"false_positive": False, "false_positive_note": None})
    assert false_positive_info(unmarked)["active"] is False
    truncated = r.model_copy(update={"truncated": True})
    assert any("los adjuntos NO se analizaron" in t for t in recommendations(truncated))
