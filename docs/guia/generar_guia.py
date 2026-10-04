"""Genera docs/Guia-de-instalacion-Centinela.pdf a partir de docs/guia/contenido.py.

Uso (desde la raíz del repo):
    pip install reportlab
    python docs/guia/generar_guia.py

Para cambiar el texto, editar contenido.py y volver a generar.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import reportlab
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    CondPageBreak,
    KeepTogether,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from contenido import CONTENIDO, REPO  # noqa: E402

VERSION = "0.1.0"
SALIDA = Path(__file__).resolve().parents[1] / "Guia-de-instalacion-Centinela.pdf"

# ----------------------------------------------------------------------------- estilo
# Fuente Bitstream Vera (licencia libre, incluida en reportlab): cubre los acentos del español.

FONT_DIR = Path(os.path.dirname(reportlab.__file__)) / "fonts"
pdfmetrics.registerFont(TTFont("Vera", str(FONT_DIR / "Vera.ttf")))
pdfmetrics.registerFont(TTFont("Vera-Bold", str(FONT_DIR / "VeraBd.ttf")))
pdfmetrics.registerFont(TTFont("Vera-Italic", str(FONT_DIR / "VeraIt.ttf")))
pdfmetrics.registerFont(TTFont("Vera-BoldItalic", str(FONT_DIR / "VeraBI.ttf")))
pdfmetrics.registerFontFamily(
    "Vera", normal="Vera", bold="Vera-Bold", italic="Vera-Italic", boldItalic="Vera-BoldItalic"
)

AZUL = colors.HexColor("#14325c")
ACENTO = colors.HexColor("#0f8b8d")
GRIS = colors.HexColor("#5b6472")
FONDO_CODIGO = colors.HexColor("#f2f4f7")
BORDE = colors.HexColor("#d5dae1")
CALLOUT = {
    "importante": (colors.HexColor("#fdecea"), colors.HexColor("#c0392b"), "Importante"),
    "consejo": (colors.HexColor("#e8f6f3"), ACENTO, "Consejo"),
    "nota": (colors.HexColor("#eef2fb"), AZUL, "Nota"),
}

S = {
    "titulo": ParagraphStyle("titulo", fontName="Vera-Bold", fontSize=30, leading=36, textColor=AZUL),
    "subtitulo": ParagraphStyle("subtitulo", fontName="Vera", fontSize=14, leading=20, textColor=GRIS),
    "h1": ParagraphStyle(
        "h1", fontName="Vera-Bold", fontSize=17, leading=22, textColor=AZUL, spaceBefore=6, spaceAfter=8
    ),
    "h2": ParagraphStyle(
        "h2", fontName="Vera-Bold", fontSize=12.5, leading=16, textColor=ACENTO, spaceBefore=10, spaceAfter=4
    ),
    "p": ParagraphStyle("p", fontName="Vera", fontSize=9.6, leading=14, spaceAfter=6),
    "li": ParagraphStyle("li", fontName="Vera", fontSize=9.6, leading=13.6, leftIndent=14, bulletIndent=3),
    "celda": ParagraphStyle("celda", fontName="Vera", fontSize=8.6, leading=11.5),
    "celda_b": ParagraphStyle(
        "celda_b", fontName="Vera-Bold", fontSize=8.6, leading=11.5, textColor=colors.white
    ),
    "code": ParagraphStyle("code", fontName="Courier", fontSize=8.4, leading=11),
    "callout": ParagraphStyle("callout", fontName="Vera", fontSize=9.2, leading=13),
    "toc": ParagraphStyle("toc", fontName="Vera", fontSize=10.5, leading=17),
    "centro": ParagraphStyle(
        "centro", fontName="Vera", fontSize=9, leading=13, alignment=TA_CENTER, textColor=GRIS
    ),
}

ANCHO = A4[0] - 40 * mm


# ----------------------------------------------------------------------------- render


def _inline(text: str) -> str:
    """`codigo` -> fuente monoespaciada (escapando & < > adentro); el resto pasa como marcado de reportlab."""
    out, in_code = [], False
    for i, part in enumerate(text.split("`")):
        if i:
            in_code = not in_code
        if in_code:
            part = part.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            out.append(f'<font name="Courier" color="#14325c">{part}</font>')
        else:
            out.append(part)
    return "".join(out)


def _caja(contenido, fondo, estilo_extra: list) -> Table:
    t = Table([[contenido]], colWidths=[ANCHO])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), fondo),
                ("LEFTPADDING", (0, 0), (-1, -1), 9),
                ("RIGHTPADDING", (0, 0), (-1, -1), 9),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                *estilo_extra,
            ]
        )
    )
    return t


def _callout(kind: str, text: str) -> list:
    fondo, borde, etiqueta = CALLOUT[kind]
    p = Paragraph(
        f'<font name="Vera-Bold" color="{borde.hexval()}">{etiqueta}.</font> {_inline(text)}', S["callout"]
    )
    return [Spacer(1, 3), _caja(p, fondo, [("LINEBEFORE", (0, 0), (0, -1), 3, borde)]), Spacer(1, 7)]


def _code(text: str) -> list:
    return [
        _caja(Preformatted(text, S["code"]), FONDO_CODIGO, [("BOX", (0, 0), (-1, -1), 0.6, BORDE)]),
        Spacer(1, 7),
    ]


def _tabla(rows: list[list[str]], anchos_mm: list[float]) -> list:
    data = []
    for r, row in enumerate(rows):
        estilo = S["celda_b"] if r == 0 else S["celda"]
        data.append([Paragraph(_inline(c) if r else c, estilo) for c in row])
    t = Table(data, colWidths=[w * mm for w in anchos_mm], repeatRows=1)
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), AZUL),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f9fb")]),
                ("GRID", (0, 0), (-1, -1), 0.5, BORDE),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return [t, Spacer(1, 8)]


def _lista(items: list[str], numerada: bool = False) -> list:
    out = []
    for i, it in enumerate(items, 1):
        out.append(Paragraph(_inline(it), S["li"], bulletText=f"{i}." if numerada else "•"))
        out.append(Spacer(1, 2.5))
    out.append(Spacer(1, 4))
    return out


def construir_story() -> list:
    story: list = [
        Spacer(1, 55 * mm),
        Paragraph("Centinela", S["titulo"]),
        Spacer(1, 4),
        Paragraph("Guía de instalación y puesta en marcha", S["subtitulo"]),
        Spacer(1, 10),
        Paragraph(
            "Análisis pasivo y en tiempo real del correo de tu empresa: detecta troyanos de acceso remoto, "
            "programas que roban contraseñas y phishing, sin bloquear ni tocar tus mails.",
            S["p"],
        ),
        Spacer(1, 18),
        Paragraph(f"Versión {VERSION}  ·  {REPO}", S["centro"]),
        Spacer(1, 14),
        Paragraph("<b>Contenido</b>", S["h2"]),
    ]
    story += [Paragraph(b[1], S["toc"]) for b in CONTENIDO if b[0] == "h1"]
    story.append(PageBreak())

    anterior = None
    for bloque in CONTENIDO:
        tipo = bloque[0]
        if tipo == "h1":
            story += [CondPageBreak(60 * mm), Paragraph(bloque[1], S["h1"])]
        elif tipo == "h2":
            story += [CondPageBreak(35 * mm), Paragraph(bloque[1], S["h2"])]
        elif tipo == "p":
            story.append(Paragraph(_inline(bloque[1]), S["p"]))
        elif tipo == "code":
            if anterior == "p":  # el párrafo que presenta un comando queda en la misma página que el comando
                story.append(KeepTogether([story.pop(), *_code(bloque[1])]))
            else:
                story += _code(bloque[1])
        elif tipo == "lista":
            story += _lista(bloque[1])
        elif tipo == "pasos":
            story += _lista(bloque[1], numerada=True)
        elif tipo == "tabla":
            story += _tabla(bloque[1], bloque[2])
        elif tipo == "callout":
            story.append(KeepTogether(_callout(bloque[1], bloque[2])))
        elif tipo == "salto":
            story.append(CondPageBreak(120 * mm))
        else:
            raise ValueError(f"bloque desconocido: {tipo}")
        anterior = tipo
    return story


def _pie(canvas, doc) -> None:
    if doc.page == 1:
        return
    canvas.saveState()
    canvas.setFont("Vera", 7.5)
    canvas.setFillColor(GRIS)
    canvas.drawString(20 * mm, 12 * mm, "Centinela - Guía de instalación")
    canvas.drawRightString(A4[0] - 20 * mm, 12 * mm, f"Página {doc.page}")
    canvas.setStrokeColor(BORDE)
    canvas.line(20 * mm, 15 * mm, A4[0] - 20 * mm, 15 * mm)
    canvas.restoreState()


def verificar_glifos() -> None:
    """Falla si algún carácter no existe en la fuente (saldría como un cuadrado en el PDF)."""
    vera = pdfmetrics.getFont("Vera").face
    faltan: set[str] = set()

    def textos(obj):
        if isinstance(obj, str):
            yield obj
        elif isinstance(obj, (list, tuple)):
            for x in obj:
                yield from textos(x)

    for bloque in CONTENIDO:
        for t in textos(bloque[1:]):
            for ch in t:
                if bloque[0] == "code":
                    try:
                        ch.encode("cp1252")
                    except UnicodeEncodeError:
                        faltan.add(ch)
                elif ch != "\n" and ord(ch) not in vera.charToGlyph:
                    faltan.add(ch)
    if faltan:
        raise SystemExit(f"caracteres sin glifo en la fuente: {sorted(faltan)!r}")


def main() -> None:
    verificar_glifos()
    doc = SimpleDocTemplate(
        str(SALIDA),
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=18 * mm,
        bottomMargin=22 * mm,
        title="Centinela - Guía de instalación",
        author="Centinela",
        subject="Instalación y puesta en marcha de Centinela",
    )
    doc.build(construir_story(), onFirstPage=_pie, onLaterPages=_pie)
    print(f"generado: {SALIDA}")


if __name__ == "__main__":
    main()
