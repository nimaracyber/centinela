"""Analizador de tipo de archivo (por artifact): extensiones peligrosas y disfraces de nombre/tipo.

No abre ni ejecuta nada: trabaja con el nombre del archivo, el Content-Type declarado en el mail, el tipo
real detectado por magic bytes (`Artifact.detected_type`, ver docs/ARCHITECTURE.md) y la relación
padre/hijo de los artifacts extraídos de comprimidos (`ctx.message.artifacts`, por `parent_id`).

Reglas: extensión peligrosa, ejecutable dentro de un comprimido/imagen de disco, doble extensión
("factura.pdf.exe", "factura.pdf      .exe"), caracteres de control bidi (RTLO) en el nombre, extensión que
no coincide con el contenido real, Content-Type engañoso, imágenes de disco (ISO/IMG/VHD: esquivan la
"marca de internet" de Windows), comprimido con contraseña, límites de extracción (posible bomba de
compresión) y comprimidos cuyo único contenido es un ejecutable.

Artifacts "solo listados" (`listing_only`: entradas de un zip cifrado, demasiado grandes...): no tienen
contenido, pero su NOMBRE sí se analiza (doble extensión, ejecutable dentro del comprimido, comprimido que
solo trae un programa): ver "factura.exe" dentro de un zip con contraseña es justamente la señal. Las reglas
que miran el contenido real (tipo detectado, Content-Type) no se aplican a ellos.

Contraseñas: la bandera va en el contenedor (`password_protected` = tenía contraseña; `encrypted` = quedó
contenido sin abrir, la señal más fuerte). PDF y documentos de Office cifrados los evalúan sus analizadores.
"""

from __future__ import annotations

import logging
import unicodedata
from collections.abc import Callable
from typing import TYPE_CHECKING

from centinela.analyzers.base import ArtifactAnalyzer
from centinela.core.models import Finding, FindingCategory, Severity
from centinela.parsing.archives import (
    NOTE_CORRUPT,
    NOTE_DEPTH,
    NOTE_DUPLICATE,
    NOTE_ENCRYPTED,
    NOTE_MAX_ARTIFACTS,
    NOTE_MSG_BODY,
    NOTE_NOT_EXTRACTED,
    NOTE_RAR_UNSUPPORTED,
    NOTE_SUSPICIOUS_PATH,
    NOTE_SYMLINK,
    NOTE_TIMEOUT,
    NOTE_TOO_LARGE,
    NOTE_UNSUPPORTED,
    NOTE_ZIP_BOMB,
)

if TYPE_CHECKING:
    from centinela.analyzers.base import AnalysisContext
    from centinela.core.models import Artifact

log = logging.getLogger(__name__)

NAME = "filetype"
_MAX_NAME = 512

_BIDI = frozenset("‪‫‬‭‮⁦⁧⁨⁩‎‏؜")
_INVISIBLE = frozenset("​‌‍﻿⁠­᠎")

# extensión -> (score, explicación para un no-técnico)
_SCRIPT_WIN = "es un script de Windows que se ejecuta con doble clic"
_DANGEROUS: dict[str, tuple[int, str]] = {
    "exe": (45, "es un programa: al abrirlo se ejecuta en la computadora"),
    "scr": (45, "es un 'protector de pantalla' de Windows, que en realidad es un programa"),
    "com": (45, "es un programa de Windows"),
    "pif": (45, "es un acceso a programa de Windows que se ejecuta al abrirlo"),
    "cpl": (45, "es un módulo del Panel de control: un programa que se ejecuta al abrirlo"),
    "msi": (45, "es un instalador de programas"),
    "msp": (40, "es un parche de instalación de Windows"),
    "msc": (40, "es una consola de administración de Windows que puede ejecutar comandos"),
    "jar": (45, "es un programa Java"),
    "js": (45, _SCRIPT_WIN),
    "jse": (45, _SCRIPT_WIN),
    "vbs": (45, _SCRIPT_WIN),
    "vbe": (45, _SCRIPT_WIN),
    "wsf": (45, _SCRIPT_WIN),
    "wsh": (45, _SCRIPT_WIN),
    "hta": (45, "es una 'aplicación HTML' que se ejecuta con permisos completos en la computadora"),
    "ps1": (45, "es un script de PowerShell (comandos de Windows)"),
    "psm1": (35, "es un módulo de PowerShell (comandos de Windows)"),
    "psd1": (35, "es un archivo de datos de PowerShell"),
    "bat": (45, "es un archivo de comandos de Windows"),
    "cmd": (45, "es un archivo de comandos de Windows"),
    "lnk": (45, "es un acceso directo que puede lanzar comandos ocultos"),
    "one": (
        40,
        "es un cuaderno de OneNote, muy usado para esconder programas detrás de un botón 'hacer doble clic'",
    ),
    "chm": (40, "es un archivo de ayuda compilado que puede ejecutar código"),
    "reg": (45, "modifica el registro (la configuración interna) de Windows"),
    "url": (
        40,
        "es un acceso directo a internet, usado para saltar las protecciones de Windows (SmartScreen)",
    ),
    "iqy": (40, "es una consulta web de Excel que puede descargar y ejecutar contenido"),
    "slk": (40, "es un formato de planilla antiguo usado para ejecutar comandos"),
    "appx": (45, "es un paquete de instalación de aplicaciones de Windows"),
    "appxbundle": (45, "es un paquete de instalación de aplicaciones de Windows"),
    "msix": (45, "es un paquete de instalación de aplicaciones de Windows"),
    "msixbundle": (45, "es un paquete de instalación de aplicaciones de Windows"),
    "xll": (45, "es un complemento de Excel que en realidad es un programa"),
    "dll": (40, "es una biblioteca de programa (código ejecutable)"),
    "sys": (40, "es un controlador de Windows (código que corre con máximos privilegios)"),
    "gadget": (40, "es un gadget de escritorio de Windows (un programa)"),
    "application": (45, "es un instalador ClickOnce que instala y ejecuta una aplicación"),
    "settingcontent-ms": (45, "es un acceso de Configuración de Windows abusado para ejecutar comandos"),
    "library-ms": (40, "es una biblioteca de Windows que puede mostrar archivos remotos del atacante"),
    "search-ms": (40, "es una búsqueda guardada de Windows que puede mostrar archivos remotos del atacante"),
    "inf": (35, "es un archivo de instalación de Windows que puede ejecutar comandos"),
    "scf": (35, "es un archivo de comandos del Explorador que puede filtrar la contraseña de Windows"),
    "mht": (35, "es una página web archivada que se abre con componentes antiguos y vulnerables de Windows"),
    "mhtml": (
        35,
        "es una página web archivada que se abre con componentes antiguos y vulnerables de Windows",
    ),
}
_DISK_EXTS = frozenset({"iso", "img", "vhd", "vhdx"})
_DISK_TYPES = frozenset({"iso", "udf", "vhd", "vhdx", "img"})
_ARCHIVE_TYPES = frozenset({"zip", "jar", "7z", "rar", "gzip", "bzip2", "xz", "tar", "cab"}) | _DISK_TYPES
_ARCHIVE_EXTS = (
    frozenset({"zip", "rar", "7z", "gz", "tgz", "bz2", "xz", "tar", "cab", "arj", "lzh", "ace", "z"})
    | _DISK_EXTS
)

_BINARY_EXEC_TYPES = frozenset({"pe", "elf", "macho", "msi", "lnk", "chm"})
_LOTL_TYPES = frozenset({"url_shortcut", "iqy", "slk", "reg", "settingcontent", "library-ms", "search-ms"})
_TEXT_EXTS = frozenset({"txt", "csv", "xml", "json", "log", "md"})

# extensiones "de documento" (lo que la víctima cree que abre) -> (tipos esperados, alternativas benignas -> INFO)
_IMAGES = {"image/jpeg", "image/png", "image/gif", "image/bmp", "image/webp", "image/ico"}
_DOC_EXPECTED: dict[str, frozenset[str]] = {}
_DOC_BENIGN: dict[str, frozenset[str]] = {}
for _e, (_strict, _benign) in {
    "pdf": ({"pdf"}, {"text"}),
    "doc dot": ({"ole"}, {"rtf", "ooxml", "html", "xml", "text", "eml"}),
    "xls xlt": ({"ole"}, {"ooxml", "html", "xml", "text"}),
    "ppt pps pot": ({"ole"}, {"ooxml"}),
    "docx docm dotx dotm xlsx xlsm xltx xltm xlsb pptx pptm ppsx ppsm potx": ({"ooxml"}, {"zip", "ole"}),
    "odt ods odp odg": ({"zip"}, {"ooxml"}),
    "rtf": ({"rtf"}, {"text", "ole"}),
    "txt csv log md": ({"text"}, {"html", "xml"}),
    "xml": ({"xml", "text"}, {"html"}),
    "json": ({"text"}, set()),
    "jpg jpeg jpe": ({"image/jpeg"}, _IMAGES),
    "png": ({"image/png"}, _IMAGES),
    "gif": ({"image/gif"}, _IMAGES),
    "bmp": ({"image/bmp"}, _IMAGES),
    "webp": ({"image/webp"}, _IMAGES),
    "ico": ({"image/ico"}, _IMAGES),
    "tif tiff heic heif": (set(), _IMAGES),
    "mp3 mp4 avi mov wav wma wmv mkv m4a ogg": (set(), set()),
}.items():
    for _x in _e.split():
        _DOC_EXPECTED[_x] = frozenset(_strict)
        _DOC_BENIGN[_x] = frozenset(_benign)
_DOC_LIKE = frozenset(_DOC_EXPECTED)
_DOUBLE_INNER = _DOC_LIKE | frozenset({"zip", "rar", "7z", "html", "htm"})

_BENIGN_DECLARED_PREFIXES = (
    "image/",
    "audio/",
    "video/",
    "text/plain",
    "text/csv",
    "application/vnd.oasis.opendocument",
)
_BENIGN_DECLARED = frozenset(
    {
        "application/pdf", "application/msword", "application/vnd.ms-excel", "application/vnd.ms-powerpoint",
        "application/rtf", "text/rtf", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    }
)  # fmt: skip

_TYPE_DESC = {
    "pe": "un programa de Windows",
    "elf": "un programa de Linux",
    "macho": "un programa de Mac",
    "msi": "un instalador de Windows",
    "lnk": "un acceso directo de Windows",
    "chm": "un archivo de ayuda que puede ejecutar código",
    "url_shortcut": "un acceso directo a internet",
    "iqy": "una consulta web de Excel",
    "slk": "una planilla SYLK que puede ejecutar comandos",
    "reg": "un archivo que modifica el registro de Windows",
    "settingcontent": "un acceso de Configuración de Windows",
    "library-ms": "una biblioteca de Windows",
    "search-ms": "una búsqueda guardada de Windows",
    "script/js": "un script JavaScript de Windows",
    "script/vbs": "un script VBScript",
    "script/ps1": "un script de PowerShell",
    "script/bat": "un archivo de comandos (.bat/.cmd)",
    "script/wsf": "un script de Windows (.wsf)",
    "script/hta": "una aplicación HTML (.hta)",
    "script/vba": "código de macros VBA",
    "script/python": "un script de Python",
    "script/sh": "un script de comandos de Linux/Mac",
    "html": "una página web (HTML)",
    "svg": "una imagen SVG con capacidad de contener código",
    "zip": "un comprimido ZIP",
    "rar": "un comprimido RAR",
    "7z": "un comprimido 7-Zip",
    "iso": "una imagen de disco ISO",
}

# notas de extracción (vocabulario de parsing/archives.py). Las partes van separadas por "; ".
_LIMIT_NOTES = (NOTE_ZIP_BOMB, NOTE_DEPTH, NOTE_MAX_ARTIFACTS, NOTE_TIMEOUT, NOTE_TOO_LARGE)
_INFO_NOTES = (
    NOTE_UNSUPPORTED,
    NOTE_RAR_UNSUPPORTED,
    NOTE_DUPLICATE,
    NOTE_CORRUPT,
    NOTE_SUSPICIOUS_PATH,
    NOTE_SYMLINK,
)
_SILENT_NOTES = (NOTE_ENCRYPTED, NOTE_MSG_BODY)  # las cubre la regla de contraseña / son solo descriptivas
_MAX_NOTE_PARTS = 20
# notas de otros productores (o futuras): heurística por palabras
_LIMIT_WORDS = (
    "limite", "limit", "bomb", "ratio", "profundidad", "depth", "presupuesto", "budget", "demasiad", "too many",
    "too large", "excede", "exceed", "maxim", "tamano", "size",
)  # fmt: skip
_JUNK_NAMES = frozenset({"desktop.ini", "thumbs.db", ".ds_store", "autorun.inf"})
# tipos cuyo cifrado evalúa su propio analizador (pdf / office / onenote): no se cuenta dos veces
_ENCRYPTION_OWNED_ELSEWHERE = frozenset({"pdf", "ole", "ooxml", "rtf", "onenote"})
_LISTED_NOTE = (
    " No se pudo extraer para revisarlo por dentro (por ejemplo, porque el comprimido tiene contraseña): se lo "
    "detectó por el nombre."
)


# --------------------------------------------------------------------------- helpers de nombre


def _basename(name: str) -> str:
    return name.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1][:_MAX_NAME]


def clean_filename(name: str) -> str:
    """Nombre como lo trata Windows: sin caracteres invisibles/bidi/de control, sin puntos ni espacios finales."""
    s = "".join(c for c in name if c not in _BIDI and c not in _INVISIBLE and unicodedata.category(c) != "Cc")
    return s.rstrip(" .")


def real_extension(name: str | None) -> str:
    if not name:
        return ""
    clean = clean_filename(_basename(name))
    if "." not in clean:
        return ""
    return clean.rsplit(".", 1)[-1].strip().lower()


def _escaped(name: str) -> str:
    return "".join(f"<U+{ord(c):04X}>" if (c in _BIDI or c in _INVISIBLE) else c for c in name)[:300]


def visual_filename(name: str) -> str:
    """Aproximación de cómo se VE en pantalla un nombre con U+202E (RLO): lo que sigue se muestra al revés."""
    out: list[str] = []
    i, n = 0, len(name)
    while i < n:
        ch = name[i]
        if ch in ("‮", "⁧"):
            end_mark = "‬" if ch == "‮" else "⁩"
            j = name.find(end_mark, i + 1)
            seg = name[i + 1 : j if j != -1 else n]
            out.append(clean_filename(seg)[::-1])
            i = j + 1 if j != -1 else n
            continue
        if ch not in _BIDI and ch not in _INVISIBLE:
            out.append(ch)
        i += 1
    return "".join(out)[:300]


def _type_desc(detected: str) -> str:
    return _TYPE_DESC.get(detected, f"un archivo de tipo '{detected}'")


def is_executable_type(detected: str) -> bool:
    """Tipos detectados que se ejecutan al abrirlos (código VBA suelto no: lo cubre el analizador de Office)."""
    return (
        detected in _BINARY_EXEC_TYPES
        or detected in _LOTL_TYPES
        or (detected.startswith("script/") and detected != "script/vba")
    )


def _is_exec(a: Artifact) -> bool:
    ext = real_extension(a.filename)
    return is_executable_type(a.detected_type) or (ext in _DANGEROUS and ext not in ("mht", "mhtml", "one"))


def _is_container(a: Artifact) -> bool:
    return a.detected_type in _ARCHIVE_TYPES or real_extension(a.filename) in _ARCHIVE_EXTS


def _is_junk(a: Artifact) -> bool:
    name = (a.filename or "").replace("\\", "/")
    base = _basename(name).lower()
    return "__macosx/" in name.lower() or base.startswith("._") or base in _JUNK_NAMES


ChildrenFn = Callable[[str], list["Artifact"]]


def _children(children_of: ChildrenFn, parent: Artifact, depth: int = 0) -> list[Artifact]:
    """Hijos reales del contenedor (incluidos los solo listados); si tiene un único hijo que es otro
    contenedor, se baja (zip -> iso -> exe, zip -> zip cifrado -> exe listado)."""
    kids = [a for a in children_of(parent.id) if a.id != parent.id and not _is_junk(a)]
    if len(kids) == 1 and depth < 3 and _is_container(kids[0]):
        sub = _children(children_of, kids[0], depth + 1)
        if sub:
            return sub
    return kids


def is_password_protected(a: Artifact) -> bool:
    """El contenedor tenía contraseña (se haya podido abrir o no)."""
    return bool(a.password_protected or a.encrypted)


def _norm(text: str) -> str:
    s = unicodedata.normalize("NFKD", text[:500].lower())
    return "".join(c for c in s if not unicodedata.combining(c))


def classify_note(part: str) -> str:
    """'limit' | 'info' | 'silent' para UNA parte de `extraction_note`."""
    p = part.strip()
    if p.startswith(NOTE_NOT_EXTRACTED):  # "no extraído: <motivo>" (entradas solo listadas)
        p = p[len(NOTE_NOT_EXTRACTED) :].lstrip(" :").strip()
    if not p or p.startswith(_SILENT_NOTES):
        return "silent"
    if p.startswith(_LIMIT_NOTES):
        return "limit"
    if p.startswith(_INFO_NOTES):
        return "info"
    return "limit" if any(w in _norm(p) for w in _LIMIT_WORDS) else "info"


def _note_parts(note: str) -> list[tuple[str, str]]:
    """[(parte, clase)] de una `extraction_note` (acotado)."""
    parts = [p.strip() for p in note[:2000].split("; ") if p.strip()][:_MAX_NOTE_PARTS]
    return [(p, classify_note(p)) for p in parts]


def _finding(art: Artifact, rule: str, title: str, description: str, severity: Severity, score: int,
             evidence: dict[str, object], category: FindingCategory = FindingCategory.SUSPICIOUS_FILE) -> Finding:  # fmt: skip
    ev: dict[str, object] = {"filename": _escaped(art.filename or ""), "detected_type": art.detected_type}
    if art.listing_only:
        ev["listing_only"] = True
    ev.update(evidence)
    return Finding(
        analyzer=NAME,
        rule=rule,
        title=title[:300],
        description=description,
        category=category,
        severity=severity,
        score=max(0, min(100, score)),
        artifact_id=art.id,
        evidence=ev,
    )


# --------------------------------------------------------------------------- análisis


def analyze_artifact(
    art: Artifact, all_artifacts: list[Artifact], children_of: ChildrenFn | None = None
) -> list[Finding]:
    """Versión sincrónica (barata: solo nombres y metadatos). `children_of(id)`: hijos directos de un
    artifact (en el analizador, `AnalysisContext.children`)."""
    if children_of is None:

        def children_of(pid: str) -> list[Artifact]:
            return [a for a in all_artifacts if a.parent_id == pid]

    out: list[Finding] = []
    raw_name = _basename(art.filename or "")
    clean = clean_filename(raw_name)
    ext = real_extension(raw_name)
    shown = clean or art.id
    listed = art.listing_only  # sin contenido: solo cuentan el nombre y los metadatos
    # el tipo real sale del contenido: una entrada solo listada no lo tiene
    detected = "unknown" if listed else (art.detected_type or "unknown")
    listed_txt = _LISTED_NOTE if listed else ""
    parent = next((a for a in all_artifacts if a.id == art.parent_id), None) if art.parent_id else None
    parent_name = (
        _basename(parent.filename) if parent is not None and parent.filename else (art.parent_id or "")
    )
    subsumed = False  # una regla de disfraz ya explica la extensión peligrosa

    # 1) caracteres bidi (RTLO) en el nombre
    if any(c in _BIDI for c in raw_name):
        visual = visual_filename(raw_name)
        out.append(
            _finding(
                art,
                "filetype.rtlo",
                f"Nombre de archivo con caracteres que dan vuelta el texto (se ve como '{visual[:80]}')",
                f"El nombre contiene caracteres de control invisibles (como U+202E) que invierten el orden de las "
                f"letras en pantalla: se ve como '{visual}', pero el archivo real termina en .{ext or '?'}. Es un "
                "truco para disfrazar programas de documentos. No abrirlo." + listed_txt,
                Severity.HIGH,
                80,
                {"visual_name": visual, "real_extension": ext},
            )
        )
        subsumed = True

    # 2) doble extensión / relleno de espacios antes de la extensión real
    if not subsumed and ext and (ext in _DANGEROUS or ext in _DISK_EXTS) and clean.count(".") >= 1:
        stem = clean.rsplit(".", 1)[0]
        parts = [p.strip(" _-\t") for p in stem.split(".")]
        inner = next((p.lower() for p in reversed(parts[1:]) if p), "") if len(parts) > 1 else ""
        padded = len(stem) - len(stem.rstrip(" _")) >= 5
        if inner in _DOUBLE_INNER or padded:
            fake = f"{parts[0]}.{inner}" if inner in _DOUBLE_INNER else stem.rstrip(" _")
            reason = _DANGEROUS.get(ext, (45, "es una imagen de disco que puede contener programas"))[1]
            out.append(
                _finding(
                    art,
                    "filetype.double_extension",
                    f"Archivo con doble extensión: '{shown[:80]}'",
                    f"El nombre está armado para que parezca '{fake[:80]}', pero en realidad es un .{ext}: {reason}. "
                    "Windows suele ocultar la última extensión (o la empuja fuera de la vista con espacios), así "
                    "que la persona cree abrir un documento. No abrirlo." + listed_txt,
                    Severity.HIGH,
                    75,
                    {"real_extension": ext, "fake_extension": inner or None, "padded": padded},
                )
            )
            subsumed = True

    # 3) extensión peligrosa / ejecutable dentro de un comprimido
    exec_like = (ext in _DANGEROUS) or is_executable_type(detected)
    if not subsumed and exec_like and ext not in _DISK_EXTS:
        score, reason = _DANGEROUS.get(ext, (45, f"es {_type_desc(detected)}"))
        if ext not in _DANGEROUS:
            reason = f"es {_type_desc(detected)}"
        if art.depth > 0 and _is_exec(art):
            out.append(
                _finding(
                    art,
                    "filetype.executable_in_archive",
                    f"Programa o script escondido dentro de un comprimido ('{shown[:60]}')",
                    f"Dentro de '{parent_name[:80]}' hay un archivo '{shown[:80]}' que {reason}. Meter el "
                    "ejecutable dentro de un ZIP, RAR o ISO es la forma habitual de esquivar los filtros de "
                    "adjuntos del correo. No abrirlo." + listed_txt,
                    Severity.HIGH,
                    65,
                    {"extension": ext, "parent": parent_name[:200], "depth": art.depth},
                )
            )
        elif ext in _DANGEROUS:  # adjunto directo, o .one/.mht dentro de un comprimido
            out.append(
                _finding(
                    art,
                    "filetype.dangerous_extension",
                    f"Adjunto peligroso: archivo .{ext} ('{shown[:60]}')",
                    f"'{shown[:80]}' {reason}. Proveedores y clientes casi nunca necesitan mandar este tipo de "
                    "archivo por mail; es una de las formas más comunes de instalar virus que roban contraseñas, "
                    "toman control de la computadora o secuestran los archivos (ransomware)." + listed_txt,
                    Severity.MEDIUM,
                    score,
                    {"extension": ext},
                )
            )

    # 4) imágenes de disco
    if ext in _DISK_EXTS or detected in _DISK_TYPES:
        kind = ext if ext in _DISK_EXTS else detected
        out.append(
            _finding(
                art,
                "filetype.disk_image",
                f"Adjunto de imagen de disco (.{kind})",
                "Los archivos .iso, .img y .vhd se usan para esquivar las protecciones de Windows: al abrirlos, lo "
                "que tienen adentro pierde la marca de 'descargado de internet' y Windows no muestra advertencias. "
                "Casi nunca se mandan por mail con fines legítimos.",
                Severity.MEDIUM,
                45,
                {"extension": ext},
            )
        )

    # 5) extensión vs contenido real
    mismatch_high = False
    if detected not in ("unknown", "") and ext:
        if ext in _DOC_LIKE and detected not in _DOC_EXPECTED[ext]:
            if detected in _BINARY_EXEC_TYPES or (is_executable_type(detected) and ext not in _TEXT_EXTS):
                mismatch_high = True
                out.append(
                    _finding(
                        art,
                        "filetype.type_mismatch",
                        f"El archivo dice ser .{ext} pero en realidad es {_type_desc(detected)}",
                        f"'{shown[:80]}' tiene extensión .{ext}, pero su contenido real es {_type_desc(detected)}. "
                        "Disfrazar un programa de documento o imagen es una técnica típica de malware. No abrirlo.",
                        Severity.HIGH,
                        80,
                        {"extension": ext},
                    )
                )
            elif is_executable_type(detected):
                out.append(
                    _finding(
                        art,
                        "filetype.type_mismatch",
                        f"El archivo .{ext} contiene {_type_desc(detected)}",
                        f"'{shown[:80]}' es un archivo de texto que en realidad contiene {_type_desc(detected)}. "
                        "Por sí solo no se ejecuta, pero es inusual y puede ser parte de un ataque.",
                        Severity.MEDIUM,
                        25,
                        {"extension": ext},
                    )
                )
            elif detected in _ARCHIVE_TYPES and detected not in _DOC_BENIGN[ext]:
                out.append(
                    _finding(
                        art,
                        "filetype.type_mismatch",
                        f"El archivo dice ser .{ext} pero es {_type_desc(detected)}",
                        f"'{shown[:80]}' es en realidad {_type_desc(detected)} disfrazado de .{ext}. Algunos "
                        "programas lo abren igual por su contenido, y así se esquivan los filtros de adjuntos.",
                        Severity.MEDIUM,
                        40,
                        {"extension": ext},
                    )
                )
            elif detected in ("html", "svg") and detected not in _DOC_BENIGN[ext]:
                out.append(
                    _finding(
                        art,
                        "filetype.type_mismatch",
                        f"El archivo dice ser .{ext} pero es una página web",
                        f"'{shown[:80]}' es en realidad {_type_desc(detected)} disfrazada de .{ext}. Suele mostrar "
                        "un formulario falso para robar usuario y contraseña.",
                        Severity.MEDIUM,
                        35,
                        {"extension": ext},
                    )
                )
            else:  # alternativas benignas (_DOC_BENIGN) u otros documentos: solo contexto
                out.append(
                    _finding(
                        art,
                        "filetype.type_mismatch",
                        f"La extensión .{ext} no coincide con el tipo real ({detected})",
                        "El tipo real del archivo no coincide exactamente con su extensión. Suele ser inofensivo "
                        "(por ejemplo, un .doc guardado como RTF o una imagen PNG con extensión .jpg).",
                        Severity.INFO,
                        0,
                        {"extension": ext, "known_benign_variant": detected in _DOC_BENIGN[ext]},
                    )
                )
        elif is_executable_type(detected) and ext not in _DANGEROUS and ext not in _DOC_LIKE:
            out.append(
                _finding(
                    art,
                    "filetype.hidden_executable",
                    f"Programa con una extensión que no lo delata ('{shown[:60]}')",
                    f"El archivo es {_type_desc(detected)} pero tiene extensión .{ext}. Puede ser un ejecutable "
                    "renombrado para pasar los filtros; alcanza con que alguien le cambie el nombre para que funcione.",
                    Severity.MEDIUM,
                    40,
                    {"extension": ext},
                )
            )
    elif not ext and is_executable_type(detected):
        out.append(
            _finding(
                art,
                "filetype.hidden_executable",
                f"Programa sin extensión ('{shown[:60]}')",
                f"El archivo no tiene extensión pero es {_type_desc(detected)}. Puede ser un ejecutable renombrado "
                "para pasar los filtros.",
                Severity.MEDIUM,
                40,
                {"extension": ""},
            )
        )

    # 6) Content-Type declarado vs contenido ejecutable
    declared = (art.declared_content_type or "").split(";", 1)[0].strip().lower()
    if declared and is_executable_type(detected) and not mismatch_high:
        if declared in _BENIGN_DECLARED or declared.startswith(_BENIGN_DECLARED_PREFIXES):
            out.append(
                _finding(
                    art,
                    "filetype.content_type_mismatch",
                    f"El adjunto se declara como '{declared}' pero es {_type_desc(detected)}",
                    "El mail presenta el adjunto como un documento o imagen, pero su contenido real es ejecutable. "
                    "Es un intento de engañar a los filtros y a quien lo recibe.",
                    Severity.MEDIUM,
                    30,
                    {"declared_content_type": declared},
                )
            )

    # 7) contenedor con contraseña: una sola vez, en el contenedor (no en cada entrada); PDF/Office cifrados
    #    los evalúan sus propios analizadores
    # si el padre ya lo informa con igual o más fuerza, no se repite (una contraseña no cuenta N veces)
    parent_covers = parent is not None and (
        parent.encrypted or (parent.password_protected and not art.encrypted)
    )
    if (
        is_password_protected(art)
        and not parent_covers
        and art.detected_type not in _ENCRYPTION_OWNED_ELSEWHERE
    ):
        inside = [
            _escaped(_basename(k.filename or k.id))[:120] for k in children_of(art.id)[:50] if not _is_junk(k)
        ][:10]
        seen_txt = f" Adentro se ve: {', '.join(n[:60] for n in inside[:3])}." if inside else ""
        ev_pw: dict[str, object] = {"opened": not art.encrypted, "password_protected": True}
        if inside:
            ev_pw["entries"] = inside
        if art.encrypted:  # quedó contenido sin abrir: la señal más fuerte
            out.append(
                _finding(
                    art,
                    "filetype.encrypted_archive",
                    f"Archivo protegido con contraseña que no se pudo revisar ('{shown[:60]}')",
                    "El adjunto está protegido con contraseña, así que ningún antivirus puede revisar qué tiene "
                    "adentro. Los atacantes lo usan justamente para eso (y ponen la contraseña en el texto del "
                    "mail). Confirmar con el remitente por otro medio antes de abrirlo." + seen_txt,
                    Severity.MEDIUM,
                    35,
                    ev_pw,
                    category=FindingCategory.POLICY,
                )
            )
        else:
            out.append(
                _finding(
                    art,
                    "filetype.encrypted_archive",
                    f"Archivo protegido con contraseña ('{shown[:60]}')",
                    "El adjunto venía protegido con contraseña. Centinela lo pudo abrir (con la contraseña escrita "
                    "en el mail o una de las habituales) y revisó su contenido, pero mandar archivos con contraseña "
                    "es una técnica conocida para que los antivirus del correo no los revisen. Si no se esperaba, "
                    "confirmar con el remitente por otro medio antes de abrirlo.",
                    Severity.MEDIUM,
                    25,
                    ev_pw,
                    category=FindingCategory.POLICY,
                )
            )

    # 8) notas de extracción (vocabulario de parsing/archives.py; la de contraseña la cubre la regla 7)
    if art.extraction_note:
        parts = _note_parts(art.extraction_note)
        shown_parts = [p for p, kind in parts if kind != "silent"]
        note = "; ".join(shown_parts)[:300]
        if any(kind == "limit" for _p, kind in parts):
            out.append(
                _finding(
                    art,
                    "filetype.extraction_limit",
                    f"No se pudo revisar todo el contenido de '{shown[:60]}'",
                    f"Al abrir el archivo se llegó a un límite de seguridad ({note}). Puede ser un archivo enorme o "
                    "una 'bomba de compresión' armada para trabar los antivirus; lo que quedó sin revisar podría "
                    "ser peligroso.",
                    Severity.MEDIUM,
                    30,
                    {"note": note},
                    category=FindingCategory.POLICY,
                )
            )
        elif shown_parts:
            out.append(
                _finding(
                    art,
                    "filetype.extraction_note",
                    f"Aviso al revisar '{shown[:60]}'",
                    f"Durante el análisis del archivo se registró: {note}",
                    Severity.INFO,
                    0,
                    {"note": note},
                    category=FindingCategory.POLICY,
                )
            )

    # 9) comprimido cuyo único contenido es ejecutable (también si las entradas solo se pudieron LISTAR,
    #    por ejemplo un zip con contraseña que trae "factura.exe": el nombre alcanza)
    if _is_container(art):
        kids = _children(children_of, art)
        if kids and len(kids) <= 5 and all(_is_exec(k) for k in kids):
            names = [_escaped(_basename(k.filename or k.id)) for k in kids]
            single = len(kids) == 1
            any_listed = any(k.listing_only for k in kids)
            out.append(
                _finding(
                    art,
                    "filetype.archive_only_executable",
                    f"'{shown[:60]}' contiene solo {'un programa' if single else 'programas'} ({names[0][:60]})",
                    "El comprimido o imagen de disco no trae documentos: solo "
                    + ("un ejecutable o script" if single else "ejecutables o scripts")
                    + ". Es el envoltorio típico del malware que llega por mail ('factura.zip' con 'factura.exe' "
                    "adentro). No abrirlo."
                    + (
                        " El contenido no se pudo extraer (por ejemplo, por la contraseña), pero los nombres "
                        "alcanzan para reconocerlo."
                        if any_listed
                        else ""
                    ),
                    Severity.HIGH,
                    70 if single else 60,
                    {"children": names, "children_listing_only": any_listed},
                )
            )

    # 10) adjuntos HTML/SVG directos (formularios falsos / HTML smuggling)
    if (
        art.depth == 0
        and (detected in ("html", "svg") or ext in ("html", "htm", "shtml", "xhtml", "svg"))
        and ext not in _DANGEROUS
    ):
        out.append(
            _finding(
                art,
                "filetype.html_attachment",
                f"Adjunto de página web ('{shown[:60]}')",
                "Los adjuntos HTML o SVG se abren en el navegador y se usan para mostrar formularios falsos de "
                "inicio de sesión o para armar archivos maliciosos sin pasar por internet. Si pide usuario y "
                "contraseña, no completarlo.",
                Severity.LOW,
                10,
                {"extension": ext},
            )
        )
    return out


class FileTypeAnalyzer(ArtifactAnalyzer):
    """Extensiones peligrosas, dobles extensiones, RTLO, tipo real vs. declarado, ISO/VHD y comprimidos."""

    name = NAME

    def accepts(self, artifact: Artifact) -> bool:
        return True

    async def analyze(self, ctx: AnalysisContext, artifact: Artifact) -> list[Finding]:
        # solo metadatos y nombres (sin leer el contenido): no hace falta to_thread. Las entradas "solo
        # listadas" (listing_only) también se analizan: su nombre es la señal.
        return analyze_artifact(artifact, ctx.message.artifacts, ctx.children)
