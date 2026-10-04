# Arquitectura de Centinela

Centinela analiza en tiempo real y de forma **pasiva** el correo entrante de una PyME para detectar
malware (RATs, stealers, loaders, ransomware droppers) y phishing en adjuntos y links.
**Nunca bloquea, borra ni mueve mails**: etiqueta (label/categoría/keyword) y alerta.
**Los archivos nunca salen de la empresa**: solo se consultan hashes SHA-256 en servicios de reputación.

## Flujo

```
 ┌──────────── conectores (ingest) ────────────┐
 │ IMAP IDLE · Gmail API · Microsoft Graph ·    │      ┌─────────── worker ───────────┐
 │ SMTP journal (copias BCC) · carpeta .eml     │─────▶│ parse MIME + unpack recursivo │
 └──────────────────────────────────────────────┘ cola │ analizadores en paralelo      │
 ┌──────── milter (Postfix, inline) ───────────┐ Redis │ scoring → veredicto           │
 │ analiza con timeout y agrega X-Centinela-*  │──────▶│ storage (Postgres/SQLite)     │
 └──────────────────────────────────────────────┘      │ acciones: etiquetar + alertar │
                                                       └───────────────┬───────────────┘
                                         dashboard web + API REST + /metrics (FastAPI)
```

Roles de proceso (`centinela run --role ...`): `ingest`, `worker`, `api`, o `all` (todo en un proceso,
cola en memoria, SQLite: el modo para una oficina chica sin Redis/Postgres).

## Mapa de módulos (src/centinela/)

| Módulo | Responsabilidad |
|---|---|
| `core/models.py` | **Contrato** de datos (RawMessage, ParsedMessage, Artifact, Finding, Verdict, AnalysisResult). |
| `core/config.py` | **Contrato** de configuración (YAML + `${ENV}`). |
| `core/pipeline.py` | Orquesta parse → analizadores → scoring. |
| `core/scoring.py` | `score_findings(findings, cfg: ScoringConfig, message: ParsedMessage) -> Verdict` |
| `core/defang.py` | `neutralize()`: corta palabras clave de ataque y recorta payloads codificados en la evidencia (ver abajo). |
| `core/cache.py`, `core/state.py`, `core/queue.py` | Protocolos + implementaciones en memoria. |
| `parsing/mime.py` | `parse_message(raw: RawMessage, limits: LimitsConfig) -> ParsedMessage` (sync, CPU) |
| `parsing/filetype.py` | `detect_type(data: bytes, filename: str \| None) -> str` (vocabulario abajo) |
| `parsing/archives.py` | `expand(artifact, limits, passwords, budget: ExtractionBudget) -> list[Artifact]`; constantes `NOTE_*` de las notas de extracción |
| `parsing/urls.py` | `extract_urls_text(text, source=...) / extract_urls_html(html, source=...) -> list[ExtractedUrl]` |
| `analyzers/*.py` | Ver `analyzers/__init__.py` (ANALYZERS) y `analyzers/base.py`. |
| `connectors/*.py` | Ver `connectors/__init__.py` (CONNECTORS) y `connectors/base.py`. `_headers.py`: recorte a solo-encabezados para mails grandes. |
| `storage/db.py` | `SqlResultStore(settings)` (SQLAlchemy async; Postgres o SQLite; esquema versionado con migraciones aditivas, hoy v2). |
| `storage/state.py` | `DbStateStore` (implementa `core.state.StateStore`, secretos cifrados con Fernet). |
| `storage/redis_queue.py` | `RedisStreamQueue` (implementa `core.queue.WorkQueue`). |
| `actions/dispatcher.py` | `ActionDispatcher.dispatch(result) -> list[str]`: etiquetar + alertar con dedup. |
| `actions/alerts/*.py` | Canales: `email`, `telegram`, `webhook` (json/slack/teams/discord/google_chat), `syslog` (CEF). `format.py` arma los textos. |
| `runtime.py` | `Runtime`: arma todo desde Settings; `process(raw)`, `run_ingest`, `run_worker`, `run_all`, `health()`. Atributos `settings`, `storage` (alias de `store`), `queue`, `pipeline`, `connectors`, `channels`. |
| `api/app.py` | `create_app(runtime) -> FastAPI`: dashboard (Jinja2 + JS mínimo propio, sin CDNs), REST `/api/v1`, `/healthz`, `/readyz`, `/metrics`. |
| `cli.py` | Typer: `run`, `scan`, `check-config`, `auth`, `hash-password`, `gen-key`, `test-alert`, `rules check`, `version`. |

### Códigos de salida del CLI

`0` ok · `1` (solo `scan`) sospechoso · `2` (solo `scan`) malicioso · `3` (solo `scan`) error de análisis ·
`4` configuración inválida o faltan secretos (ej: dashboard sin `admin_password_hash`/`secret_key`).
`scan --offline` no consulta reputación y no usa ClamAV: nada sale de la PC.

## Mails demasiado grandes

Ningún conector descarta en silencio un mail que supera `limits.max_message_bytes` (sería una evasión
trivial): emite solo los encabezados con `RawMessage.truncated=True` y `original_size`. El pipeline agrega
el hallazgo `policy.message_too_large` (POLICY, MEDIUM 35 → al menos *sospechoso*) y el dashboard lo marca.

## Evidencia neutralizada

La evidencia de cada `Finding` pasa por `core/defang.neutralize()` al construirse: las palabras clave de
comandos de ataque se parten con «·» (`power·shell`, `Download·String`) y los bloques base64/hex largos se
recortan. Así la base de datos, el dashboard, la salida JSON y los mails de alerta de Centinela no contienen
comandos literales y **el antivirus del cliente no los marca como amenaza**. Los links no se tocan acá
(se desactivan al mostrarlos: `hxxp`, `[.]`), para no romper links de referencia legítimos.

## Vocabulario de `Artifact.detected_type`

Producido por `parsing/filetype.detect_type` (magic bytes primero, extensión como desempate para texto):

| valor | qué es |
|---|---|
| `pe` | ejecutable/DLL Windows (exe, dll, scr, cpl, xll, sys…) — `MZ` + PE header válido |
| `dotnet` | NO se usa como tipo: un PE .NET sigue siendo `pe`; el analizador `pe` lo detecta |
| `elf`, `macho` | ejecutables Linux / macOS |
| `msi` | OLE con CLSID de Windows Installer |
| `ole` | OLE2/CFB (doc/xls/ppt legacy, msg de Outlook, etc.) |
| `ooxml` | ZIP con `[Content_Types].xml` (docx/xlsx/pptx/docm/xlsm…) |
| `rtf` | `{\rt` |
| `pdf` | `%PDF` en los primeros 1024 bytes |
| `onenote` | GUID de cabecera OneNote (.one) |
| `chm` | `ITSF` |
| `zip`, `jar`, `7z`, `rar`, `gzip`, `bzip2`, `xz`, `tar`, `cab`, `iso`, `udf`, `vhd`, `vhdx`, `img` | contenedores |
| `lnk` | acceso directo Windows (`4C 00 00 00 01 14 02 00`) |
| `eml` | mail adjunto (message/rfc822) — `mime.py` lo parsea recursivamente |
| `html`, `svg`, `xml` | marcado (un `.hta` NO es `html`: es `script/hta`, lo analiza `HtmlAnalyzer`) |
| `script/js`, `script/vbs`, `script/ps1`, `script/bat`, `script/wsf`, `script/hta`, `script/vba`, `script/python`, `script/sh` | scripts (por extensión + heurística de contenido) |
| `url_shortcut`, `iqy`, `slk`, `reg`, `settingcontent`, `library-ms`, `search-ms` | formatos "living off the land" abusados |
| `image/png`, `image/jpeg`, `image/gif`, `image/bmp`, `image/webp`, `image/ico` | imágenes |
| `text` | texto plano no reconocido |
| `unknown` | binario no reconocido |

## Reglas transversales

1. **Nunca ejecutar** nada de un artifact. Nada de `subprocess` con contenido del mail, ni abrir con apps.
2. **Nunca subir archivos** a terceros. Reputación solo por hash (y URLs solo si `privacy.url_lookups`).
3. **Defensivo ante input hostil**: límites de `LimitsConfig` (tamaño, profundidad, ratio de compresión,
   cantidad de artifacts, presupuesto total descomprimido), sin path traversal al extraer (se extrae
   a memoria, no a disco), timeouts en todo I/O de red, regex sin backtracking catastrófico.
4. **Textos para humanos en español rioplatense neutro**, claros para un no-técnico. Identificadores
   de código en inglés. Docstrings/comentarios en español.
5. **Ids de regla estables** con prefijo del módulo: `office.vba.autoexec`, `pe.stealer_imports`,
   `yara.<RuleName>`, `rep.malwarebazaar`, `headers.dmarc_fail`, `url.ip_literal`...
6. **Guía de severidad / score** (el scoring combina con noisy-OR: `1 - Π(1 - s/100)`):
   - Firma de familia concreta (YARA de familia, ClamAV, hash conocido malicioso): CRITICAL, 90–100, categoría MALWARE/REPUTATION, setear `malware_family`.
   - Técnica de entrega claramente maliciosa (macro autoexec + shell/download, LNK que lanza powershell, HTML smuggling que arma un .exe/.zip, Follina, template injection remota, ejecutable con icono de PDF/doble extensión): HIGH, 60–85.
   - Sospechoso por sí solo pero con usos legítimos (macro sin autoexec, ejecutable adjunto, zip con contraseña, PDF con JavaScript, SPF fail): MEDIUM, 25–45.
   - Señales débiles (acortador de URL, remitente nuevo, dominio recién visto): LOW, 5–15.
   - INFO = 0 (solo contexto).
7. **Logging**: `logging.getLogger(__name__)`; nunca loguear secretos, tokens, ni cuerpos de mail completos.
8. **Tests**: `tests/<area>/test_*.py`, cada subcarpeta de tests con `__init__.py`. Helpers en
   `tests/helpers.py` (`make_artifact`, `build_eml`, `make_raw`, `eicar`), fixtures en `tests/conftest.py`
   (`settings`, `http`, `make_ctx`). Sin red real (respx / servidores asyncio falsos locales), sin malware
   real. Correr con `pytest` desde la raíz del repo.
9. **Muestras de prueba armadas por partes**: las cadenas que un antivirus reconoce (comandos de descarga,
   EICAR...) se escriben partidas (`"power" "shell"`, o con un helper que une fragmentos) para que los
   archivos del repo no las contengan literales. Ver [PENDIENTES.md](PENDIENTES.md).
