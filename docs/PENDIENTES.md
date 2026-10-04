# Pendientes conocidos

Estado al publicar la versión 0.1.0. Ordenado por prioridad.

## 1. Tests de los analizadores de ejecutables y scripts

`src/centinela/analyzers/pe.py`, `scripts.py`, `lnk.py`, `html.py` y el motor compartido `_indicators.py`
están implementados y los ejercitan los tests end-to-end (`tests/e2e/`), pero **no tienen suite propia**
(`tests/analyzers_exec/` no existe todavía). Cubrir, para cada analizador: `accepts()`, cada familia de
heurísticas, no-detección sobre muestras benignas (un .bat administrativo, un newsletter HTML, un PE sin
rasgos raros) y entradas rotas/hostiles (cabeceras truncadas, líneas enormes, base64 anidado) que deben
terminar rápido y sin excepciones.

Seguir la regla 9 de [ARCHITECTURE.md](ARCHITECTURE.md): las muestras se arman por partes.

## 2. Muestras de prueba escritas literalmente

Algunos tests todavía tienen comandos de ataque de prueba (inertes, con IPs de documentación) escritos
literalmente. Windows Defender puede marcar estos archivos al clonar el repo o al correr los tests. Hay que
reescribirlos partiendo las palabras clave (`"power" "shell"`, concatenación implícita de Python o un helper
que une fragmentos), sin cambiar lo que prueban:

| Archivo | Apariciones aprox. |
|---|---|
| `tests/analyzers_engines/samples.py` | 12 |
| `tests/analyzers_docs/test_office.py` | 7 |
| `tests/analyzers_docs/test_onenote.py` | 4 |
| `tests/parsing/test_filetype.py` | 4 |
| `tests/e2e/test_pipeline_e2e.py` | 2 |
| `tests/analyzers_docs/test_pdf.py` | 1 |
| `tests/parsing/test_archives.py` | 1 |

Las reglas YARA (`rules/yara/**`) necesitan esas cadenas por definición; si algún antivirus las marca,
documentar la exclusión de esa carpeta en el README en vez de partirlas.

## 3. Revisión independiente

Pendiente una revisión externa de:
- **Seguridad**: entradas hostiles (tiempos y memoria con adjuntos armados), dashboard (auth, CSRF, XSS),
  listeners milter/SMTP (abuso sin autenticación, agotamiento de recursos), secretos en logs.
- **Calidad de detección**: corpus sintético de mails benignos reales de la región (ARCA/AFIP, bancos,
  Mercado Pago, newsletters) y de patrones maliciosos, midiendo falsos positivos y negativos.
- **Sistema corriendo**: `centinela run --role all` con conector `directory`, alertas por webhook y dashboard.

## 4. Mejoras técnicas conocidas

- **Postgres**: la migración de esquema v1→v2 solo está probada con SQLite. Agregar un servicio Postgres al CI.
- **Office**: `analyzers/office.py` busca contraseñas con su propia regex sobre el cuerpo; debería usar
  `centinela.parsing.mime.message_password_candidates()` (incluye asunto, HTML y .eml adjuntos).
- **SMTP journal**: copias mayores a 2× `max_message_bytes` se rechazan con 552 (aiosmtpd descarta los datos
  al pasar el límite); entre 1× y 2× se analizan solo los encabezados.
- **Milter**: con mails más grandes que el límite se analiza el cuerpo parcial; los adjuntos cortados pueden
  dar hashes que no coinciden con el archivo real.
- **Quishing**: no se decodifican códigos QR en imágenes (phishing por QR no se detecta).
- **`/metrics`** no tiene autenticación: no exponerlo a internet (agregar token opcional).
- **Analizador de URLs**: agrupa por regla (hasta 20 dominios por hallazgo) en vez de un hallazgo por dominio,
  para no sobre-puntuar newsletters con muchos acortadores.
