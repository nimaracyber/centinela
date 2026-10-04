# Reglas YARA de Centinela

Reglas que el analizador `yara` (`src/centinela/analyzers/yara_scan.py`) compila al arrancar y aplica
a **cada archivo** del mail: adjuntos y todo lo que se extrae de ZIP/RAR/7z/ISO/documentos.
Se compilan con [YARA-X](https://virustotal.github.io/yara-x/) (si no está instalado, con
`yara-python` como alternativa).

```
rules/yara/
├── rats/         troyanos de acceso remoto (AsyncRAT, DCRat, Quasar, njRAT, Remcos, XWorm, NanoCore,
│                 Warzone/AveMaria, VenomRAT, abuso de NetSupport Manager)
├── stealers/     ladrones de información (AgentTesla, FormBook/XLoader, Lumma, RedLine/META, Vidar,
│                 StealC, Snake Keylogger, Raccoon, Rhadamanthys)
├── loaders/      descargadores (GuLoader, loaders .NET/scripts con ejecutables codificados)
└── techniques/   técnicas de entrega independientes de la familia (PE en base64, PowerShell que
                  descarga y ejecuta, macros autoexec, JS/VBS droppers, LNK con LOLBins, HTA,
                  HTML smuggling, Follina, CVE-2017-11882, robo de credenciales, exfiltración por
                  Telegram/Discord)
```

Se cargan **todos** los `*.yar` / `*.yara` de forma recursiva desde cada carpeta de
`analyzers.yara.rules_dirs` (por defecto `rules/yara`; las rutas relativas se buscan primero en el
directorio de trabajo y después en la raíz del proyecto). Cada archivo se compila en su **propio
namespace**, así que dos archivos pueden tener reglas con el mismo nombre sin chocar.
Un archivo con errores de sintaxis **se saltea con un warning en el log**; el resto sigue funcionando.

## Convenciones de `meta`

| campo | obligatorio | valores | uso en Centinela |
|---|---|---|---|
| `author` | sí (reglas propias) | `"Centinela"` | — |
| `description` | sí | texto **en español**, claro para un no-técnico | se muestra en la alerta y el dashboard |
| `reference` | sí | URL pública (Malpedia, blog del vendor, MITRE ATT&CK, CVE) | evidencia |
| `date` | sí | `AAAA-MM-DD` | — |
| `category` | sí | `rat` · `stealer` · `loader` · `ransomware` · `backdoor` · `technique` · `generic` (también `exploit`, `phishing`) | familias ⇒ categoría **MALWARE**; `technique`/`generic`/`exploit` ⇒ **SUSPICIOUS_FILE**; `phishing` ⇒ **PHISHING** |
| `family` | en reglas de familia | nombre canónico (`AsyncRAT`, `AgentTesla`, `Lumma Stealer`...) | `Finding.malware_family` |
| `severity` | sí | `critical` · `high` · `medium` · `low` · `info` | `Finding.severity` |
| `score` | sí | entero 0–100 | aporte al score del mail (noisy-OR) |
| `title` | opcional | título corto en español | si falta se arma uno a partir de la categoría y la familia |

Guía de severidad (igual que `docs/ARCHITECTURE.md`):

- Regla de **familia concreta**: `critical`, 90–100.
- **Técnica de entrega claramente maliciosa** (LNK que lanza PowerShell, HTML smuggling que arma un
  ZIP/EXE, Follina, macro autoexec que descarga): `high`, 60–85.
- **Sospechoso con usos legítimos**: `medium`, 25–45.
- Señales débiles: `low`, 5–15.

El id del hallazgo es `yara.<NombreDeLaRegla>`: se puede silenciar o ajustar una regla puntual con
`scoring.rule_overrides` en `config.yaml` (ej.: `yara.Technique_HTML_Smuggling_Generic: 0`).

### Reglas sin nuestra `meta` (reglas de la comunidad)

Si una regla no tiene `category`/`severity`, el analizador infiere:

- familia desde `family`, `malware_family`, `malware` o `threat_name` (`Windows.Trojan.AgentTesla` ⇒ `AgentTesla`);
- `score` desde `score` (signature-base usa 0–100) o, si no hay, 40 (60 si hay familia);
- severidad desde el score (≥90 critical, ≥60 high, ≥25 medium, >0 low);
- categoría: MALWARE si hay familia, si no SUSPICIOUS_FILE.

La `description` se muestra tal cual (puede estar en inglés).

## Calidad: cómo escribir una regla nueva

1. **Indicadores públicos solamente** (Malpedia, informes de vendors, signature-base, análisis de
   sandbox públicos). Citá la fuente en `reference`.
2. **Varias condiciones**: nunca un solo string genérico. Combiná N-de-M strings + restricción de tipo
   de archivo:
   - ejecutable Windows: `uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550`
   - texto/script: `uint16(0) != 0x5A4D`
   - LNK: `uint32(0) == 0x0000004C and uint32(4) == 0x00021401`
   - OLE: `uint32be(0) == 0xD0CF11E0` · RTF: `uint32be(0) == 0x7B5C7274` · ZIP: `uint32(0) == 0x04034B50`
3. **Límite de tamaño** (`filesize < 15MB`, etc.) y nada de regex sin literales (YARA-X avisa
   "slow pattern": no deben quedar warnings).
4. **Probala**: `tests/analyzers_engines/test_yara_rules.py` compila cada archivo con YARA-X en modo
   estricto, valida la `meta` y corre cada regla contra una muestra sintética inerte (que tiene que
   disparar) y contra un corpus benigno (que no tiene que disparar nada). Agregá ahí tu muestra.
5. Nunca subas malware real al repositorio.

## Sumar reglas de la comunidad

Podés montar más carpetas y agregarlas en `config.yaml`:

```yaml
analyzers:
  yara:
    rules_dirs:
      - rules/yara                 # las de Centinela
      - /rules/community           # montada como volumen en docker compose
```

Fuentes recomendadas (revisá la licencia antes de redistribuir):

| repositorio | licencia | notas |
|---|---|---|
| [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) | Detection Rule License (DRL) 1.1 | Uso libre con atribución. Centinela define las variables externas que usa (`filename`, `filepath`, `extension`, `filetype`, `owner`) y las completa en cada escaneo con el nombre, la ruta dentro del mail (`att0/factura.zip/x.exe`), la extensión y el tipo detectado del archivo. |
| [reversinglabs/reversinglabs-yara-rules](https://github.com/reversinglabs/reversinglabs-yara-rules) | MIT | Muy buena cobertura de familias; meta `malware`/`malware_type` que Centinela entiende. |
| [elastic/protections-artifacts](https://github.com/elastic/protections-artifacts) | Elastic License 2.0 | Se puede usar internamente; **no** la redistribuyas como servicio. Meta `threat_name` que Centinela entiende. |
| [YARAHQ/yara-forge](https://github.com/YARAHQ/yara-forge) | según cada regla | Paquetes ya curados y deduplicados de muchas fuentes ("core" es el de menos falsos positivos). |

Consejos:

- Empezá con un set chico y de baja tasa de falsos positivos (ej.: YARA Forge *core*). Las reglas de
  "hunting" (`SUSP_`, `HKTL_`, `PUA_`) generan ruido en mails comerciales.
- Si una regla de la comunidad molesta, silenciala con `scoring.rule_overrides` en vez de borrarla.
- YARA-X es más estricto que YARA clásico en algunas expresiones regulares: Centinela compila en modo
  compatible (`relaxed_re_syntax`) y, si igual falla, saltea solo ese archivo y lo informa en el log.
