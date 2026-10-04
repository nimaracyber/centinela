# Cómo contribuir

¡Gracias! Lo que más valor aporta:

1. **Reglas YARA** nuevas o mejores (ver `rules/yara/README.md`): familias que estén llegando por mail a PyMEs
   de la región, con referencia pública y bajo índice de falsos positivos.
2. **Heurísticas** en los analizadores (`src/centinela/analyzers/`), siempre con test de detección **y** de no-detección.
3. **Conectores** para más proveedores.
4. Reportes de **falsos positivos** (sin adjuntar el mail real: describí el patrón o usá un mail sintético).

## Entorno

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check . && ruff format .
```

## Reglas de oro

- **Nunca** subas malware real, mails reales ni datos personales al repo, ni siquiera en tests.
  Los tests usan muestras sintéticas inertes construidas en el propio test.
- Ningún analizador ejecuta, abre con aplicaciones ni sube a terceros el contenido de un adjunto.
- Todo input es hostil: límites de tamaño, profundidad, tiempo; regex sin backtracking catastrófico.
- Textos para el usuario en español claro (el lector es el dueño de una PyME, no un analista).
- Ids de regla estables (`modulo.nombre`): los usuarios los usan en `rule_overrides`.

## Agregar un analizador

1. Crear `src/centinela/analyzers/mi_analizador.py` con una clase `MessageAnalyzer` o `ArtifactAnalyzer`
   (ver `analyzers/base.py`).
2. Registrarla en `ANALYZERS` (`analyzers/__init__.py`).
3. Tests en `tests/<area>/`.

## Agregar un conector

Implementar `Connector` (`connectors/base.py`), su `*ConnectorConfig` en `core/config.py` y registrarlo en
`connectors/__init__.py`. Requisitos: no marcar como leído, no mover/borrar, guardar cursor después de
`emit`, reconectar con backoff, `apply_verdict` idempotente.
