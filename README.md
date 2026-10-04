<div align="center">

# 🛡️ Centinela

**Análisis pasivo y en tiempo real del correo de tu PyME.**
Detecta RATs, stealers, loaders y phishing en adjuntos y links — sin bloquear ni tocar tus mails.

[![CI](https://github.com/tu-usuario/centinela/actions/workflows/ci.yml/badge.svg)](https://github.com/tu-usuario/centinela/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/licencia-Apache--2.0-green)

</div>

---

La mayoría de los incidentes en empresas chicas empiezan con **un mail**: una "factura" que en realidad es un
ejecutable, un ZIP con contraseña que esconde un *stealer*, un acceso directo (`.lnk`) que lanza PowerShell,
o un link a una página que copia el login de Microsoft 365. Los filtros de los proveedores dejan pasar
una parte, y una sola PC infectada alcanza para perder las claves del home banking o todo el servidor.

**Centinela** se conecta a tus buzones, analiza cada mail apenas llega y te avisa (Telegram, mail, Slack, Teams…)
si encuentra algo peligroso. Además marca el mail con una etiqueta visible (`Centinela/Malicioso`) para que nadie lo abra.

- 🔌 **Funciona con todo**: Gmail / Google Workspace, Microsoft 365 / Outlook, cualquier IMAP (hosting propio,
  Yahoo, iCloud, Zoho, webmail cPanel/Plesk), gateway Postfix (milter) o copias por BCC/journaling.
- 👀 **Pasivo**: nunca bloquea, borra ni mueve mails. No los marca como leídos. Solo etiqueta y avisa.
- 🔒 **Privado**: los adjuntos **nunca salen de tu empresa**. Solo se consulta el hash SHA-256 en servicios de reputación (opcional).
- 🧠 **Análisis en profundidad**: abre ZIP/7z/RAR/ISO/IMG recursivamente (incluso con contraseña escrita en el mail),
  inspecciona macros de Office, PDFs, OneNote, accesos directos, scripts, ejecutables y HTML.
- 🗣️ **En español claro**: cada alerta explica qué pasó y **qué hacer**, pensado para quien no es técnico.

## ¿Qué detecta?

| Amenaza | Cómo |
|---|---|
| **RATs** (AsyncRAT, Remcos, XWorm, njRAT, Quasar, DCRat, NanoCore, Warzone…) | Reglas YARA por familia + ClamAV + heurísticas de ejecutables .NET |
| **Stealers** (AgentTesla, Lumma, RedLine, Vidar, StealC, FormBook, Snake…) | YARA + imports/strings de robo de credenciales de navegadores, wallets, Telegram/Discord |
| **Loaders / droppers** (GuLoader, scripts JS/VBS/PowerShell, LNK, HTA) | Desofuscación (base64, `-EncodedCommand`), LOLBins (`certutil`, `mshta`, `rundll32`…) |
| **Documentos armados** | Macros VBA/XLM con autoejecución, DDE, *template injection*, Follina (CVE-2022-30190), Equation Editor (CVE-2017-11882), PDFs con JavaScript/Launch, OneNote con adjuntos |
| **Trucos de entrega** | Doble extensión (`factura.pdf.exe`), caracteres RTLO, ISO/IMG/VHD, ZIP con contraseña, HTML/SVG *smuggling*, tipo real ≠ extensión |
| **Phishing** | Links engañosos, dominios parecidos al tuyo o a bancos/AFIP-ARCA/Mercado Pago/Microsoft, punycode, IPs, archivos en hostings abusados, formularios de login locales |
| **Suplantación / BEC** | SPF/DKIM/DMARC fallidos, tu propio dominio falsificado, nombre visible engañoso, Reply-To distinto, pedidos de cambio de CBU |
| **Malware conocido** | SHA-256 en MalwareBazaar y VirusTotal (solo el hash) + firmas de ClamAV |

Cada hallazgo suma a un **score de 0 a 100** → `limpio` / `sospechoso` / `malicioso`.

## Instalación rápida (Docker)

```bash
git clone https://github.com/tu-usuario/centinela.git
cd centinela
cp .env.example .env
cp config.example.yaml config.yaml
docker compose run --rm api gen-key          # pegar las claves en .env
docker compose run --rm api hash-password    # pegar el hash en .env
# editar config.yaml: dominios de tu empresa, conectores y canales de alerta
docker compose run --rm api check-config
docker compose up -d
```

El dashboard queda en `http://127.0.0.1:8080` (publicalo solo detrás de un reverse proxy con HTTPS).

**¿Oficina chica, una sola PC/NAS?** Usá el modo liviano (SQLite, sin Redis ni Postgres):

```bash
docker compose -f docker-compose.lite.yml up -d
```

### Probar sin instalar nada en servidores

```bash
pip install -e .
centinela scan mail-sospechoso.eml --offline
```

Código de salida: `0` limpio, `1` sospechoso, `2` malicioso.

## Conectores

| Proveedor | Conector | Tiempo real | Etiqueta |
|---|---|---|---|
| Google Workspace | `gmail` (cuenta de servicio, todos los buzones) | Pub/Sub o polling 20 s | Label de Gmail |
| Gmail personal | `gmail` (`auth: oauth_user`) | polling 20 s | Label de Gmail |
| Microsoft 365 / Exchange Online | `graph` (app registration) | delta query 20 s | Categoría de Outlook |
| Outlook.com / Hotmail | `imap` + OAuth2 | IMAP IDLE | Keyword IMAP |
| Hosting propio, Yahoo, iCloud, Zoho, cPanel… | `imap` | IMAP IDLE | Keyword IMAP |
| Servidor Postfix propio | `milter` | inline | Headers `X-Centinela-*` (+ prefijo en asunto opcional) |
| Cualquiera que permita reenviar copias | `smtp_journal` | inmediato | (solo alertas) |

Guía paso a paso de cada uno en [docs/CONECTORES.md](docs/CONECTORES.md).

## Arquitectura

```
 IMAP IDLE · Gmail API · Microsoft Graph · SMTP journal ──▶ cola (Redis) ──▶ workers ──▶ PostgreSQL
 Postfix milter (inline, con timeout) ─────────────────────────────────────▶   │
                                                                                ├─▶ etiqueta el mail original
     parse MIME + desempaquetado recursivo → analizadores en paralelo          ├─▶ alertas (Telegram/mail/Slack/Teams/Discord/syslog)
     (ClamAV · YARA-X · Office · PDF · PE · scripts · LNK · HTML · OneNote ·   └─▶ dashboard web + API + métricas Prometheus
      headers · URLs · contenido · reputación por hash) → scoring
```

Detalle en [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Los workers escalan horizontalmente
(`docker compose up -d --scale worker=4`).

## Privacidad y seguridad

- Los archivos adjuntos **no se guardan ni se envían a terceros**. Solo se guardan metadatos y hashes.
- Las consultas de reputación envían únicamente el SHA-256 (se pueden desactivar: `privacy.hash_lookups: false`).
- Los contenedores corren sin privilegios, con sistema de archivos de solo lectura y sin capabilities.
- Ver [SECURITY.md](SECURITY.md) para el modelo de amenazas y cómo reportar vulnerabilidades.

> ⚠️ Centinela es una capa de **detección**: complementa (no reemplaza) al antivirus de las PCs y al filtro
> del proveedor de correo. Un mail marcado como limpio no es garantía absoluta.

## Estado del proyecto

Versión 0.1.0. Lo que falta y las limitaciones conocidas están en [docs/PENDIENTES.md](docs/PENDIENTES.md).

> **Nota sobre antivirus:** los tests y las reglas YARA contienen, a propósito, fragmentos de técnicas de
> ataque (inertes, sin código funcional) para verificar la detección. Algún antivirus puede marcar archivos
> de `tests/` o `rules/` al clonar el repo: es esperable en herramientas de detección.

## Contribuir

Reglas YARA, heurísticas, conectores y reportes de falsos positivos son bienvenidos. Ver [CONTRIBUTING.md](CONTRIBUTING.md).

## Licencia

[Apache-2.0](LICENSE).
