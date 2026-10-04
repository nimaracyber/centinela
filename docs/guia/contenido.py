"""Contenido de la guía de instalación (lo usa generar_guia.py).

Bloques: ("h1", txt) ("h2", txt) ("p", txt) ("code", txt) ("lista", [..]) ("pasos", [..])
         ("tabla", [[encabezados..], [fila..]...], [anchos_mm]) ("callout", "importante"|"consejo"|"nota", txt) ("salto",)
En los textos: <b>negrita</b>, <i>itálica</i> y `código` entre comillas invertidas.
"""

REPO = "https://github.com/nimaracyber/centinela"

CONTENIDO: list[tuple] = [
    ("h1", "1. Qué es Centinela"),
    (
        "p",
        "Centinela es un sistema que <b>vigila el correo de tu empresa en tiempo real</b>. Cada vez que llega un "
        "mail, lo revisa: los adjuntos (incluso dentro de ZIP, RAR o ISO), los links, el remitente y el texto. Si "
        "encuentra algo peligroso (un troyano de acceso remoto, un programa que roba contraseñas, una página falsa "
        "del banco), <b>te avisa</b> por Telegram, mail, Slack o Teams y <b>le pone una etiqueta al mail</b> "
        "(por ejemplo `Centinela/Malicioso`) para que nadie lo abra.",
    ),
    ("h2", "Lo que hace y lo que no"),
    (
        "lista",
        [
            "<b>Es pasivo:</b> nunca borra, mueve ni bloquea mails, y no los marca como leídos. Solo etiqueta y avisa.",
            "<b>Es privado:</b> los archivos adjuntos <b>nunca salen de tu empresa</b>. Como mucho se consulta la "
            "huella digital del archivo (su hash SHA-256) en bases públicas de malware, y eso se puede apagar.",
            "<b>No reemplaza al antivirus</b> de las PCs ni al filtro de tu proveedor de correo: es una capa más.",
            "<b>Analiza los mails que llegan desde que lo instalás</b>, no los que ya estaban en el buzón.",
            "<b>Corre en tu propio equipo</b> (una PC, servidor o NAS de la oficina) dentro de Docker.",
        ],
    ),
    ("h2", "Cómo funciona por dentro"),
    (
        "tabla",
        [
            ["Pieza", "Qué hace"],
            [
                "Conectores",
                "Se conectan a tus buzones (Gmail, Microsoft 365, IMAP...) y traen cada mail nuevo.",
            ],
            [
                "Analizadores",
                "Revisan adjuntos, links y remitente: ClamAV, reglas YARA, macros de Office, PDFs, ejecutables, "
                "accesos directos, scripts, HTML, SPF/DKIM/DMARC, dominios parecidos al tuyo.",
            ],
            ["Puntaje", "Cada hallazgo suma puntos (0 a 100): limpio, sospechoso o malicioso."],
            [
                "Acciones",
                "Etiqueta el mail original y manda la alerta con una explicación en español y qué hacer.",
            ],
            ["Panel web", "Un dashboard para ver qué llegó, por qué se marcó y marcar falsos positivos."],
        ],
        [32, 138],
    ),
    ("salto",),
    # ------------------------------------------------------------------------
    ("h1", "2. Antes de empezar"),
    ("p", "Tené esto a mano. Con todo listo, la instalación lleva entre 1 y 2 horas."),
    (
        "tabla",
        [
            ["Necesitás", "Detalle"],
            [
                "Un equipo siempre encendido",
                "PC, mini-PC, servidor o NAS. Mínimo 4 GB de RAM (8 GB recomendado) y 20 GB libres de disco. Ideal: "
                "Linux (Ubuntu 24.04). También sirve Windows 10/11 con Docker Desktop.",
            ],
            [
                "Internet",
                "Para actualizar las firmas del antivirus ClamAV y, si lo activás, consultar hashes.",
            ],
            [
                "Acceso a los buzones",
                "Depende del proveedor: contraseña de aplicación (IMAP), cuenta de administrador de Google Workspace "
                "o de Microsoft 365. Ver el Paso 5.",
            ],
            ["Un canal de alertas", "Lo más simple: un bot de Telegram (gratis, se crea en 2 minutos)."],
            [
                "Los dominios de tu empresa",
                "Por ejemplo `miempresa.com.ar`: sirven para detectar suplantaciones.",
            ],
        ],
        [45, 125],
    ),
    ("h2", "Elegí el modo de instalación"),
    (
        "tabla",
        [
            ["", "Modo liviano", "Modo completo"],
            [
                "Para quién",
                "Oficina chica, pocos buzones, un solo equipo",
                "Varios buzones o mucho volumen de mails",
            ],
            [
                "Qué levanta",
                "Centinela + ClamAV (base SQLite)",
                "Centinela en partes + PostgreSQL + Redis + ClamAV",
            ],
            ["Archivo", "`docker-compose.lite.yml`", "`docker-compose.yml`"],
            ["Milter / copias SMTP", "No", "Sí"],
        ],
        [32, 69, 69],
    ),
    (
        "callout",
        "consejo",
        "Si dudás, empezá con el <b>modo liviano</b>. Más adelante podés pasar al completo reutilizando .env, "
        "config.yaml y secrets/; solo los conectores con login (Gmail personal, Outlook.com) necesitan repetir `auth`, "
        "y el historial del panel empieza de cero.",
    ),
    ("salto",),
    # ------------------------------------------------------------------------
    ("h1", "3. Paso 1: instalar Docker"),
    ("h2", "En Linux (Ubuntu / Debian)"),
    ("p", "Abrí una terminal (Ctrl+Alt+T) y ejecutá el instalador oficial de Docker y Git:"),
    (
        "code",
        "curl -fsSL https://get.docker.com | sudo sh\nsudo usermod -aG docker $USER\nsudo apt install -y git",
    ),
    ("p", "Cerrá la sesión y volvé a entrar (para que tome el permiso). Verificá:"),
    ("code", "docker compose version"),
    ("h2", "En Windows 10 / 11"),
    (
        "pasos",
        [
            "Descargá <b>Docker Desktop</b> desde docker.com e instalalo con las opciones por defecto (usa WSL 2).",
            "Reiniciá la PC cuando lo pida y abrí Docker Desktop hasta que diga <i>Engine running</i>.",
            "En <b>Settings > General</b> activá <i>Start Docker Desktop when you sign in</i>, para que arranque solo.",
            "Instalá <b>Git</b> desde git-scm.com con las opciones por defecto.",
            "Abrí <b>PowerShell</b> y verificá con `docker compose version`.",
        ],
    ),
    (
        "callout",
        "importante",
        "En Windows, la PC tiene que quedar <b>encendida y sin suspenderse</b>. Además, Docker Desktop arranca recién "
        "cuando alguien <b>inicia sesión</b>: después de un reinicio (por ejemplo por Windows Update), Centinela no "
        "vigila hasta que alguien entre. Dejá la sesión iniciada con la pantalla bloqueada y revisá con "
        "`docker compose ps` después de cada reinicio. Para un equipo dedicado, conviene Linux.",
    ),
    # ------------------------------------------------------------------------
    ("h1", "4. Paso 2: descargar Centinela"),
    ("p", "Con Git (recomendado, así después actualizar es un comando):"),
    ("code", f"git clone {REPO}.git\ncd centinela"),
    (
        "p",
        "Sin Git: en la página del repositorio tocá <b>Code > Download ZIP</b> y descomprimilo. La carpeta se llama "
        "`centinela-main`; si quedó una dentro de otra, usá la que tiene el archivo `docker-compose.yml`.",
    ),
    (
        "callout",
        "nota",
        "Si el repositorio es <b>privado</b>, para descargarlo tenés que iniciar sesión en GitHub (por ejemplo con "
        "GitHub Desktop: <i>File > Clone repository</i>).",
    ),
    (
        "callout",
        "importante",
        "<b>Todos los comandos de esta guía se ejecutan dentro de la carpeta del proyecto</b> (la que tiene "
        "`docker-compose.yml`). Para abrir una terminal ahí: en Windows 11, clic derecho sobre la carpeta > <i>Abrir en "
        "Terminal</i>; en Windows 10, Shift + clic derecho > <i>Abrir la ventana de PowerShell aquí</i>; en Linux, "
        "`cd` hasta la carpeta.",
    ),
    ("p", "Creá la carpeta para credenciales (va a quedar fuera de Git):"),
    ("code", "mkdir secrets"),
    ("salto",),
    # ------------------------------------------------------------------------
    ("h1", "5. Paso 3: archivos de configuración"),
    (
        "p",
        "Centinela usa dos archivos: <b>.env</b> (secretos: claves y contraseñas) y <b>config.yaml</b> (todo lo demás). "
        "Copialos desde los ejemplos:",
    ),
    ("code", "cp .env.example .env\ncp config.example.yaml config.yaml"),
    (
        "callout",
        "consejo",
        "<b>Cómo editar estos archivos.</b> Windows: `notepad .env` y `notepad config.yaml` (guardás con Ctrl+S). "
        "Linux: `nano .env` (guardás con Ctrl+O y Enter, salís con Ctrl+X). En la terminal de Linux se copia con "
        "Ctrl+Shift+C y se pega con Ctrl+Shift+V (Ctrl+C corta el comando que está corriendo). "
        "En <b>config.yaml</b> la sangría es con <b>espacios, nunca con Tab</b>, y cambia el significado: respetá la "
        'alineación de los ejemplos. Una línea que empieza con # es un comentario (no se usa); "descomentar" es '
        "borrar ese # y el espacio que le sigue.",
    ),
    (
        "callout",
        "importante",
        "<b>.env</b> y <b>config.yaml</b> tienen secretos: no los subas nunca a GitHub (ya están en .gitignore), "
        "no los mandes por mail y hacé copia de seguridad en un lugar seguro. En .env, si un valor tiene $, # o "
        "espacios, escribilo entre comillas simples: `CLAVE='ab$c#1'`.",
    ),
    ("h2", "Comandos según el modo"),
    (
        "p",
        "En esta guía los comandos usan el modo completo. Si elegiste el <b>modo liviano</b>, cambialos así:",
    ),
    (
        "tabla",
        [
            ["Modo completo", "Modo liviano"],
            ["`docker compose ...`", "`docker compose -f docker-compose.lite.yml ...`"],
            ["`... run --rm --no-deps worker <comando>`", "`... run --rm --no-deps centinela <comando>`"],
            ["`... run --rm ingest auth <conector>`", "`... run --rm --no-deps centinela auth <conector>`"],
            [
                "Servicios `ingest`, `worker`, `api` (en logs, restart...)",
                "`centinela` (en modo liviano hay un solo servicio)",
            ],
        ],
        [85, 85],
    ),
    ("h2", "3.1 Construir la imagen"),
    (
        "p",
        "<b>Solo modo completo, antes que nada:</b> abrí <b>.env</b> y en `POSTGRES_PASSWORD` poné una contraseña "
        "larga hecha <b>solo de letras y números</b> (por ejemplo 24 caracteres): va dentro de una dirección y los "
        "símbolos la rompen. No la cambies después de instalar. Sin eso, ningún comando de Docker arranca.",
    ),
    ("p", "Después construí la imagen. La primera vez tarda unos minutos:"),
    ("code", "docker compose build"),
    ("h2", "3.2 Generar las claves"),
    ("code", "docker compose run --rm --no-deps worker gen-key"),
    (
        "p",
        "Te muestra dos líneas (`CENTINELA_ENCRYPTION_KEY=...` y `CENTINELA_DASHBOARD_SECRET_KEY=...`). Copialas y "
        "pegalas en <b>.env</b>, reemplazando las líneas vacías con el mismo nombre.",
    ),
    ("h2", "3.3 Contraseña del panel web"),
    ("code", "docker compose run --rm --no-deps worker hash-password"),
    (
        "p",
        "Escribí una contraseña de al menos 12 caracteres y repetila (mientras escribís <b>no se ve nada en "
        "pantalla</b>: es normal). Te devuelve un texto largo que empieza con `$argon2id$`. En <b>config.yaml</b>, "
        "buscá `admin_password_hash: ''` y pegá ese texto <b>entre las dos comillas simples</b>:",
    ),
    ("code", "  admin_password_hash: '$argon2id$v=19$m=65536,t=3,p=4$...'"),
    (
        "callout",
        "consejo",
        "El usuario del panel es `admin` (se puede cambiar en `admin_user`). Guardá la contraseña en un lugar seguro: "
        "si la perdés, repetí este paso.",
    ),
    ("salto",),
    # ------------------------------------------------------------------------
    ("h1", "6. Paso 4: datos de tu empresa"),
    ("p", "En <b>config.yaml</b>, sección `general`:"),
    (
        "code",
        'general:\n  company_name: "Mi Empresa SRL"\n  company_domains: ["miempresa.com.ar"]\n'
        "  trusted_domains: []        # socios o proveedores de confianza (opcional)\n"
        '  trusted_authserv_ids: []   # Gmail/Workspace: ["mx.google.com"]; M365: ["mx.microsoft.com"]',
    ),
    (
        "lista",
        [
            "<b>company_domains</b>: todos los dominios de tu empresa. Es clave: así detecta mails que se hacen pasar "
            "por ustedes y dominios parecidos (miempresa-pagos.com, rniempresa.com).",
            "<b>trusted_authserv_ids</b>: quién firma los controles SPF/DKIM/DMARC. Con hosting propio o si no sabés, "
            "dejalo vacío `[]`.",
        ],
    ),
    ("h2", "Base de datos según el modo"),
    ("p", "Modo completo: dejá las dos líneas como vienen. Modo liviano: comentalas y descomentá estas dos:"),
    ("code", 'database_url: "sqlite+aiosqlite:////data/centinela.db"\nredis_url: ""'),
    # ------------------------------------------------------------------------
    ("h1", "7. Paso 5: conectar los buzones"),
    (
        "callout",
        "importante",
        "En config.yaml, la sección `connectors:` trae <b>todos los ejemplos comentados</b>. Pegá debajo de "
        "`connectors:` el bloque de tu proveedor (o descomentá el ejemplo), sin repetir la línea `connectors:` y "
        "respetando la sangría. Cada conector lleva un nombre único (minúsculas y guiones). Podés poner varios.",
    ),
    (
        "tabla",
        [
            ["Tu correo", "Conector", "Qué necesitás"],
            [
                "Hosting propio (cPanel, Plesk), Zoho, Yahoo, iCloud",
                "imap",
                "Servidor IMAP, usuario y contraseña (Yahoo/iCloud: <i>contraseña de aplicación</i>)",
            ],
            [
                "Gmail personal (@gmail.com)",
                "imap",
                "`imap.gmail.com` + contraseña de aplicación (con verificación en 2 pasos)",
            ],
            ["Google Workspace (dominio propio)", "gmail", "Cuenta de servicio con delegación de dominio"],
            ["Microsoft 365 / Exchange Online", "graph", "Registrar una app en Entra ID"],
            [
                "Outlook.com / Hotmail personal",
                "imap + oauth2",
                "Registrar una app + `auth` (ver docs/CONECTORES.md)",
            ],
            [
                "Servidor de correo propio (Postfix)",
                "milter",
                "Acceso a la configuración de Postfix (modo completo)",
            ],
            [
                "Cualquiera que permita reenviar copias",
                "smtp_journal",
                "Regla de copia o journaling (solo alertas)",
            ],
        ],
        [60, 26, 84],
    ),
    ("h2", "A) IMAP (hosting propio, Zoho, Yahoo, iCloud, Gmail personal)"),
    (
        "code",
        "connectors:\n  - name: ventas\n    type: imap\n    host: mail.miempresa.com.ar\n    port: 993\n"
        '    username: ventas@miempresa.com.ar\n    password: "${IMAP_VENTAS_PASSWORD}"\n'
        '    folders: ["INBOX", "Junk"]',
    ),
    (
        "p",
        "En <b>.env</b> agregá la línea `IMAP_VENTAS_PASSWORD=la-contraseña` (entre comillas simples si tiene $ o #). "
        "Repetí el bloque por cada buzón, cambiando `name`, `username` y el nombre de la variable. Para Gmail personal "
        "usá `host: imap.gmail.com` y una contraseña de aplicación (Cuenta de Google > Seguridad).",
    ),
    ("h2", "B) Google Workspace"),
    (
        "pasos",
        [
            "En console.cloud.google.com creá un proyecto y habilitá <b>Gmail API</b>.",
            "Creá una <b>cuenta de servicio</b>, generá una clave JSON y guardala como `secrets/google-sa.json`. En "
            "Windows, activá antes <i>Vista > Mostrar > Extensiones de nombre de archivo</i>, para que no quede "
            "`google-sa.json.json`. Si Google no deja crear la clave, un administrador tiene que desactivar la política "
            "`iam.disableServiceAccountKeyCreation` para ese proyecto.",
            "En admin.google.com: <b>Seguridad > Acceso y control de datos > Controles de API > Delegación de todo el "
            "dominio</b>. Agregá el <b>ID único</b> de la cuenta de servicio (un número; también figura como client_id "
            "dentro del JSON) con el permiso `https://www.googleapis.com/auth/gmail.modify`.",
            "En Linux, dale permiso de lectura al archivo: `chmod 644 secrets/google-sa.json`.",
        ],
    ),
    (
        "code",
        "  - name: workspace\n    type: gmail\n    auth: service_account\n"
        "    service_account_file: /config/secrets/google-sa.json\n"
        '    mailboxes: ["ventas@miempresa.com.ar", "admin@miempresa.com.ar"]',
    ),
    ("h2", "C) Microsoft 365"),
    (
        "pasos",
        [
            "En entra.microsoft.com: <b>Registros de aplicaciones > Nuevo registro</b>. En <i>Información general</i> "
            "copiá el <b>Id. de aplicación (cliente)</b> (va en `client_id`) y el <b>Id. de directorio (inquilino)</b> "
            "(va en `tenant_id`).",
            "<b>Permisos de API > Microsoft Graph > Permisos de aplicación</b>: `Mail.ReadWrite`. Tocá "
            "<b>Conceder consentimiento de administrador</b>.",
            "<b>Certificados y secretos > Nuevo secreto</b>. Copiá la columna <b>Valor</b> (no el <i>Id. de "
            "secreto</i>): se muestra una sola vez. Pegalo en .env como `GRAPH_CLIENT_SECRET=...`. Anotá la fecha de "
            "vencimiento y renovalo antes.",
            "Recomendado: limitá la app a los buzones que querés vigilar (ver docs/CONECTORES.md, RBAC for Applications).",
        ],
    ),
    (
        "code",
        '  - name: m365\n    type: graph\n    tenant_id: "<id del tenant>"\n    client_id: "<id de la app>"\n'
        '    client_secret: "${GRAPH_CLIENT_SECRET}"\n    mailboxes: ["ventas@miempresa.com.ar"]',
    ),
    ("p", "Para comprobar que la app tiene acceso:"),
    ("code", "docker compose run --rm ingest auth m365"),
    ("h2", "D) Outlook.com / Hotmail y Gmail con OAuth"),
    (
        "p",
        "Estos necesitan un login interactivo una sola vez, después de configurar el conector (pasos en "
        "docs/CONECTORES.md):",
    ),
    ("code", "docker compose run --rm ingest auth <nombre-del-conector>"),
    (
        "lista",
        [
            "<b>Outlook.com:</b> te muestra un código. Abrí microsoft.com/devicelogin, ingresalo e iniciá sesión. La "
            "terminal sigue sola.",
            "<b>Gmail con OAuth:</b> te da una dirección para abrir en el navegador. Al autorizar, el navegador muestra "
            'un error de "localhost" (es normal): copiá la dirección completa de la barra y pegala en la terminal.',
        ],
    ),
    (
        "callout",
        "nota",
        "Centinela pide solo los permisos mínimos: leer y poner etiquetas. Si en un conector ponés `tag: false`, alcanza "
        "con permisos de solo lectura (en ese caso solo avisa, no etiqueta).",
    ),
    ("salto",),
    # ------------------------------------------------------------------------
    ("h1", "8. Paso 6: alertas"),
    ("h2", "Telegram (recomendado)"),
    (
        "pasos",
        [
            "En Telegram, hablale a <b>@BotFather</b>, mandá `/newbot` y seguí las instrucciones. Te da un "
            "<b>token</b>.",
            'Creá un grupo (por ejemplo "Alertas de correo"), agregá al bot y escribí cualquier mensaje en el grupo.',
            "En el navegador abrí `https://api.telegram.org/bot<TOKEN>/getUpdates` (con tu token) y buscá "
            '`"chat":{"id":`. Copiá el número <b>completo, con el signo menos</b> (por ejemplo -4123456789). Si la '
            'página muestra `"result":[]`, mandá en el grupo `/start@NombreDeTuBot` y recargá.',
            "En <b>.env</b>: `TELEGRAM_BOT_TOKEN=...` y `TELEGRAM_CHAT_ID=...`.",
        ],
    ),
    (
        "p",
        "config.yaml ya trae el canal `telegram-soporte` listo para usar esas variables. También hay ejemplos "
        "comentados de <b>mail</b>, <b>Slack</b>, <b>Teams</b>, <b>Discord</b> y <b>syslog</b> (para un SIEM).",
    ),
    (
        "lista",
        [
            "`min_level: suspicious` avisa de sospechosos y maliciosos; `malicious` solo de maliciosos.",
            "Si la misma campaña llega a 30 buzones, recibís <b>una</b> alerta (no 30), pero todos los mails se etiquetan.",
            "En `actions > alerts`, `dashboard_base_url` es la dirección del panel que va como link en cada alerta "
            '(por ejemplo `"http://192.168.1.50:8080"`). Si lo dejás vacío, las alertas no llevan link.',
        ],
    ),
    ("h2", "Consultas de reputación (opcional, gratis)"),
    (
        "p",
        "Mejoran la detección de malware conocido. Solo se envía el hash del archivo, nunca el archivo. Creá las "
        "claves y ponelas en .env:",
    ),
    (
        "lista",
        [
            "<b>MalwareBazaar</b>: cuenta gratuita en auth.abuse.ch, variable `MALWAREBAZAAR_API_KEY`.",
            "<b>VirusTotal</b>: cuenta gratuita en virustotal.com (4 consultas por minuto), variable `VIRUSTOTAL_API_KEY`.",
        ],
    ),
    ("p", "Si no querés que salga nada, poné `hash_lookups: false` en la sección `privacy`."),
    # ------------------------------------------------------------------------
    ("h1", "9. Paso 7: verificar y arrancar"),
    (
        "p",
        "<b>1.</b> Revisá la configuración. Tiene que decir <i>Configuración válida</i> y no mostrar avisos:",
    ),
    ("code", "docker compose run --rm --no-deps worker check-config"),
    ("p", "<b>2.</b> Probá las alertas (te tiene que llegar un aviso de PRUEBA):"),
    ("code", "docker compose run --rm --no-deps worker test-alert"),
    ("p", "<b>3.</b> Arrancá todo:"),
    ("code", "docker compose up -d\ndocker compose ps"),
    (
        "callout",
        "nota",
        'La primera vez, `docker compose up -d` puede quedarse <b>varios minutos en "Waiting"</b> mientras ClamAV '
        "descarga sus firmas: no lo cortes. Si termina con <i>dependency failed to start ... unhealthy</i>, esperá 5 "
        "minutos y volvé a correr `docker compose up -d`. Al final, todos los servicios tienen que figurar "
        "<i>running</i> o <i>healthy</i> en `docker compose ps`.",
    ),
    ("p", "<b>4.</b> Mirá los registros para confirmar que los conectores entraron a los buzones:"),
    ("code", "docker compose logs -f ingest"),
    (
        "p",
        "Salís con Ctrl+C (Centinela sigue funcionando). <b>check-config no prueba las contraseñas: esto sí.</b> Si "
        "aparecen líneas con `ERROR` y el nombre de tu conector, leé el mensaje y buscalo en <i>Problemas "
        "frecuentes</i>.",
    ),
    ("salto",),
    # ------------------------------------------------------------------------
    ("h1", "10. Paso 8: el panel web"),
    (
        "p",
        "En el mismo equipo abrí `http://127.0.0.1:8080` en el navegador e ingresá con `admin` y la contraseña del "
        "paso 3.3. Vas a ver:",
    ),
    (
        "tabla",
        [
            ["Página", "Para qué sirve"],
            [
                "Resumen",
                "Mails analizados, sospechosos y maliciosos de las últimas 24 h y 7 días; familias de malware.",
            ],
            ["Mensajes", "Todos los mails con filtros. Al entrar a uno ves por qué se marcó y qué hacer."],
            ["Campañas", "El mismo adjunto que llegó a varios buzones (ataques dirigidos a la empresa)."],
            [
                "Estado",
                "Base de datos, cola y ClamAV. En modo liviano también los conectores; en modo completo, el estado de "
                "los conectores se ve con `docker compose logs ingest`.",
            ],
        ],
        [30, 140],
    ),
    (
        "lista",
        [
            "<b>Falso positivo:</b> si Centinela marcó algo que estaba bien, entrá al mensaje y tocá <i>Marcar como "
            "falso positivo</i>. Si un remitente se marca seguido sin razón, agregalo a `trusted_senders` en "
            "`scoring`.",
        ],
    ),
    ("h2", "Verlo desde otra PC de la oficina"),
    (
        "p",
        "Por seguridad, el panel solo se abre desde el equipo donde corre Centinela. Para verlo desde otra PC de la "
        'red local: en `docker-compose.yml` (o `docker-compose.lite.yml`) cambiá la línea `"127.0.0.1:8080:8080"` '
        'por `"8080:8080"`, ejecutá `docker compose up -d` y entrá a `http://IP-del-equipo:8080`.',
    ),
    (
        "callout",
        "importante",
        "<b>Nunca redirijas el puerto 8080 a internet en el router.</b> El panel muestra datos sensibles de los mails. "
        "Para verlo desde afuera de la oficina, usá una VPN (por ejemplo Tailscale o WireGuard).",
    ),
    ("h2", "Probar que detecta"),
    (
        "lista",
        [
            "Mandate un mail normal desde otra cuenta: en 1 o 2 minutos tiene que aparecer en <b>Mensajes</b> como "
            "<i>Limpio</i>. Eso confirma que el conector funciona.",
            "Si tu proveedor lo permite, mandate un .zip con cualquier archivo renombrado a `factura.pdf.exe`: tiene "
            "que salir <i>Sospechoso</i> o <i>Malicioso</i>, con alerta y etiqueta. Gmail y Microsoft 365 suelen "
            "bloquear ese adjunto antes de que llegue, y eso también está bien.",
        ],
    ),
    # ------------------------------------------------------------------------
    ("h1", "11. Mantenimiento"),
    ("h2", "Actualizar Centinela"),
    ("code", "git pull\ndocker compose up -d --build"),
    ("p", "Las firmas de ClamAV se actualizan solas. Conviene actualizar Centinela una vez por mes."),
    ("h2", "Copias de seguridad"),
    (
        "lista",
        [
            "Guardá en un lugar seguro: <b>.env</b>, <b>config.yaml</b> y la carpeta <b>secrets/</b>.",
            "Base de datos, modo completo (sirve en Windows y Linux):",
        ],
    ),
    (
        "code",
        "docker compose exec -T postgres pg_dump -U centinela -f /tmp/backup.sql centinela\n"
        "docker compose cp postgres:/tmp/backup.sql ./backup.sql",
    ),
    ("lista", ["Base de datos, modo liviano (se detiene un momento para que la copia quede completa):"]),
    (
        "code",
        "docker compose -f docker-compose.lite.yml stop centinela\n"
        "docker compose -f docker-compose.lite.yml cp centinela:/data/centinela.db ./backup.db\n"
        "docker compose -f docker-compose.lite.yml start centinela",
    ),
    ("h2", "Otros ajustes útiles"),
    (
        "lista",
        [
            "<b>Retención:</b> `retention_days` en `general` (por defecto 180 días). Lo más viejo se borra solo.",
            "<b>Reglas YARA propias o de la comunidad:</b> copiá los archivos .yar a `rules/custom/` y reiniciá con "
            "`docker compose restart worker`. Verificá con `... run --rm --no-deps worker rules check`.",
            '<b>Silenciar una regla</b> que da falsos positivos: en `scoring`, `rule_overrides: {"url.shortener": 0}` '
            "(el nombre de la regla aparece en cada hallazgo del panel).",
            "<b>Más capacidad</b> (modo completo): `docker compose up -d --scale worker=3`.",
        ],
    ),
    ("salto",),
    # ------------------------------------------------------------------------
    ("h1", "12. Problemas frecuentes"),
    (
        "tabla",
        [
            ["Síntoma", "Qué revisar"],
            [
                "check-config dice que no puede iniciar el dashboard",
                "Falta o está mal `admin_password_hash` (config.yaml) o `CENTINELA_DASHBOARD_SECRET_KEY` (.env). "
                "Repetí los pasos 3.2 y 3.3.",
            ],
            [
                '"conector imap ...: falta password u oauth2"',
                "La variable de la contraseña está vacía en .env o tiene otro nombre que en config.yaml.",
            ],
            [
                '"variable de entorno no definida"',
                "Falta esa variable en .env (o tiene otro nombre). Si no la usás, borrá o comentá la línea en config.yaml.",
            ],
            [
                '"no such service"',
                "Estás en modo liviano: el servicio se llama `centinela` (ver la tabla del Paso 3).",
            ],
            [
                "IMAP: falla el login",
                "Yahoo, iCloud y Gmail exigen <i>contraseña de aplicación</i>, no la normal. Revisá host y puerto (993).",
            ],
            [
                "Gmail: error 403 / unauthorized_client",
                "La delegación de dominio no tiene el permiso gmail.modify o el ID está mal. Puede tardar unos minutos "
                "en aplicarse.",
            ],
            [
                "Microsoft 365: error 401 / 403",
                "Falta el <i>consentimiento de administrador</i>, el secreto venció o se copió el Id. en lugar del Valor.",
            ],
            [
                "ClamAV figura unhealthy",
                "La primera descarga de firmas tarda: esperá 5 a 10 minutos y volvé a correr `docker compose up -d`. "
                "Necesita internet.",
            ],
            [
                "Cambié .env y no toma el cambio",
                "`docker compose restart` no relee .env: usá `docker compose up -d`.",
            ],
            [
                "No llegan alertas",
                "Corré `test-alert`. Revisá token, chat_id (con el signo menos), `min_level` y que el bot esté en el grupo.",
            ],
            [
                "Muchos falsos positivos",
                "Usá `trusted_domains`, `trusted_senders` o `rule_overrides`, y marcá falsos positivos en el panel.",
            ],
            [
                "El antivirus marca archivos de tests/ o rules/",
                "Es esperable: contienen fragmentos inertes de técnicas de ataque para probar la detección. No afectan "
                "al funcionamiento.",
            ],
        ],
        [55, 115],
    ),
    ("p", "Para ver errores en detalle: `docker compose logs --tail 200 worker` (o `ingest`, `api`)."),
    # ------------------------------------------------------------------------
    ("h1", "13. Seguridad y privacidad"),
    (
        "lista",
        [
            "Los <b>archivos adjuntos no salen</b> de tu red. Por defecto solo se consulta su hash, y se puede apagar.",
            "Por defecto se guardan <b>metadatos</b> (remitente, asunto, hallazgos, hashes), no el contenido de los mails.",
            "Los contenedores de Centinela corren sin privilegios y con disco de solo lectura (la base de datos, Redis y "
            "ClamAV usan las imágenes oficiales).",
            "Los permisos de OAuth guardados se cifran con `CENTINELA_ENCRYPTION_KEY`: si perdés esa clave, hay que "
            "repetir el `auth`.",
            "Usá contraseñas largas, no expongas el panel a internet y mantené el equipo actualizado.",
        ],
    ),
    ("h1", "14. Comandos útiles"),
    (
        "tabla",
        [
            ["Comando", "Qué hace"],
            ["`docker compose up -d`", "Arranca todo; también aplica cambios en .env"],
            ["`docker compose ps`", "Muestra el estado de cada servicio"],
            ["`docker compose logs -f ingest`", "Registros en vivo (Ctrl+C para salir)"],
            ["`docker compose restart`", "Reinicia; alcanza si cambiaste solo config.yaml"],
            ["`docker compose down`", "Detiene todo (los datos se conservan)"],
            ["`... run --rm --no-deps worker check-config`", "Valida la configuración"],
            ["`... run --rm --no-deps worker test-alert`", "Manda una alerta de prueba"],
            ["`... run --rm --no-deps worker rules check`", "Verifica las reglas YARA"],
            ["`git pull` + `docker compose up -d --build`", "Actualiza Centinela"],
        ],
        [85, 85],
    ),
    (
        "p",
        "En modo liviano: `docker compose -f docker-compose.lite.yml ...` y el servicio `centinela`. Documentación "
        "completa en el repositorio: README.md, docs/CONECTORES.md, docs/ARCHITECTURE.md y docs/PENDIENTES.md.",
    ),
]
