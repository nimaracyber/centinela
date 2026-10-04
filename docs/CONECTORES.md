# Guía de conectores

Centinela pide siempre **los permisos mínimos**: leer mails y (si querés etiquetas) agregar una etiqueta.
Si ponés `tag: false` en un conector, alcanza con permisos de solo lectura.
En todos los casos: **no marca como leído, no mueve, no borra**.

- [Google Workspace (todos los buzones)](#google-workspace)
- [Gmail personal](#gmail-personal)
- [Microsoft 365 / Exchange Online](#microsoft-365)
- [IMAP: hosting propio, Yahoo, iCloud, Zoho…](#imap)
- [Outlook.com / Hotmail personal](#outlookcom--hotmail)
- [Servidor Postfix propio (milter)](#postfix-milter)
- [Copias por BCC / journaling (cualquier proveedor)](#copias-por-bcc--journaling)

---

## Google Workspace

Una cuenta de servicio con **delegación de dominio** permite leer todos los buzones que listes, sin contraseñas.

1. En [console.cloud.google.com](https://console.cloud.google.com) creá un proyecto y habilitá **Gmail API**.
2. *IAM y administración → Cuentas de servicio* → crear cuenta → *Claves* → agregar clave JSON.
   Guardala como `secrets/google-sa.json` (carpeta montada en solo lectura).
3. En [admin.google.com](https://admin.google.com) → *Seguridad → Acceso y control de datos → Controles de API →
   Delegación de todo el dominio* → **Agregar** con el *Client ID* de la cuenta de servicio y el scope:
   - `https://www.googleapis.com/auth/gmail.modify` (para etiquetar), o
   - `https://www.googleapis.com/auth/gmail.readonly` (si el conector tiene `tag: false`).
4. Configurar:

```yaml
- name: workspace
  type: gmail
  auth: service_account
  service_account_file: /config/secrets/google-sa.json
  mailboxes: ["ventas@miempresa.com", "admin@miempresa.com"]
```

**Tiempo real (opcional)**: creá un tópico de Pub/Sub, dale el rol *Pub/Sub Publisher* a
`gmail-api-push@system.gserviceaccount.com` sobre ese tópico, creá una suscripción **pull** y a la cuenta de
servicio dale *Pub/Sub Subscriber*. Luego agregá `pubsub_topic` y `pubsub_subscription`.
No hace falta exponer ninguna URL pública. Sin esto, Centinela consulta el historial cada 20 s.

## Gmail personal

> Lo más simple para una cuenta @gmail.com es el conector **IMAP** (`imap.gmail.com`) con una
> *contraseña de aplicación* (requiere tener activada la verificación en 2 pasos). OAuth es la alternativa:

1. En Google Cloud: habilitá **Gmail API**, configurá la *pantalla de consentimiento* (tipo externo) y creá un
   **ID de cliente OAuth de tipo "App de escritorio"**. Descargá el JSON como `secrets/google-oauth-client.json`
   (en Linux: `chmod 644 secrets/google-oauth-client.json`).
2. En la pantalla de consentimiento tocá **Publicar app**: si queda "En prueba", Google vence el permiso a los 7 días.
3. Configurá el conector con `auth: oauth_user` y `oauth_client_file: /config/secrets/google-oauth-client.json`.
4. Ejecutá una vez `docker compose run --rm ingest auth gmail-personal` (modo liviano:
   `docker compose -f docker-compose.lite.yml run --rm --no-deps centinela auth gmail-personal`). Te da una
   dirección para abrir en el navegador (puede ser en otra PC); al autorizar, el navegador muestra un error de
   "localhost": es normal. Copiá la dirección completa de la barra y pegala en la terminal. El token queda guardado
   **cifrado** en la base (necesita `encryption_key`).

> `auth` se corre en el servicio `ingest` (modo completo) porque necesita la base de datos y salida a internet;
> el servicio `api` está en una red interna sin internet.

## Microsoft 365

1. En [entra.microsoft.com](https://entra.microsoft.com) → *Registros de aplicaciones* → **Nuevo registro** (una sola organización).
2. *Permisos de API → Microsoft Graph → Permisos de aplicación*:
   - `Mail.ReadWrite` (para categorizar) o `Mail.Read` (si `tag: false`).
   - Opcional `MailboxSettings.ReadWrite` para crear las categorías con color.
   - **Conceder consentimiento de administrador**.
3. *Certificados y secretos* → nuevo secreto (o subí un certificado y usá `certificate_file`).
4. **Muy recomendado — limitar a los buzones necesarios** (por defecto un permiso de aplicación ve *todos* los buzones).
   Con Exchange Online PowerShell, usando *RBAC for Applications*:

   ```powershell
   New-ServicePrincipal -AppId <client_id> -ObjectId <object_id_del_enterprise_app> -DisplayName "Centinela"
   New-ManagementScope -Name "Centinela-Buzones" -RecipientRestrictionFilter "MemberOfGroup -eq '<DN del grupo>'"
   New-ManagementRoleAssignment -App <client_id> -Role "Application Mail.ReadWrite" -CustomResourceScope "Centinela-Buzones"
   ```

   (Si usás este método, no otorgues el permiso `Mail.ReadWrite` en Entra: la asignación de Exchange lo reemplaza.)
5. Configurar:

```yaml
- name: m365
  type: graph
  tenant_id: "<tenant-id>"
  client_id: "<client-id>"
  client_secret: "${GRAPH_CLIENT_SECRET}"
  mailboxes: ["ventas@miempresa.com"]
```

`tenant_id` es el *Id. de directorio (inquilino)* y `client_id` el *Id. de aplicación (cliente)*, ambos en
*Información general* de la app. Del secreto copiá la columna **Valor** (no el *Id. de secreto*): se muestra una sola
vez y vence (6 meses por defecto): renovalo antes.

Verificá con `docker compose run --rm ingest auth m365`.

## IMAP

Sirve para casi cualquier proveedor. Datos típicos:

| Proveedor | host | Notas |
|---|---|---|
| cPanel / Plesk / hosting | `mail.tudominio.com` | usuario = dirección completa |
| Yahoo | `imap.mail.yahoo.com` | requiere **contraseña de aplicación** |
| iCloud | `imap.mail.me.com` | requiere **contraseña específica de app** |
| Zoho | `imap.zoho.com` (o `.eu`, `.in`) | habilitar IMAP en la configuración |
| Gmail (sin API) | `imap.gmail.com` | contraseña de aplicación (requiere 2FA) |

```yaml
- name: oficina
  type: imap
  host: mail.miempresa.com
  username: ventas@miempresa.com
  password: "${IMAP_OFICINA_PASSWORD}"
  folders: ["INBOX", "Junk"]
```

Centinela abre las carpetas en **modo solo lectura** y descarga con `BODY.PEEK` (no marca como leído).
La etiqueta se agrega como *keyword* IMAP (`$Centinela_Malicious` / `$Centinela_Suspicious`), visible como
etiqueta en Thunderbird y en varios webmails. En Gmail-por-IMAP se usa un label real.

## Outlook.com / Hotmail

Microsoft ya no permite contraseñas por IMAP en cuentas personales: hay que usar OAuth2.

1. En [entra.microsoft.com](https://entra.microsoft.com) registrá una app con *Tipos de cuenta: cuentas personales de Microsoft*
   y habilitá *Permitir flujos de cliente público*. Permiso delegado: `IMAP.AccessAsUser.All` + `offline_access`.
2. Configurá:

```yaml
- name: hotmail
  type: imap
  host: outlook.office365.com
  username: duenio@hotmail.com
  oauth2: { provider: microsoft, client_id: "<app-id>", tenant: consumers }
```

3. `docker compose run --rm ingest auth hotmail` → te muestra un código: abrí microsoft.com/devicelogin, ingresalo e
   iniciá sesión. La terminal sigue sola (no hay que pegar nada).

## Postfix (milter)

Para quien tiene servidor de correo propio. Centinela recibe cada mail **antes** de que llegue al buzón,
lo analiza con un tiempo máximo (`inline_timeout_s`) y agrega headers. **Siempre acepta el mail.**

```yaml
- name: gateway
  type: milter
  listen_port: 8899
  inline_timeout_s: 15
  subject_prefix: "[SOSPECHOSO] "   # opcional
```

En `/etc/postfix/main.cf`:

```
smtpd_milters = inet:<ip-de-centinela>:8899
non_smtpd_milters = $smtpd_milters
milter_default_action = accept
milter_protocol = 6
milter_content_timeout = 30s
```

Headers agregados: `X-Centinela-Verdict`, `X-Centinela-Score`, `X-Centinela-Families`, `X-Centinela-Id`.
Centinela elimina cualquier `X-Centinela-*` que venga de afuera (un atacante podría falsificarlos).
Podés usar esos headers en reglas de Sieve/Outlook para mover a una carpeta, si alguna vez querés dejar de ser pasivo.
Si el análisis tarda más que el timeout, el mail se entrega sin headers y la alerta llega igual unos segundos después.

## Copias por BCC / journaling

Funciona con cualquier proveedor que pueda enviar una **copia** de los mails entrantes a otra dirección/servidor.
Como Centinela recibe una copia, no puede etiquetar el original: **solo alerta**.

```yaml
- name: journal
  type: smtp_journal
  listen_port: 2525
  allowed_senders: ["203.0.113.10/32"]   # IPs autorizadas a entregar copias
```

- **Google Workspace**: *Gmail → Cumplimiento → Enrutamiento (Routing)* → regla para mensajes entrantes →
  *Agregar más destinatarios* → servidor SMTP de Centinela.
- **Exchange / Microsoft 365**: regla de *journaling* hacia una dirección que entregue en Centinela
  (Centinela desarma el reporte de journaling y analiza el mail original).
- **cPanel / hosting**: *Reenviadores* → copia a una casilla cuyo MX apunte a Centinela.

El puerto 2525 **no debe quedar abierto a internet** salvo para las IPs de `allowed_senders`.
