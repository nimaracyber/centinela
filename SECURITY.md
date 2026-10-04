# Seguridad

## Reportar una vulnerabilidad

No abras un issue público. Usá **GitHub → Security → Report a vulnerability** (private vulnerability reporting)
de este repositorio. Respondemos dentro de 72 h hábiles y coordinamos la divulgación.

Interesan especialmente:
- Ejecución de código o escape a partir de un mail/adjunto hostil (Centinela procesa malware a propósito).
- Evasiones sistemáticas de detección (ej: un formato de contenedor que el parser no abre).
- Bypass de autenticación del dashboard, XSS, CSRF, lectura de secretos.
- Fugas de datos: cualquier camino por el que un archivo o el contenido de un mail salga de la empresa.

## Modelo de amenaza (resumen)

| Activo | Protección |
|---|---|
| Adjuntos hostiles | Nunca se ejecutan ni se abren con aplicaciones. Se procesan en memoria con límites de tamaño, profundidad, ratio de compresión y tiempo. Contenedores read-only, sin capabilities, usuario sin privilegios. |
| Privacidad del correo | Los archivos nunca salen: solo se consulta el SHA-256 (configurable). Los links solo se consultan si `privacy.url_lookups: true`. Por defecto no se guarda el cuerpo de los mails. |
| Credenciales de buzones | En variables de entorno / archivos montados read-only. Tokens OAuth cifrados (Fernet) en la base. Permisos mínimos en cada proveedor (lectura + etiquetado). |
| Dashboard | Argon2, cookies firmadas HttpOnly/SameSite=Strict, CSRF, rate limit de login, CSP estricta, sin recursos externos. Publicarlo solo detrás de HTTPS. |
| Alertas | Sin contenido de adjuntos ni cuerpos; links "desactivados" (hxxp, [.]) para que nadie haga clic desde la alerta. |

## Qué NO es Centinela

Es una capa de **detección pasiva**: no reemplaza al antivirus/EDR de las PCs ni al filtro de tu proveedor
de correo. Un mail marcado como limpio no es garantía de que sea seguro.
