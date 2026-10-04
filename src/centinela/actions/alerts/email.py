"""Alertas por mail (SMTP).

- `smtplib` corre en `asyncio.to_thread` (no bloquea el loop).
- Seguridad: `starttls` (por defecto, puerto 587) o `ssl` (465) SIEMPRE con verificación de certificado y
  de nombre de host (`ssl.create_default_context()`); si el servidor no ofrece STARTTLS, falla (no hay
  degradación silenciosa a texto plano). Con `security: none` no se envían credenciales: si hay `username`
  configurado el canal se rechaza al arrancar.
- `ca_file`: CA propia (PEM) para relays SMTP internos con certificado emitido por la empresa. Se agrega a
  las CAs del sistema (la verificación sigue siendo obligatoria). Se carga al crear el canal: si el archivo
  no existe o no es un PEM válido, el canal se rechaza al arrancar con un mensaje claro.
- El mail es multipart/alternative (texto + HTML simple con CSS inline). Asunto:
  `[Centinela] 🔴 Mail malicioso: <asunto truncado>`.
- `notify_recipient: true` manda ADEMÁS un aviso más suave a los destinatarios originales del mail que
  sean de la empresa (`general.company_domains`), sin datos técnicos. Si ese segundo envío falla, se
  registra y NO se lanza excepción (la alerta principal ya salió y un reintento la duplicaría).
- Headers anti-loop: `Auto-Submitted: auto-generated` (RFC 3834) y `X-Auto-Response-Suppress: All`
  (Exchange/Outlook), más `X-Centinela-Alert` para reconocer (y no reanalizar) las propias alertas.
"""

from __future__ import annotations

import asyncio
import logging
import re
import smtplib
import socket
import ssl
from datetime import UTC, datetime
from email.message import EmailMessage
from email.utils import format_datetime, formataddr, make_msgid, parseaddr
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING

from centinela.actions.alerts import AlertDeliveryError, describe_exception
from centinela.actions.alerts.base import AlertChannel
from centinela.actions.alerts.format import Alert, build_alert

if TYPE_CHECKING:
    import httpx

    from centinela.core.config import EmailAlertConfig, Settings
    from centinela.core.models import AnalysisResult

log = logging.getLogger(__name__)

EMAIL_TEXT_MAX_CHARS = 20_000  # la parte de texto acompaña al HTML (que va con el detalle completo)

_ADDR_RE = re.compile(
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,10}"
)


def _valid_addr(addr: str) -> bool:
    return len(addr) <= 254 and bool(_ADDR_RE.fullmatch(addr)) and ".." not in addr


@lru_cache(maxsize=1)
def _local_hostname() -> str:
    """Nombre para EHLO, igual que smtplib pero calculado una sola vez (getfqdn puede tardar segundos)."""
    fqdn = socket.getfqdn()
    if "." in fqdn:
        return fqdn
    try:
        return f"[{socket.gethostbyname(socket.gethostname())}]"
    except OSError:
        return "[127.0.0.1]"


def _domain_of(addr: str) -> str:
    return addr.rpartition("@")[2].lower()


MAX_CA_FILE_BYTES = 1024 * 1024  # un bundle de CAs razonable pesa decenas/cientos de KB


def _context_with_ca(channel: str, ca_file: Path) -> ssl.SSLContext:
    """Contexto con verificación obligatoria que confía en las CAs del sistema + la CA propia."""
    try:
        size = ca_file.stat().st_size
    except OSError:
        raise ValueError(f"canal {channel!r}: no existe o no se puede leer ca_file ({ca_file})") from None
    if not ca_file.is_file() or size > MAX_CA_FILE_BYTES:
        raise ValueError(f"canal {channel!r}: ca_file ({ca_file}) no es un archivo PEM válido")
    ctx = ssl.create_default_context()
    try:
        ctx.load_verify_locations(cafile=str(ca_file))
    except (OSError, ssl.SSLError, ValueError):
        raise ValueError(
            f"canal {channel!r}: ca_file ({ca_file}) no contiene certificados PEM válidos"
        ) from None
    return ctx


def _config_addr(raw: str) -> tuple[str, str] | None:
    """("Nombre", "dir@dominio") de un valor de config, o None si es inválido (incluye CR/LF y otros
    caracteres de control, que permitirían inyectar headers)."""
    if not raw or len(raw) > 320 or any(ord(ch) < 32 or ord(ch) == 127 for ch in raw):
        return None
    display, addr = parseaddr(raw)
    return (display, addr) if _valid_addr(addr) else None


class EmailChannel(AlertChannel):
    type = "email"
    timeout_s = 20.0  # timeout de socket por operación SMTP
    max_recipient_notifications = 10

    def __init__(self, config: EmailAlertConfig, settings: Settings, http: httpx.AsyncClient) -> None:
        super().__init__(config, settings, http)
        name = config.name
        parsed_from = _config_addr(config.from_addr)
        if parsed_from is None:
            raise ValueError(f"canal {name!r}: from_addr no es una dirección válida")
        display, from_addr = parsed_from
        self._from_addr = from_addr
        # si from_addr no trae nombre visible, se muestra "Centinela"
        self._from_header = formataddr((display or "Centinela", from_addr))
        parsed_to = [_config_addr(a) for a in config.to]
        if not parsed_to or any(p is None for p in parsed_to):
            raise ValueError(f"canal {name!r}: 'to' vacío o con direcciones inválidas")
        self._to = [p[1] for p in parsed_to if p is not None]
        if config.security == "none" and config.username:
            raise ValueError(
                f"canal {name!r}: no se envían usuario y contraseña sin cifrar; usá security: starttls o ssl"
            )
        self._password = config.password.get_secret_value() if config.password else None
        self._custom_ctx: ssl.SSLContext | None = None
        if config.ca_file is not None:
            if config.security == "none":
                log.warning("canal %r: ca_file no se usa con security: none (sin TLS)", name)
            else:
                self._custom_ctx = _context_with_ca(name, Path(config.ca_file))

    # ------------------------------------------------------------------ armado

    def _ssl_context(self) -> ssl.SSLContext:
        """Contexto TLS con verificación de certificado y hostname (se puede sobreescribir en tests).
        Con `ca_file`, el contexto (ya cargado al crear el canal) confía además en esa CA."""
        if self._custom_ctx is not None:
            return self._custom_ctx
        return ssl.create_default_context()

    def _base_message(self, alert: Alert, subject: str, to: list[str]) -> EmailMessage:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = self._from_header
        msg["To"] = ", ".join(to)
        msg["Date"] = format_datetime(datetime.now(UTC))
        msg["Message-ID"] = make_msgid(idstring="centinela", domain=_domain_of(self._from_addr))
        msg["Auto-Submitted"] = "auto-generated"
        msg["X-Auto-Response-Suppress"] = "All"
        msg["X-Centinela-Alert"] = alert.result_id
        msg["X-Centinela-Verdict"] = alert.level
        msg["X-Centinela-Score"] = str(alert.score)
        if alert.level == "malicious":
            msg["Importance"] = "high"
            msg["X-Priority"] = "1"
        return msg

    def build_admin_message(self, alert: Alert) -> EmailMessage:
        msg = self._base_message(alert, alert.email_subject(), self._to)
        msg.set_content(alert.to_text(max_len=EMAIL_TEXT_MAX_CHARS), charset="utf-8")
        msg.add_alternative(alert.to_html_email(), subtype="html", charset="utf-8")
        return msg

    def build_recipient_message(self, alert: Alert, recipients: list[str]) -> EmailMessage:
        msg = self._base_message(alert, alert.recipient_email_subject(), recipients)
        msg.set_content(alert.to_recipient_text(), charset="utf-8")
        msg.add_alternative(alert.to_recipient_html(), subtype="html", charset="utf-8")
        return msg

    def recipients_to_notify(self, result: AnalysisResult) -> list[str]:
        """Destinatarios originales que son de la empresa (y no están ya entre los admins)."""
        domains = [
            d.strip().lower().lstrip("@").rstrip(".")
            for d in self.settings.general.company_domains
            if d and d.strip()
        ]
        if not domains:
            return []
        admins = {a.lower() for a in self._to}
        out: list[str] = []
        for raw in result.to[:200]:
            addr = parseaddr(raw or "")[1].strip().lower()
            if not _valid_addr(addr) or addr in admins or addr in out:
                continue
            dom = _domain_of(addr)
            if any(dom == d or dom.endswith("." + d) for d in domains):
                out.append(addr)
                if len(out) >= self.max_recipient_notifications:
                    break
        return out

    # ------------------------------------------------------------------ envío

    async def send(self, result: AnalysisResult) -> None:
        alert = build_alert(result, self.settings)
        admin_msg = self.build_admin_message(alert)
        extra: tuple[EmailMessage, list[str]] | None = None
        if self.config.notify_recipient:
            rcpts = self.recipients_to_notify(result)
            if rcpts:
                extra = (self.build_recipient_message(alert, rcpts), rcpts)
        await asyncio.to_thread(self._deliver, admin_msg, extra)

    def _connect(self) -> smtplib.SMTP:
        cfg = self.config
        ctx = self._ssl_context()
        if cfg.security == "ssl":
            smtp: smtplib.SMTP = smtplib.SMTP_SSL(
                cfg.smtp_host,
                cfg.smtp_port,
                local_hostname=_local_hostname(),
                timeout=self.timeout_s,
                context=ctx,
            )
        else:
            smtp = smtplib.SMTP(
                cfg.smtp_host, cfg.smtp_port, local_hostname=_local_hostname(), timeout=self.timeout_s
            )
        try:
            smtp.ehlo()
            if cfg.security == "starttls":
                smtp.starttls(context=ctx)  # SMTPNotSupportedError si el server no ofrece STARTTLS
                smtp.ehlo()
        except BaseException:
            smtp.close()
            raise
        return smtp

    def _deliver(self, admin_msg: EmailMessage, extra: tuple[EmailMessage, list[str]] | None) -> None:
        cfg = self.config
        where = f"{cfg.smtp_host}:{cfg.smtp_port}"
        secrets = [self._password]
        try:
            smtp = self._connect()
        except ssl.SSLCertVerificationError as exc:
            # no se arregla reintentando: certificado vencido, de otro host o de una CA desconocida
            hint = "" if cfg.ca_file else "; si el servidor usa una CA propia, configurá ca_file"
            raise AlertDeliveryError(
                f"SMTP {where}: el certificado TLS no es válido ({describe_exception(exc, secrets)}){hint}",
                channel=self.name,
                retryable=False,
            ) from None
        except ssl.SSLError as exc:
            raise AlertDeliveryError(
                f"SMTP {where}: falló TLS / certificado ({describe_exception(exc, secrets)})",
                channel=self.name,
            ) from None
        except (OSError, smtplib.SMTPException) as exc:
            raise AlertDeliveryError(
                f"SMTP {where}: no se pudo conectar ({describe_exception(exc, secrets)})", channel=self.name
            ) from None
        try:
            if cfg.username:
                smtp.login(cfg.username, self._password or "")
            refused = smtp.send_message(admin_msg, from_addr=self._from_addr, to_addrs=self._to)
            if refused:
                log.warning("SMTP %s rechazó %d destinatario(s) de la alerta", where, len(refused))
            if extra is not None:
                msg, rcpts = extra
                try:
                    refused = smtp.send_message(msg, from_addr=self._from_addr, to_addrs=rcpts)
                    if refused:
                        log.warning("SMTP %s rechazó %d destinatario(s) del aviso", where, len(refused))
                except (OSError, smtplib.SMTPException) as exc:
                    log.warning(
                        "no se pudo avisar al destinatario del mail (%s)", describe_exception(exc, secrets)
                    )
        except smtplib.SMTPAuthenticationError:
            raise AlertDeliveryError(
                f"SMTP {where}: usuario o contraseña rechazados", channel=self.name, retryable=False
            ) from None
        except (OSError, smtplib.SMTPException) as exc:
            raise AlertDeliveryError(
                f"SMTP {where}: {describe_exception(exc, secrets)}", channel=self.name
            ) from None
        finally:
            try:
                smtp.quit()
            except (OSError, smtplib.SMTPException):
                smtp.close()
