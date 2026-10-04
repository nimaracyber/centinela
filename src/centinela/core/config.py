"""Configuración de Centinela: un único YAML (config.yaml) con interpolación de variables de entorno.

Los secretos NUNCA van en el YAML en claro: se escriben como ${VARIABLE} y se leen del entorno
(o de un archivo `.env` que docker compose inyecta). Ver config.example.yaml.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Annotated, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

_ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)(?::-([^}]*))?\}")


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="before")
    @classmethod
    def _blank_to_none(cls, data: object) -> object:
        """`${VAR:-}` vacío en un campo opcional (secretos, rutas) => None, no string vacío."""
        if not isinstance(data, dict):
            return data
        out = dict(data)
        for name, field in cls.model_fields.items():
            if out.get(name) == "" and not field.is_required() and field.default is None:
                out[name] = None
        return out


# --------------------------------------------------------------------------- general


class GeneralConfig(_Base):
    company_name: str = "Mi Empresa"
    company_domains: list[str] = Field(
        default_factory=list
    )  # dominios propios: para detectar suplantación y lookalikes
    # dominios de socios/proveedores/ESP de confianza: se excluyen de heurísticas DÉBILES de links y remitente
    # (nunca de firmas de malware ni de reputación)
    trusted_domains: list[str] = Field(default_factory=list)
    # authserv-id de los Authentication-Results confiables (los que agrega TU proveedor, ej: "mx.google.com",
    # "*.prod.outlook.com"). Vacío = se confía en el Authentication-Results de más arriba.
    trusted_authserv_ids: list[str] = Field(default_factory=list)
    data_dir: Path = Path("/data")
    timezone: str = "America/Argentina/Buenos_Aires"
    log_level: str = "INFO"
    log_json: bool = True
    retention_days: int = 180  # resultados más viejos se purgan automáticamente


class LimitsConfig(_Base):
    """Límites defensivos: Centinela procesa archivos hostiles."""

    max_message_bytes: int = 60 * 1024 * 1024
    max_artifact_bytes: int = 50 * 1024 * 1024
    max_total_extracted_bytes: int = 300 * 1024 * 1024  # anti zip-bomb
    max_archive_depth: int = 4
    max_artifacts: int = 500
    max_compression_ratio: int = 200  # ratio descomprimido/comprimido por entrada
    analyzer_timeout_s: float = 60.0
    message_timeout_s: float = 240.0
    archive_passwords: list[str] = Field(
        default_factory=lambda: ["infected", "malware", "virus", "1234", "123456", "password"]
    )
    # RAR comprimido/cifrado requiere una herramienta externa (unar/unrar) sobre un archivo temporal privado.
    # Si es False, los .rar solo se listan (nombres y tamaños) sin extraer.
    allow_external_unrar: bool = True


class PrivacyConfig(_Base):
    """Qué puede salir de la red de la empresa. Por diseño, los ARCHIVOS nunca salen."""

    hash_lookups: bool = True  # consultar SHA-256 en MalwareBazaar / VirusTotal
    url_lookups: bool = False  # consultar URLs en URLhaus (las URLs pueden contener tokens personales)
    store_bodies: bool = False  # guardar cuerpo del mail en la base (por defecto solo metadatos)


# --------------------------------------------------------------------------- conectores


class ConnectorBase(_Base):
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,62}$")
    enabled: bool = True
    tag: bool = True  # si False, este conector nunca modifica el buzón (solo alertas)


class ImapOAuth2Config(_Base):
    """XOAUTH2 para IMAP (Outlook.com personal, Gmail sin API, etc.)."""

    provider: Literal["microsoft", "google"]
    client_id: str
    client_secret: SecretStr | None = None  # obligatorio para google
    tenant: str = "consumers"  # microsoft: "consumers" | "organizations" | <tenant-id>
    # el refresh token se obtiene con `centinela auth <conector>` y se guarda cifrado en el state store

    @model_validator(mode="after")
    def _google_secret(self) -> ImapOAuth2Config:
        if self.provider == "google" and not self.client_secret:
            raise ValueError("oauth2 con provider google requiere client_secret")
        return self


class ImapConnectorConfig(ConnectorBase):
    """IMAP genérico: Yahoo, iCloud, Zoho, webmail de hosting (cPanel/Plesk), Dovecot propio, Outlook.com..."""

    type: Literal["imap"]
    host: str
    port: int = 993
    security: Literal["ssl", "starttls"] = "ssl"
    username: str
    password: SecretStr | None = None  # app password (Yahoo/iCloud/Gmail exigen app password)
    oauth2: ImapOAuth2Config | None = None
    folders: list[str] = Field(default_factory=lambda: ["INBOX"])
    idle: bool = True  # IMAP IDLE = tiempo real; si el server no lo soporta cae a polling
    poll_interval_s: int = 60
    backfill_hours: int = 0  # al arrancar por primera vez, analizar también los mails de las últimas N horas
    tag_mode: Literal["keyword", "none"] = (
        "keyword"  # keyword IMAP ($Centinela_Malicious) visible en Thunderbird y otros
    )

    @model_validator(mode="after")
    def _auth(self) -> ImapConnectorConfig:
        if not self.password and not self.oauth2:
            raise ValueError(f"conector imap '{self.name}': falta password u oauth2")
        return self


class GmailConnectorConfig(ConnectorBase):
    """Gmail / Google Workspace vía Gmail API.

    - Workspace: cuenta de servicio con delegación de dominio -> todos los buzones listados en `mailboxes`.
    - Gmail personal: OAuth de usuario (`centinela auth gmail <conector>`), un buzón.
    """

    type: Literal["gmail"]
    auth: Literal["service_account", "oauth_user"] = "service_account"
    service_account_file: Path | None = None
    oauth_client_file: Path | None = None
    mailboxes: list[str] = Field(default_factory=list)  # vacío + service_account = error
    # Tiempo real opcional vía Cloud Pub/Sub (pull: no requiere URL pública). Sin esto: polling de history.
    pubsub_topic: str | None = None  # projects/<p>/topics/<t>  (destino de users.watch)
    pubsub_subscription: str | None = None  # projects/<p>/subscriptions/<s>  (de donde se hace pull)
    poll_interval_s: int = 20
    label_query: str = "in:inbox OR in:spam"  # qué mails mirar
    backfill_hours: int = 0


class GraphConnectorConfig(ConnectorBase):
    """Microsoft 365 / Exchange Online vía Microsoft Graph (app registration, client credentials)."""

    type: Literal["graph"]
    tenant_id: str
    client_id: str
    client_secret: SecretStr | None = None
    certificate_file: Path | None = None
    mailboxes: list[str] = Field(default_factory=list)
    folders: list[str] = Field(default_factory=lambda: ["inbox", "junkemail"])
    poll_interval_s: int = 20  # delta query; no requiere exponer ninguna URL pública
    backfill_hours: int = 0


class MilterConnectorConfig(ConnectorBase):
    """Gateway: Postfix/Sendmail llaman a Centinela por el protocolo milter. Pasivo: SIEMPRE acepta el mail."""

    type: Literal["milter"]
    listen_host: str = "0.0.0.0"  # noqa: S104 - dentro del contenedor
    listen_port: int = 8899
    inline_timeout_s: float = (
        15.0  # espera máxima para poder agregar headers; si se pasa, acepta sin tocar y alerta después
    )
    add_headers: bool = True  # X-Centinela-Verdict / X-Centinela-Score
    subject_prefix: str | None = None  # ej: "[SOSPECHOSO] " ; None = no tocar el asunto


class SmtpJournalConnectorConfig(ConnectorBase):
    """Recibe COPIAS de los mails (BCC/journaling/reenvío automático). Funciona con cualquier proveedor
    que permita reenviar una copia. No puede etiquetar el original: solo alerta."""

    type: Literal["smtp_journal"]
    listen_host: str = "0.0.0.0"  # noqa: S104
    listen_port: int = 2525
    allowed_senders: list[str] = Field(default_factory=list)  # IPs/CIDR autorizadas a entregar copias
    require_tls: bool = False
    tls_cert_file: Path | None = None
    tls_key_file: Path | None = None
    unwrap_journal: bool = (
        True  # desenvolver reportes de journaling de Exchange (mail adjunto como message/rfc822)
    )
    tag: bool = False

    @model_validator(mode="after")
    def _check(self) -> SmtpJournalConnectorConfig:
        import ipaddress

        for entry in self.allowed_senders:
            try:
                ipaddress.ip_network(entry, strict=False)
            except ValueError as exc:
                raise ValueError(
                    f"smtp_journal '{self.name}': allowed_senders inválido '{entry}' (usar IP o CIDR)"
                ) from exc
        if bool(self.tls_cert_file) != bool(self.tls_key_file):
            raise ValueError(f"smtp_journal '{self.name}': tls_cert_file y tls_key_file van juntos")
        if self.require_tls and not self.tls_cert_file:
            raise ValueError(f"smtp_journal '{self.name}': require_tls necesita tls_cert_file y tls_key_file")
        return self


class DirectoryConnectorConfig(ConnectorBase):
    """Vigila una carpeta y analiza los .eml que aparecen (integraciones caseras, tests, exportes)."""

    type: Literal["directory"]
    path: Path
    poll_interval_s: int = 5
    tag: bool = False


ConnectorConfig = Annotated[
    ImapConnectorConfig
    | GmailConnectorConfig
    | GraphConnectorConfig
    | MilterConnectorConfig
    | SmtpJournalConnectorConfig
    | DirectoryConnectorConfig,
    Field(discriminator="type"),
]


# --------------------------------------------------------------------------- analizadores


class ClamAVConfig(_Base):
    enabled: bool = True
    host: str = "clamav"
    port: int = 3310
    timeout_s: float = 30.0
    max_stream_bytes: int = 25 * 1024 * 1024  # igual o menor que StreamMaxLength de clamd


class YaraConfig(_Base):
    enabled: bool = True
    rules_dirs: list[Path] = Field(default_factory=lambda: [Path("rules/yara")])
    timeout_s: int = 30


class ReputationConfig(_Base):
    enabled: bool = True
    malwarebazaar_api_key: SecretStr | None = None  # abuse.ch Auth-Key (gratis)
    virustotal_api_key: SecretStr | None = None  # gratis = 4 req/min, 500/día
    urlhaus_api_key: SecretStr | None = None
    cache_ttl_hours: int = 24  # resultados positivos (hash malicioso)
    negative_cache_ttl_hours: int = 6  # "hash desconocido": más corto para enganchar campañas nuevas
    virustotal_requests_per_minute: int = 4  # cuota gratuita; subir con una API key premium
    timeout_s: float = 10.0


class AnalyzersConfig(_Base):
    clamav: ClamAVConfig = Field(default_factory=ClamAVConfig)
    yara: YaraConfig = Field(default_factory=YaraConfig)
    reputation: ReputationConfig = Field(default_factory=ReputationConfig)
    disabled: list[str] = Field(default_factory=list)  # nombres de analizadores a desactivar
    extra_brands: list[str] = Field(default_factory=list)  # marcas propias del rubro a proteger de lookalikes


class ScoringConfig(_Base):
    suspicious_threshold: int = Field(default=30, ge=1, le=100)
    malicious_threshold: int = Field(default=70, ge=1, le=100)
    trusted_senders: list[str] = Field(
        default_factory=list
    )  # bajan el peso de heurísticas débiles, nunca de firmas
    rule_overrides: dict[str, int] = Field(default_factory=dict)  # rule id -> score (0 = silenciar regla)

    @model_validator(mode="after")
    def _order(self) -> ScoringConfig:
        if self.suspicious_threshold >= self.malicious_threshold:
            raise ValueError("suspicious_threshold debe ser menor que malicious_threshold")
        return self


# --------------------------------------------------------------------------- acciones


class TagConfig(_Base):
    enabled: bool = True
    min_level: Literal["suspicious", "malicious"] = "suspicious"
    label_suspicious: str = "Centinela/Sospechoso"
    label_malicious: str = "Centinela/Malicioso"


class AlertChannelBase(_Base):
    name: str
    enabled: bool = True
    min_level: Literal["suspicious", "malicious"] = "suspicious"


class EmailAlertConfig(AlertChannelBase):
    type: Literal["email"]
    smtp_host: str
    smtp_port: int = 587
    security: Literal["starttls", "ssl", "none"] = "starttls"
    username: str | None = None
    password: SecretStr | None = None
    from_addr: str
    to: list[str]
    notify_recipient: bool = False  # avisar también al destinatario del mail sospechoso
    ca_file: Path | None = None  # CA propia para relays SMTP internos


class TelegramAlertConfig(AlertChannelBase):
    type: Literal["telegram"]
    bot_token: SecretStr
    chat_id: str
    message_thread_id: int | None = None  # tema dentro de un grupo con "topics"


class WebhookAlertConfig(AlertChannelBase):
    """Webhook genérico (JSON) o con formato para Slack / Microsoft Teams / Discord / Google Chat."""

    type: Literal["webhook"]
    url: SecretStr
    format: Literal["json", "slack", "teams", "discord", "google_chat"] = "json"
    hmac_secret: SecretStr | None = None  # firma X-Centinela-Signature (solo format=json)


class SyslogAlertConfig(AlertChannelBase):
    """Para SIEM/Wazuh: CEF sobre syslog UDP/TCP."""

    type: Literal["syslog"]
    host: str
    port: int = 514
    protocol: Literal["udp", "tcp"] = "udp"


AlertChannelConfig = Annotated[
    EmailAlertConfig | TelegramAlertConfig | WebhookAlertConfig | SyslogAlertConfig,
    Field(discriminator="type"),
]


class AlertsConfig(_Base):
    dashboard_base_url: str | None = None  # para incluir link al detalle en las alertas
    channels: list[AlertChannelConfig] = Field(default_factory=list)
    dedup_window_minutes: int = 60  # no repetir alerta por el mismo hash/campaña dentro de la ventana


class ActionsConfig(_Base):
    tag: TagConfig = Field(default_factory=TagConfig)
    alerts: AlertsConfig = Field(default_factory=AlertsConfig)


# --------------------------------------------------------------------------- infraestructura


class DashboardConfig(_Base):
    enabled: bool = True
    host: str = "0.0.0.0"  # noqa: S104
    port: int = 8080
    admin_user: str = "admin"
    admin_password_hash: SecretStr | None = None  # argon2; generar con `centinela hash-password`
    secret_key: SecretStr | None = None  # firma de cookies de sesión; obligatorio si enabled
    session_hours: int = 12
    trusted_proxies: list[str] = Field(default_factory=list)


class Settings(_Base):
    general: GeneralConfig = Field(default_factory=GeneralConfig)
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    privacy: PrivacyConfig = Field(default_factory=PrivacyConfig)
    database_url: str = "sqlite+aiosqlite:///data/centinela.db"
    redis_url: str | None = None  # None/"" => cola en memoria (modo todo-en-uno, sin Redis)
    encryption_key: SecretStr | None = None  # Fernet; cifra tokens OAuth en el state store
    connectors: list[ConnectorConfig] = Field(default_factory=list)
    analyzers: AnalyzersConfig = Field(default_factory=AnalyzersConfig)
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)
    actions: ActionsConfig = Field(default_factory=ActionsConfig)
    dashboard: DashboardConfig = Field(default_factory=DashboardConfig)

    @field_validator("redis_url")
    @classmethod
    def _empty_redis(cls, v: str | None) -> str | None:
        return v or None

    @model_validator(mode="after")
    def _unique_names(self) -> Settings:
        names = [c.name for c in self.connectors]
        dupes = {n for n in names if names.count(n) > 1}
        if dupes:
            raise ValueError(f"nombres de conector repetidos: {sorted(dupes)}")
        return self

    def connector(self, name: str) -> ConnectorConfig:
        for c in self.connectors:
            if c.name == name:
                return c
        raise KeyError(name)


def _interpolate(value: object, env: dict[str, str]) -> object:
    if isinstance(value, str):

        def repl(m: re.Match[str]) -> str:
            var, default = m.group(1), m.group(2)
            if var in env:
                return env[var]
            if default is not None:
                return default
            raise ValueError(f"variable de entorno no definida: {var}")

        return _ENV_RE.sub(repl, value)
    if isinstance(value, list):
        return [_interpolate(v, env) for v in value]
    if isinstance(value, dict):
        return {k: _interpolate(v, env) for k, v in value.items()}
    return value


def load_settings(path: str | Path | None = None, env: dict[str, str] | None = None) -> Settings:
    """Carga config.yaml (ruta explícita, $CENTINELA_CONFIG o ./config.yaml). Sin archivo => defaults."""
    env = dict(os.environ) if env is None else env
    path = Path(path or env.get("CENTINELA_CONFIG", "config.yaml"))
    data: dict = {}
    if path.exists():
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return Settings.model_validate(_interpolate(data, env))
