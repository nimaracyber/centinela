"""Estado persistente (cursores de conectores) y secretos (tokens OAuth) en la tabla `kv_state`.

Implementa `centinela.core.state.StateStore`.

- Valores comunes: texto plano (cursores: UID IMAP, historyId de Gmail, deltaLink de Graph...).
- Secretos: cifrados con Fernet usando `Settings.encryption_key`. Sin clave configurada, Centinela
  SE NIEGA a guardar secretos (nunca quedan en claro en la base). Admite rotación de clave:
  `encryption_key: "NUEVA,VIEJA"` cifra con la primera y descifra con cualquiera.
- Los secretos viven en un espacio de nombres separado (`secret:<clave>`), igual que en
  `MemoryStateStore`: `get()` nunca devuelve un secreto y `get_secret()` nunca un valor común.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

import sqlalchemy as sa
from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine

from centinela.core.models import utcnow
from centinela.storage.db import kv_state

if TYPE_CHECKING:
    from centinela.core.config import Settings

log = logging.getLogger(__name__)

SECRET_PREFIX = "secret:"  # noqa: S105 - prefijo de clave, no una contraseña
MAX_KEY_LEN = 400
MAX_VALUE_LEN = 1_000_000

MSG_NO_KEY = (
    "No hay clave de cifrado configurada (encryption_key / CENTINELA_ENCRYPTION_KEY). Centinela no guarda "
    "credenciales sin cifrar: generá una clave con `centinela gen-key`, agregala al archivo .env y reiniciá."
)
MSG_BAD_KEY = (
    "La encryption_key configurada no es válida: tiene que ser una clave Fernet (44 caracteres en base64). "
    "Generá una nueva con `centinela gen-key`."
)


class SecretStoreError(RuntimeError):
    """Error al guardar o leer un secreto (falta la clave, clave inválida o dato que no se puede descifrar)."""


def _build_fernet(key: str | None) -> tuple[MultiFernet | None, str | None]:
    if not key or not key.strip():
        return None, MSG_NO_KEY
    try:
        keys = [Fernet(k.strip().encode()) for k in key.split(",") if k.strip()]
    except (ValueError, TypeError):
        return None, MSG_BAD_KEY
    if not keys:
        return None, MSG_NO_KEY
    return MultiFernet(keys), None


class DbStateStore:
    """`DbStateStore(store_o_engine, settings)`: comparte el engine del `SqlResultStore`."""

    def __init__(
        self, source: Any, settings: Settings | None = None, *, encryption_key: str | None = None
    ) -> None:
        engine = source if isinstance(source, AsyncEngine) else getattr(source, "engine", None)
        if not isinstance(engine, AsyncEngine):
            raise TypeError("DbStateStore necesita un SqlResultStore o un AsyncEngine")
        self.engine: AsyncEngine = engine
        if encryption_key is None and settings is not None and settings.encryption_key is not None:
            encryption_key = settings.encryption_key.get_secret_value()
        self._fernet, self._key_problem = _build_fernet(encryption_key)
        if self._key_problem == MSG_BAD_KEY:
            log.error(MSG_BAD_KEY)
        self._ready = False
        self._ready_lock = asyncio.Lock()

    @property
    def can_store_secrets(self) -> bool:
        return self._fernet is not None

    @property
    def key_problem(self) -> str | None:
        """Por qué no se pueden guardar secretos (mensaje en español para el usuario), o None si se puede."""
        return self._key_problem

    async def init(self) -> None:
        """Crea la tabla kv_state si hace falta (si ya corrió SqlResultStore.init() no hace nada)."""
        if self._ready:
            return
        async with self._ready_lock:
            if self._ready:
                return
            async with self.engine.begin() as conn:
                await conn.run_sync(lambda c: kv_state.create(c, checkfirst=True))
            self._ready = True

    # ------------------------------------------------------------- helpers

    @staticmethod
    def _check_key(key: str) -> None:
        if not isinstance(key, str) or not key:
            raise ValueError("la clave de estado no puede estar vacía")
        if len(key) > MAX_KEY_LEN:
            raise ValueError(f"clave de estado demasiado larga ({len(key)} > {MAX_KEY_LEN})")

    @staticmethod
    def _check_plain_key(key: str) -> None:
        DbStateStore._check_key(key)
        if key.startswith(SECRET_PREFIX):
            raise ValueError(f"las claves que empiezan con '{SECRET_PREFIX}' están reservadas para secretos")

    async def _read(self, db_key: str, is_secret: bool) -> str | None:
        await self.init()
        async with self.engine.connect() as conn:
            row = (
                await conn.execute(
                    sa.select(kv_state.c.value, kv_state.c.is_secret).where(kv_state.c.key == db_key)
                )
            ).first()
        if row is None or bool(row.is_secret) != is_secret:
            return None
        return row.value

    async def _write(self, db_key: str, value: str, is_secret: bool) -> None:
        if len(value) > MAX_VALUE_LEN:
            raise ValueError(f"valor de estado demasiado grande ({len(value)} caracteres)")
        await self.init()
        values = {"value": value, "is_secret": is_secret, "updated_at": utcnow()}
        dialect = self.engine.dialect.name
        for attempt in range(3):
            try:
                async with self.engine.begin() as conn:
                    if dialect in {"sqlite", "postgresql"}:
                        if dialect == "sqlite":
                            from sqlalchemy.dialects.sqlite import insert as dialect_insert
                        else:
                            from sqlalchemy.dialects.postgresql import insert as dialect_insert
                        stmt = dialect_insert(kv_state).values(key=db_key, **values)
                        stmt = stmt.on_conflict_do_update(index_elements=[kv_state.c.key], set_=values)
                        await conn.execute(stmt)
                    else:  # genérico: UPDATE y si no existía INSERT
                        res = await conn.execute(
                            kv_state.update().where(kv_state.c.key == db_key).values(**values)
                        )
                        if not res.rowcount:
                            await conn.execute(kv_state.insert().values(key=db_key, **values))
                return
            except IntegrityError:
                if attempt == 2:
                    raise
                await asyncio.sleep(0.05)
            except sa.exc.OperationalError as exc:
                if "locked" not in str(exc).lower() or attempt == 2:
                    raise
                await asyncio.sleep(0.1 * (attempt + 1))

    # ------------------------------------------------------------- StateStore

    async def get(self, key: str) -> str | None:
        self._check_plain_key(key)
        return await self._read(key, is_secret=False)

    async def set(self, key: str, value: str) -> None:
        self._check_plain_key(key)
        await self._write(key, str(value), is_secret=False)

    async def delete(self, key: str) -> None:
        """Borra el valor común y el secreto con ese nombre (igual que MemoryStateStore)."""
        self._check_key(key)
        await self.init()
        async with self.engine.begin() as conn:
            await conn.execute(kv_state.delete().where(kv_state.c.key.in_([key, SECRET_PREFIX + key])))

    async def get_secret(self, key: str) -> str | None:
        self._check_key(key)
        token = await self._read(SECRET_PREFIX + key, is_secret=True)
        if token is None:
            return None
        if self._fernet is None:
            raise SecretStoreError(f"No se puede leer el secreto '{key}': {self._key_problem}")
        try:
            return self._fernet.decrypt(token.encode("ascii")).decode("utf-8")
        except (InvalidToken, UnicodeError, ValueError) as exc:
            raise SecretStoreError(
                f"No se pudo descifrar el secreto '{key}': la encryption_key cambió o el dato está dañado. "
                "Si cambiaste la clave, configurá 'NUEVA,VIEJA' o volvé a autorizar el conector con "
                "`centinela auth <conector>`."
            ) from exc

    async def set_secret(self, key: str, value: str) -> None:
        self._check_key(key)
        if self._fernet is None:
            raise SecretStoreError(f"No se puede guardar el secreto '{key}': {self._key_problem}")
        token = self._fernet.encrypt(str(value).encode("utf-8")).decode("ascii")
        await self._write(SECRET_PREFIX + key, token, is_secret=True)


__all__ = ["DbStateStore", "SecretStoreError"]
