from __future__ import annotations

import pytest
import sqlalchemy as sa
from cryptography.fernet import Fernet
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import create_async_engine

from centinela.core.state import StateStore
from centinela.storage.db import SqlResultStore, kv_state
from centinela.storage.state import MSG_BAD_KEY, DbStateStore, SecretStoreError

REFRESH_TOKEN = "1//0gFakeRefreshTokenForTestsOnly-abcdefghijklmnop"


@pytest.fixture
async def store(settings):
    s = SqlResultStore(settings)
    await s.init()
    yield s
    await s.close()


async def _rows(store) -> dict[str, tuple[str, bool]]:
    async with store.engine.connect() as conn:
        rows = (await conn.execute(sa.select(kv_state.c.key, kv_state.c.value, kv_state.c.is_secret))).all()
    return {k: (v, bool(s)) for k, v, s in rows}


async def test_plain_values_without_key(settings, store):
    state = DbStateStore(store, settings)
    assert isinstance(state, StateStore)
    assert state.can_store_secrets is False
    assert await state.get("connector:imap1:uid") is None
    await state.set("connector:imap1:uid", "100")
    await state.set("connector:imap1:uid", "101")  # upsert
    assert await state.get("connector:imap1:uid") == "101"
    await state.delete("connector:imap1:uid")
    assert await state.get("connector:imap1:uid") is None
    await state.delete("no-existe")  # no rompe


async def test_key_problem_explains_why_secrets_cannot_be_stored(settings, store):
    assert "gen-key" in DbStateStore(store, settings).key_problem
    assert DbStateStore(store, settings, encryption_key="no-es-fernet").key_problem == MSG_BAD_KEY
    ok = DbStateStore(store, settings, encryption_key=Fernet.generate_key().decode())
    assert ok.key_problem is None and ok.can_store_secrets


async def test_refuses_to_store_secrets_without_key(settings, store):
    state = DbStateStore(store, settings)
    with pytest.raises(SecretStoreError, match="encryption_key") as exc:
        await state.set_secret("gmail:refresh_token", REFRESH_TOKEN)
    assert "gen-key" in str(exc.value)
    assert REFRESH_TOKEN not in str(exc.value)
    assert await _rows(store) == {}  # nada en claro en la base
    assert await state.get_secret("gmail:refresh_token") is None  # no hay nada guardado: None, sin error


async def test_secret_roundtrip_is_encrypted_at_rest(settings, store):
    settings.encryption_key = SecretStr(Fernet.generate_key().decode())
    state = DbStateStore(store, settings)
    assert state.can_store_secrets
    await state.set_secret("gmail:refresh_token", REFRESH_TOKEN)
    assert await state.get_secret("gmail:refresh_token") == REFRESH_TOKEN
    rows = await _rows(store)
    ((db_key, (value, is_secret)),) = rows.items()
    assert db_key == "secret:gmail:refresh_token" and is_secret is True
    assert REFRESH_TOKEN not in value and "refresh" not in value
    # los espacios de nombres no se mezclan (igual que MemoryStateStore)
    assert await state.get("gmail:refresh_token") is None
    await state.set("gmail:refresh_token", "cursor-no-secreto")
    assert await state.get("gmail:refresh_token") == "cursor-no-secreto"
    assert await state.get_secret("gmail:refresh_token") == REFRESH_TOKEN
    await state.set_secret("gmail:refresh_token", "rotado")
    assert await state.get_secret("gmail:refresh_token") == "rotado"
    await state.delete("gmail:refresh_token")  # borra ambos
    assert await state.get("gmail:refresh_token") is None
    assert await state.get_secret("gmail:refresh_token") is None


async def test_persists_across_instances_and_key_rotation(settings, store):
    old_key, new_key = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    await DbStateStore(store, encryption_key=old_key).set_secret("graph:token", "s3cr3t")
    # otro proceso, misma clave
    assert await DbStateStore(store, encryption_key=old_key).get_secret("graph:token") == "s3cr3t"
    # clave cambiada sin rotación: error claro (no devuelve basura ni None silencioso)
    with pytest.raises(SecretStoreError, match="descifrar"):
        await DbStateStore(store, encryption_key=new_key).get_secret("graph:token")
    # rotación "NUEVA,VIEJA": descifra lo viejo, cifra con la nueva
    rotated = DbStateStore(store, encryption_key=f"{new_key},{old_key}")
    assert await rotated.get_secret("graph:token") == "s3cr3t"
    await rotated.set_secret("graph:token", "s3cr3t-2")
    assert await DbStateStore(store, encryption_key=new_key).get_secret("graph:token") == "s3cr3t-2"
    # sin clave no se puede leer un secreto existente
    with pytest.raises(SecretStoreError, match="encryption_key"):
        await DbStateStore(store, settings).get_secret("graph:token")


async def test_invalid_key_is_reported(store):
    state = DbStateStore(store, encryption_key="no-es-una-clave-fernet")
    assert state.can_store_secrets is False
    with pytest.raises(SecretStoreError) as exc:
        await state.set_secret("x", "y")
    assert MSG_BAD_KEY in str(exc.value)
    await state.set("x", "plain ok")  # el estado común sigue funcionando
    assert await state.get("x") == "plain ok"


async def test_tampered_ciphertext_raises(store):
    key = Fernet.generate_key().decode()
    state = DbStateStore(store, encryption_key=key)
    await state.set_secret("t", "valor")
    async with store.engine.begin() as conn:
        await conn.execute(kv_state.update().where(kv_state.c.key == "secret:t").values(value="gAAAAAbasura"))
    with pytest.raises(SecretStoreError):
        await state.get_secret("t")


async def test_key_validation(store):
    state = DbStateStore(store, encryption_key=Fernet.generate_key().decode())
    with pytest.raises(ValueError):
        await state.set("", "x")
    with pytest.raises(ValueError):
        await state.set("k" * 1000, "x")
    with pytest.raises(ValueError):
        await state.set("secret:tramposo", "x")  # prefijo reservado
    with pytest.raises(ValueError):
        await state.get("secret:tramposo")
    with pytest.raises(ValueError):
        await state.set("grande", "x" * 2_000_000)
    long_value = "https://graph.microsoft.com/v1.0/delta?$deltatoken=" + "A" * 5000
    await state.set("connector:graph:delta", long_value)
    assert await state.get("connector:graph:delta") == long_value


async def test_works_with_bare_engine(tmp_path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{(tmp_path / 's.db').as_posix()}")
    state = DbStateStore(engine, encryption_key=Fernet.generate_key().decode())
    await state.set("a", "1")  # crea kv_state sola si hace falta
    await state.set_secret("b", "2")
    assert await state.get("a") == "1" and await state.get_secret("b") == "2"
    await engine.dispose()
    with pytest.raises(TypeError):
        DbStateStore(object())
