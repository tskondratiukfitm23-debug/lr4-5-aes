"""Життєвий цикл ключів: KDF, політики, повторне використання, статуси, ліміти, сховище."""
import json
import os
import stat
from datetime import timedelta

import pytest

from aeslab import config
from aeslab.engine import decrypt_file, encrypt_file
from aeslab.errors import (InvalidParams, KeyExhausted, KeyExpired, KeyLength, KeyRetired, KeyReuse, KeyRevoked,
                           NonceLimit, NonceReuse, WeakPassword, WrongPassword)
from aeslab.keystore import check_password_policy, iso, utcnow
from aeslab.modes import REGISTRY
from aeslab.params import CipherParams
from tests.conftest import FAST, PW, PW2


def test_keystore_has_no_secrets_and_0600(ks, ctx):
    raw = open(ks.path, encoding="utf-8").read()
    assert PW not in raw
    e = json.loads(raw)["keys"][0]
    assert set(e) >= {"salt", "verifier", "kdf", "key_id", "status", "expires_at", "max_uses", "uses"}
    assert len(bytes.fromhex(e["salt"])) >= 16
    assert e["kdf"]["iterations"] == FAST
    if os.name == "posix":
        assert stat.S_IMODE(os.stat(ks.path).st_mode) == 0o600


def test_default_iterations_policy():
    assert config.PBKDF2_ITERATIONS >= 310_000


def test_min_iterations_enforced(tmp_path):
    from aeslab.keystore import KeyStore
    with pytest.raises(InvalidParams):
        KeyStore(str(tmp_path / "k.json")).create("x", PW, iterations=1000)


def test_scrypt_kdf(ks):
    e = ks.create("s", PW, kdf="scrypt")
    assert ks.unlock(e, PW).key_id == e["key_id"]


def test_wrong_password_detected_before_decrypt(ks, ctx):
    with pytest.raises(WrongPassword):
        ks.unlock(ctx.entry, PW + "x")


@pytest.mark.parametrize("pw", ["short1!A", "alllowercaseletters", "Password123!!", "abcdefghijkl1"])
def test_weak_passwords(pw):
    with pytest.raises(WeakPassword):
        check_password_policy(pw)


def test_duplicate_label_and_password_reuse(ks, ctx):
    with pytest.raises(KeyReuse):
        ks.create("test", PW2, iterations=FAST)
    with pytest.raises(KeyReuse):
        ks.create("another", PW, iterations=FAST)        # той самий пароль вже використовується


def test_same_password_different_salt_gives_different_keys(ks):
    a = ks.create("a", PW, iterations=FAST, check_password_reuse=False)
    b = ks.create("b", PW, iterations=FAST, check_password_reuse=False)
    assert a["salt"] != b["salt"] and a["key_id"] != b["key_id"]


def test_key_separation_per_mode(ctx):
    k1 = ctx.derive("aes-gcm", 256).enc_key
    k2 = ctx.derive("aes-ctr-hmac", 256).enc_key
    k3 = ctx.derive("aes-gcm", 128).enc_key
    assert len({k1, k2, k3[:32]}) == 3 and len(k3) == 16
    keys = ctx.derive("aes-cbc-hmac", 192)
    assert len(keys.enc_key) == 24 and len(keys.mac_key) == 32 and keys.enc_key != keys.mac_key[:24]


def test_invalid_key_length(ks, ctx):
    with pytest.raises(KeyLength):
        ctx.derive("aes-gcm", 512)
    with pytest.raises(KeyLength):
        ctx.derive("chacha20-poly1305", 128)
    with pytest.raises(KeyLength):
        ks.create("bad", PW2, iterations=FAST, key_bits=160)


def test_max_uses(ks, tmp_path, make_file, logger):
    e = ks.create("lim", PW, iterations=FAST, max_uses=2)
    c = ks.unlock(e, PW)
    src = make_file(10)
    for i in range(2):
        encrypt_file(src, str(tmp_path / f"{i}.enc"), c, CipherParams(), ks=ks, logger=logger)
    with pytest.raises(KeyExhausted):
        encrypt_file(src, str(tmp_path / "x.enc"), c, CipherParams(), ks=ks, logger=logger)
    assert not (tmp_path / "x.enc").exists()


def test_gcm_nonce_limit(ks, ctx, tmp_path, make_file, logger, monkeypatch):
    monkeypatch.setattr(config, "GCM_RANDOM_NONCE_LIMIT", 1)
    src = make_file(10)
    encrypt_file(src, str(tmp_path / "1.enc"), ctx, CipherParams(), ks=ks, logger=logger)
    with pytest.raises(NonceLimit):
        encrypt_file(src, str(tmp_path / "2.enc"), ctx, CipherParams(), ks=ks, logger=logger)
    encrypt_file(src, str(tmp_path / "3.enc"), ctx, CipherParams(mode="cbc"), ks=ks, logger=logger)  # інші режими — ок


def test_nonce_reuse_detected(ks, ctx, tmp_path, make_file, logger, monkeypatch):
    mode = REGISTRY["aes-gcm"]
    monkeypatch.setattr(mode, "new_iv", lambda p: b"\x01" * 12)
    src = make_file(10)
    encrypt_file(src, str(tmp_path / "1.enc"), ctx, CipherParams(), ks=ks, logger=logger)
    with pytest.raises(NonceReuse):
        encrypt_file(src, str(tmp_path / "2.enc"), ctx, CipherParams(), ks=ks, logger=logger)


def test_expired_key(ks, ctx, tmp_path, make_file, logger):
    src, enc = make_file(10), str(tmp_path / "e.enc")
    encrypt_file(src, enc, ctx, CipherParams(), ks=ks, logger=logger)
    ctx.entry["expires_at"] = iso(utcnow() - timedelta(days=1))
    with pytest.raises(KeyExpired):
        encrypt_file(src, str(tmp_path / "x.enc"), ctx, CipherParams(), ks=ks, logger=logger)
    decrypt_file(enc, str(tmp_path / "e.dec"), ctx, ks=ks, logger=logger)    # дешифрування дозволене


def test_rotation_and_statuses(ks, ctx, tmp_path, make_file, logger):
    src, enc = make_file(100), str(tmp_path / "e.enc")
    encrypt_file(src, enc, ctx, CipherParams(), ks=ks, logger=logger)
    with pytest.raises(KeyReuse):
        ks.rotate("test", PW, PW)
    old, new = ks.rotate("test", PW, PW2, iterations=FAST)
    assert old["status"] == "retired" and old["rotated_to"] == new["key_id"] and new["rotated_from"] == old["key_id"]
    assert ks.find(label="test")["key_id"] == new["key_id"]
    with pytest.raises(KeyRetired):
        encrypt_file(src, str(tmp_path / "x.enc"), ctx, CipherParams(), ks=ks, logger=logger)
    decrypt_file(enc, str(tmp_path / "e.dec"), ctx, ks=ks, logger=logger)    # старі файли читаються
    ks.set_status(old, "revoked", "test")
    with pytest.raises(KeyRevoked):
        decrypt_file(enc, str(tmp_path / "e2.dec"), ctx, ks=ks, logger=logger)
    with pytest.raises(KeyRevoked):
        ks.set_status(old, "active")
    with pytest.raises(KeyRevoked):
        ks.unlock(old, PW)


def test_wipe(ctx):
    ctx.wipe()
    with pytest.raises(InvalidParams):
        ctx.derive("aes-gcm", 256)
