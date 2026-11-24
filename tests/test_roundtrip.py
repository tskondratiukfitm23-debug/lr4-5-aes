"""Round-trip для всіх режимів, довжин ключів, доповнень, розмірів і параметрів."""
import pytest

from aeslab import config
from aeslab.engine import decrypt_file, encrypt_file
from aeslab.modes import REGISTRY
from aeslab.params import CipherParams

SIZES = [0, 1, 15, 16, 17, 4096, 65536, 65537, 200_003]


def roundtrip(src, tmp_path, ctx, ks, logger, params, aad=None):
    enc, dec = str(tmp_path / "f.enc"), str(tmp_path / "f.dec")
    encrypt_file(src, enc, ctx, params, ks=ks, logger=logger)
    decrypt_file(enc, dec, ctx, aad=aad, ks=ks, logger=logger)
    assert open(dec, "rb").read() == open(src, "rb").read()
    return enc


@pytest.mark.parametrize("mode", list(REGISTRY))
@pytest.mark.parametrize("size", SIZES)
def test_all_modes_sizes(mode, size, tmp_path, ctx, ks, logger, make_file):
    roundtrip(make_file(size), tmp_path, ctx, ks, logger, CipherParams(mode=mode))


@pytest.mark.parametrize("mode", list(REGISTRY))
@pytest.mark.parametrize("bits", [128, 192, 256])
def test_key_lengths(mode, bits, tmp_path, ctx, ks, logger, make_file):
    if bits not in REGISTRY[mode].spec.key_bits:
        pytest.skip("довжина не підтримується режимом")
    roundtrip(make_file(1000), tmp_path, ctx, ks, logger, CipherParams(mode=mode, key_bits=bits))


@pytest.mark.parametrize("padding", ["pkcs7", "ansix923", "iso7816"])
@pytest.mark.parametrize("size", [0, 15, 16, 31, 1000])
def test_cbc_paddings(padding, size, tmp_path, ctx, ks, logger, make_file):
    roundtrip(make_file(size), tmp_path, ctx, ks, logger, CipherParams(mode="cbc", padding=padding))


@pytest.mark.parametrize("mode,tag", [("gcm", 12), ("gcm", 16), ("cbc", 16), ("ctr", 24), ("cfb", 32)])
def test_tag_lengths(mode, tag, tmp_path, ctx, ks, logger, make_file):
    enc = roundtrip(make_file(777), tmp_path, ctx, ks, logger, CipherParams(mode=mode, tag_len=tag))
    assert enc


def test_gcm_16_byte_nonce_and_aad(tmp_path, ctx, ks, logger, make_file):
    roundtrip(make_file(5000), tmp_path, ctx, ks, logger, CipherParams(mode="gcm", iv_len=16, aad=b"ctx"), aad=b"ctx")


def test_large_file_multi_chunk(tmp_path, ctx, ks, logger, make_file, monkeypatch):
    monkeypatch.setattr(config, "IO_CHUNK", 64 * 1024)   # багато ітерацій потокової обробки
    src = make_file(5 * 1024 * 1024 + 123)
    for mode in REGISTRY:
        roundtrip(src, tmp_path, ctx, ks, logger, CipherParams(mode=mode))


def test_ciphertexts_differ_each_time(tmp_path, ctx, ks, logger, make_file):
    src = make_file(100)
    a, b = str(tmp_path / "a"), str(tmp_path / "b")
    encrypt_file(src, a, ctx, CipherParams(), ks=ks, logger=logger)
    encrypt_file(src, b, ctx, CipherParams(), ks=ks, logger=logger)
    assert open(a, "rb").read() != open(b, "rb").read()   # новий nonce щоразу
