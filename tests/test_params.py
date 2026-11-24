"""Валідація CipherParams та схем доповнення."""
import pytest

from aeslab.errors import BadPadding, InvalidParams, KeyLength, UnsupportedMode
from aeslab.modes import resolve_params
from aeslab.params import PADDINGS, CipherParams


def test_defaults():
    p = resolve_params(CipherParams(mode="gcm"))
    assert (p.mode, p.iv_len, p.tag_len, p.padding, p.block_size) == ("aes-gcm", 12, 16, "none", 128)
    p = resolve_params(CipherParams(mode="cbc"))
    assert (p.iv_len, p.tag_len, p.padding) == (16, 32, "pkcs7")


@pytest.mark.parametrize("kw,exc", [
    (dict(mode="gcm", block_size=256), InvalidParams),
    (dict(mode="gcm", iv_len=8), InvalidParams),
    (dict(mode="gcm", tag_len=8), InvalidParams),
    (dict(mode="gcm", padding="pkcs7"), InvalidParams),
    (dict(mode="cbc", padding="zero"), InvalidParams),
    (dict(mode="cbc", tag_len=8), InvalidParams),
    (dict(mode="ctr", iv_len=12), InvalidParams),
    (dict(mode="gcm", key_bits=512), KeyLength),
    (dict(mode="chacha", key_bits=128), KeyLength),
    (dict(mode="ecb"), UnsupportedMode),
])
def test_invalid(kw, exc):
    with pytest.raises(exc):
        resolve_params(CipherParams(**kw))


@pytest.mark.parametrize("name", list(PADDINGS))
@pytest.mark.parametrize("n", range(0, 33))
def test_padding_roundtrip(name, n):
    pad = PADDINGS[name]
    data = bytes(range(n))
    padded = data + pad.pad_bytes(n)
    assert len(padded) % 16 == 0 and len(padded) > n
    assert padded[:-16] + pad.unpad(padded[-16:]) == data


@pytest.mark.parametrize("name,block", [("pkcs7", b"A" * 15 + b"\x00"), ("pkcs7", b"A" * 14 + b"\x01\x02"),
                                        ("ansix923", b"A" * 13 + b"\x01\x00\x03"), ("iso7816", b"A" * 16),
                                        ("pkcs7", b"A" * 15 + b"\x11")])
def test_bad_padding(name, block):
    with pytest.raises(BadPadding):
        PADDINGS[name].unpad(block)


def test_repl_param_setter():
    p = CipherParams(mode="cbc").set_from_text("padding", "ISO7816").set_from_text("tag-len", "16")
    assert resolve_params(p).padding == "iso7816" and p.tag_len == 16
    with pytest.raises(InvalidParams):
        p.set_from_text("tag_len", "abc")
    with pytest.raises(InvalidParams):
        p.set_from_text("unknown", "1")
