"""Виявлення підміни, класифікація помилок і атомарність (немає вихідного файлу при невдачі)."""
import json
import os
import struct

import pytest

from aeslab.engine import RawKeyContext, decrypt_file, encrypt_file
from aeslab.errors import (AuthFailed, BadFormat, BadMagic, KeyMismatch, TamperDetected, Truncated)
from aeslab.modes import REGISTRY, get_mode
from aeslab.params import CipherParams


@pytest.fixture
def encrypted(tmp_path, ctx, ks, logger, make_file):
    def _enc(mode, size=10_000, aad=b"aad"):
        enc = str(tmp_path / f"{mode}.enc")
        encrypt_file(make_file(size), enc, ctx, CipherParams(mode=mode, aad=aad, segment_size=4096
                     if get_mode(mode).spec.family == "aead-segmented" else None), ks=ks, logger=logger)
        return enc, open(enc, "rb").read()
    return _enc


def hdr_len(d):
    return 7 + struct.unpack(">H", d[5:7])[0]


def attempt(tmp_path, ctx, ks, logger, data, exc, aad=b"aad", c=None):
    bad, out = str(tmp_path / "bad.enc"), str(tmp_path / "out.dec")
    with open(bad, "wb") as f:
        f.write(data)
    with pytest.raises(exc):
        decrypt_file(bad, out, c or ctx, aad=aad, ks=ks, logger=logger)
    assert not os.path.exists(out), "неавтентифікований вихідний файл не має з'являтися"
    assert not [p for p in os.listdir(tmp_path) if p.endswith(".part")], "тимчасові файли мають видалятися"


def flip(d, i):
    b = bytearray(d)
    b[i] ^= 1
    return bytes(b)


@pytest.mark.parametrize("mode", list(REGISTRY))
def test_bitflip_body(mode, tmp_path, ctx, ks, logger, encrypted):
    _, d = encrypted(mode)
    attempt(tmp_path, ctx, ks, logger, flip(d, hdr_len(d) + 100), TamperDetected)


@pytest.mark.parametrize("mode", list(REGISTRY))
def test_tag_modified(mode, tmp_path, ctx, ks, logger, encrypted):
    _, d = encrypted(mode)
    attempt(tmp_path, ctx, ks, logger, flip(d, len(d) - 1), TamperDetected)


@pytest.mark.parametrize("mode", list(REGISTRY))
def test_header_modified(mode, tmp_path, ctx, ks, logger, encrypted):
    _, d = encrypted(mode)
    hl = hdr_len(d)
    h = json.loads(d[7:hl])
    h["iv"] = ("0" if h["iv"][0] != "0" else "1") + h["iv"][1:]
    blob = json.dumps(h, separators=(",", ":"), sort_keys=True).encode()
    attempt(tmp_path, ctx, ks, logger, d[:5] + struct.pack(">H", len(blob)) + blob + d[hl:], TamperDetected)


@pytest.mark.parametrize("mode", list(REGISTRY))
def test_truncate_and_append(mode, tmp_path, ctx, ks, logger, encrypted):
    _, d = encrypted(mode)
    attempt(tmp_path, ctx, ks, logger, d[:-3], (TamperDetected, Truncated))
    attempt(tmp_path, ctx, ks, logger, d + b"\x00" * 16, TamperDetected)
    attempt(tmp_path, ctx, ks, logger, d[:9], Truncated)


def test_segment_truncation_detected(tmp_path, ctx, ks, logger, encrypted):
    _, d = encrypted("chacha20-poly1305", size=3 * 4096 + 10)
    attempt(tmp_path, ctx, ks, logger, d[:hdr_len(d) + 2 * (4096 + 16)], Truncated)


@pytest.mark.parametrize("mode", list(REGISTRY))
def test_wrong_aad(mode, tmp_path, ctx, ks, logger, encrypted):
    enc, d = encrypted(mode)
    attempt(tmp_path, ctx, ks, logger, d, TamperDetected, aad=b"other")


def test_wrong_raw_key_is_auth_failed(tmp_path, ctx, ks, logger, encrypted):
    _, d = encrypted("gcm")
    raw = RawKeyContext(key_id=ctx.key_id, master=os.urandom(32))
    attempt(tmp_path, ctx, ks, logger, d, AuthFailed, c=raw)


def test_bad_magic_and_format(tmp_path, ctx, ks, logger, encrypted):
    _, d = encrypted("gcm")
    attempt(tmp_path, ctx, ks, logger, b"ZZZZ" + d[4:], BadMagic)
    attempt(tmp_path, ctx, ks, logger, d[:4] + b"\x09" + d[5:], BadFormat)
    hl = hdr_len(d)
    attempt(tmp_path, ctx, ks, logger, d[:7] + b"{" * (hl - 7) + d[hl:], BadFormat)


def test_key_mismatch(tmp_path, ctx, ks, logger, encrypted):
    from tests.conftest import FAST, PW2
    _, d = encrypted("gcm")
    other = ks.unlock(ks.create("other", PW2, iterations=FAST), PW2)
    attempt(tmp_path, ctx, ks, logger, d, KeyMismatch, c=other)


def test_existing_output_not_overwritten_on_failure(tmp_path, ctx, ks, logger, encrypted):
    _, d = encrypted("cbc")
    out = tmp_path / "out.dec"
    out.write_bytes(b"old content")
    bad = tmp_path / "bad.enc"
    bad.write_bytes(flip(d, len(d) - 40))
    with pytest.raises(TamperDetected):
        decrypt_file(str(bad), str(out), ctx, aad=b"aad", ks=ks, logger=logger)
    assert out.read_bytes() == b"old content"
