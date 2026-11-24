"""Спільні фікстури: тимчасове сховище ключів зі зниженими ітераціями KDF (для швидкості тестів)."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aeslab.keystore import KeyStore  # noqa: E402
from aeslab.logging_setup import get_logger  # noqa: E402

PW = "Test-Passw0rd!2026"
PW2 = "Other-Passw0rd#2026"
FAST = 1000


@pytest.fixture
def logger(tmp_path):
    return get_logger(str(tmp_path / "logs" / "test.jsonl"))


@pytest.fixture
def ks(tmp_path, logger):
    return KeyStore(str(tmp_path / "keystore.json"), min_iterations=FAST)


@pytest.fixture
def ctx(ks):
    e = ks.create("test", PW, iterations=FAST)
    return ks.unlock(e, PW)


@pytest.fixture
def make_file(tmp_path):
    def _make(size, name="plain.bin"):
        p = tmp_path / name
        p.write_bytes(os.urandom(size))
        return str(p)
    return _make
