"""Окремий інтерфейс налаштування параметрів шифрування (CipherParams) та схеми доповнення.

AES — блоковий шифр із *фіксованим* розміром блоку 128 біт (FIPS-197). Змінюється лише довжина
ключа (128/192/256). Тому ``block_size`` присутній у параметрах для повноти/документування, але
будь-яке значення, відмінне від 128, відхиляється валідацією.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict, replace

from .errors import InvalidParams, BadPadding

AES_BLOCK_BITS = 128
AES_BLOCK = AES_BLOCK_BITS // 8


# ---------------------------------------------------------------------------
# Схеми доповнення (padding) — потрібні лише блоковим режимам (CBC)
# ---------------------------------------------------------------------------
class Padding:
    """Базова схема доповнення до кратності розміру блоку."""

    name = "base"

    def pad_bytes(self, total_len: int, block: int = AES_BLOCK) -> bytes:  # pragma: no cover - abstract
        raise NotImplementedError

    def unpad(self, last_block: bytes, block: int = AES_BLOCK) -> bytes:  # pragma: no cover - abstract
        """Отримує останній блок відкритого тексту, повертає його без доповнення."""
        raise NotImplementedError


class PKCS7(Padding):
    """PKCS#7 (RFC 5652): N байтів зі значенням N."""

    name = "pkcs7"

    def pad_bytes(self, total_len, block=AES_BLOCK):
        n = block - (total_len % block)
        return bytes([n]) * n

    def unpad(self, last_block, block=AES_BLOCK):
        n = last_block[-1] if last_block else 0
        if not 1 <= n <= block or last_block[-n:] != bytes([n]) * n:
            raise BadPadding("Некоректне доповнення PKCS#7")
        return last_block[:-n]


class ANSIX923(Padding):
    """ANSI X9.23: нулі + останній байт = кількість доданих байтів."""

    name = "ansix923"

    def pad_bytes(self, total_len, block=AES_BLOCK):
        n = block - (total_len % block)
        return b"\x00" * (n - 1) + bytes([n])

    def unpad(self, last_block, block=AES_BLOCK):
        n = last_block[-1] if last_block else 0
        if not 1 <= n <= block or last_block[-n:-1] != b"\x00" * (n - 1):
            raise BadPadding("Некоректне доповнення ANSI X9.23")
        return last_block[:-n]


class ISO7816(Padding):
    """ISO/IEC 7816-4: байт 0x80, далі нулі."""

    name = "iso7816"

    def pad_bytes(self, total_len, block=AES_BLOCK):
        n = block - (total_len % block)
        return b"\x80" + b"\x00" * (n - 1)

    def unpad(self, last_block, block=AES_BLOCK):
        stripped = last_block.rstrip(b"\x00")
        if not stripped or stripped[-1] != 0x80 or len(last_block) - len(stripped) + 1 > block:
            raise BadPadding("Некоректне доповнення ISO/IEC 7816-4")
        return stripped[:-1]


PADDINGS: dict[str, Padding] = {p.name: p for p in (PKCS7(), ANSIX923(), ISO7816())}


# ---------------------------------------------------------------------------
# Параметри
# ---------------------------------------------------------------------------
@dataclass
class CipherParams:
    """Параметри операції шифрування.

    Поля зі значенням ``None`` заповнюються типовими значеннями обраного режиму в
    :func:`aeslab.modes.resolve_params`, після чого виконується валідація за специфікацією режиму.
    """

    mode: str = "aes-gcm"
    key_bits: int = 256                 # 128 / 192 / 256 (ChaCha20 — лише 256)
    block_size: int = AES_BLOCK_BITS    # фіксовано 128 біт для AES
    iv_len: int | None = None           # довжина IV/nonce, байт
    padding: str | None = None          # pkcs7 / ansix923 / iso7816 / none
    tag_len: int | None = None          # довжина тегу автентичності, байт
    aad: bytes | None = field(default=None, repr=False)  # додаткові автентифіковані дані (не шифруються)
    segment_size: int | None = None     # для сегментованих AEAD

    def copy(self, **changes) -> "CipherParams":
        return replace(self, **changes)

    def public_dict(self) -> dict:
        """Словник для журналу/інтерфейсу (AAD — лише ознака наявності)."""
        d = asdict(self)
        d["aad"] = bool(self.aad)
        return d

    def set_from_text(self, name: str, value: str) -> "CipherParams":
        """Змінити параметр за текстовим значенням (використовується REPL)."""
        name = name.replace("-", "_")
        if name not in {"key_bits", "block_size", "iv_len", "padding", "tag_len", "aad", "segment_size"}:
            raise InvalidParams(f"Невідомий параметр '{name}'")
        if value.lower() in {"default", "auto"}:
            return self.copy(**{name: None if name != "key_bits" else 256})
        if name == "aad":
            return self.copy(aad=None if value.lower() in {"none", ""} else value.encode("utf-8"))
        if name == "padding":
            return self.copy(padding=value.lower())
        try:
            return self.copy(**{name: int(value)})
        except ValueError:
            raise InvalidParams(f"Параметр '{name}' має бути цілим числом") from None
