"""Реєстр режимів шифрування (plugin-подібна архітектура).

Кожен режим — клас-нащадок :class:`CipherMode` з описом :class:`ModeSpec`, зареєстрований
декоратором :func:`register_mode`. Додавання нового режиму = один новий клас (див. docs/02_modes.md).

Усі режими забезпечують *автентифіковане* шифрування:
  * AEAD-режими (GCM, GCM-SIV, ChaCha20-Poly1305) — вбудований тег;
  * класичні режими (CBC, CTR, CFB) — схема Encrypt-then-MAC з HMAC-SHA256.
Заголовок файлу завжди входить до автентифікованих даних (захист від підміни режиму/IV/key_id).
"""
from __future__ import annotations

import hmac
import os
import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, hmac as hmac_lib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes as cmodes
from cryptography.hazmat.primitives.ciphers import aead

from . import config
from .errors import AuthFailed, BadFormat, InvalidParams, KeyLength, Truncated, UnsupportedMode
from .params import AES_BLOCK, AES_BLOCK_BITS, PADDINGS, CipherParams


@dataclass(frozen=True)
class DerivedKeys:
    """Ключі для однієї операції (отримані через HKDF з майстер-ключа)."""

    enc_key: bytes
    mac_key: bytes | None = None


@dataclass(frozen=True)
class ModeSpec:
    """Опис режиму: допустимі значення параметрів та характеристики безпеки."""

    name: str
    title: str
    family: str                              # aead-stream / aead-segmented / etm
    key_bits: tuple = (128, 192, 256)
    iv_lens: tuple = (16,)
    default_iv: int = 16
    paddings: tuple = ("none",)
    default_padding: str = "none"
    tag_lens: tuple = (32,)
    default_tag: int = 32
    needs_mac_key: bool = False
    aliases: tuple = ()
    security: str = ""                       # коротка характеристика для таблиць
    risks: str = ""
    extra: dict = field(default_factory=dict)


def assoc_data(header: bytes, aad: bytes | None) -> bytes:
    """Автентифіковані дані = сирі байти заголовка || len(AAD) (8 байт) || AAD."""
    aad = aad or b""
    return header + struct.pack(">Q", len(aad)) + aad


def check_key(key: bytes, allowed_bits: tuple) -> None:
    """Суворий контроль довжини ключа перед створенням шифру."""
    if len(key) * 8 not in allowed_bits:
        raise KeyLength(f"Довжина ключа {len(key) * 8} біт не дозволена (допустимо: {allowed_bits})")


class CipherMode(ABC):
    """Базовий клас режиму. ``fi`` встановлено на початок тіла (після заголовка)."""

    spec: ModeSpec

    def new_iv(self, p: CipherParams) -> bytes:
        return os.urandom(p.iv_len)

    @abstractmethod
    def encrypt(self, fi: BinaryIO, fo: BinaryIO, keys: DerivedKeys, p: CipherParams,
                iv: bytes, header: bytes) -> None: ...

    @abstractmethod
    def decrypt(self, fi: BinaryIO, fo: BinaryIO, keys: DerivedKeys, p: CipherParams,
                iv: bytes, header: bytes, body_len: int) -> None: ...


REGISTRY: dict[str, CipherMode] = {}
ALIASES: dict[str, str] = {}


def register_mode(cls):
    """Декоратор реєстрації режиму в реєстрі."""
    inst = cls()
    REGISTRY[cls.spec.name] = inst
    for a in cls.spec.aliases:
        ALIASES[a] = cls.spec.name
    return cls


def get_mode(name: str) -> CipherMode:
    key = ALIASES.get(name.lower(), name.lower())
    if key not in REGISTRY:
        raise UnsupportedMode(f"Режим '{name}' не підтримується. Доступні: {', '.join(REGISTRY)}")
    return REGISTRY[key]


def resolve_params(p: CipherParams) -> CipherParams:
    """Заповнити типові значення режиму та перевірити всі параметри."""
    mode = get_mode(p.mode)
    s = mode.spec
    p = p.copy(mode=s.name,
               iv_len=p.iv_len if p.iv_len is not None else s.default_iv,
               padding=(p.padding or s.default_padding).lower(),
               tag_len=p.tag_len if p.tag_len is not None else s.default_tag,
               segment_size=p.segment_size or (config.DEFAULT_SEGMENT if s.family == "aead-segmented" else None))
    if p.block_size != AES_BLOCK_BITS:
        raise InvalidParams("Розмір блоку AES фіксований — 128 біт (FIPS-197); інші значення неможливі")
    if p.key_bits not in s.key_bits:
        raise KeyLength(f"{s.title}: довжина ключа {p.key_bits} не підтримується (допустимо {s.key_bits})")
    if p.iv_len not in s.iv_lens:
        raise InvalidParams(f"{s.title}: довжина IV/nonce {p.iv_len} байт неприпустима (допустимо {s.iv_lens})")
    if p.padding not in s.paddings:
        raise InvalidParams(f"{s.title}: доповнення '{p.padding}' неприпустиме (допустимо {s.paddings})")
    if p.tag_len not in s.tag_lens:
        raise InvalidParams(f"{s.title}: довжина тегу {p.tag_len} неприпустима (допустимо {s.tag_lens})")
    if p.segment_size is not None and not (1024 <= p.segment_size <= 16 * 1024 * 1024):
        raise InvalidParams("Розмір сегмента має бути в межах 1 KiB … 16 MiB")
    if p.aad is not None and len(p.aad) > 64 * 1024:
        raise InvalidParams("AAD занадто велика (макс. 64 KiB)")
    return p


def _read_exact(fi: BinaryIO, n: int) -> bytes:
    data = fi.read(n)
    if len(data) != n:
        raise Truncated()
    return data


# ---------------------------------------------------------------------------
# AES-GCM (потоковий AEAD)
# ---------------------------------------------------------------------------
@register_mode
class AesGcm(CipherMode):
    spec = ModeSpec(
        name="aes-gcm", title="AES-GCM", family="aead-stream",
        iv_lens=(12, 16), default_iv=12, tag_lens=(12, 13, 14, 15, 16), default_tag=16, aliases=("gcm",),
        security="AEAD (конфіденційність + цілісність + автентичність), 1 прохід, паралелізується",
        risks="Повтор nonce катастрофічний (витік XOR відкритих текстів і ключа H → підробка тегів); "
              "≤2^32 повідомлень на ключ із випадковими nonce; ≤64 GiB на повідомлення; укорочений тег слабший",
    )

    def encrypt(self, fi, fo, keys, p, iv, header):
        check_key(keys.enc_key, self.spec.key_bits)
        enc = Cipher(algorithms.AES(keys.enc_key), cmodes.GCM(iv)).encryptor()
        enc.authenticate_additional_data(assoc_data(header, p.aad))
        while chunk := fi.read(config.IO_CHUNK):
            fo.write(enc.update(chunk))
        fo.write(enc.finalize())
        fo.write(enc.tag[: p.tag_len])

    def decrypt(self, fi, fo, keys, p, iv, header, body_len):
        check_key(keys.enc_key, self.spec.key_bits)
        if body_len < p.tag_len:
            raise Truncated("Файл обрізаний: відсутній тег GCM")
        start = fi.tell()
        fi.seek(start + body_len - p.tag_len)
        tag = _read_exact(fi, p.tag_len)
        fi.seek(start)
        dec = Cipher(algorithms.AES(keys.enc_key), cmodes.GCM(iv, tag, min_tag_length=p.tag_len)).decryptor()
        dec.authenticate_additional_data(assoc_data(header, p.aad))
        remaining = body_len - p.tag_len
        while remaining:
            chunk = _read_exact(fi, min(config.IO_CHUNK, remaining))
            remaining -= len(chunk)
            fo.write(dec.update(chunk))      # пишеться лише у тимчасовий файл (див. engine)
        try:
            fo.write(dec.finalize())
        except InvalidTag:
            raise AuthFailed() from None


# ---------------------------------------------------------------------------
# Encrypt-then-MAC (класичні режими + HMAC-SHA256)
# ---------------------------------------------------------------------------
class EncryptThenMac(CipherMode):
    """AES-<режим> + HMAC-SHA256 за схемою Encrypt-then-MAC.

    MAC = HMAC-SHA256(mac_key, header || len(AAD) || AAD || ciphertext), усічений до tag_len.
    Під час дешифрування MAC перевіряється *до* розшифрування (захист від padding oracle).
    """

    def cipher_mode(self, iv: bytes):  # pragma: no cover - abstract
        raise NotImplementedError

    def _mac(self, keys, header, aad):
        if not keys.mac_key or len(keys.mac_key) < 32:
            raise KeyLength("Ключ HMAC має бути не коротшим за 256 біт")
        m = hmac_lib.HMAC(keys.mac_key, hashes.SHA256())
        m.update(assoc_data(header, aad))
        return m

    def encrypt(self, fi, fo, keys, p, iv, header):
        check_key(keys.enc_key, self.spec.key_bits)
        mac = self._mac(keys, header, p.aad)
        enc = Cipher(algorithms.AES(keys.enc_key), self.cipher_mode(iv)).encryptor()
        pad = PADDINGS.get(p.padding)
        total = 0
        while chunk := fi.read(config.IO_CHUNK):
            total += len(chunk)
            ct = enc.update(chunk)
            fo.write(ct)
            mac.update(ct)
        tail = enc.update(pad.pad_bytes(total)) if pad else b""
        tail += enc.finalize()
        fo.write(tail)
        mac.update(tail)
        fo.write(mac.finalize()[: p.tag_len])

    def decrypt(self, fi, fo, keys, p, iv, header, body_len):
        check_key(keys.enc_key, self.spec.key_bits)
        ct_len = body_len - p.tag_len
        if ct_len < 0:
            raise Truncated("Файл обрізаний: відсутній HMAC")
        start = fi.tell()
        # Прохід 1: перевірка HMAC (нічого не розшифровуємо до успішної перевірки)
        mac = self._mac(keys, header, p.aad)
        remaining = ct_len
        while remaining:
            chunk = _read_exact(fi, min(config.IO_CHUNK, remaining))
            remaining -= len(chunk)
            mac.update(chunk)
        tag = _read_exact(fi, p.tag_len)
        if not hmac.compare_digest(mac.finalize()[: p.tag_len], tag):
            raise AuthFailed()
        pad = PADDINGS.get(p.padding)
        if pad and (ct_len == 0 or ct_len % AES_BLOCK):
            raise BadFormat("Довжина шифротексту не кратна розміру блоку")
        # Прохід 2: розшифрування (останній блок утримується для зняття доповнення)
        fi.seek(start)
        dec = Cipher(algorithms.AES(keys.enc_key), self.cipher_mode(iv)).decryptor()
        held = b""
        remaining = ct_len
        while remaining:
            chunk = _read_exact(fi, min(config.IO_CHUNK, remaining))
            remaining -= len(chunk)
            pt = held + dec.update(chunk)
            if pad:
                held, pt = pt[-AES_BLOCK:], pt[:-AES_BLOCK]
            fo.write(pt)
        held += dec.finalize()
        fo.write(pad.unpad(held) if pad else held)


@register_mode
class AesCbcHmac(EncryptThenMac):
    spec = ModeSpec(
        name="aes-cbc-hmac", title="AES-CBC + HMAC-SHA256", family="etm",
        paddings=("pkcs7", "ansix923", "iso7816"), default_padding="pkcs7",
        tag_lens=(16, 20, 24, 28, 32), default_tag=32, needs_mac_key=True, aliases=("cbc",),
        security="Конфіденційність (CBC) + цілісність/автентичність (HMAC, EtM); шифрування послідовне",
        risks="Без MAC або з MAC-then-Encrypt — padding oracle (Vaudenay 2002, POODLE, Lucky13); "
              "IV має бути непередбачуваним; повтор IV розкриває спільні префікси; 2 проходи при дешифруванні",
    )

    def cipher_mode(self, iv):
        return cmodes.CBC(iv)


@register_mode
class AesCtrHmac(EncryptThenMac):
    spec = ModeSpec(
        name="aes-ctr-hmac", title="AES-CTR + HMAC-SHA256", family="etm",
        tag_lens=(16, 20, 24, 28, 32), default_tag=32, needs_mac_key=True, aliases=("ctr",),
        security="Потоковий режим без доповнення, паралелізується; цілісність через HMAC (EtM)",
        risks="Повтор лічильника/nonce = повтор гами (XOR відкритих текстів); без MAC — повна "
              "пластичність (bit-flipping)",
    )

    def cipher_mode(self, iv):
        return cmodes.CTR(iv)


@register_mode
class AesCfbHmac(EncryptThenMac):
    """Приклад розширення: новий режим додано ~10 рядками (див. docs/02_modes.md)."""

    spec = ModeSpec(
        name="aes-cfb-hmac", title="AES-CFB + HMAC-SHA256", family="etm",
        tag_lens=(16, 20, 24, 28, 32), default_tag=32, needs_mac_key=True, aliases=("cfb",),
        security="Самосинхронізований потоковий режим; цілісність через HMAC (EtM)",
        risks="Шифрування послідовне (повільніше); повтор IV розкриває перший блок; без MAC — пластичність",
    )

    def cipher_mode(self, iv):
        try:  # cryptography ≥ 47 переносить CFB до «decrepit» (застарілі режими)
            from cryptography.hazmat.decrepit.ciphers.modes import CFB
        except ImportError:  # pragma: no cover - старіші версії
            CFB = cmodes.CFB
        return CFB(iv)


# ---------------------------------------------------------------------------
# Сегментовані AEAD (схема STREAM, Hoang–Reyhanitabar–Rogaway–Vizár 2015)
# ---------------------------------------------------------------------------
class SegmentedAead(CipherMode):
    """Файл ділиться на сегменти; nonce_i = prefix(7) || i (4 байти) || last_flag (1 байт).

    Захищає від перестановки (лічильник у nonce) і від обрізання по межі сегмента (прапорець
    останнього сегмента). Кожен сегмент автентифікується разом із заголовком та AAD.
    """

    aead_cls = None

    def _aead(self, keys):
        check_key(keys.enc_key, self.spec.key_bits)
        return self.aead_cls(keys.enc_key)

    @staticmethod
    def _nonce(prefix: bytes, idx: int, last: bool) -> bytes:
        if idx >= 2 ** 32:
            raise InvalidParams("Перевищено максимальну кількість сегментів")
        return prefix + struct.pack(">I", idx) + (b"\x01" if last else b"\x00")

    def encrypt(self, fi, fo, keys, p, iv, header):
        a = self._aead(keys)
        ad = assoc_data(header, p.aad)
        idx = 0
        cur = fi.read(p.segment_size)
        while True:
            nxt = fi.read(p.segment_size)
            last = not nxt
            fo.write(a.encrypt(self._nonce(iv, idx, last), cur, ad))
            if last:
                break
            cur, idx = nxt, idx + 1

    def decrypt(self, fi, fo, keys, p, iv, header, body_len):
        a = self._aead(keys)
        ad = assoc_data(header, p.aad)
        seg_ct = p.segment_size + 16
        if body_len < 16:
            raise Truncated("Файл обрізаний: відсутній тег сегмента")
        idx, remaining = 0, body_len
        while remaining:
            ct = _read_exact(fi, min(seg_ct, remaining))
            remaining -= len(ct)
            last = remaining == 0
            try:
                fo.write(a.decrypt(self._nonce(iv, idx, last), ct, ad))
            except InvalidTag:
                if last and len(ct) == seg_ct:
                    try:  # сегмент валідний, але не останній → хвіст відрізано
                        a.decrypt(self._nonce(iv, idx, False), ct, ad)
                        raise Truncated("Файл обрізаний: відсутні фінальні сегменти") from None
                    except InvalidTag:
                        pass
                raise AuthFailed() from None
            idx += 1


@register_mode
class ChaCha20Poly1305Mode(SegmentedAead):
    aead_cls = aead.ChaCha20Poly1305
    spec = ModeSpec(
        name="chacha20-poly1305", title="ChaCha20-Poly1305 (не-AES)", family="aead-segmented",
        key_bits=(256,), iv_lens=(7,), default_iv=7, tag_lens=(16,), default_tag=16, aliases=("chacha",),
        security="AEAD (RFC 8439), швидкий і константночасовий без апаратного AES; сегментований STREAM",
        risks="Повтор nonce катастрофічний (як у GCM); не схвалений FIPS; лише 256-бітний ключ",
    )


def _gcm_siv_available() -> bool:
    try:
        aead.AESGCMSIV(b"\x00" * 32).encrypt(b"\x00" * 12, b"", None)
        return True
    except Exception:  # старий OpenSSL (< 3.2) або старий cryptography
        return False


if hasattr(aead, "AESGCMSIV") and _gcm_siv_available():
    @register_mode
    class AesGcmSiv(SegmentedAead):
        aead_cls = aead.AESGCMSIV
        spec = ModeSpec(
            name="aes-gcm-siv", title="AES-GCM-SIV", family="aead-segmented",
            key_bits=(128, 256), iv_lens=(7,), default_iv=7, tag_lens=(16,), default_tag=16, aliases=("siv",),
            security="AEAD, стійкий до повтору nonce (RFC 8452): повтор розкриває лише рівність повідомлень",
            risks="Двопрохідний (повільніший за GCM); потребує OpenSSL ≥ 3.2; не потоковий — лише посегментно",
        )


def list_modes() -> list[ModeSpec]:
    return [m.spec for m in REGISTRY.values()]
