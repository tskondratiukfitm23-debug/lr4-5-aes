"""Формат файлу-контейнера AES-Lab v2.

    +--------+-----+--------+-------------------+------------------------------+
    | MAGIC  | VER | HDRLEN | HEADER (JSON,UTF8)| BODY (залежить від режиму)   |
    | 4 B    | 1 B | 2 B BE | HDRLEN байтів     |                              |
    +--------+-----+--------+-------------------+------------------------------+

BODY:
  * aes-gcm:                 ciphertext || tag (tag_len)
  * aes-{cbc,ctr,cfb}-hmac:  ciphertext || HMAC-SHA256[:tag_len]
  * сегментовані AEAD:       seg_0 || tag_0 || seg_1 || tag_1 || ... (останній із прапорцем final)

Байти MAGIC..HEADER (саме сирі байти, без повторної серіалізації) входять до автентифікованих
даних кожного режиму, тож будь-яка зміна заголовка виявляється.
"""
from __future__ import annotations

import json
import struct
from datetime import datetime, timezone
from typing import BinaryIO

from . import config
from .errors import AesLabError, BadFormat, BadMagic, Truncated, UnsupportedMode
from .modes import resolve_params
from .params import CipherParams

PREFIX_LEN = 4 + 1 + 2
REQUIRED = {"mode": str, "key_id": str, "key_bits": int, "iv": str, "tag": int}


def build_header(p: CipherParams, key_id: str, iv: bytes) -> bytes:
    """Серіалізувати заголовок (компактний JSON із сортованими ключами)."""
    h = {
        "v": config.FORMAT_VERSION,
        "mode": p.mode,
        "key_id": key_id,
        "key_bits": p.key_bits,
        "iv": iv.hex(),
        "pad": p.padding,
        "tag": p.tag_len,
        "aad": bool(p.aad),
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if p.segment_size:
        h["seg"] = p.segment_size
    blob = json.dumps(h, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(blob) > config.MAX_HEADER_LEN:
        raise BadFormat("Заголовок завеликий")
    return config.MAGIC + bytes([config.FORMAT_VERSION]) + struct.pack(">H", len(blob)) + blob


def read_header(fi: BinaryIO) -> tuple[dict, bytes]:
    """Прочитати та перевірити заголовок. Повертає (словник, сирі байти заголовка)."""
    prefix = fi.read(PREFIX_LEN)
    if len(prefix) < 4:
        if prefix and config.MAGIC.startswith(prefix):
            raise Truncated("Файл обрізаний: неповний заголовок")
        raise BadMagic()
    if prefix[:4] != config.MAGIC:
        raise BadMagic()
    if len(prefix) < PREFIX_LEN:
        raise Truncated("Файл обрізаний: неповний заголовок")
    if prefix[4] != config.FORMAT_VERSION:
        raise BadFormat(f"Непідтримувана версія формату: {prefix[4]}")
    (hlen,) = struct.unpack(">H", prefix[5:7])
    if not 2 <= hlen <= config.MAX_HEADER_LEN:
        raise BadFormat("Некоректна довжина заголовка")
    blob = fi.read(hlen)
    if len(blob) != hlen:
        raise Truncated("Файл обрізаний: неповний заголовок")
    try:
        hdr = json.loads(blob.decode("utf-8"))
        if not isinstance(hdr, dict):
            raise ValueError
        for k, t in REQUIRED.items():
            if not isinstance(hdr.get(k), t):
                raise ValueError(k)
        bytes.fromhex(hdr["iv"])
    except (ValueError, UnicodeDecodeError):
        raise BadFormat("Заголовок пошкоджено (некоректний JSON або поля)") from None
    return hdr, prefix + blob


def params_from_header(hdr: dict, aad: bytes | None) -> tuple[CipherParams, bytes]:
    """Відновити CipherParams із заголовка (з повною валідацією)."""
    iv = bytes.fromhex(hdr["iv"])
    p = CipherParams(mode=hdr["mode"], key_bits=hdr["key_bits"], iv_len=len(iv), padding=hdr.get("pad"),
                     tag_len=hdr["tag"], aad=aad, segment_size=hdr.get("seg"))
    try:
        return resolve_params(p), iv
    except UnsupportedMode:
        raise
    except AesLabError as e:
        raise BadFormat(f"Заголовок містить неприпустимі параметри: {e.message}") from None
