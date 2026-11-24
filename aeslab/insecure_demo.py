"""⚠️ НЕБЕЗПЕЧНІ режими — ЛИШЕ для демонстрації атак (tamper_demo). НЕ входять до реєстру режимів.

* AES-CBC без MAC — пластичний (bit-flipping) і вразливий до padding oracle;
* AES-CTR без MAC — повністю пластичний (зміна біта шифротексту = зміна того самого біта тексту).
"""
from __future__ import annotations

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .errors import BadPadding
from .params import AES_BLOCK, PKCS7

_PAD = PKCS7()


def cbc_nomac_encrypt(key: bytes, iv: bytes, pt: bytes) -> bytes:
    e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return e.update(pt + _PAD.pad_bytes(len(pt))) + e.finalize()


def cbc_nomac_decrypt(key: bytes, iv: bytes, ct: bytes) -> bytes:
    """Розшифрування без перевірки цілісності; кидає BadPadding — це і є «оракул»."""
    d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    pt = d.update(ct) + d.finalize()
    return pt[:-AES_BLOCK] + _PAD.unpad(pt[-AES_BLOCK:])


def ctr_nomac(key: bytes, nonce: bytes, data: bytes) -> bytes:
    c = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()
    return c.update(data) + c.finalize()


def padding_oracle_attack_last_block(oracle, iv: bytes, ct: bytes) -> tuple[bytes, int]:
    """Класична атака Воденé: відновлює ОСТАННІЙ блок відкритого тексту, маючи лише оракул
    ``oracle(iv, ct) -> bool`` («доповнення коректне?»). Повертає (відкритий блок, кількість запитів).
    """
    blocks = [iv] + [ct[i:i + AES_BLOCK] for i in range(0, len(ct), AES_BLOCK)]
    prev, target = blocks[-2], blocks[-1]
    inter = bytearray(AES_BLOCK)          # D_K(target)
    queries = 0
    for pos in range(AES_BLOCK - 1, -1, -1):
        pad_val = AES_BLOCK - pos
        found = False
        for guess in range(256):
            forged = bytearray(AES_BLOCK)
            for j in range(pos + 1, AES_BLOCK):
                forged[j] = inter[j] ^ pad_val
            forged[pos] = guess
            queries += 1
            if oracle(bytes(forged), target):
                if pos == AES_BLOCK - 1:          # відкидаємо хибний збіг типу \x02\x02
                    forged[pos - 1] ^= 0xFF
                    queries += 1
                    if not oracle(bytes(forged), target):
                        continue
                inter[pos] = guess ^ pad_val
                found = True
                break
        if not found:
            raise RuntimeError("Атака не вдалася (оракул не дає інформації)")
    return bytes(i ^ p for i, p in zip(inter, prev)), queries


def make_oracle(key: bytes):
    """Оракул на базі CBC без MAC: True, якщо доповнення коректне."""
    def oracle(iv: bytes, ct: bytes) -> bool:
        try:
            cbc_nomac_decrypt(key, iv, ct)
            return True
        except BadPadding:
            return False
    return oracle
