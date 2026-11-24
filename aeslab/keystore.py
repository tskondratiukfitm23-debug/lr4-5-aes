"""Генерування, зберігання та життєвий цикл ключів.

Схема виведення ключів::

    password ──PBKDF2-HMAC-SHA256 (≥310 000 ітерацій, salt 16 B)──► master (32 B)   [або scrypt]
    master ──HKDF-SHA256(info="aeslab/v2/verifier")──► verifier (зберігається для перевірки пароля)
    master ──HKDF-SHA256(info="aeslab/v2/key-id")────► key_id (публічний відбиток, 8 B hex)
    master ──HKDF-SHA256(info="aeslab/v2/<mode>/<bits>")─► enc_key (16/24/32 B) || mac_key (32 B)

У keystore.json *ніколи* не зберігаються пароль, майстер-ключ чи робочі ключі — лише salt,
параметри KDF, verifier, метадані та лічильники. Файл створюється з правами 0600.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from . import config
from .errors import (InvalidParams, KeyExhausted, KeyExpired, KeyLength, KeyNotFound, KeyRetired,
                     KeyReuse, KeyRevoked, NonceLimit, NonceReuse, WeakPassword, WrongPassword)
from .modes import DerivedKeys, get_mode

STATUSES = ("active", "retired", "revoked")
COMMON_WORDS = ("password", "qwerty", "123456", "111111", "admin", "letmein", "iloveyou", "welcome", "пароль")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None) -> str | None:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


def parse_iso(s: str | None) -> datetime | None:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) if s else None


def check_password_policy(pw: str) -> None:
    """Політика паролів: довжина ≥ 12, ≥ 3 класи символів, без поширених слів."""
    problems = []
    if len(pw) < config.MIN_PASSWORD_LEN:
        problems.append(f"довжина менше {config.MIN_PASSWORD_LEN} символів")
    classes = sum(bool(re.search(r, pw)) for r in (r"[a-zа-яіїєґ]", r"[A-ZА-ЯІЇЄҐ]", r"\d", r"[^\w\s]|_"))
    if classes < config.MIN_PASSWORD_CLASSES:
        problems.append(f"менше {config.MIN_PASSWORD_CLASSES} класів символів (малі/великі/цифри/спецсимволи)")
    if any(w in pw.lower() for w in COMMON_WORDS):
        problems.append("містить поширене слово/послідовність")
    if problems:
        raise WeakPassword("Пароль слабкий: " + "; ".join(problems))


def _hkdf(master: bytes, salt: bytes, info: str, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info.encode()).derive(master)


def run_kdf(password: str, salt: bytes, kdf: dict) -> bytes:
    """Обчислити майстер-ключ (32 B) з пароля за параметрами KDF."""
    pw = password.encode("utf-8")
    if kdf["name"] == "pbkdf2-hmac-sha256":
        return PBKDF2HMAC(hashes.SHA256(), config.MASTER_KEY_BYTES, salt, kdf["iterations"]).derive(pw)
    if kdf["name"] == "scrypt":
        return Scrypt(salt=salt, length=config.MASTER_KEY_BYTES, n=kdf["n"], r=kdf["r"], p=kdf["p"]).derive(pw)
    raise InvalidParams(f"Невідомий KDF: {kdf['name']}")


class KeyContext:
    """Розблокований ключ у пам'яті процесу (майстер-ключ у bytearray для подальшого затирання)."""

    def __init__(self, entry: dict, master: bytes):
        self.entry = entry
        self._master = bytearray(master)

    @property
    def key_id(self) -> str:
        return self.entry["key_id"]

    @property
    def label(self) -> str:
        return self.entry["label"]

    def derive(self, mode: str, key_bits: int) -> DerivedKeys:
        """Вивести незалежні ключі для конкретного режиму і довжини (розділення ключів через HKDF)."""
        if not self._master:
            raise InvalidParams("Ключ уже затерто з пам'яті")
        spec = get_mode(mode).spec
        if key_bits not in (128, 192, 256) or key_bits not in spec.key_bits:
            raise KeyLength(f"Неприпустима довжина ключа {key_bits} для {spec.title}")
        enc_len = key_bits // 8
        mac_len = config.MAC_KEY_BYTES if spec.needs_mac_key else 0
        okm = _hkdf(bytes(self._master), bytes.fromhex(self.entry["salt"]),
                    f"aeslab/v2/{spec.name}/{key_bits}", enc_len + mac_len)
        enc, mac = okm[:enc_len], okm[enc_len:] or None
        if len(enc) != enc_len or (mac_len and len(mac) != mac_len):
            raise KeyLength("Помилка контролю довжини виведеного ключа")
        return DerivedKeys(enc, mac)

    def wipe(self) -> None:
        """Затерти майстер-ключ (best effort — Python може мати копії в пам'яті)."""
        for i in range(len(self._master)):
            self._master[i] = 0
        self._master = bytearray()


class KeyStore:
    """Сховище метаданих ключів (JSON, права 0600, атомарний запис)."""

    def __init__(self, path: str = config.KEYSTORE_PATH, min_iterations: int = config.MIN_PBKDF2_ITERATIONS):
        self.path = path
        self.min_iterations = min_iterations
        self.warnings: list[str] = []
        self.db = {"version": 2, "keys": []}
        if os.path.exists(path):
            mode = stat.S_IMODE(os.stat(path).st_mode)
            if os.name == "posix" and mode & 0o077:
                self.warnings.append(f"Небезпечні права на {path}: {oct(mode)} (рекомендовано 0600)")
            with open(path, "r", encoding="utf-8") as f:
                self.db = json.load(f)
            if "version" not in self.db:   # старий формат стартового проєкту
                self.warnings.append("Сховище старого формату (v1) — ключі потрібно створити заново")
                self.db = {"version": 2, "keys": [], "legacy": self.db.get("keys", [])}

    # ------------------------------------------------------------------ збереження
    def save(self) -> None:
        d = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(d, exist_ok=True)
        tmp = self.path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(self.db, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)
        if os.name == "posix":
            os.chmod(self.path, 0o600)

    # ------------------------------------------------------------------ пошук
    @property
    def keys(self) -> list[dict]:
        return self.db["keys"]

    def find(self, label: str | None = None, key_id: str | None = None) -> dict:
        """Знайти ключ за key_id або за міткою (для мітки — пріоритет активного ключа)."""
        if key_id:
            for k in self.keys:
                if k["key_id"] == key_id:
                    return k
            raise KeyNotFound(f"Ключ з key_id={key_id} не знайдено у сховищі")
        cands = [k for k in self.keys if k["label"] == label]
        if not cands:
            raise KeyNotFound(f"Ключ з міткою '{label}' не знайдено")
        active = [k for k in cands if k["status"] == "active"]
        return active[-1] if active else cands[-1]

    # ------------------------------------------------------------------ створення
    def create(self, label: str, password: str, kdf: str = "pbkdf2", iterations: int = config.PBKDF2_ITERATIONS,
               key_bits: int = config.DEFAULT_KEY_BITS, expires_days: int | None = config.DEFAULT_EXPIRES_DAYS,
               max_uses: int = config.DEFAULT_MAX_USES, enforce_policy: bool = True,
               check_password_reuse: bool = True, rotated_from: str | None = None) -> dict:
        """Ініціалізувати новий ключ. Повертає запис метаданих (без секретів)."""
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", label or ""):
            raise InvalidParams("Мітка: 1–64 символи [A-Za-z0-9_.-]")
        if rotated_from is None and any(k["label"] == label for k in self.keys):
            raise KeyReuse(f"Мітка '{label}' уже існує — використайте 'key rotate'")
        if key_bits not in (128, 192, 256):
            raise KeyLength("Довжина ключа AES має бути 128, 192 або 256 біт")
        if enforce_policy:
            check_password_policy(password)
        if kdf == "pbkdf2":
            if iterations < self.min_iterations:
                raise InvalidParams(f"Кількість ітерацій PBKDF2 має бути ≥ {self.min_iterations}")
            kdf_params = {"name": "pbkdf2-hmac-sha256", "iterations": iterations}
        elif kdf == "scrypt":
            kdf_params = {"name": "scrypt", "n": config.SCRYPT_N, "r": config.SCRYPT_R, "p": config.SCRYPT_P}
        else:
            raise InvalidParams("KDF має бути pbkdf2 або scrypt")
        if check_password_reuse:
            self._ensure_password_not_reused(password)

        salt = os.urandom(config.SALT_BYTES)
        if any(k["salt"] == salt.hex() for k in self.keys):            # практично неможливо, але перевіряємо
            raise KeyReuse("Згенеровано сіль, що вже використовується")
        master = run_kdf(password, salt, kdf_params)
        verifier = _hkdf(master, salt, "aeslab/v2/verifier", config.VERIFIER_BYTES)
        key_id = _hkdf(master, salt, "aeslab/v2/key-id", 8).hex()
        if any(k["key_id"] == key_id for k in self.keys):
            raise KeyReuse("Ідентичний ключовий матеріал уже існує")
        now = utcnow()
        entry = {
            "label": label, "key_id": key_id, "status": "active",
            "kdf": kdf_params, "salt": salt.hex(), "verifier": verifier.hex(), "key_bits": key_bits,
            "created_at": iso(now),
            "expires_at": iso(now + timedelta(days=expires_days)) if expires_days else None,
            "max_uses": max_uses, "uses": 0, "gcm_invocations": 0, "last_used_at": None,
            "recent_iv_fps": [], "rotated_from": rotated_from, "rotated_to": None,
            "status_changed_at": iso(now), "status_reason": "created",
        }
        self.keys.append(entry)
        self.save()
        return entry

    def _ensure_password_not_reused(self, password: str) -> None:
        for k in self.keys:
            if self._verify(k, password) is not None:
                raise KeyReuse(f"Цей пароль уже використовується ключем '{k['label']}' ({k['key_id']})")

    # ------------------------------------------------------------------ розблокування
    @staticmethod
    def _verify(entry: dict, password: str) -> bytes | None:
        salt = bytes.fromhex(entry["salt"])
        master = run_kdf(password, salt, entry["kdf"])
        ver = _hkdf(master, salt, "aeslab/v2/verifier", config.VERIFIER_BYTES)
        return master if hmac.compare_digest(ver.hex(), entry["verifier"]) else None

    def unlock(self, entry: dict, password: str) -> KeyContext:
        """Перевірити пароль (verifier) і повернути розблокований ключ."""
        if entry["status"] == "revoked":
            raise KeyRevoked(f"Ключ '{entry['label']}' ({entry['key_id']}) відкликано")
        master = self._verify(entry, password)
        if master is None:
            raise WrongPassword(f"Неправильний пароль для ключа '{entry['label']}'")
        return KeyContext(entry, master)

    # ------------------------------------------------------------------ політики використання
    def authorize_encrypt(self, entry: dict, mode: str) -> None:
        if entry["status"] == "revoked":
            raise KeyRevoked()
        if entry["status"] == "retired":
            raise KeyRetired(f"Ключ '{entry['label']}' виведено з обігу (ротація) — шифрування заборонено")
        exp = parse_iso(entry.get("expires_at"))
        if exp and utcnow() >= exp:
            raise KeyExpired(f"Термін дії ключа минув {entry['expires_at']} — виконайте ротацію")
        if entry["uses"] >= entry["max_uses"]:
            raise KeyExhausted(f"Ключ використано {entry['uses']} разів (ліміт {entry['max_uses']})")
        if get_mode(mode).spec.name == "aes-gcm" and entry["gcm_invocations"] >= config.GCM_RANDOM_NONCE_LIMIT:
            raise NonceLimit()

    def authorize_decrypt(self, entry: dict) -> list[str]:
        """Дешифрування дозволене для active/retired/expired; заборонене для revoked."""
        if entry["status"] == "revoked":
            raise KeyRevoked()
        warn = []
        if entry["status"] == "retired":
            warn.append("ключ виведено з обігу — рекомендується перешифрувати файл новим ключем (rekey)")
        exp = parse_iso(entry.get("expires_at"))
        if exp and utcnow() >= exp:
            warn.append("термін дії ключа минув")
        return warn

    def reserve_use(self, key_id: str, mode: str, iv: bytes) -> None:
        """Зарахувати використання ДО шифрування: лічильники, контроль повтору IV/nonce."""
        e = self.find(key_id=key_id)
        self.authorize_encrypt(e, mode)
        fp = hashlib.sha256(get_mode(mode).spec.name.encode() + b"|" + iv).hexdigest()[:16]
        if fp in e["recent_iv_fps"]:
            raise NonceReuse()
        e["recent_iv_fps"] = (e["recent_iv_fps"] + [fp])[-config.RECENT_NONCE_CACHE:]
        e["uses"] += 1
        if get_mode(mode).spec.name == "aes-gcm":
            e["gcm_invocations"] += 1
        e["last_used_at"] = iso(utcnow())
        self.save()

    # ------------------------------------------------------------------ життєвий цикл
    def set_status(self, entry: dict, status: str, reason: str = "") -> dict:
        if status not in STATUSES:
            raise InvalidParams(f"Статус має бути одним із {STATUSES}")
        if entry["status"] == "revoked" and status != "revoked":
            raise KeyRevoked("Відкликаний ключ не можна повернути в обіг")
        entry["status"] = status
        entry["status_changed_at"] = iso(utcnow())
        entry["status_reason"] = reason or status
        self.save()
        return entry

    def rotate(self, label: str, old_password: str, new_password: str, **create_kw) -> tuple[dict, dict]:
        """Ротація: перевірити старий пароль, створити новий ключ з тією ж міткою, старий → retired."""
        old = self.find(label=label)
        ctx = self.unlock(old, old_password)
        ctx.wipe()
        if old_password == new_password:
            raise KeyReuse("Новий пароль збігається зі старим")
        new = self.create(label, new_password, rotated_from=old["key_id"], **create_kw)
        old["rotated_to"] = new["key_id"]
        self.set_status(old, "retired", f"rotated → {new['key_id']}")
        return old, new
