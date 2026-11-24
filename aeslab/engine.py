"""Шифрування/дешифрування файлів: атомарний запис, класифікація помилок, журналювання.

Гарантія атомарності: результат пишеться у тимчасовий файл у тому ж каталозі й
перейменовується (os.replace) *лише після* успішної перевірки тегу/HMAC. За будь-якої помилки
тимчасовий файл видаляється, тож неавтентифікований відкритий текст ніколи не з'являється
за цільовим шляхом.
"""
from __future__ import annotations

import contextlib
import hashlib
import logging
import os
import secrets
import time
from dataclasses import dataclass

from .container import build_header, params_from_header, read_header
from .errors import AesLabError, AuthFailed, FileIOError, InvalidParams, KeyMismatch, TamperDetected
from .keystore import KeyContext, KeyStore
from .logging_setup import log_event
from .modes import DerivedKeys, get_mode, resolve_params
from .params import CipherParams

# fsync гарантує, що результат фізично записано до перейменування. Бенчмарк може вимкнути його,
# щоб виміряти обчислювальну складову (див. benchmark.py --fsync).
FSYNC = True


@dataclass
class RawKeyContext:
    """Контекст із «сирими» ключами без перевірки пароля (для бенчмарку та демонстрацій).

    ``verified=False``: збій тегу класифікується як AUTH_FAILED (ключ не підтверджено).
    """

    key_id: str
    keys: DerivedKeys | None = None
    master: bytes | None = None
    label: str = "raw"
    verified: bool = False
    entry: dict | None = None

    def derive(self, mode: str, key_bits: int) -> DerivedKeys:
        if self.master is not None:
            from .keystore import KeyContext as _KC
            return _KC({"salt": "00" * 16, "key_id": self.key_id, "label": self.label}, self.master).derive(mode, key_bits)
        return self.keys


@contextlib.contextmanager
def atomic_writer(path: str):
    """Відкрити тимчасовий файл (0600) поруч із ``path``; при успіху — os.replace, інакше — видалити."""
    d = os.path.dirname(os.path.abspath(path)) or "."
    if not os.path.isdir(d):
        raise FileIOError(f"Каталог для вихідного файлу не існує: {d}")
    tmp = os.path.join(d, f".{os.path.basename(path)}.{secrets.token_hex(4)}.part")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    f = os.fdopen(fd, "wb")
    try:
        yield f
        f.flush()
        if FSYNC:
            os.fsync(f.fileno())
        f.close()
        os.replace(tmp, path)
    except BaseException:
        f.close()
        with contextlib.suppress(FileNotFoundError):
            os.remove(tmp)
        raise


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while b := f.read(1 << 20):
            h.update(b)
    return h.hexdigest()


def peek_header(path: str) -> dict:
    """Прочитати заголовок контейнера без ключа (для вибору ключа за key_id та команди info)."""
    try:
        with open(path, "rb") as fi:
            hdr, raw = read_header(fi)
    except OSError as e:
        raise FileIOError(f"Не вдалося відкрити '{path}': {e.strerror}") from None
    hdr["_header_len"] = len(raw)
    hdr["_file_size"] = os.path.getsize(path)
    return hdr


def _check_paths(in_path: str, out_path: str) -> None:
    if not os.path.isfile(in_path):
        raise FileIOError(f"Вхідний файл не знайдено: {in_path}")
    if os.path.exists(out_path) and os.path.samefile(in_path, out_path):
        raise InvalidParams("Вхідний і вихідний файли мають бути різними")


def _common(op, ctx, in_path, out_path):
    return {"op": op, "key_id": getattr(ctx, "key_id", None), "label": getattr(ctx, "label", None),
            "in_file": os.path.basename(in_path), "out_file": os.path.basename(out_path)}


def encrypt_file(in_path: str, out_path: str, ctx: KeyContext | RawKeyContext, params: CipherParams,
                 ks: KeyStore | None = None, logger: logging.Logger | None = None,
                 hash_output: bool = True) -> dict:
    """Зашифрувати файл. ``ks`` — сховище для перевірки політик та лічильників (None — без обліку)."""
    fields = _common("encrypt", ctx, in_path, out_path)
    fields["mode"] = params.mode
    t0, c0 = time.perf_counter(), time.process_time()
    try:
        p = resolve_params(params)
        fields.update(mode=p.mode, key_bits=p.key_bits, padding=p.padding, tag_len=p.tag_len, aad=bool(p.aad))
        _check_paths(in_path, out_path)
        mode = get_mode(p.mode)
        iv = mode.new_iv(p)
        if ks is not None:
            ks.reserve_use(ctx.key_id, p.mode, iv)          # політики + контроль повтору nonce/IV
        keys = ctx.derive(p.mode, p.key_bits)
        header = build_header(p, ctx.key_id, iv)
        with open(in_path, "rb") as fi, atomic_writer(out_path) as fo:
            fo.write(header)
            mode.encrypt(fi, fo, keys, p, iv, header)
        res = {**fields, "status": "success", "in_size": os.path.getsize(in_path),
               "out_size": os.path.getsize(out_path),
               "duration_s": round(time.perf_counter() - t0, 6), "cpu_s": round(time.process_time() - c0, 6)}
        if hash_output:
            res["out_sha256"] = sha256_file(out_path)
        log_event("encrypt", logging.INFO, logger, **res)
        return res
    except AesLabError as e:
        _log_fail(logger, fields, e, t0)
        raise
    except OSError as e:
        err = FileIOError(f"Помилка вводу-виводу: {e.strerror or e}")
        _log_fail(logger, fields, err, t0)
        raise err from None


def decrypt_file(in_path: str, out_path: str, ctx: KeyContext | RawKeyContext, aad: bytes | None = None,
                 ks: KeyStore | None = None, logger: logging.Logger | None = None,
                 hash_input: bool = True) -> dict:
    """Розшифрувати файл з обов'язковою перевіркою автентичності до появи результату."""
    fields = _common("decrypt", ctx, in_path, out_path)
    t0, c0 = time.perf_counter(), time.process_time()
    try:
        _check_paths(in_path, out_path)
        fields["in_size"] = os.path.getsize(in_path)
        if hash_input:
            fields["in_sha256"] = sha256_file(in_path)
        with open(in_path, "rb") as fi:
            hdr, header = read_header(fi)
            fields.update(mode=hdr.get("mode"), file_key_id=hdr.get("key_id"))
            p, iv = params_from_header(hdr, aad)
            fields.update(mode=p.mode, key_bits=p.key_bits, aad=bool(aad))
            if hdr["key_id"] != ctx.key_id:
                raise KeyMismatch(f"Файл зашифровано ключем {hdr['key_id']}, а обрано {ctx.key_id}")
            if ks is not None and getattr(ctx, "entry", None):
                for w in ks.authorize_decrypt(ctx.entry):
                    log_event("key_warning", logging.WARNING, logger, key_id=ctx.key_id, warning=w)
            keys = ctx.derive(p.mode, p.key_bits)
            body_len = fields["in_size"] - len(header)
            with atomic_writer(out_path) as fo:
                try:
                    get_mode(p.mode).decrypt(fi, fo, keys, p, iv, header, body_len)
                except AuthFailed:
                    if getattr(ctx, "verified", True):
                        # Пароль підтверджено verifier'ом і key_id збігся → причина — зміна даних/AAD
                        raise TamperDetected() from None
                    raise
        res = {**fields, "status": "success", "out_size": os.path.getsize(out_path),
               "duration_s": round(time.perf_counter() - t0, 6), "cpu_s": round(time.process_time() - c0, 6)}
        log_event("decrypt", logging.INFO, logger, **res)
        return res
    except AesLabError as e:
        _log_fail(logger, fields, e, t0)
        raise
    except OSError as e:
        err = FileIOError(f"Помилка вводу-виводу: {e.strerror or e}")
        _log_fail(logger, fields, err, t0)
        raise err from None


def _log_fail(logger, fields, e: AesLabError, t0) -> None:
    level = logging.ERROR if e.code in {"TAMPER_DETECTED", "AUTH_FAILED", "KEY_REVOKED", "NONCE_REUSE",
                                        "BAD_MAGIC", "BAD_FORMAT", "TRUNCATED", "KEY_MISMATCH"} else logging.WARNING
    log_event(fields["op"], level, logger, **fields, status="fail", error_code=e.code, error=e.message,
              duration_s=round(time.perf_counter() - t0, 6))
