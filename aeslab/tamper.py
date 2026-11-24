"""Імітація підміни зашифрованих файлів і перевірка виявлення втручання.

Для кожного автентифікованого режиму виконуються систематичні сценарії атак, для небезпечних
режимів без MAC (CBC/CTR) — демонстрація непомітної підміни та атаки padding oracle.
Результати: outputs/tamper_results.md, outputs/tamper_results.csv; події — у журналі.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import secrets
import shutil
import string
import struct
import sys
import tempfile

from . import config
from .engine import RawKeyContext, decrypt_file, encrypt_file
from .errors import AesLabError
from .insecure_demo import (cbc_nomac_decrypt, cbc_nomac_encrypt, ctr_nomac, make_oracle,
                            padding_oracle_attack_last_block)
from .keystore import KeyStore
from .logging_setup import get_logger, log_event
from .modes import REGISTRY
from .params import CipherParams

SEG = 4096          # невеликі сегменти, щоб файл мав кілька сегментів


def _rand_password() -> str:
    """Випадковий пароль для демонстраційного ключа (ніде не виводиться і не зберігається)."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return "Aa1!" + "".join(secrets.choice(alphabet) for _ in range(20))


def _split(data: bytes):
    hlen = struct.unpack(">H", data[5:7])[0]
    return 7 + hlen, json.loads(data[7:7 + hlen])


def _rebuild(data: bytes, mutate) -> bytes:
    """Змінити поля JSON-заголовка і коректно перепакувати (атакувальник знає формат)."""
    hl, hdr = _split(data)
    mutate(hdr)
    blob = json.dumps(hdr, separators=(",", ":"), sort_keys=True).encode()
    return data[:5] + struct.pack(">H", len(blob)) + blob + data[hl:]


def _flip(data: bytes, pos: int, mask: int = 0x01) -> bytes:
    b = bytearray(data)
    b[pos] ^= mask
    return bytes(b)


MODE_SWAP = {"aes-cbc-hmac": ("aes-ctr-hmac", "none"), "aes-ctr-hmac": ("aes-cfb-hmac", "none"),
             "aes-cfb-hmac": ("aes-cbc-hmac", "pkcs7"), "chacha20-poly1305": ("aes-gcm-siv", "none"),
             "aes-gcm-siv": ("chacha20-poly1305", "none")}


def scenarios(mode: str, other_key_id: str):
    """Сценарії модифікації файлу: (id, опис, функція(data)->data)."""
    seg = REGISTRY[mode].spec.family == "aead-segmented"

    def body_mid(d):
        hl, _ = _split(d)
        return _flip(d, hl + (len(d) - hl) // 2)

    def body_first(d):
        hl, _ = _split(d)
        return _flip(d, hl, 0x80)

    def header_iv(d):
        def m(h):
            h["iv"] = ("1" if h["iv"][0] != "1" else "2") + h["iv"][1:]
        return _rebuild(d, m)

    def header_algo(d):
        if mode == "aes-gcm":
            return _rebuild(d, lambda h: h.update(tag=12))        # спроба «понизити» довжину тегу
        tgt, pad = MODE_SWAP[mode]
        return _rebuild(d, lambda h: h.update(mode=tgt, pad=pad))

    def header_keyid(d):
        return _rebuild(d, lambda h: h.update(key_id=other_key_id))

    def swap(d):
        hl, _ = _split(d)
        n = SEG + 16 if seg else 16
        a, b = hl, hl + n
        return d[:a] + d[b:b + n] + d[a:b] + d[b + n:]

    def cut_segment(d):
        hl, _ = _split(d)
        body = len(d) - hl
        if seg:
            n = SEG + 16
            full = body // n if body % n else body // n - 1
            return d[:hl + full * n] if full else d[:hl + n // 2]
        return d[:hl + body // 2]

    return [
        ("T01", "Інверсія біта в середині шифротексту", body_mid),
        ("T02", "Зміна першого байта шифротексту", body_first),
        ("T03", "Зміна останнього байта тегу/HMAC", lambda d: _flip(d, len(d) - 1)),
        ("T04", "Підміна IV/nonce у заголовку", header_iv),
        ("T05", "Підміна алгоритму/параметрів у заголовку (downgrade)", header_algo),
        ("T06", "Підміна key_id у заголовку", header_keyid),
        ("T07", "Пошкодження сигнатури MAGIC", lambda d: b"XLAB" + d[4:]),
        ("T08", "Обрізання хвоста (−5 байтів)", lambda d: d[:-5]),
        ("T09", "Обрізання тіла (половина / по межі сегмента STREAM)", cut_segment),
        ("T10", "Обрізання до неповного заголовка", lambda d: d[:10]),
        ("T11", "Додавання 16 байтів у кінець", lambda d: d + secrets.token_bytes(16)),
        ("T12", "Перестановка блоків 0↔1 (для STREAM — сегментів)", swap),
    ]


def run(outdir: str, sample: str | None, log_path: str | None) -> list[dict]:
    logger = get_logger(log_path)
    work = tempfile.mkdtemp(prefix="tamper_", dir=os.path.abspath(outdir))
    rows: list[dict] = []
    try:
        ks = KeyStore(os.path.join(work, "keystore.json"))
        pw, pw2 = _rand_password(), _rand_password()
        main_e = ks.create("tamper-demo", pw, expires_days=30)
        other_e = ks.create("tamper-other", pw2, expires_days=30)
        ctx = ks.unlock(main_e, pw)
        plain = os.path.join(work, "plain.bin")
        base = open(sample, "rb").read() if sample else b""
        with open(plain, "wb") as f:
            f.write((base or b"Confidential report line. ") * max(1, 20000 // max(1, len(base) or 26)))
        out = os.path.join(work, "out.dec")
        aad = b"doc-id=42;owner=lab"

        def attempt(sid, title, mode, path, c=ctx, use_aad=aad, comment=""):
            if os.path.exists(out):
                os.remove(out)
            log_event("tamper_test", logger=logger, scenario=sid, mode=mode, status="start")
            code, exit_code = "—", 0
            try:
                decrypt_file(path, out, c, aad=use_aad, ks=ks, logger=logger, hash_input=False)
                detected = False
            except AesLabError as e:
                detected, code, exit_code = True, e.code, e.exit_code
            rows.append({"id": sid, "scenario": title, "mode": mode, "detected": "так" if detected else "НІ",
                         "error_code": code, "exit_code": exit_code,
                         "output_created": "так" if os.path.exists(out) else "ні", "comment": comment})

        for mode in REGISTRY:
            enc = os.path.join(work, f"{mode}.enc")
            p = CipherParams(mode=mode, aad=aad, segment_size=SEG if REGISTRY[mode].spec.family == "aead-segmented" else None)
            encrypt_file(plain, enc, ctx, p, ks=ks, logger=logger, hash_output=False)
            data = open(enc, "rb").read()
            attempt("T00", "Контроль: немодифікований файл", mode, enc, comment="очікується успіх")
            for sid, title, fn in scenarios(mode, other_e["key_id"]):
                bad = os.path.join(work, f"{mode}.{sid}.enc")
                with open(bad, "wb") as f:
                    f.write(fn(data))
                attempt(sid, title, mode, bad)
            # Неправильна AAD
            attempt("T13", "Неправильна AAD (контекст)", mode, enc, use_aad=b"doc-id=43;owner=lab")
            # Неправильний пароль — виявляється verifier'ом ДО дешифрування
            try:
                ks.unlock(main_e, pw + "x")
                rows.append({"id": "T14", "scenario": "Неправильний пароль", "mode": mode, "detected": "НІ",
                             "error_code": "—", "exit_code": 0, "output_created": "—", "comment": ""})
            except AesLabError as e:
                log_event("key_unlock", logger=logger, key_id=main_e["key_id"], status="fail", error_code=e.code)
                rows.append({"id": "T14", "scenario": "Неправильний пароль", "mode": mode, "detected": "так",
                             "error_code": e.code, "exit_code": e.exit_code, "output_created": "ні",
                             "comment": "verifier у keystore, дешифрування не починалось"})
            # Неправильний ключ в обхід verifier'а: AUTH_FAILED (неможливо відрізнити від підміни)
            attempt("T15", "Неправильний ключ (в обхід перевірки пароля)", mode, enc,
                    c=RawKeyContext(key_id=main_e["key_id"], master=secrets.token_bytes(32)),
                    comment="тег не збігся: підміна чи хибний ключ — нерозрізненно")

        # --- Політики ключів
        g = os.path.join(work, "aes-gcm.enc")
        # Повтор nonce: «зламаний» генератор повертає той самий nonce
        mode_obj = REGISTRY["aes-gcm"]
        fixed = secrets.token_bytes(12)
        orig = mode_obj.new_iv
        mode_obj.new_iv = lambda p: fixed
        try:
            encrypt_file(plain, os.path.join(work, "n1.enc"), ctx, CipherParams(mode="aes-gcm"), ks=ks, logger=logger,
                         hash_output=False)
            try:
                encrypt_file(plain, os.path.join(work, "n2.enc"), ctx, CipherParams(mode="aes-gcm"), ks=ks,
                             logger=logger, hash_output=False)
                rows.append({"id": "K01", "scenario": "Повторне використання nonce (зламаний RNG)", "mode": "aes-gcm",
                             "detected": "НІ", "error_code": "—", "exit_code": 0, "output_created": "так", "comment": ""})
            except AesLabError as e:
                rows.append({"id": "K01", "scenario": "Повторне використання nonce (зламаний RNG)", "mode": "aes-gcm",
                             "detected": "так", "error_code": e.code, "exit_code": e.exit_code,
                             "output_created": "так" if os.path.exists(os.path.join(work, "n2.enc")) else "ні",
                             "comment": "відбиток nonce уже є в keystore — шифрування заблоковано"})
        finally:
            mode_obj.new_iv = orig
        # Відкликаний ключ
        ks.set_status(main_e, "revoked", "демонстрація компрометації")
        attempt("K02", "Дешифрування відкликаним ключем", "aes-gcm", g, comment="статус revoked")
        try:
            encrypt_file(plain, os.path.join(work, "r.enc"), ctx, CipherParams(), ks=ks, logger=logger)
            rows.append({"id": "K03", "scenario": "Шифрування відкликаним ключем", "mode": "aes-gcm", "detected": "НІ",
                         "error_code": "—", "exit_code": 0, "output_created": "так", "comment": ""})
        except AesLabError as e:
            rows.append({"id": "K03", "scenario": "Шифрування відкликаним ключем", "mode": "aes-gcm", "detected": "так",
                         "error_code": e.code, "exit_code": e.exit_code, "output_created": "ні", "comment": ""})
        ctx.wipe()
        insecure = insecure_demos(work, logger)
        rows += insecure["rows"]
        rows_insecure_details = insecure["details"]
    finally:
        shutil.rmtree(work, ignore_errors=True)
    write_reports(rows, rows_insecure_details, outdir)
    return rows


def insecure_demos(work: str, logger) -> dict:
    """Демонстрації для режимів БЕЗ MAC (непомітна підміна) і атака padding oracle."""
    rows, details = [], {}
    key, iv = secrets.token_bytes(32), secrets.token_bytes(16)
    msg = b"AMOUNT=0000100;;TO=UA2132231300000260072335660;MEMO=salary-2026-11"
    # 1) CBC без MAC: XOR у IV змінює перший блок відкритого тексту передбачувано
    ct = cbc_nomac_encrypt(key, iv, msg)
    delta = bytes(a ^ b for a, b in zip(b"AMOUNT=0000100;;", b"AMOUNT=9999100;;"))
    forged_iv = bytes(a ^ b for a, b in zip(iv, delta))
    pt = cbc_nomac_decrypt(key, forged_iv, ct)
    details["cbc_bitflip"] = (msg[:16].decode(), pt[:16].decode())
    rows.append({"id": "I01", "scenario": "CBC без MAC: bit-flipping через IV (сума 0000100→9999100)",
                 "mode": "aes-cbc (без MAC, демо)", "detected": "НІ", "error_code": "—", "exit_code": 0,
                 "output_created": "так", "comment": f"розшифровано без помилок: «{pt[:16].decode()}»"})
    # 2) CBC без MAC: зміна блоку шифротексту C1 → контрольована зміна P2, P1 — «сміття»
    ct2 = bytearray(ct)
    for i, (a, b) in enumerate(zip(b"TO=UA21322313000", b"TO=UA99999999000")):
        ct2[i] ^= a ^ b
    pt2 = cbc_nomac_decrypt(key, iv, bytes(ct2))
    details["cbc_block"] = pt2[16:32].decode(errors="replace")
    rows.append({"id": "I02", "scenario": "CBC без MAC: зміна блоку C1 → підміна рахунку в P2",
                 "mode": "aes-cbc (без MAC, демо)", "detected": "НІ", "error_code": "—", "exit_code": 0,
                 "output_created": "так", "comment": f"P2 = «{pt2[16:32].decode(errors='replace')}», P1 зіпсовано"})
    # 3) CTR без MAC: довільна точкова підміна
    nonce = secrets.token_bytes(16)
    c = bytearray(ctr_nomac(key, nonce, msg))
    for i, (a, b) in enumerate(zip(b"0000100", b"9999999")):
        c[7 + i] ^= a ^ b
    p3 = ctr_nomac(key, nonce, bytes(c))
    rows.append({"id": "I03", "scenario": "CTR без MAC: точкова підміна суми", "mode": "aes-ctr (без MAC, демо)",
                 "detected": "НІ", "error_code": "—", "exit_code": 0, "output_created": "так",
                 "comment": f"«{p3[:16].decode()}», решта тексту не пошкоджена"})
    # 4) Padding oracle проти CBC без MAC
    secret = b"PIN=4921;CARD=5375-4111-0000-1234;CVV=987;EXP=1"    # 47 B: останній блок = 15 B даних + 0x01
    ct4 = cbc_nomac_encrypt(key, iv, secret)
    recovered, q = padding_oracle_attack_last_block(make_oracle(key), iv, ct4)
    recovered = recovered[:-recovered[-1]]                       # зняти PKCS#7
    details["oracle"] = (recovered, q)
    rows.append({"id": "I04", "scenario": "Padding oracle: відновлення останнього блоку без ключа",
                 "mode": "aes-cbc (без MAC, демо)", "detected": "НІ", "error_code": "BAD_PADDING (оракул)", "exit_code": 22,
                 "output_created": "—", "comment": f"відновлено {recovered!r} за {q} запитів"})
    log_event("insecure_demo", 30, logger, scenario="padding_oracle", mode="aes-cbc-nomac", status="success",
              queries=q)
    # 5) Та сама атака проти AES-CBC+HMAC (EtM): оракул завжди «невдача» → атака неможлива
    rk = RawKeyContext(key_id="oracle-test", master=secrets.token_bytes(32))
    src = os.path.join(work, "secret.txt")
    with open(src, "wb") as f:
        f.write(secret)
    encf = os.path.join(work, "secret.cbc")
    encrypt_file(src, encf, rk, CipherParams(mode="aes-cbc-hmac"), logger=logger, hash_output=False)
    raw = open(encf, "rb").read()
    hl, hdr = _split(raw)
    body = raw[hl:-32]
    codes = set()

    def etm_oracle(prev: bytes, target: bytes) -> bool:
        forged = raw[:hl] + body[:-32] + prev + target + raw[-32:]
        fp = os.path.join(work, "forged.cbc")
        with open(fp, "wb") as f:
            f.write(forged)
        try:
            decrypt_file(fp, os.path.join(work, "forged.out"), rk, logger=logger, hash_input=False)
            return True
        except AesLabError as e:
            codes.add(e.code)
            return False

    try:
        padding_oracle_attack_last_block(etm_oracle, bytes.fromhex(hdr["iv"]), body)
        ok = False
    except RuntimeError:
        ok = True
    rows.append({"id": "I05", "scenario": "Padding oracle проти AES-CBC+HMAC (EtM)", "mode": "aes-cbc-hmac",
                 "detected": "так" if ok else "НІ", "error_code": ",".join(sorted(codes)) or "—", "exit_code": 21,
                 "output_created": "ні", "comment": "HMAC перевіряється до зняття доповнення — оракул не дає інформації"})
    return {"rows": rows, "details": details}


def write_reports(rows, details, outdir):
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "tamper_results.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    modes = list(REGISTRY)
    ids = list(dict.fromkeys(r["id"] for r in rows if r["id"].startswith("T")))
    idx = {(r["id"], r["mode"]): r for r in rows}
    L = ["# Результати імітації підміни (tamper_demo)", "",
         "Для кожного автентифікованого режиму зашифровано файл ≈20 KB (з AAD), потім файл модифіковано й "
         "виконано дешифрування через той самий програмний шлях, що й у CLI. «Вихід створено: ні» — підтверджує "
         "атомарність (жодного неавтентифікованого відкритого тексту на диску).", "",
         "## 1. Матриця виявлення (код помилки для кожного режиму)", "",
         "| ID | Сценарій | " + " | ".join(modes) + " |", "|---|---|" + "---|" * len(modes)]
    for i in ids:
        title = next(r["scenario"] for r in rows if r["id"] == i)
        cells = []
        for m in modes:
            r = idx.get((i, m))
            if not r:
                cells.append("—")
            elif i == "T00":
                cells.append("✅ OK" if r["detected"] == "НІ" else f"❌ {r['error_code']}")
            else:
                cells.append(("✅ " if r["detected"] == "так" else "❌ НЕ ВИЯВЛЕНО ") + r["error_code"])
        L.append(f"| {i} | {title} | " + " | ".join(cells) + " |")
    t = [r for r in rows if r["id"].startswith("T") and r["id"] != "T00"]
    det = sum(r["detected"] == "так" for r in t)
    leaked = sum(r["output_created"] == "так" for r in t)
    L += ["", f"**Підсумок:** виявлено {det} з {len(t)} атак на автентифіковані режими; "
              f"вихідний файл створено у {leaked} випадках з {len(t)}.", "",
          "## 2. Політики ключів та небезпечні режими", "",
          "| ID | Сценарій | Режим | Виявлено | Код | Вихід створено | Коментар |", "|---|---|---|:--:|---|:--:|---|"]
    for r in rows:
        if r["id"][0] in "KI":
            L.append(f"| {r['id']} | {r['scenario']} | {r['mode']} | {r['detected']} | {r['error_code']} | "
                     f"{r['output_created']} | {r['comment']} |")
    if details:
        o, n = details["cbc_bitflip"]
        rec, q = details["oracle"]
        L += ["", "## 3. Деталі демонстрацій без MAC", "",
              f"* **CBC bit-flipping:** оригінальний блок `{o}` → після XOR в IV `{n}`; дешифрування успішне, "
              "доповнення коректне — програма без MAC не має жодного способу помітити підміну.",
              f"* **Зміна блоку C1:** другий блок став `{details['cbc_block']}` (рахунок отримувача підмінено), перший — сміття.",
              f"* **Padding oracle:** лише за відповіддю «доповнення коректне/некоректне» відновлено останній блок "
              f"`{rec!r}` за {q} запитів (≤ 16·256 = 4096) без знання ключа.",
              "* **AES-CBC+HMAC:** та сама атака зупиняється на першому байті: кожен підроблений шифротекст відхиляється "
              "ще на перевірці HMAC (код однаковий для всіх запитів), тож оракул не існує."]
    L += ["", "## 4. Пояснення кодів", "",
          "* `TAMPER_DETECTED` — пароль підтверджено verifier'ом і key_id збігся, отже тег не зійшовся через зміну даних/заголовка або іншу AAD.",
          "* `AUTH_FAILED` — тег не зійшовся, а ключ не підтверджено (наприклад, «сирий» ключ): криптографічно неможливо "
          "відрізнити неправильний ключ від підміни — обидва випадки дають випадковий тег.",
          "* `BAD_FORMAT` — заголовок змінено так, що параметри стали неприпустимими (до криптоперевірки).",
          "* `KEY_MISMATCH` / `KEY_NOT_FOUND` — key_id у заголовку не відповідає ключу.",
          "* `TRUNCATED` — файл обрізано (неповний заголовок або відсутній фінальний сегмент STREAM).",
          "* `BAD_MAGIC` — файл не є контейнером AES-Lab.",
          "* `WRONG_PASSWORD` — неправильний пароль виявлено до дешифрування (verifier).",
          "* `NONCE_REUSE`, `KEY_REVOKED` — спрацювали політики життєвого циклу ключів."]
    with open(os.path.join(outdir, "tamper_results.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="tamper_demo.py", description="Імітація підміни зашифрованих файлів")
    ap.add_argument("--outdir", default="outputs")
    ap.add_argument("--sample", default="data/sample.txt" if os.path.exists("data/sample.txt") else None)
    ap.add_argument("--log-file", default=config.LOG_PATH)
    a = ap.parse_args(argv)
    os.makedirs(a.outdir, exist_ok=True)
    rows = run(a.outdir, a.sample, a.log_file)
    t = [r for r in rows if r["id"].startswith(("T", "K")) and r["id"] != "T00"]
    det = sum(r["detected"] == "так" for r in t)
    ctrl = all(r["detected"] == "НІ" for r in rows if r["id"] == "T00")
    print(f"Автентифіковані режими: виявлено {det}/{len(t)} атак; контрольні файли розшифровано: {'так' if ctrl else 'НІ'}")
    for r in rows:
        if r["id"].startswith("I"):
            print(f"  {r['id']} {r['scenario']}: виявлено={r['detected']} ({r['comment']})")
    print(f"Результати → {a.outdir}/tamper_results.md, {a.outdir}/tamper_results.csv")
    return 0 if det == len(t) and ctrl else 1


if __name__ == "__main__":
    sys.exit(main())
