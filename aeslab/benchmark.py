"""Бенчмарк: швидкодія та ресурси шифрування/дешифрування файлів різного розміру для всіх режимів,
а також вартість KDF (PBKDF2 при різних ітераціях, scrypt).

Результати: outputs/benchmark_results.csv, outputs/benchmark_results.md, outputs/*.png
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import logging
import os
import platform
try:
    import resource
except ImportError:  # Windows
    resource = None
import statistics
import sys
import time
import tracemalloc
from datetime import datetime, timezone

import cryptography
from cryptography.hazmat.backends.openssl import backend as ossl

from .engine import RawKeyContext, decrypt_file, encrypt_file
from .keystore import run_kdf
from .modes import REGISTRY, list_modes
from .params import CipherParams

UNITS = {"kb": 1024, "mb": 1024 ** 2, "gb": 1024 ** 3, "b": 1}
MiB = 1024 * 1024

# Якісна оцінка безпеки (для таблиці порівняння)
SECURITY = {
    "aes-gcm": dict(kind="AEAD", integrity="так (GHASH-тег)", misuse="катастрофічний (втрата автентичності, XOR текстів)",
                    parallel="так / так", padding="ні", passes="1 / 1", limit="2^32 повідомлень (випадк. nonce), 64 GiB/повід.",
                    fips="так (SP 800-38D)", score=5),
    "aes-cbc-hmac": dict(kind="EtM", integrity="так (HMAC-SHA256)", misuse="повтор IV: витік спільних префіксів",
                         parallel="ні / так", padding="так (PKCS7/X9.23/7816)", passes="1 / 2",
                         limit="~2^64 блоків (birthday) — практично без обмежень", fips="так (SP 800-38A + FIPS 198)", score=4),
    "aes-ctr-hmac": dict(kind="EtM", integrity="так (HMAC-SHA256)", misuse="катастрофічний (повтор гами)",
                         parallel="так / так", padding="ні", passes="1 / 2", limit="2^64 блоків на nonce",
                         fips="так (SP 800-38A + FIPS 198)", score=4),
    "aes-cfb-hmac": dict(kind="EtM", integrity="так (HMAC-SHA256)", misuse="повтор IV: витік першого блоку",
                         parallel="ні / так", padding="ні", passes="1 / 2", limit="~2^64 блоків",
                         fips="так (SP 800-38A)", score=3),
    "chacha20-poly1305": dict(kind="AEAD (STREAM)", integrity="так (Poly1305 на сегмент)",
                              misuse="катастрофічний (як GCM)", parallel="так* / так*", padding="ні", passes="1 / 1",
                              limit="2^32 сегментів × 64 KiB; nonce-префікс 56 біт", fips="ні (RFC 8439)", score=5),
    "aes-gcm-siv": dict(kind="AEAD (STREAM)", integrity="так (POLYVAL-тег на сегмент)",
                        misuse="стійкий: розкриває лише рівність сегментів", parallel="ні / так*",
                        padding="ні", passes="2 / 1", limit="2^32 сегментів; ~2^48 повідомлень на ключ",
                        fips="ні (RFC 8452)", score=5),
}


def parse_size(s: str) -> int:
    s = s.strip().lower()
    for u in ("gb", "mb", "kb", "b"):
        if s.endswith(u):
            return int(float(s[: -len(u)]) * UNITS[u])
    return int(s)


def human(n: int) -> str:
    for u, d in (("MB", MiB), ("KB", 1024)):
        if n >= d:
            v = n / d
            return f"{v:.0f} {u}" if v == int(v) else f"{v:.1f} {u}"
    return f"{n} B"


def ensure_file(path: str, size: int) -> None:
    """Згенерувати тестовий файл випадкових даних (не зберігається в репозиторії)."""
    if os.path.exists(path) and os.path.getsize(path) == size:
        return
    with open(path, "wb") as f:
        left = size
        while left:
            n = min(left, 4 * MiB)
            f.write(os.urandom(n))
            left -= n


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while b := f.read(MiB):
            h.update(b)
    return h.hexdigest()


def env_info() -> dict:
    cpu = platform.processor() or "?"
    flags = ""
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name") and cpu in ("?", "x86_64", ""):
                    cpu = line.split(":", 1)[1].strip()
                if line.startswith("flags"):
                    flags = line
                    break
    except OSError:
        pass
    return {"cpu": cpu, "aes_ni": "aes" in flags.split(), "pclmul": "pclmulqdq" in flags.split(),
            "cores": os.cpu_count(), "python": platform.python_version(), "os": platform.platform(),
            "cryptography": cryptography.__version__, "openssl": ossl.openssl_version_text(),
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}


def bench_files(sizes, modes, repeat, key_bits, datadir, warmup=True):
    """Виміри для кожного (розмір, режим). Повертає список агрегованих рядків."""
    quiet = logging.getLogger("aeslab.bench")
    quiet.addHandler(logging.NullHandler())
    quiet.propagate = False
    os.makedirs(datadir, exist_ok=True)
    rows = []
    for size in sizes:
        src = os.path.join(datadir, f"plain_{size}.bin")
        ensure_file(src, size)
        src_hash = sha(src)
        for mname in modes:
            spec = REGISTRY[mname].spec
            bits = key_bits if key_bits in spec.key_bits else max(spec.key_bits)
            ctx = RawKeyContext(key_id="bench", master=os.urandom(32))
            p = CipherParams(mode=mname, key_bits=bits)
            enc, dec = os.path.join(datadir, "tmp.enc"), os.path.join(datadir, "tmp.dec")
            if warmup:
                encrypt_file(src, enc, ctx, p, logger=quiet, hash_output=False)
            et, ec, dt, dc = [], [], [], []
            for _ in range(repeat):
                t0, c0 = time.perf_counter(), time.process_time()
                encrypt_file(src, enc, ctx, p, logger=quiet, hash_output=False)
                et.append(time.perf_counter() - t0); ec.append(time.process_time() - c0)
                t0, c0 = time.perf_counter(), time.process_time()
                decrypt_file(enc, dec, ctx, logger=quiet, hash_input=False)
                dt.append(time.perf_counter() - t0); dc.append(time.process_time() - c0)
            ok = sha(dec) == src_hash
            out_size = os.path.getsize(enc)
            # Окремий прохід для пікової пам'яті (tracemalloc уповільнює, тому не змішуємо з таймінгами)
            tracemalloc.start()
            encrypt_file(src, enc, ctx, p, logger=quiet, hash_output=False)
            _, peak_e = tracemalloc.get_traced_memory()
            tracemalloc.reset_peak()
            decrypt_file(enc, dec, ctx, logger=quiet, hash_input=False)
            _, peak_d = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            m = statistics.mean
            sd = (lambda x: statistics.stdev(x) if len(x) > 1 else 0.0)
            row = {
                "size_bytes": size, "size": human(size), "mode": mname, "key_bits": bits, "repeat": repeat,
                "enc_mean_s": m(et), "enc_std_s": sd(et), "dec_mean_s": m(dt), "dec_std_s": sd(dt),
                "enc_mib_s": size / MiB / m(et), "dec_mib_s": size / MiB / m(dt),
                "enc_cpu_s": m(ec), "dec_cpu_s": m(dc),
                "enc_peak_mem_kib": peak_e / 1024, "dec_peak_mem_kib": peak_d / 1024,
                "out_size": out_size, "overhead_bytes": out_size - size,
                "overhead_pct": (out_size - size) / size * 100 if size else 0.0, "roundtrip_ok": ok,
                "fsync": __import__("aeslab.engine", fromlist=["FSYNC"]).FSYNC,
            }
            rows.append(row)
            print(f"  {human(size):>7} {mname:<18} enc {row['enc_mib_s']:9.1f} MiB/s  dec {row['dec_mib_s']:9.1f} MiB/s  "
                  f"+{row['overhead_bytes']} B  {'OK' if ok else 'FAIL'}", flush=True)
            for f in (enc, dec):
                if os.path.exists(f):
                    os.remove(f)
    return rows


def bench_kdf(iterations_list, repeat=3):
    rows = []
    salt = os.urandom(16)
    for it in iterations_list:
        ts = []
        for _ in range(repeat):
            t0 = time.perf_counter()
            run_kdf("Bench-Passw0rd!", salt, {"name": "pbkdf2-hmac-sha256", "iterations": it})
            ts.append(time.perf_counter() - t0)
        rows.append({"kdf": "PBKDF2-HMAC-SHA256", "param": f"{it} ітерацій", "iterations": it,
                     "mean_s": statistics.mean(ts), "std_s": statistics.stdev(ts) if len(ts) > 1 else 0,
                     "guesses_per_s_1core": 1 / statistics.mean(ts)})
        print(f"  PBKDF2 {it:>9} ітерацій: {statistics.mean(ts) * 1000:8.1f} мс", flush=True)
    for n in (2 ** 14, 2 ** 15, 2 ** 17):
        ts = []
        for _ in range(repeat):
            t0 = time.perf_counter()
            run_kdf("Bench-Passw0rd!", salt, {"name": "scrypt", "n": n, "r": 8, "p": 1})
            ts.append(time.perf_counter() - t0)
        rows.append({"kdf": "scrypt", "param": f"N=2^{n.bit_length() - 1}, r=8, p=1 (~{128 * 8 * n // MiB} MiB RAM)",
                     "iterations": n, "mean_s": statistics.mean(ts), "std_s": statistics.stdev(ts) if len(ts) > 1 else 0,
                     "guesses_per_s_1core": 1 / statistics.mean(ts)})
        print(f"  scrypt N=2^{n.bit_length() - 1}: {statistics.mean(ts) * 1000:8.1f} мс", flush=True)
    return rows


def write_csv(rows, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        for r in rows:
            w.writerow({k: (f"{v:.6f}" if isinstance(v, float) else v) for k, v in r.items()})


def plots(rows, kdf_rows, outdir):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib не встановлено — графіки пропущено")
        return []
    files = []
    modes = list(dict.fromkeys(r["mode"] for r in rows))
    for op, title in (("enc", "Шифрування"), ("dec", "Дешифрування")):
        fig, ax = plt.subplots(figsize=(9, 5.5))
        for mname in modes:
            rs = [r for r in rows if r["mode"] == mname]
            ax.plot([r["size_bytes"] for r in rs], [r[f"{op}_mib_s"] for r in rs], marker="o", label=mname)
        ax.set_xscale("log"); ax.set_yscale("log")
        ax.set_xlabel("Розмір файлу, байт (лог.)"); ax.set_ylabel("Пропускна здатність, MiB/s (лог.)")
        ax.set_title(f"{title}: пропускна здатність за режимами"); ax.grid(True, which="both", alpha=.3); ax.legend()
        fn = os.path.join(outdir, f"benchmark_throughput_{op}.png"); fig.tight_layout(); fig.savefig(fn, dpi=130)
        plt.close(fig); files.append(fn)
    big = max(r["size_bytes"] for r in rows)
    rs = [r for r in rows if r["size_bytes"] == big]
    fig, ax = plt.subplots(figsize=(9, 5))
    x = range(len(rs)); w = .38
    ax.bar([i - w / 2 for i in x], [r["enc_mib_s"] for r in rs], w, label="шифрування")
    ax.bar([i + w / 2 for i in x], [r["dec_mib_s"] for r in rs], w, label="дешифрування")
    ax.set_xticks(list(x)); ax.set_xticklabels([r["mode"] for r in rs], rotation=20)
    ax.set_ylabel("MiB/s"); ax.set_title(f"Порівняння режимів на файлі {human(big)}"); ax.legend(); ax.grid(axis="y", alpha=.3)
    fn = os.path.join(outdir, "benchmark_modes_largest.png"); fig.tight_layout(); fig.savefig(fn, dpi=130)
    plt.close(fig); files.append(fn)
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar([r["mode"] for r in rs], [r["dec_peak_mem_kib"] / 1024 for r in rs], color="tab:orange", label="дешифрування")
    ax.bar([r["mode"] for r in rs], [r["enc_peak_mem_kib"] / 1024 for r in rs], color="tab:blue", alpha=.7, label="шифрування")
    ax.set_ylabel("Пікова пам'ять (tracemalloc), MiB"); ax.set_title(f"Пам'ять на файлі {human(big)}")
    ax.legend(); plt.setp(ax.get_xticklabels(), rotation=20)
    fn = os.path.join(outdir, "benchmark_memory.png"); fig.tight_layout(); fig.savefig(fn, dpi=130)
    plt.close(fig); files.append(fn)
    if kdf_rows:
        pr = [r for r in kdf_rows if r["kdf"].startswith("PBKDF2")]
        fig, ax = plt.subplots(figsize=(8, 4.5))
        ax.plot([r["iterations"] for r in pr], [r["mean_s"] * 1000 for r in pr], marker="o")
        ax.set_xlabel("Ітерації PBKDF2-HMAC-SHA256"); ax.set_ylabel("Час виведення ключа, мс")
        ax.set_title("Вартість PBKDF2 (лінійна від кількості ітерацій)"); ax.grid(alpha=.3)
        fn = os.path.join(outdir, "benchmark_kdf.png"); fig.tight_layout(); fig.savefig(fn, dpi=130)
        plt.close(fig); files.append(fn)
    return files


def write_md(rows, kdf_rows, env, path, pngs):
    L = ["# Результати бенчмарку AES-Lab", "",
         f"Дата: {env['date']} · CPU: {env['cpu']} ({env['cores']} логічних ядер, AES-NI: "
         f"{'так' if env['aes_ni'] else 'ні'}, PCLMULQDQ: {'так' if env['pclmul'] else 'ні'}) · Python {env['python']} · "
         f"cryptography {env['cryptography']} · {env['openssl']}", "",
         f"Методика: файли випадкових даних; для кожного розміру і режиму — прогрів + {rows[0]['repeat']} повторів "
         "шифрування й дешифрування повного файлу з атомарним записом (тимчасовий файл + os.replace); "
         f"fsync {'увімкнено' if rows[0].get('fsync') else 'вимкнено (вимірюється обчислювальна складова + запис у кеш ФС; у CLI fsync додає затримку пристрою)'}. "
         "Час — `perf_counter` (середнє ± ст. відхилення), CPU — `process_time`, пам'ять — пік `tracemalloc` в окремому "
         "проході (Python-алокації; внутрішні буфери OpenSSL не враховуються). Ключі — 256 біт (сирий ключ без KDF, "
         "щоб виміряти саме шифр). MiB/s = розмір / середній час. Правильність кожного round-trip перевірено SHA-256.", ""]
    L += ["## 1. Повна таблиця вимірів", "",
          "| Розмір | Режим | Шифр., мс (±σ) | Дешифр., мс (±σ) | Шифр., MiB/s | Дешифр., MiB/s | CPU шифр./дешифр., мс | "
          "Пік пам'яті шифр./дешифр., KiB | Накладні, B (%) | OK |",
          "|---|---|---:|---:|---:|---:|---:|---:|---:|:--:|"]
    for r in rows:
        L.append(f"| {r['size']} | {r['mode']} | {r['enc_mean_s'] * 1000:.2f} ± {r['enc_std_s'] * 1000:.2f} | "
                 f"{r['dec_mean_s'] * 1000:.2f} ± {r['dec_std_s'] * 1000:.2f} | {r['enc_mib_s']:.1f} | {r['dec_mib_s']:.1f} | "
                 f"{r['enc_cpu_s'] * 1000:.1f} / {r['dec_cpu_s'] * 1000:.1f} | {r['enc_peak_mem_kib']:.0f} / {r['dec_peak_mem_kib']:.0f} | "
                 f"{r['overhead_bytes']} ({r['overhead_pct']:.2f}%) | {'✅' if r['roundtrip_ok'] else '❌'} |")
    big = max(r["size_bytes"] for r in rows)
    rs = sorted([r for r in rows if r["size_bytes"] == big], key=lambda r: -(r["enc_mib_s"] + r["dec_mib_s"]))
    L += ["", f"## 2. Узагальнена таблиця (файл {human(big)}, впорядковано за швидкодією)", "",
          "| Місце | Режим | Шифр., MiB/s | Дешифр., MiB/s | Відносно найшвидшого | Тип | Цілісність | Стійкість до повтору nonce/IV | Оцінка безпеки (1–5) |",
          "|:--:|---|---:|---:|---:|---|---|---|:--:|"]
    best = rs[0]["enc_mib_s"] + rs[0]["dec_mib_s"]
    for i, r in enumerate(rs, 1):
        s = SECURITY.get(r["mode"], {})
        L.append(f"| {i} | {r['mode']} | {r['enc_mib_s']:.1f} | {r['dec_mib_s']:.1f} | "
                 f"{(r['enc_mib_s'] + r['dec_mib_s']) / best * 100:.0f}% | {s.get('kind', '')} | {s.get('integrity', '')} | "
                 f"{s.get('misuse', '')} | {s.get('score', '')} |")
    L += ["", "## 3. Порівняння режимів за рівнем безпеки", "",
          "| Режим | Тип | Паралелізм шифр./дешифр. | Доповнення | Проходів шифр./дешифр. | Обмеження обсягу | Стандарт | Ризики |",
          "|---|---|---|---|---|---|---|---|"]
    for s in list_modes():
        q = SECURITY.get(s.name, {})
        L.append(f"| {s.name} | {q.get('kind', '')} | {q.get('parallel', '')} | {q.get('padding', '')} | {q.get('passes', '')} | "
                 f"{q.get('limit', '')} | {q.get('fips', '')} | {s.risks} |")
    L += ["", "\\* для сегментованих режимів — паралелізм можливий між сегментами (у цій реалізації сегменти обробляються послідовно).", ""]
    if kdf_rows:
        L += ["## 4. Вартість виведення ключа (KDF)", "",
              "| KDF | Параметри | Час, мс (±σ) | Спроб підбору/с на 1 ядро |", "|---|---|---:|---:|"]
        for r in kdf_rows:
            L.append(f"| {r['kdf']} | {r['param']} | {r['mean_s'] * 1000:.1f} ± {r['std_s'] * 1000:.1f} | {r['guesses_per_s_1core']:.1f} |")
        L.append("")
    small = min(r["size_bytes"] for r in rows)
    rsm = {r["mode"]: r for r in rows if r["size_bytes"] == small}
    rb = {r["mode"]: r for r in rs}
    L += ["## 5. Висновки щодо доцільності режимів", "",
          f"1. **Найшвидший на великих файлах** — `{rs[0]['mode']}` ({rs[0]['enc_mib_s']:.0f}/{rs[0]['dec_mib_s']:.0f} MiB/s), "
          f"найповільніший — `{rs[-1]['mode']}` ({rs[-1]['enc_mib_s']:.0f}/{rs[-1]['dec_mib_s']:.0f} MiB/s).",
          f"2. **Малі файли ({human(small)})**: час визначається фіксованими витратами (відкриття файлів, заголовок, атомарне перейменування, "
          f"HKDF), тому різниця між режимами мізерна (≈{min(r['enc_mean_s'] for r in rsm.values()) * 1000:.2f}–"
          f"{max(r['enc_mean_s'] for r in rsm.values()) * 1000:.2f} мс); накладні витрати розміру відносно великі "
          f"(до {max(r['overhead_pct'] for r in rsm.values()):.0f}%).",
          "3. **AES-GCM** — рекомендований режим за замовчуванням: AEAD за 1 прохід, апаратне прискорення AES-NI+PCLMULQDQ, "
          "стандарт NIST. Обов'язкові умови: унікальний nonce (контролюється лічильником і кешем у keystore), ліміт 2^32 "
          "шифрувань на ключ, тег 128 біт.",
          "4. **AES-CBC + HMAC-SHA256** — безпечний за схеми Encrypt-then-MAC, але повільніший: шифрування CBC не "
          "паралелізується, а дешифрування вимагає двох проходів (спершу HMAC, потім розшифрування) — "
          f"{rb.get('aes-cbc-hmac', rs[0])['dec_mib_s']:.0f} MiB/s проти {rb.get('aes-gcm', rs[0])['dec_mib_s']:.0f} MiB/s у GCM. "
          "Доцільний для сумісності з легасі-системами.",
          "5. **AES-CTR/CFB + HMAC** — коректні EtM-конструкції, проте не дають переваг над GCM; CFB найменш доцільний "
          "(послідовне шифрування, перенесено в cryptography до «decrepit»).",
          "6. **AES-GCM-SIV** — найкращий вибір, коли неможливо гарантувати унікальність nonce (розподілені системи, "
          "клонування ВМ): повтор nonce розкриває лише рівність повідомлень. Ціна — два проходи при шифруванні.",
          "7. **ChaCha20-Poly1305** — альтернатива для платформ без AES-NI (мобільні/вбудовані), константночасова "
          "програмна реалізація; на x86 з AES-NI зазвичай поступається AES-GCM.",
          "8. **Пам'ять**: потокові режими (GCM, *-HMAC) мають сталий пік ≈ розміру буфера (1 MiB) незалежно від розміру "
          "файлу; сегментовані AEAD — ≈ 2 сегменти (64 KiB) — придатні для файлів будь-якого розміру.",
          "9. **KDF**: 310 000 ітерацій PBKDF2 — компроміс між затримкою розблокування (див. табл. 4) і вартістю перебору "
          "паролів; scrypt додатково стійкий до GPU/ASIC завдяки вимогам до пам'яті.", ""]
    if pngs:
        L += ["## 6. Графіки", ""] + [f"![{os.path.basename(p)}]({os.path.basename(p)})" for p in pngs] + [""]
    if resource:
        L.append(f"Пікове RSS процесу бенчмарку (ru_maxrss): {resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024:.1f} MiB.")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="benchmark.py", description="Бенчмарк режимів шифрування AES-Lab")
    ap.add_argument("--sizes", nargs="+", default=["1KB", "100KB", "1MB", "10MB", "50MB"])
    ap.add_argument("--modes", nargs="+", default=list(REGISTRY), help=f"доступні: {', '.join(REGISTRY)}")
    ap.add_argument("--repeat", type=int, default=5)
    ap.add_argument("--key-bits", type=int, default=256, choices=(128, 192, 256))
    ap.add_argument("--outdir", default="outputs")
    ap.add_argument("--datadir", default="bench_data", help="тимчасові тестові файли (не для git)")
    ap.add_argument("--kdf-iterations", nargs="+", type=int, default=[100_000, 310_000, 600_000, 1_000_000])
    ap.add_argument("--no-kdf", action="store_true")
    ap.add_argument("--no-plots", action="store_true")
    ap.add_argument("--fsync", action="store_true", help="виконувати fsync після кожного файлу (як у CLI)")
    ap.add_argument("--keep-data", action="store_true", help="не видаляти згенеровані файли")
    a = ap.parse_args(argv)
    from .modes import get_mode
    from . import engine
    engine.FSYNC = a.fsync
    modes = [get_mode(m).spec.name for m in a.modes]
    sizes = [parse_size(s) for s in a.sizes]
    os.makedirs(a.outdir, exist_ok=True)
    env = env_info()
    print(f"Середовище: {env['cpu']} | AES-NI={env['aes_ni']} | {env['openssl']}")
    rows = bench_files(sizes, modes, a.repeat, a.key_bits, a.datadir)
    kdf_rows = [] if a.no_kdf else bench_kdf(a.kdf_iterations)
    write_csv(rows, os.path.join(a.outdir, "benchmark_results.csv"))
    if kdf_rows:
        write_csv(kdf_rows, os.path.join(a.outdir, "benchmark_kdf.csv"))
    pngs = [] if a.no_plots else plots(rows, kdf_rows, a.outdir)
    write_md(rows, kdf_rows, env, os.path.join(a.outdir, "benchmark_results.md"), pngs)
    if not a.keep_data:
        for s in sizes:
            fp = os.path.join(a.datadir, f"plain_{s}.bin")
            if os.path.exists(fp):
                os.remove(fp)
        if os.path.isdir(a.datadir) and not os.listdir(a.datadir):
            os.rmdir(a.datadir)
    print(f"Результати → {a.outdir}/benchmark_results.md, benchmark_results.csv" + (", PNG-графіки" if pngs else ""))
    return 0 if all(r["roundtrip_ok"] for r in rows) else 1


if __name__ == "__main__":
    sys.exit(main())
