"""Аналіз журналу AES-Lab (JSONL): зведена статистика та виявлення аномалій.

Правила аномалій (налаштовуються аргументами):
  A1  серія збоїв автентичності (TAMPER_DETECTED/AUTH_FAILED) ≥ N за W секунд для одного key_id;
  A2  підбір пароля: WRONG_PASSWORD ≥ N за W секунд для одного ключа;
  A3  будь-яка спроба використати відкликаний ключ (KEY_REVOKED);
  A4  повторне використання nonce (NONCE_REUSE) — критична подія;
  A5  пошкоджені/чужі файли (BAD_MAGIC/BAD_FORMAT/TRUNCATED) ≥ N за сесію;
  A6  небезпечні практики: пароль у командному рядку, небезпечні права keystore, демо-режими без MAC.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from collections import Counter, defaultdict, deque
from datetime import datetime

from . import config

AUTH_FAIL = {"TAMPER_DETECTED", "AUTH_FAILED"}
FORMAT_FAIL = {"BAD_MAGIC", "BAD_FORMAT", "TRUNCATED"}


def load(path: str) -> tuple[list[dict], int]:
    """Завантажити записи з основного файлу та ротаційних копій (.1 … .N), у хронологічному порядку."""
    files = sorted(glob.glob(path + ".*"), key=lambda p: -int(p.rsplit(".", 1)[1]) if p.rsplit(".", 1)[1].isdigit() else 0)
    files = [f for f in files if f.rsplit(".", 1)[1].isdigit()] + ([path] if os.path.exists(path) else [])
    recs, bad = [], 0
    for fp in files:
        with open(fp, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                    r["_t"] = datetime.fromisoformat(r["ts"].replace("Z", "+00:00"))
                    recs.append(r)
                except (ValueError, KeyError):
                    bad += 1
    recs.sort(key=lambda r: r["_t"])
    return recs, bad


def sliding(records, key_fn, threshold, window):
    """Знайти ключі, для яких ≥ threshold подій потрапляють у вікно window секунд.

    Повертає [(ключ, макс. кількість у вікні, початок, кінець)].
    """
    q, best = defaultdict(deque), {}
    for r in records:
        k = key_fn(r)
        dq = q[k]
        dq.append(r["_t"])
        while (r["_t"] - dq[0]).total_seconds() > window:
            dq.popleft()
        if len(dq) >= threshold and len(dq) > best.get(k, (0,))[0]:
            best[k] = (len(dq), dq[0], r["_t"])
    return [(k, *v) for k, v in best.items()]


def analyze(recs, n_auth=3, w_auth=60, n_pw=3, w_pw=300, n_fmt=3) -> dict:
    fails = [r for r in recs if r.get("status") == "fail"]
    a = []
    for k, n, t0, t1 in sliding([r for r in fails if r.get("error_code") in AUTH_FAIL],
                                lambda r: r.get("key_id") or r.get("file_key_id"), n_auth, w_auth):
        a.append(("A1", "ВИСОКА", f"Серія збоїв автентичності: {n} подій за ≤{w_auth} с для key_id={k} "
                                  f"({t0:%H:%M:%S}–{t1:%H:%M:%S}) — можлива підміна файлів або атака"))
    for k, n, t0, t1 in sliding([r for r in fails if r.get("error_code") == "WRONG_PASSWORD"],
                                lambda r: r.get("key_id"), n_pw, w_pw):
        a.append(("A2", "ВИСОКА", f"Можливий підбір пароля: {n} невдалих спроб за ≤{w_pw} с для key_id={k}"))
    rev = [r for r in fails if r.get("error_code") == "KEY_REVOKED"]
    if rev:
        a.append(("A3", "КРИТИЧНА", f"Спроби використати відкликаний ключ: {len(rev)} "
                                    f"(key_id: {', '.join(sorted({str(r.get('key_id')) for r in rev}))})"))
    nr = [r for r in fails if r.get("error_code") == "NONCE_REUSE"]
    if nr:
        a.append(("A4", "КРИТИЧНА", f"Виявлено повторне використання nonce/IV: {len(nr)} — перевірте RNG/клонування ВМ, "
                                    "виконайте ротацію ключа"))
    by_sess = Counter(r.get("session") for r in fails if r.get("error_code") in FORMAT_FAIL)
    for s, n in by_sess.items():
        if n >= n_fmt:
            a.append(("A5", "СЕРЕДНЯ", f"Сесія {s}: {n} пошкоджених/чужих файлів (BAD_MAGIC/BAD_FORMAT/TRUNCATED)"))
    pw_argv = [r for r in recs if r.get("event") == "insecure_password_source"]
    if pw_argv:
        a.append(("A6", "НИЗЬКА", f"Пароль передавався в командному рядку {len(pw_argv)} раз(и)"))
    ks_warn = [r for r in recs if r.get("event") == "keystore_warning"]
    if ks_warn:
        a.append(("A6", "СЕРЕДНЯ", f"Попередження щодо keystore: {ks_warn[-1].get('warning')}"))
    demo = [r for r in recs if r.get("event") == "insecure_demo"]
    if demo:
        a.append(("A6", "ІНФО", f"Запуски демонстрацій небезпечних режимів без MAC: {len(demo)}"))
    ops = [r for r in recs if r.get("event") in ("encrypt", "decrypt")]
    dur = [r["duration_s"] for r in ops if r.get("status") == "success" and "duration_s" in r]
    return {
        "total": len(recs), "period": (recs[0]["_t"], recs[-1]["_t"]) if recs else None,
        "sessions": len({r.get("session") for r in recs}),
        "events": Counter(r.get("event") for r in recs), "levels": Counter(r.get("level") for r in recs),
        "status": Counter((r.get("event"), r.get("status")) for r in ops),
        "modes": Counter((r.get("mode"), r.get("event"), r.get("status")) for r in ops),
        "keys": Counter((r.get("label") or "-", r.get("key_id") or r.get("file_key_id"), r.get("status"))
                        for r in recs if r.get("event") in ("encrypt", "decrypt", "key_unlock")),
        "errors": Counter(r.get("error_code") for r in fails),
        "bytes": sum(r.get("in_size", 0) for r in ops if r.get("status") == "success"),
        "avg_ms": (sum(dur) / len(dur) * 1000) if dur else 0, "anomalies": a,
        "last_fails": fails[-10:],
    }


def report(res: dict, bad: int, path: str) -> str:
    L = ["# Звіт аналізу журналу AES-Lab", "", f"Джерело: `{path}` (+ ротаційні копії). Некоректних рядків: {bad}.", ""]
    if res["period"]:
        L.append(f"Записів: **{res['total']}**, сесій: {res['sessions']}, період: {res['period'][0]:%Y-%m-%d %H:%M:%S} – "
                 f"{res['period'][1]:%Y-%m-%d %H:%M:%S} UTC. Оброблено даних (успішно): {res['bytes'] / 1024:.1f} KiB, "
                 f"середня тривалість успішної операції: {res['avg_ms']:.2f} мс.")
    L += ["", "## 1. Аномалії та інциденти", ""]
    if res["anomalies"]:
        L += ["| Правило | Важливість | Опис |", "|---|---|---|"]
        L += [f"| {c} | {s} | {d} |" for c, s, d in res["anomalies"]]
    else:
        L.append("Аномалій не виявлено.")

    def table(title, head, items):
        L.extend(["", f"## {title}", "", "| " + " | ".join(head) + " | Кількість |",
                  "|" + "---|" * (len(head) + 1)])
        for k, v in items:
            k = k if isinstance(k, tuple) else (k,)
            L.append("| " + " | ".join(str(x) for x in k) + f" | {v} |")

    table("2. Події", ["Подія"], res["events"].most_common())
    table("3. Рівні", ["Рівень"], res["levels"].most_common())
    table("4. Операції за статусом", ["Операція", "Статус"], res["status"].most_common())
    table("5. Режими", ["Режим", "Операція", "Статус"], sorted(res["modes"].items(), key=lambda x: str(x[0])))
    table("6. Ключі", ["Мітка", "key_id", "Статус"], res["keys"].most_common())
    table("7. Коди помилок", ["error_code"], res["errors"].most_common())
    L += ["", "## 8. Останні невдалі операції", "", "| Час (UTC) | Подія | Режим | key_id | Код | Файл |", "|---|---|---|---|---|---|"]
    for r in res["last_fails"]:
        L.append(f"| {r['_t']:%H:%M:%S} | {r.get('event')} | {r.get('mode', '')} | {r.get('key_id') or r.get('file_key_id', '')} | "
                 f"{r.get('error_code')} | {r.get('in_file', '')} |")
    return "\n".join(L) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="log_analyzer.py", description="Аналіз журналу AES-Lab")
    ap.add_argument("--log", default=config.LOG_PATH)
    ap.add_argument("--out", default=os.path.join("outputs", "log_report.md"))
    ap.add_argument("--auth-threshold", type=int, default=3)
    ap.add_argument("--auth-window", type=int, default=60)
    ap.add_argument("--pw-threshold", type=int, default=3)
    ap.add_argument("--pw-window", type=int, default=300)
    a = ap.parse_args(argv)
    recs, bad = load(a.log)
    if not recs:
        print(f"Журнал порожній або не знайдений: {a.log}")
        return 1
    res = analyze(recs, a.auth_threshold, a.auth_window, a.pw_threshold, a.pw_window)
    md = report(res, bad, a.log)
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(md)
    print(f"Записів: {res['total']}, сесій: {res['sessions']}, помилок: {sum(res['errors'].values())}, "
          f"аномалій: {len(res['anomalies'])}")
    for c, s, d in res["anomalies"]:
        print(f"  [{c}][{s}] {d}")
    print(f"Звіт → {a.out}")
    return 2 if any(s in ("КРИТИЧНА", "ВИСОКА") for _, s, _ in res["anomalies"]) else 0


if __name__ == "__main__":
    sys.exit(main())
