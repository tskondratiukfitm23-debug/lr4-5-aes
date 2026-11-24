"""Наскрізні тести CLI/REPL (через subprocess) та журналювання/аналізу логів."""
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PW = "Cli-Test-Passw0rd!"


def run(args, tmp_path, env_extra=None, stdin=None):
    env = {**os.environ, "AES_LAB_PASSWORD": PW, "AES_LAB_MIN_ITERATIONS": "1000", **(env_extra or {})}
    return subprocess.run([sys.executable, os.path.join(ROOT, "aes_cli.py"), "--keystore", str(tmp_path / "ks.json"),
                           "--log-file", str(tmp_path / "logs" / "aes.jsonl"), *args],
                          capture_output=True, text=True, env=env, input=stdin, cwd=tmp_path, timeout=120)


@pytest.fixture
def cli(tmp_path):
    (tmp_path / "in.txt").write_text("Секретний звіт ЛР4-5\n" * 100, encoding="utf-8")
    r = run(["key", "new", "--label", "lab", "--iterations", "1000"], tmp_path)
    assert r.returncode == 0, r.stderr
    return tmp_path


def logs(tmp_path):
    return [json.loads(x) for x in (tmp_path / "logs" / "aes.jsonl").read_text(encoding="utf-8").splitlines()]


@pytest.mark.parametrize("mode", ["gcm", "cbc", "ctr", "cfb", "chacha", "siv"])
def test_cli_enc_dec(cli, mode):
    assert run(["enc", "--in", "in.txt", "--out", "f.enc", "--label", "lab", "--mode", mode, "--aad", "id=1"],
               cli).returncode == 0
    r = run(["dec", "--in", "f.enc", "--out", "f.dec", "--aad", "id=1"], cli)
    assert r.returncode == 0, r.stderr
    assert (cli / "f.dec").read_bytes() == (cli / "in.txt").read_bytes()


def test_cli_exit_codes(cli):
    run(["enc", "--in", "in.txt", "--out", "f.enc", "--label", "lab", "--mode", "cbc", "--padding", "iso7816"], cli)
    d = bytearray((cli / "f.enc").read_bytes())
    d[-40] ^= 1
    (cli / "bad.enc").write_bytes(bytes(d))
    r = run(["dec", "--in", "bad.enc", "--out", "bad.dec"], cli)
    assert r.returncode == 20 and "TAMPER_DETECTED" in r.stderr and not (cli / "bad.dec").exists()
    r = run(["dec", "--in", "f.enc", "--out", "x.dec"], cli, {"AES_LAB_PASSWORD": "Wrong-Passw0rd!!"})
    assert r.returncode == 30 and "WRONG_PASSWORD" in r.stderr
    r = run(["dec", "--in", "in.txt", "--out", "x.dec"], cli)
    assert r.returncode == 10
    r = run(["enc", "--in", "in.txt", "--out", "x.enc", "--label", "lab", "--mode", "gcm", "--iv-len", "5"], cli)
    assert r.returncode == 2
    r = run(["key", "new", "--label", "weak", "--iterations", "1000"], cli, {"AES_LAB_PASSWORD": "qwerty"})
    assert r.returncode == 37
    r = run(["key", "revoke", "--label", "lab", "--reason", "test"], cli)
    assert r.returncode == 0
    r = run(["dec", "--in", "f.enc", "--out", "x.dec"], cli)
    assert r.returncode == 32


def test_cli_rotate_and_rekey(cli):
    run(["enc", "--in", "in.txt", "--out", "f.enc", "--label", "lab"], cli)
    new_pw = "Rotated-Passw0rd!"
    r = run(["key", "rotate", "--label", "lab", "--iterations", "1000"], cli, {"AES_LAB_NEW_PASSWORD": new_pw})
    assert r.returncode == 0, r.stderr
    r = run(["rekey", "--in", "f.enc", "--out", "g.enc", "--label", "lab"], cli,
            {"AES_LAB_OLD_PASSWORD": PW, "AES_LAB_PASSWORD": new_pw})
    assert r.returncode == 0, r.stderr
    r = run(["dec", "--in", "g.enc", "--out", "g.dec"], cli, {"AES_LAB_PASSWORD": new_pw})
    assert r.returncode == 0 and (cli / "g.dec").read_bytes() == (cli / "in.txt").read_bytes()


def test_repl_dynamic_mode_switch(cli):
    script = "\n".join(["use lab", "mode cbc", "set padding ansix923", "enc in.txt a.enc", "mode chacha",
                        "enc in.txt b.enc", "mode gcm", "set tag_len 12", "set iv_len 3", "status",
                        "enc in.txt c.enc", "dec a.enc a.dec", "dec b.enc b.dec", "dec c.enc c.dec", "quit"]) + "\n"
    r = run(["shell"], cli, stdin=script)
    assert r.returncode == 0, r.stderr
    assert "INVALID_PARAMS" in r.stdout          # set iv_len 3 відхилено без виходу з оболонки
    for n in "abc":
        assert (cli / f"{n}.dec").read_bytes() == (cli / "in.txt").read_bytes()
    hdr = json.loads(run(["info", "--in", "a.enc"], cli).stdout)
    assert hdr["mode"] == "aes-cbc-hmac" and hdr["pad"] == "ansix923"
    events = [x["event"] for x in logs(cli)]
    assert "repl_mode_change" in events and "repl_param_change" in events


def test_logs_structure_and_no_secrets(cli):
    run(["enc", "--in", "in.txt", "--out", "f.enc", "--label", "lab"], cli)
    run(["dec", "--in", "f.enc", "--out", "f.dec"], cli, {"AES_LAB_PASSWORD": "Wrong-Passw0rd!!"})
    r = run(["--password", PW, "dec", "--in", "f.enc", "--out", "f.dec"], cli)
    assert "УВАГА" in r.stderr
    raw = (cli / "logs" / "aes.jsonl").read_text(encoding="utf-8")
    assert PW not in raw and "Wrong-Passw0rd" not in raw
    recs = logs(cli)
    enc = next(x for x in recs if x["event"] == "encrypt")
    assert {"ts", "level", "op", "mode", "key_id", "status", "duration_s", "in_size", "out_sha256"} <= set(enc)
    assert enc["ts"].endswith("Z")
    assert any(x.get("error_code") == "WRONG_PASSWORD" for x in recs)
    assert any(x["event"] == "insecure_password_source" for x in recs)


def test_log_analyzer_detects_anomalies(cli):
    run(["enc", "--in", "in.txt", "--out", "f.enc", "--label", "lab"], cli)
    d = bytearray((cli / "f.enc").read_bytes())
    d[-1] ^= 1
    (cli / "bad.enc").write_bytes(bytes(d))
    for _ in range(3):
        run(["dec", "--in", "bad.enc", "--out", "x"], cli)
        run(["dec", "--in", "f.enc", "--out", "x"], cli, {"AES_LAB_PASSWORD": "Wrong-Passw0rd!!"})
    sys.path.insert(0, ROOT)
    from aeslab.log_analyzer import analyze, load
    recs, bad = load(str(cli / "logs" / "aes.jsonl"))
    res = analyze(recs)
    codes = {a[0] for a in res["anomalies"]}
    assert bad == 0 and {"A1", "A2"} <= codes
    assert res["errors"]["TAMPER_DETECTED"] == 3
