"""Командний інтерфейс (CLI) та інтерактивна оболонка (REPL) AES-Lab."""
from __future__ import annotations

import argparse
import cmd
import getpass
import json
import logging
import os
import shlex
import sys
import tempfile

from . import __version__, config
from .container import params_from_header
from .engine import decrypt_file, encrypt_file, peek_header
from .errors import AesLabError, InvalidParams, KeyMismatch, WrongPassword
from .keystore import KeyContext, KeyStore
from .logging_setup import get_logger, log_event
from .modes import get_mode, list_modes, resolve_params
from .params import CipherParams

# ---------------------------------------------------------------------------
# Паролі
# ---------------------------------------------------------------------------
def get_password(args, prompt: str = "Пароль: ", confirm: bool = False, env: str = config.PASSWORD_ENV) -> str:
    """Отримати пароль: --password (небажано) → змінна середовища → getpass (без відлуння)."""
    if getattr(args, "password", None):
        print("⚠️  УВАГА: пароль у командному рядку видно в історії shell та списку процесів. "
              f"Використовуйте {config.PASSWORD_ENV} або інтерактивне введення.", file=sys.stderr)
        log_event("insecure_password_source", logging.WARNING, source="argv")
        return args.password
    if os.environ.get(env):
        return os.environ[env]
    pw = getpass.getpass(prompt)
    if confirm and getpass.getpass("Повторіть пароль: ") != pw:
        raise InvalidParams("Паролі не збігаються")
    return pw


def unlock_logged(ks: KeyStore, entry: dict, password: str) -> KeyContext:
    """Розблокувати ключ із журналюванням успіху/невдачі (виявлення підбору пароля)."""
    try:
        ctx = ks.unlock(entry, password)
    except AesLabError as e:
        log_event("key_unlock", logging.WARNING if isinstance(e, WrongPassword) else logging.ERROR,
                  key_id=entry["key_id"], label=entry["label"], status="fail", error_code=e.code)
        raise
    log_event("key_unlock", key_id=entry["key_id"], label=entry["label"], status="success")
    return ctx


def open_keystore(args) -> KeyStore:
    ks = KeyStore(args.keystore, min_iterations=int(os.environ.get("AES_LAB_MIN_ITERATIONS",
                                                                     config.MIN_PBKDF2_ITERATIONS)))
    for w in ks.warnings:
        print("⚠️ ", w, file=sys.stderr)
        log_event("keystore_warning", logging.WARNING, warning=w)
    return ks


def params_from_args(args, default_bits: int = 256) -> CipherParams:
    return CipherParams(mode=args.mode, key_bits=args.key_bits or default_bits, iv_len=args.iv_len,
                        padding=args.padding, tag_len=args.tag_len,
                        aad=args.aad.encode("utf-8") if args.aad else None, segment_size=args.segment_size)


def _entry_view(e: dict) -> dict:
    hide = {"verifier", "recent_iv_fps"}
    return {k: v for k, v in e.items() if k not in hide}


# ---------------------------------------------------------------------------
# Команди
# ---------------------------------------------------------------------------
def cmd_key(args) -> int:
    ks = open_keystore(args)
    a = args.action
    if a == "new":
        pw = get_password(args, "Новий пароль: ", confirm=True)
        e = ks.create(args.label, pw, kdf=args.kdf, iterations=args.iterations, key_bits=args.key_bits,
                      expires_days=args.expires_days, max_uses=args.max_uses,
                      check_password_reuse=not args.no_reuse_check)
        log_event("key_create", label=e["label"], key_id=e["key_id"], kdf=e["kdf"]["name"], key_bits=e["key_bits"],
                  status="success")
        print(f"✅ Ключ створено: label={e['label']} key_id={e['key_id']} KDF={e['kdf']} "
              f"дійсний до {e['expires_at']} ліміт={e['max_uses']}")
    elif a == "list":
        if not ks.keys:
            print("Сховище порожнє. Створіть ключ: key new --label <мітка>")
        print(f"{'LABEL':<14}{'KEY_ID':<18}{'STATUS':<9}{'BITS':<6}{'USES':>8}  {'EXPIRES':<21}KDF")
        for e in ks.keys:
            kdf = e["kdf"]["name"] + (f"/{e['kdf'].get('iterations')}" if "iterations" in e["kdf"] else "")
            print(f"{e['label']:<14}{e['key_id']:<18}{e['status']:<9}{e['key_bits']:<6}"
                  f"{e['uses']:>8}  {str(e['expires_at']):<21}{kdf}")
    elif a == "info":
        print(json.dumps(_entry_view(ks.find(args.label, args.key_id)), ensure_ascii=False, indent=2))
    elif a == "verify":
        e = ks.find(args.label, args.key_id)
        unlock_logged(ks, e, get_password(args)).wipe()
        print(f"✅ Пароль правильний для {e['label']} ({e['key_id']})")
    elif a == "rotate":
        old_pw = get_password(args, "Поточний пароль: ")
        new_pw = os.environ.get("AES_LAB_NEW_PASSWORD") or getpass.getpass("Новий пароль: ")
        if not os.environ.get("AES_LAB_NEW_PASSWORD") and getpass.getpass("Повторіть новий пароль: ") != new_pw:
            raise InvalidParams("Паролі не збігаються")
        old = ks.find(label=args.label)
        try:
            old, new = ks.rotate(args.label, old_pw, new_pw, kdf=args.kdf, iterations=args.iterations,
                                 key_bits=args.key_bits or old["key_bits"], expires_days=args.expires_days,
                                 max_uses=args.max_uses)
        except AesLabError as e:
            log_event("key_rotate", logging.WARNING, label=args.label, key_id=old["key_id"], status="fail",
                      error_code=e.code)
            raise
        log_event("key_rotate", label=args.label, key_id=new["key_id"], old_key_id=old["key_id"], status="success")
        print(f"✅ Ротацію виконано: {old['key_id']} → retired; новий активний ключ {new['key_id']}")
    elif a in ("retire", "revoke"):
        e = ks.find(args.label, args.key_id)
        ks.set_status(e, "retired" if a == "retire" else "revoked", args.reason or a)
        log_event("key_status_change", logging.WARNING if a == "revoke" else logging.INFO,
                  label=e["label"], key_id=e["key_id"], new_status=e["status"], reason=args.reason, status="success")
        print(f"Ключ {e['label']} ({e['key_id']}) → {e['status']}")
    return 0


def cmd_enc(args) -> int:
    ks = open_keystore(args)
    e = ks.find(label=args.label)
    p = resolve_params(params_from_args(args, e["key_bits"]))
    ks.authorize_encrypt(e, p.mode)               # ранній відказ до введення пароля
    ctx = unlock_logged(ks, e, get_password(args))
    try:
        r = encrypt_file(args.infile, args.outfile, ctx, p, ks=ks)
    finally:
        ctx.wipe()
    print(f"✅ Зашифровано [{r['mode']}, AES-{r['key_bits']}] {r['in_size']} → {r['out_size']} B "
          f"за {r['duration_s']:.4f} с → {args.outfile}")
    return 0


def resolve_key_for_file(ks: KeyStore, path: str, label: str | None, op: str = "decrypt") -> tuple[dict, dict]:
    """Визначити ключ за key_id із заголовка файлу (з журналюванням помилок формату)."""
    try:
        hdr = peek_header(path)
        e = ks.find(key_id=hdr["key_id"])
        if label and e["label"] != label:
            raise KeyMismatch(f"Файл зашифровано ключем '{e['label']}' ({e['key_id']}), а не '{label}'")
        return hdr, e
    except AesLabError as err:
        log_event(op, logging.ERROR if err.code != "KEY_NOT_FOUND" else logging.WARNING, in_file=os.path.basename(path),
                  label=label, status="fail", error_code=err.code, error=err.message)
        raise


def cmd_dec(args) -> int:
    ks = open_keystore(args)
    _, e = resolve_key_for_file(ks, args.infile, args.label)
    ks.authorize_decrypt(e)
    ctx = unlock_logged(ks, e, get_password(args))
    try:
        r = decrypt_file(args.infile, args.outfile, ctx, aad=args.aad.encode("utf-8") if args.aad else None, ks=ks)
    finally:
        ctx.wipe()
    print(f"✅ Розшифровано й автентифіковано [{r['mode']}] {r['in_size']} → {r['out_size']} B "
          f"за {r['duration_s']:.4f} с → {args.outfile}")
    return 0


def cmd_rekey(args) -> int:
    """Перешифрування файлу новим (активним) ключем — після ротації."""
    ks = open_keystore(args)
    hdr, old = resolve_key_for_file(ks, args.infile, None, op="rekey")
    new = ks.find(label=args.label)
    old_ctx = unlock_logged(ks, old, os.environ.get("AES_LAB_OLD_PASSWORD")
                            or getpass.getpass(f"Пароль старого ключа {old['label']} ({old['key_id']}): "))
    new_ctx = unlock_logged(ks, new, get_password(args, f"Пароль нового ключа {new['label']}: "))
    aad = args.aad.encode("utf-8") if args.aad else None
    p, _ = params_from_header(hdr, aad)
    with tempfile.TemporaryDirectory(dir=os.path.dirname(os.path.abspath(args.outfile))) as td:
        tmp = os.path.join(td, "plain")
        try:
            decrypt_file(args.infile, tmp, old_ctx, aad=aad, ks=ks)
            r = encrypt_file(tmp, args.outfile, new_ctx, p.copy(mode=args.mode or p.mode, iv_len=None,
                                                                    tag_len=None, padding=None,
                                                                    key_bits=new["key_bits"]), ks=ks)
        finally:
            old_ctx.wipe(), new_ctx.wipe()
    log_event("rekey", old_key_id=old["key_id"], key_id=new["key_id"], status="success")
    print(f"✅ Перешифровано: {old['key_id']} → {new['key_id']} [{r['mode']}] → {args.outfile}")
    return 0


def cmd_info(args) -> int:
    print(json.dumps(peek_header(args.infile), ensure_ascii=False, indent=2))
    return 0


def cmd_modes(_args) -> int:
    for s in list_modes():
        print(f"• {s.name:<18} {s.title}")
        print(f"    ключ: {s.key_bits}  IV/nonce: {s.iv_lens} (типово {s.default_iv})  "
              f"padding: {s.paddings}  тег: {s.tag_lens} (типово {s.default_tag})  псевдоніми: {s.aliases}")
        print(f"    безпека: {s.security}\n    ризики:  {s.risks}")
    return 0


# ---------------------------------------------------------------------------
# REPL
# ---------------------------------------------------------------------------
class Shell(cmd.Cmd):
    """Інтерактивна оболонка: зміна режиму/параметрів/ключа без перезапуску програми."""

    intro = ("AES-Lab shell. Введіть 'help' для списку команд, 'status' — поточні налаштування, 'quit' — вихід.\n"
             "Режим і параметри можна змінювати будь-коли: mode <назва>, set <параметр> <значення>.")

    def __init__(self, ks: KeyStore, args):
        super().__init__()
        self.ks, self.args = ks, args
        self.ctx: KeyContext | None = None
        self.params = resolve_params(CipherParams(mode=args.mode or "aes-gcm"))
        self._prompt()

    def _prompt(self):
        k = self.ctx.label if self.ctx else "-"
        self.prompt = f"[{self.params.mode} | AES-{self.params.key_bits} | key={k}]> "

    def onecmd(self, line):
        try:
            return super().onecmd(line)
        except AesLabError as e:
            print(f"❌ ПОМИЛКА [{e.code}]: {e.message}")
        except (OSError, ValueError) as e:
            print(f"❌ Помилка: {e}")
        finally:
            self._prompt()

    def emptyline(self):
        pass

    def default(self, line):
        print(f"Невідома команда: {line!r}. Введіть 'help'.")

    # --- інформація
    def do_status(self, _):
        """status — поточний ключ, режим і параметри."""
        print("Ключ:", f"{self.ctx.label} ({self.ctx.key_id}, {self.ctx.entry['status']}, "
                       f"використань {self.ctx.entry['uses']})" if self.ctx else "не обрано (use <мітка>)")
        print("Параметри:", json.dumps(self.params.public_dict(), ensure_ascii=False))

    def do_modes(self, _):
        """modes — перелік зареєстрованих режимів."""
        for s in list_modes():
            print(f"  {s.name:<18} {s.title:<28} псевдоніми: {', '.join(s.aliases)}")

    def do_keys(self, _):
        """keys — перелік ключів у сховищі."""
        cmd_key(argparse.Namespace(**{**vars(self.args), "action": "list"}))

    # --- налаштування
    def do_mode(self, arg):
        """mode <назва> — змінити режим (gcm, cbc, ctr, cfb, chacha, siv або повна назва)."""
        if not arg:
            return print("Використання: mode <назва>")
        spec = get_mode(arg.strip()).spec
        bits = self.params.key_bits if self.params.key_bits in spec.key_bits else max(spec.key_bits)
        new = resolve_params(CipherParams(mode=spec.name, key_bits=bits, aad=self.params.aad))
        log_event("repl_mode_change", old_mode=self.params.mode, new_mode=new.mode, status="success")
        self.params = new
        print(f"Режим → {new.mode} (параметри скинуто до типових: IV={new.iv_len}, padding={new.padding}, "
              f"тег={new.tag_len}, ключ AES-{new.key_bits})")

    def do_set(self, arg):
        """set <параметр> <значення> — key_bits|iv_len|padding|tag_len|aad|segment_size|block_size (default — типове)."""
        parts = arg.split(maxsplit=1)
        if len(parts) != 2:
            return print("Використання: set <параметр> <значення>")
        new = resolve_params(self.params.set_from_text(parts[0], parts[1]))   # валідація; при помилці — без змін
        log_event("repl_param_change", param=parts[0], mode=new.mode, status="success",
                  value="***" if parts[0] == "aad" else parts[1])
        self.params = new
        print("OK:", json.dumps(new.public_dict(), ensure_ascii=False))

    def do_reset(self, _):
        """reset — повернути типові параметри поточного режиму."""
        self.params = resolve_params(CipherParams(mode=self.params.mode))
        print("Параметри скинуто")

    def do_use(self, arg):
        """use <мітка> — обрати та розблокувати ключ (пароль: AES_LAB_PASSWORD або запит)."""
        if not arg:
            return print("Використання: use <мітка>")
        e = self.ks.find(label=arg.strip())
        ctx = unlock_logged(self.ks, e, get_password(argparse.Namespace(password=None),
                                                     f"Пароль для '{e['label']}': "))
        if self.ctx:
            self.ctx.wipe()
        self.ctx = ctx
        if self.params.key_bits not in (e["key_bits"],):
            self.params = resolve_params(self.params.copy(key_bits=e["key_bits"]))
        print(f"Ключ '{e['label']}' ({e['key_id']}) розблоковано")

    # --- операції
    def _need_key(self):
        if not self.ctx:
            raise InvalidParams("Спершу оберіть ключ: use <мітка>")

    def do_enc(self, arg):
        """enc <вхід> [вихід] — зашифрувати поточним режимом (типово вихід = <вхід>.enc)."""
        self._need_key()
        a = shlex.split(arg)
        if not a:
            return print("Використання: enc <вхід> [вихід]")
        out = a[1] if len(a) > 1 else a[0] + ".enc"
        r = encrypt_file(a[0], out, self.ctx, self.params, ks=self.ks)
        self.ctx.entry = self.ks.find(key_id=self.ctx.key_id)
        print(f"✅ {r['mode']}: {r['in_size']} → {r['out_size']} B, {r['duration_s']:.4f} с → {out}")

    def do_dec(self, arg):
        """dec <вхід> [вихід] — розшифрувати (режим і параметри беруться із заголовка файлу)."""
        self._need_key()
        a = shlex.split(arg)
        if not a:
            return print("Використання: dec <вхід> [вихід]")
        out = a[1] if len(a) > 1 else (a[0][:-4] if a[0].endswith(".enc") else a[0]) + ".dec"
        r = decrypt_file(a[0], out, self.ctx, aad=self.params.aad, ks=self.ks)
        print(f"✅ {r['mode']}: автентичність підтверджено, {r['out_size']} B → {out}")

    def do_info(self, arg):
        """info <файл> — показати заголовок контейнера."""
        print(json.dumps(peek_header(arg.strip()), ensure_ascii=False, indent=2))

    def do_log(self, arg):
        """log [N] — останні N записів журналу (типово 10)."""
        n = int(arg) if arg.strip().isdigit() else 10
        path = self.args.log_file
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                for line in f.readlines()[-n:]:
                    print(line.rstrip())

    def do_quit(self, _):
        """quit — вихід (майстер-ключ затирається в пам'яті)."""
        if self.ctx:
            self.ctx.wipe()
        log_event("repl_exit", status="success")
        print("До побачення.")
        return True

    do_exit = do_quit
    do_EOF = do_quit


def cmd_shell(args) -> int:
    ks = open_keystore(args)
    sh = Shell(ks, args)
    log_event("repl_start", status="success")
    if args.label:
        sh.onecmd(f"use {args.label}")
    sh.cmdloop()
    return 0


# ---------------------------------------------------------------------------
# Парсер
# ---------------------------------------------------------------------------
def _add_params(p):
    p.add_argument("--mode", default="aes-gcm", help="режим: aes-gcm (gcm), aes-cbc-hmac (cbc), aes-ctr-hmac, "
                                                     "aes-cfb-hmac, chacha20-poly1305, aes-gcm-siv")
    p.add_argument("--key-bits", type=int, choices=(128, 192, 256), help="довжина ключа AES")
    p.add_argument("--iv-len", type=int, help="довжина IV/nonce, байт")
    p.add_argument("--padding", choices=("pkcs7", "ansix923", "iso7816", "none"), help="доповнення (лише CBC)")
    p.add_argument("--tag-len", type=int, help="довжина тегу/HMAC, байт")
    p.add_argument("--segment-size", type=int, help="розмір сегмента для сегментованих AEAD")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="aes_cli.py", description="AES-Lab: автентифіковане шифрування файлів")
    ap.add_argument("--version", action="version", version=f"AES-Lab {__version__}")
    ap.add_argument("--keystore", default=config.KEYSTORE_PATH, help="шлях до сховища ключів")
    ap.add_argument("--log-file", default=config.LOG_PATH, help="шлях до журналу JSONL")
    ap.add_argument("--password", help=argparse.SUPPRESS)       # небажаний спосіб, лише для сумісності
    sp = ap.add_subparsers(dest="cmd", required=True)

    pk = sp.add_parser("key", help="керування ключами")
    ka = pk.add_subparsers(dest="action", required=True)
    kn = ka.add_parser("new", help="створити ключ")
    kr = ka.add_parser("rotate", help="ротація ключа (старий → retired)")
    for p in (kn, kr):
        p.add_argument("--label", required=True)
        p.add_argument("--kdf", choices=("pbkdf2", "scrypt"), default="pbkdf2")
        p.add_argument("--iterations", type=int, default=config.PBKDF2_ITERATIONS)
        p.add_argument("--key-bits", type=int, choices=(128, 192, 256), default=None if p is kr else 256)
        p.add_argument("--expires-days", type=int, default=config.DEFAULT_EXPIRES_DAYS)
        p.add_argument("--max-uses", type=int, default=config.DEFAULT_MAX_USES)
    kn.add_argument("--no-reuse-check", action="store_true", help="не перевіряти повтор пароля серед ключів")
    ka.add_parser("list", help="перелік ключів")
    for name in ("info", "verify", "retire", "revoke"):
        p = ka.add_parser(name)
        g = p.add_mutually_exclusive_group(required=True)
        g.add_argument("--label")
        g.add_argument("--key-id")
        if name in ("retire", "revoke"):
            p.add_argument("--reason", default="")

    pe = sp.add_parser("enc", help="зашифрувати файл")
    pe.add_argument("--in", dest="infile", required=True)
    pe.add_argument("--out", dest="outfile", required=True)
    pe.add_argument("--label", required=True)
    pe.add_argument("--aad", help="додаткові автентифіковані дані (рядок)")
    _add_params(pe)

    pd = sp.add_parser("dec", help="розшифрувати файл (режим — із заголовка)")
    pd.add_argument("--in", dest="infile", required=True)
    pd.add_argument("--out", dest="outfile", required=True)
    pd.add_argument("--label", help="очікувана мітка ключа (необов'язково; ключ визначається за key_id)")
    pd.add_argument("--aad")

    pr = sp.add_parser("rekey", help="перешифрувати файл активним ключем після ротації")
    pr.add_argument("--in", dest="infile", required=True)
    pr.add_argument("--out", dest="outfile", required=True)
    pr.add_argument("--label", required=True)
    pr.add_argument("--mode")
    pr.add_argument("--aad")

    pi = sp.add_parser("info", help="показати заголовок зашифрованого файлу")
    pi.add_argument("--in", dest="infile", required=True)
    sp.add_parser("modes", help="перелік режимів і параметрів")

    ps = sp.add_parser("shell", help="інтерактивна оболонка (REPL)")
    ps.add_argument("--label")
    ps.add_argument("--mode", default="aes-gcm")

    for name, hlp in (("bench", "бенчмарк (див. benchmark.py --help)"), ("tamper", "демонстрація підміни"),
                      ("logs", "аналіз журналу")):
        p = sp.add_parser(name, help=hlp, add_help=False)
        p.add_argument("rest", nargs=argparse.REMAINDER)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    get_logger(args.log_file)
    if args.cmd in ("bench", "tamper", "logs"):
        from . import benchmark, log_analyzer, tamper
        return {"bench": benchmark.main, "tamper": tamper.main, "logs": log_analyzer.main}[args.cmd](args.rest)
    handlers = {"key": cmd_key, "enc": cmd_enc, "dec": cmd_dec, "rekey": cmd_rekey, "info": cmd_info,
                "modes": cmd_modes, "shell": cmd_shell}
    try:
        return handlers[args.cmd](args)
    except AesLabError as e:
        print(f"❌ ПОМИЛКА [{e.code}]: {e.message}", file=sys.stderr)
        return e.exit_code
    except KeyboardInterrupt:
        print("\nПерервано користувачем", file=sys.stderr)
        return 130
