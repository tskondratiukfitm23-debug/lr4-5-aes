#!/usr/bin/env bash
# Демонстраційна CLI-сесія AES-Lab (усі етапи ЛР). Паролі беруться зі змінних середовища:
#   export AES_LAB_PASSWORD='<PASSWORD>'          # пароль ключа lab-main
#   export AES_LAB_NEW_PASSWORD='<NEW_PASSWORD>'  # новий пароль для ротації
# Запуск із кореня проєкту:  bash scripts/demo_session.sh | tee outputs/cli_session.txt
set -u
cd "$(dirname "$0")/.."
: "${AES_LAB_PASSWORD:?Встановіть AES_LAB_PASSWORD}"
: "${AES_LAB_NEW_PASSWORD:?Встановіть AES_LAB_NEW_PASSWORD}"
PY=${PYTHON:-python3}
mkdir -p outputs/demo
step() { echo; echo "=================== $* ==================="; }
run()  { echo "\$ $*"; "$@"; echo "[код виходу: $?]"; }

step "1. Ініціалізація ключа (PBKDF2-HMAC-SHA256, 310000 ітерацій, salt 16 B)"
run $PY aes_cli.py key new --label lab-main --expires-days 180 --max-uses 100000
run $PY aes_cli.py key list
run $PY aes_cli.py key verify --label lab-main

step "2. Режими та параметри"
run $PY aes_cli.py modes

step "3. Шифрування/дешифрування AES-GCM"
run $PY aes_cli.py enc --in data/sample.txt --out outputs/demo/sample_gcm.enc --label lab-main --mode gcm --aad "doc=LR4"
run $PY aes_cli.py info --in outputs/demo/sample_gcm.enc
run $PY aes_cli.py dec --in outputs/demo/sample_gcm.enc --out outputs/demo/sample_gcm.dec --aad "doc=LR4"
run cmp data/sample.txt outputs/demo/sample_gcm.dec && echo "Файли ідентичні"

step "4. AES-CBC+HMAC з AES-192 і доповненням ISO/IEC 7816-4; ChaCha20-Poly1305"
run $PY aes_cli.py enc --in data/sample.txt --out outputs/demo/sample_cbc.enc --label lab-main --mode cbc --key-bits 192 --padding iso7816 --tag-len 24
run $PY aes_cli.py dec --in outputs/demo/sample_cbc.enc --out outputs/demo/sample_cbc.dec
run $PY aes_cli.py enc --in data/sample.txt --out outputs/demo/sample_chacha.enc --label lab-main --mode chacha20-poly1305
run $PY aes_cli.py dec --in outputs/demo/sample_chacha.enc --out outputs/demo/sample_chacha.dec

step "5. Аномалії: підміна байта, неправильна AAD, неправильний пароль, не-контейнер"
$PY -c "import sys;d=bytearray(open(sys.argv[1],'rb').read());d[-20]^=1;open(sys.argv[2],'wb').write(d)" outputs/demo/sample_gcm.enc outputs/demo/sample_gcm_tampered.enc
run $PY aes_cli.py dec --in outputs/demo/sample_gcm_tampered.enc --out outputs/demo/tampered.dec --aad "doc=LR4"
run ls outputs/demo/tampered.dec
run $PY aes_cli.py dec --in outputs/demo/sample_gcm.enc --out outputs/demo/x.dec --aad "doc=LR5"
AES_LAB_PASSWORD='Wrong-Passw0rd!' run $PY aes_cli.py dec --in outputs/demo/sample_gcm.enc --out outputs/demo/x.dec
run $PY aes_cli.py dec --in data/sample.txt --out outputs/demo/x.dec

step "6. REPL: зміна режиму і параметрів без перезапуску"
printf '%s\n' "use lab-main" "status" "mode cbc" "set padding ansix923" "enc data/sample.txt outputs/demo/repl_cbc.enc" \
  "mode ctr" "enc data/sample.txt outputs/demo/repl_ctr.enc" "mode gcm" "set tag_len 12" "set iv_len 3" \
  "enc data/sample.txt outputs/demo/repl_gcm.enc" "dec outputs/demo/repl_cbc.enc" "dec outputs/demo/repl_ctr.enc" \
  "dec outputs/demo/repl_gcm.enc" "status" "quit" | $PY aes_cli.py shell
echo "[код виходу: $?]"

step "7. Ротація ключа та перешифрування старого файлу"
run $PY aes_cli.py key rotate --label lab-main
run $PY aes_cli.py key list
AES_LAB_OLD_PASSWORD="$AES_LAB_PASSWORD" AES_LAB_PASSWORD="$AES_LAB_NEW_PASSWORD" \
  run $PY aes_cli.py rekey --in outputs/demo/sample_gcm.enc --out outputs/demo/sample_rekeyed.enc --label lab-main --aad "doc=LR4"
AES_LAB_PASSWORD="$AES_LAB_NEW_PASSWORD" run $PY aes_cli.py dec --in outputs/demo/sample_rekeyed.enc --out outputs/demo/sample_rekeyed.dec --aad "doc=LR4"
run $PY aes_cli.py enc --in data/sample.txt --out outputs/demo/old_key.enc --label lab-main --mode gcm

step "8. Аналіз журналу"
run $PY log_analyzer.py --log logs/aes.jsonl --out outputs/log_report.md
