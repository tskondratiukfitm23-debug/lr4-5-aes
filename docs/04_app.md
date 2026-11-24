# Етап 4. Тестовий застосунок (CLI + REPL)

Код: `aeslab/cli.py` (точка входу — `aes_cli.py`), `aeslab/engine.py`. Запис демонстраційної сесії: `outputs/cli_session.txt` (скрипт `scripts/demo_session.sh`).

## 4.1. Сценарій «файл → шифрування → дешифрування»

```bash
export AES_LAB_PASSWORD='<PASSWORD>'           # або без змінної — запит через getpass
python3 aes_cli.py key new --label lab-main
python3 aes_cli.py enc --in data/sample.txt --out outputs/demo/sample.enc --label lab-main --mode gcm --aad "doc=LR4"
python3 aes_cli.py info --in outputs/demo/sample.enc          # заголовок (без секретів)
python3 aes_cli.py dec  --in outputs/demo/sample.enc --out outputs/demo/sample.dec --aad "doc=LR4"
cmp data/sample.txt outputs/demo/sample.dec && echo "Файли ідентичні"
```

Режим і параметри дешифрування беруться із заголовка файлу, а ключ визначається за `key_id`.

Інші приклади:
```bash
python3 aes_cli.py enc --in data/sample.txt --out s_cbc.enc --label lab-main --mode cbc --key-bits 192 --padding iso7816 --tag-len 24
python3 aes_cli.py enc --in data/sample.txt --out s_cc.enc  --label lab-main --mode chacha20-poly1305
python3 aes_cli.py key rotate --label lab-main
AES_LAB_OLD_PASSWORD='<OLD>' AES_LAB_PASSWORD='<NEW>' python3 aes_cli.py rekey --in s.enc --out s2.enc --label lab-main
```

## 4.2. Захищене зберігання ключа

* Ключі не зберігаються ніде. Вони щоразу виводяться з пароля (PBKDF2/scrypt → HKDF).
* `keystore.json` містить лише salt, параметри KDF, verifier і лічильники. Права `0600`, атомарний запис.
* Пароль передається через `AES_LAB_PASSWORD` або `getpass`. Прихований аргумент `--password` залишено лише для сумісності зі стартовим кодом. Він не показується в довідці, а кожне його використання записується в журнал як `WARNING insecure_password_source` (правило A6 аналізатора), бо пароль потрапляє в історію shell і `ps`.
* Розблокований майстер-ключ зберігається лише в пам'яті сесії. Під час `quit` у REPL буфер (`bytearray`) затирається нулями. Обмеження Python: повністю гарантувати очищення пам'яті неможливо, це враховано в рекомендаціях.
* Паролі й ключі ніколи не записуються в журнал.

## 4.3. Динамічна зміна режиму без перезапуску (REPL)

```
$ python3 aes_cli.py shell
aeslab> use lab-main              # розблокувати ключ один раз
aeslab> status
aeslab> mode cbc                  # змінити режим
aeslab> set padding ansix923      # змінити параметр
aeslab> enc data/sample.txt outputs/demo/repl_cbc.enc
aeslab> mode ctr
aeslab> enc data/sample.txt outputs/demo/repl_ctr.enc
aeslab> mode gcm
aeslab> set tag_len 12
aeslab> set iv_len 3              # некоректно → повідомлення, стан не змінено
aeslab> dec outputs/demo/repl_cbc.enc
aeslab> log 5                     # останні записи журналу
aeslab> quit
```

Команди: `status`, `modes`, `keys`, `use`, `mode`, `set`, `reset`, `enc`, `dec`, `info`, `log`, `help`, `quit`. Кожна зміна режиму чи параметра записується в журнал (`repl_mode_change`, `repl_param_change`).

## 4.4. Коди завершення CLI

| Код | Помилка | Код | Помилка |
|---:|---|---:|---|
| 0 | успіх | 23 | KEY_MISMATCH |
| 2 | INVALID_PARAMS | 30 | WRONG_PASSWORD |
| 3 | IO_ERROR | 31 | KEY_NOT_FOUND |
| 10 | BAD_MAGIC | 32 | KEY_REVOKED |
| 11 | BAD_FORMAT | 33 | KEY_EXPIRED |
| 12 | TRUNCATED | 34 | KEY_EXHAUSTED |
| 13 | UNSUPPORTED_MODE | 35 | NONCE_LIMIT |
| 20 | TAMPER_DETECTED | 36 | NONCE_REUSE |
| 21 | AUTH_FAILED | 37 | WEAK_PASSWORD |
| 22 | BAD_PADDING | 38 | KEY_REUSE |
| — | — | 39 | KEY_LENGTH |
| — | — | 40 | KEY_RETIRED |

Ненульові коди дозволяють вбудовувати застосунок у скрипти й CI.
