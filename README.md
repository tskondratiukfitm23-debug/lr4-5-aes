# AES-Lab — симетричне шифрування файлів з використанням AES

Лабораторна робота №4-5 «Реалізація симетричного шифрування з використанням AES».
Дисципліна «Прикладні аспекти програмування в системах інформаційної та кібербезпеки».
Виконав: Кондратюк Т.С., група 22340, Київський столичний університет імені Бориса Грінченка, 2026.

Застосунок на Python шифрує файли в режимах AES-GCM, AES-CBC/CTR/CFB + HMAC-SHA256 (Encrypt-then-MAC), AES-GCM-SIV і ChaCha20-Poly1305. Ключі виводяться з пароля (PBKDF2/scrypt + HKDF) і мають керований життєвий цикл. Реалізовано атомарний запис результату, структуроване журналювання з аналізатором аномалій, бенчмарк і систематичну імітацію підміни.

## Відповідність завданню

| № | Вимога | Реалізація | Документація |
|---|---|---|---|
| 1 | PBKDF2, випадковий salt, контроль довжини ключа, запобігання повторному використанню, життєвий цикл | `aeslab/keystore.py` | [docs/01_keys.md](docs/01_keys.md) |
| 2 | Режими CBC, GCM та інші, інтерфейс параметрів (блок, IV, паддинг), тег/MAC | `aeslab/modes.py`, `params.py`, `container.py` | [docs/02_modes.md](docs/02_modes.md) |
| 3 | Швидкодія і ресурси на файлах різного розміру, порівняльна таблиця | `aeslab/benchmark.py` → `outputs/benchmark_*` | [docs/03_benchmark.md](docs/03_benchmark.md) |
| 4 | CLI-застосунок, захищене зберігання ключа, зміна режиму без перезапуску | `aeslab/cli.py` (`enc`/`dec`/`shell`) | [docs/04_app.md](docs/04_app.md) |
| 5 | Журналювання, виявлення некоректного тегу, аналіз логів | `aeslab/logging_setup.py`, `log_analyzer.py` | [docs/05_logging.md](docs/05_logging.md) |
| 6 | Імітація підміни, висновки, рекомендації | `aeslab/tamper.py`, `insecure_demo.py` → `outputs/tamper_*` | [docs/06_tamper.md](docs/06_tamper.md) |

## Структура проєкту

```
aes_cli.py            CLI: key / enc / dec / rekey / info / modes / shell / bench / tamper / logs
benchmark.py          бенчмарк (обгортка над aeslab.benchmark)
tamper_demo.py        імітація підміни (обгортка над aeslab.tamper)
log_analyzer.py       аналіз журналу (обгортка над aeslab.log_analyzer)
aeslab/
  config.py           параметри й політики за замовчуванням
  errors.py           ієрархія помилок з кодами та кодами виходу
  params.py           CipherParams — інтерфейс параметрів шифрування
  modes.py            реєстр режимів (@register_mode)
  container.py        формат файлу v2 (MAGIC|VER|HDRLEN|HEADER|BODY)
  keystore.py         KDF, HKDF, keystore, статуси, ліміти, ротація
  engine.py           encrypt/decrypt/rekey, атомарний запис, журналювання
  cli.py              argparse + REPL (cmd)
  logging_setup.py    JSONL-журнал з ротацією
  log_analyzer.py     правила A1–A6, звіт Markdown
  benchmark.py        вимірювання, CSV/MD/PNG
  tamper.py           сценарії T00–T15, K01–K03, I01–I05
  insecure_demo.py    НЕБЕЗПЕЧНІ CBC/CTR без MAC — лише для демонстрацій
tests/                pytest (273 тести)
scripts/demo_session.sh   повна демонстраційна сесія CLI
docs/                 документація етапів 1–6
outputs/              результати: benchmark_*, tamper_results.*, log_report.md, cli_session.txt, графіки
data/sample.txt       тестовий файл
```

## Встановлення (Ubuntu / Linux)

```bash
sudo apt install -y python3 python3-venv git
git clone https://github.com/<ваш-акаунт>/<репозиторій>.git && cd <репозиторій>
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Потрібно: Python ≥ 3.10, `cryptography` ≥ 42 (для AES-GCM-SIV — збірка з OpenSSL ≥ 3.2; якщо режим недоступний, він просто не реєструється). `matplotlib` потрібен лише для графіків, `pytest` — для тестів.

## Швидкий старт

```bash
read -rs AES_LAB_PASSWORD; export AES_LAB_PASSWORD     # пароль: ≥12 символів, 3 класи
python3 aes_cli.py key new --label lab-main --expires-days 180 --max-uses 100000
python3 aes_cli.py key list

python3 aes_cli.py enc --in data/sample.txt --out sample.enc --label lab-main --mode gcm --aad "doc=LR4"
python3 aes_cli.py info --in sample.enc
python3 aes_cli.py dec --in sample.enc --out sample.dec --aad "doc=LR4"
cmp data/sample.txt sample.dec && echo "Файли ідентичні"

python3 aes_cli.py enc --in data/sample.txt --out s_cbc.enc --label lab-main --mode cbc --key-bits 192 --padding iso7816
python3 aes_cli.py modes            # усі режими та допустимі параметри
python3 aes_cli.py shell            # REPL: use / mode / set / enc / dec / status / log / quit
```

Пароль ніколи не передається аргументом командного рядка. Якщо `AES_LAB_PASSWORD` не задано, його запитує `getpass`.

## Відтворення результатів

```bash
python3 -m pytest -q                                          # тести
python3 benchmark.py                                          # → outputs/benchmark_results.{md,csv}, *.png
python3 tamper_demo.py --outdir outputs                       # → outputs/tamper_results.{md,csv}
export AES_LAB_NEW_PASSWORD='<NEW_PASSWORD>'
bash scripts/demo_session.sh | tee outputs/cli_session.txt    # повна CLI-сесія (етапи 1–8)
python3 log_analyzer.py --log logs/aes.jsonl --out outputs/log_report.md
```

## Ключові результати

**Тести:** 273 пройдено, 3 пропущено (комбінації довжини ключа, які ChaCha20 / GCM-SIV не підтримують).

**Швидкодія на файлі 50 MB** (Intel Xeon з AES-NI; повна таблиця для 1 KB – 50 MB — у [outputs/benchmark_results.md](outputs/benchmark_results.md)):

| Режим | Шифр., MiB/s | Дешифр., MiB/s | Пік пам'яті, KiB | Безпека (1–5) | Доцільність |
|---|---:|---:|---:|:--:|---|
| aes-gcm | 2471 | 2469 | ≈2060 | 5 | за замовчуванням |
| chacha20-poly1305 | 1319 | 1348 | ≈200 | 5 | платформи без AES-NI |
| aes-ctr-hmac | 919 | 812 | ≈3080 | 4 | сумісність |
| aes-cfb-hmac | 569 | 853 | ≈3080 | 3 | не рекомендовано |
| aes-cbc-hmac | 565 | 741 | ≈3080–4110 | 4 | легасі-системи |
| aes-gcm-siv | 475 | 475 | ≈200 | 5 | ризик повтору nonce |

**Імітація підміни** ([outputs/tamper_results.md](outputs/tamper_results.md)): у 6 автентифікованих режимах виявлено 90 атак із 90, і жодного вихідного файлу не створено. Повтор nonce і відкликаний ключ заблоковано. CBC/CTR без MAC не виявили bit-flipping (I01–I03), а padding oracle відновив блок CBC без ключа за 1801 запит. Проти CBC+HMAC (EtM) оракул не працює.

**Аналіз журналу** ([outputs/log_report.md](outputs/log_report.md)): 499 записів, 7 аномалій (2 критичні, 3 високі, 1 середня, 1 інформаційна).

## Безпека: коротко

* Ключі ніде не зберігаються. `keystore.json` (у `.gitignore`, права 0600) містить лише salt, параметри KDF, verifier і лічильники.
* Окремі ключі шифрування й MAC для кожного режиму (HKDF). Заголовок файлу автентифікується.
* Під час дешифрування MAC/тег перевіряється до видачі відкритого тексту. Результат записується атомарно.
* Журнал не містить паролів, ключів і відкритого тексту.
* Висновки про відомі вразливості й рекомендації (технічні та організаційні) — у [docs/06_tamper.md](docs/06_tamper.md).

## Ліцензія

Навчальний проєкт. Стартовий код надав викладач дисципліни.
