# Результати імітації підміни (tamper_demo)

Для кожного автентифікованого режиму зашифровано файл ≈20 KB (з AAD), потім файл модифіковано й виконано дешифрування через той самий програмний шлях, що й у CLI. «Вихід створено: ні» — підтверджує атомарність (жодного неавтентифікованого відкритого тексту на диску).

## 1. Матриця виявлення (код помилки для кожного режиму)

| ID | Сценарій | aes-gcm | aes-cbc-hmac | aes-ctr-hmac | aes-cfb-hmac | chacha20-poly1305 | aes-gcm-siv |
|---|---|---|---|---|---|---|---|
| T00 | Контроль: немодифікований файл | ✅ OK | ✅ OK | ✅ OK | ✅ OK | ✅ OK | ✅ OK |
| T01 | Інверсія біта в середині шифротексту | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED |
| T02 | Зміна першого байта шифротексту | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED |
| T03 | Зміна останнього байта тегу/HMAC | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED |
| T04 | Підміна IV/nonce у заголовку | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED |
| T05 | Підміна алгоритму/параметрів у заголовку (downgrade) | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED |
| T06 | Підміна key_id у заголовку | ✅ KEY_MISMATCH | ✅ KEY_MISMATCH | ✅ KEY_MISMATCH | ✅ KEY_MISMATCH | ✅ KEY_MISMATCH | ✅ KEY_MISMATCH |
| T07 | Пошкодження сигнатури MAGIC | ✅ BAD_MAGIC | ✅ BAD_MAGIC | ✅ BAD_MAGIC | ✅ BAD_MAGIC | ✅ BAD_MAGIC | ✅ BAD_MAGIC |
| T08 | Обрізання хвоста (−5 байтів) | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED |
| T09 | Обрізання тіла (половина / по межі сегмента STREAM) | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED | ✅ TRUNCATED | ✅ TRUNCATED |
| T10 | Обрізання до неповного заголовка | ✅ TRUNCATED | ✅ TRUNCATED | ✅ TRUNCATED | ✅ TRUNCATED | ✅ TRUNCATED | ✅ TRUNCATED |
| T11 | Додавання 16 байтів у кінець | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED |
| T12 | Перестановка блоків 0↔1 (для STREAM — сегментів) | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED |
| T13 | Неправильна AAD (контекст) | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED | ✅ TAMPER_DETECTED |
| T14 | Неправильний пароль | ✅ WRONG_PASSWORD | ✅ WRONG_PASSWORD | ✅ WRONG_PASSWORD | ✅ WRONG_PASSWORD | ✅ WRONG_PASSWORD | ✅ WRONG_PASSWORD |
| T15 | Неправильний ключ (в обхід перевірки пароля) | ✅ AUTH_FAILED | ✅ AUTH_FAILED | ✅ AUTH_FAILED | ✅ AUTH_FAILED | ✅ AUTH_FAILED | ✅ AUTH_FAILED |

**Підсумок:** виявлено 90 з 90 атак на автентифіковані режими; вихідний файл створено у 0 випадках з 90.

## 2. Політики ключів та небезпечні режими

| ID | Сценарій | Режим | Виявлено | Код | Вихід створено | Коментар |
|---|---|---|:--:|---|:--:|---|
| K01 | Повторне використання nonce (зламаний RNG) | aes-gcm | так | NONCE_REUSE | ні | відбиток nonce уже є в keystore — шифрування заблоковано |
| K02 | Дешифрування відкликаним ключем | aes-gcm | так | KEY_REVOKED | ні | статус revoked |
| K03 | Шифрування відкликаним ключем | aes-gcm | так | KEY_REVOKED | ні |  |
| I01 | CBC без MAC: bit-flipping через IV (сума 0000100→9999100) | aes-cbc (без MAC, демо) | НІ | — | так | розшифровано без помилок: «AMOUNT=9999100;;» |
| I02 | CBC без MAC: зміна блоку C1 → підміна рахунку в P2 | aes-cbc (без MAC, демо) | НІ | — | так | P2 = «TO=UA99999999000», P1 зіпсовано |
| I03 | CTR без MAC: точкова підміна суми | aes-ctr (без MAC, демо) | НІ | — | так | «AMOUNT=9999999;;», решта тексту не пошкоджена |
| I04 | Padding oracle: відновлення останнього блоку без ключа | aes-cbc (без MAC, демо) | НІ | BAD_PADDING (оракул) | — | відновлено b'4;CVV=987;EXP=1' за 1801 запитів |
| I05 | Padding oracle проти AES-CBC+HMAC (EtM) | aes-cbc-hmac | так | AUTH_FAILED | ні | HMAC перевіряється до зняття доповнення — оракул не дає інформації |

## 3. Деталі демонстрацій без MAC

* **CBC bit-flipping:** оригінальний блок `AMOUNT=0000100;;` → після XOR в IV `AMOUNT=9999100;;`; дешифрування успішне, доповнення коректне — програма без MAC не має жодного способу помітити підміну.
* **Зміна блоку C1:** другий блок став `TO=UA99999999000` (рахунок отримувача підмінено), перший — сміття.
* **Padding oracle:** лише за відповіддю «доповнення коректне/некоректне» відновлено останній блок `b'4;CVV=987;EXP=1'` за 1801 запитів (≤ 16·256 = 4096) без знання ключа.
* **AES-CBC+HMAC:** та сама атака зупиняється на першому байті: кожен підроблений шифротекст відхиляється ще на перевірці HMAC (код однаковий для всіх запитів), тож оракул не існує.

## 4. Пояснення кодів

* `TAMPER_DETECTED` — пароль підтверджено verifier'ом і key_id збігся, отже тег не зійшовся через зміну даних/заголовка або іншу AAD.
* `AUTH_FAILED` — тег не зійшовся, а ключ не підтверджено (наприклад, «сирий» ключ): криптографічно неможливо відрізнити неправильний ключ від підміни — обидва випадки дають випадковий тег.
* `BAD_FORMAT` — заголовок змінено так, що параметри стали неприпустимими (до криптоперевірки).
* `KEY_MISMATCH` / `KEY_NOT_FOUND` — key_id у заголовку не відповідає ключу.
* `TRUNCATED` — файл обрізано (неповний заголовок або відсутній фінальний сегмент STREAM).
* `BAD_MAGIC` — файл не є контейнером AES-Lab.
* `WRONG_PASSWORD` — неправильний пароль виявлено до дешифрування (verifier).
* `NONCE_REUSE`, `KEY_REVOKED` — спрацювали політики життєвого циклу ключів.
