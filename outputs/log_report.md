# Звіт аналізу журналу AES-Lab

Джерело: `logs/aes.jsonl` (+ ротаційні копії). Некоректних рядків: 0.

Записів: **499**, сесій: 18, період: 2026-11-24 20:20:55 – 2026-11-24 20:22:39 UTC. Оброблено даних (успішно): 257.6 KiB, середня тривалість успішної операції: 4.80 мс.

## 1. Аномалії та інциденти

| Правило | Важливість | Опис |
|---|---|---|
| A1 | ВИСОКА | Серія збоїв автентичності: 64 подій за ≤60 с для key_id=6f0a215a60807c43 (20:22:38–20:22:38) — можлива підміна файлів або атака |
| A1 | ВИСОКА | Серія збоїв автентичності: 256 подій за ≤60 с для key_id=oracle-test (20:22:38–20:22:39) — можлива підміна файлів або атака |
| A2 | ВИСОКА | Можливий підбір пароля: 6 невдалих спроб за ≤300 с для key_id=6f0a215a60807c43 |
| A3 | КРИТИЧНА | Спроби використати відкликаний ключ: 2 (key_id: 6f0a215a60807c43) |
| A4 | КРИТИЧНА | Виявлено повторне використання nonce/IV: 1 — перевірте RNG/клонування ВМ, виконайте ротацію ключа |
| A5 | СЕРЕДНЯ | Сесія 4d09162ffa61: 14 пошкоджених/чужих файлів (BAD_MAGIC/BAD_FORMAT/TRUNCATED) |
| A6 | ІНФО | Запуски демонстрацій небезпечних режимів без MAC: 1 |

## 2. Події

| Подія | Кількість |
|---|---|
| decrypt | 358 |
| tamper_test | 91 |
| key_unlock | 21 |
| encrypt | 17 |
| repl_mode_change | 3 |
| repl_param_change | 2 |
| key_create | 1 |
| repl_start | 1 |
| repl_exit | 1 |
| key_rotate | 1 |
| key_warning | 1 |
| rekey | 1 |
| insecure_demo | 1 |

## 3. Рівні

| Рівень | Кількість |
|---|---|
| ERROR | 346 |
| INFO | 149 |
| WARNING | 4 |

## 4. Операції за статусом

| Операція | Статус | Кількість |
|---|---|---|
| decrypt | fail | 344 |
| encrypt | success | 15 |
| decrypt | success | 14 |
| encrypt | fail | 2 |

## 5. Режими

| Режим | Операція | Статус | Кількість |
|---|---|---|---|
| aes-cbc-hmac | decrypt | fail | 268 |
| aes-cbc-hmac | decrypt | success | 3 |
| aes-cbc-hmac | encrypt | success | 4 |
| aes-cfb-hmac | decrypt | fail | 12 |
| aes-cfb-hmac | decrypt | success | 1 |
| aes-cfb-hmac | encrypt | success | 1 |
| aes-ctr-hmac | decrypt | fail | 12 |
| aes-ctr-hmac | decrypt | success | 2 |
| aes-ctr-hmac | encrypt | success | 2 |
| aes-gcm | decrypt | fail | 15 |
| aes-gcm | decrypt | success | 5 |
| aes-gcm | encrypt | fail | 2 |
| aes-gcm | encrypt | success | 5 |
| aes-gcm-siv | decrypt | fail | 12 |
| aes-gcm-siv | decrypt | success | 1 |
| aes-gcm-siv | encrypt | success | 1 |
| chacha20-poly1305 | decrypt | fail | 12 |
| chacha20-poly1305 | decrypt | success | 2 |
| chacha20-poly1305 | encrypt | success | 2 |
| None | decrypt | fail | 13 |

## 6. Ключі

| Мітка | key_id | Статус | Кількість |
|---|---|---|---|
| raw | oracle-test | fail | 256 |
| tamper-demo | 6f0a215a60807c43 | fail | 81 |
| lab-main | 5b3ef446988dd614 | success | 24 |
| tamper-demo | 6f0a215a60807c43 | success | 13 |
| - | 6f0a215a60807c43 | fail | 6 |
| raw | 6f0a215a60807c43 | fail | 6 |
| lab-main | f25e6ec9209881ad | success | 4 |
| lab-main | 5b3ef446988dd614 | fail | 3 |
| - | None | fail | 1 |
| lab-main | f25e6ec9209881ad | fail | 1 |
| raw | oracle-test | success | 1 |

## 7. Коди помилок

| error_code | Кількість |
|---|---|
| AUTH_FAILED | 262 |
| TAMPER_DETECTED | 60 |
| WRONG_PASSWORD | 8 |
| TRUNCATED | 8 |
| BAD_MAGIC | 7 |
| KEY_MISMATCH | 6 |
| KEY_REVOKED | 2 |
| NONCE_REUSE | 1 |

## 8. Останні невдалі операції

| Час (UTC) | Подія | Режим | key_id | Код | Файл |
|---|---|---|---|---|---|
| 20:22:39 | decrypt | aes-cbc-hmac | oracle-test | AUTH_FAILED | forged.cbc |
| 20:22:39 | decrypt | aes-cbc-hmac | oracle-test | AUTH_FAILED | forged.cbc |
| 20:22:39 | decrypt | aes-cbc-hmac | oracle-test | AUTH_FAILED | forged.cbc |
| 20:22:39 | decrypt | aes-cbc-hmac | oracle-test | AUTH_FAILED | forged.cbc |
| 20:22:39 | decrypt | aes-cbc-hmac | oracle-test | AUTH_FAILED | forged.cbc |
| 20:22:39 | decrypt | aes-cbc-hmac | oracle-test | AUTH_FAILED | forged.cbc |
| 20:22:39 | decrypt | aes-cbc-hmac | oracle-test | AUTH_FAILED | forged.cbc |
| 20:22:39 | decrypt | aes-cbc-hmac | oracle-test | AUTH_FAILED | forged.cbc |
| 20:22:39 | decrypt | aes-cbc-hmac | oracle-test | AUTH_FAILED | forged.cbc |
| 20:22:39 | decrypt | aes-cbc-hmac | oracle-test | AUTH_FAILED | forged.cbc |
