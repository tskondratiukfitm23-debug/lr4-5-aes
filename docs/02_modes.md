# Етап 2. Режими AES, інтерфейс параметрів, цілісність і автентичність

Код: `aeslab/modes.py` (реєстр режимів), `aeslab/params.py` (`CipherParams`), `aeslab/container.py` (формат файлу), `aeslab/engine.py` (оркестрація). Тести: `tests/test_roundtrip.py`, `tests/test_params.py`.

## 2.1. Зареєстровані режими

| Режим (псевдонім) | Конструкція | Ключ, біт | IV/nonce, B | Доповнення | Тег, B | Цілісність |
|---|---|---|---|---|---|---|
| `aes-gcm` (`gcm`) — **за замовчуванням** | AEAD, SP 800-38D | 128/192/256 | 12 (16) | — | 12–16 (типово 16) | GHASH-тег |
| `aes-cbc-hmac` (`cbc`) | AES-CBC + HMAC-SHA256, Encrypt-then-MAC | 128/192/256 | 16 | PKCS#7 / ANSI X9.23 / ISO 7816-4 | 16–32 (типово 32) | HMAC |
| `aes-ctr-hmac` (`ctr`) | AES-CTR + HMAC-SHA256, EtM | 128/192/256 | 16 | — | 16–32 | HMAC |
| `aes-cfb-hmac` (`cfb`) | AES-CFB + HMAC-SHA256, EtM | 128/192/256 | 16 | — | 16–32 | HMAC |
| `chacha20-poly1305` (`chacha`) | AEAD RFC 8439, сегментований STREAM | 256 | 7 (префікс) | — | 16 | Poly1305 на сегмент |
| `aes-gcm-siv` (`siv`) | AEAD RFC 8452, стійкий до повтору nonce, STREAM | 128/256 | 7 (префікс) | — | 16 | POLYVAL на сегмент |

Окремий модуль `aeslab/insecure_demo.py` містить **небезпечні** CBC і CTR без MAC. Вони не входять у реєстр і недоступні з CLI, а використовуються лише в tamper-демонстраціях (етап 6).

Перелік режимів з допустимими параметрами виводить команда `python3 aes_cli.py modes`.

## 2.2. Інтерфейс параметрів `CipherParams`

```python
@dataclass
class CipherParams:
    mode: str = "aes-gcm"
    key_bits: int = 256            # 128 | 192 | 256
    block_size: int = 128          # для AES фіксований (FIPS-197), інше значення відхиляється
    iv_len: int | None = None      # довжина IV/nonce (None → типова для режиму)
    padding: str | None = None     # pkcs7 | ansix923 | iso7816 | none
    tag_len: int | None = None     # довжина тегу GCM або усіченого HMAC
    aad: bytes | None = None       # додаткові автентифіковані дані (контекст)
    segment_size: int | None = None  # розмір сегмента для STREAM-AEAD (1 KiB…16 MiB)
```

`resolve_params()` заповнює типові значення режиму й перевіряє всі обмеження. Некоректна комбінація відхиляється до шифрування (`INVALID_PARAMS`, `KEY_LENGTH`). Приклади: доповнення для GCM, IV 3 байти, AES-192 для ChaCha20.

**Чому довжина блоку не налаштовується.** Блок AES завжди 128 біт: це властивість стандарту FIPS-197, а не параметр. Від довжини ключа (128/192/256) залежить лише кількість раундів (10/12/14). Параметр `block_size` присутній в інтерфейсі, але приймає лише 128, і це явно пояснюється в повідомленні про помилку.

Параметри задаються:
* в CLI: `--mode --key-bits --iv-len --padding --tag-len --segment-size --aad`;
* у REPL: `mode <назва>`, `set <параметр> <значення>`, `reset` (див. етап 4).

## 2.3. Формат файлу-контейнера (v2)

```
+--------+-----+--------+--------------------+------------------------------+
| MAGIC  | VER | HDRLEN | HEADER (JSON UTF-8)| BODY                         |
| "ALAB" | 1 B | 2 B BE | HDRLEN байтів      |                              |
+--------+-----+--------+--------------------+------------------------------+
HEADER: {"v":2,"mode":"aes-gcm","key_id":"…","key_bits":256,"iv":"<hex>","pad":"none",
         "tag":16,"aad":true,"created":"…Z"[,"seg":65536]}
BODY:  aes-gcm          → ciphertext ‖ tag
       *-hmac           → ciphertext ‖ HMAC-SHA256(...)[:tag_len]
       STREAM-AEAD      → seg0‖tag0 ‖ seg1‖tag1 ‖ … (останній сегмент позначено прапорцем final)
```

**Сирі байти** `MAGIC..HEADER` входять в автентифіковані дані кожного режиму (для GCM як AAD, для HMAC — у вхід MAC). Тому зміна режиму, IV, довжини тегу чи key_id у заголовку виявляється (захист від downgrade-атак). Користувацька AAD автентифікується, але у файлі не зберігається: її треба знати для дешифрування.

## 2.4. Перевірка цілісності й автентичності

* **AES-GCM**: тег GHASH. Розшифрування пишеться лише у тимчасовий файл (`*.part`), а `finalize()` перевіряє тег. Якщо тег неправильний, тимчасовий файл видаляється.
* **EtM (CBC/CTR/CFB + HMAC)**: `MAC = HMAC-SHA256(mac_key, header ‖ len(AAD) ‖ AAD ‖ ciphertext)`. Під час дешифрування **спочатку** потоково перевіряється MAC (порівняння в константний час), і лише потім виконується розшифрування й зняття доповнення. Так padding oracle стає неможливим.
* **STREAM-AEAD**: кожен сегмент має свій тег, nonce = префікс ‖ лічильник ‖ прапорець final. Це захищає від перестановки, видалення чи обрізання сегментів.
* **Атомарність** (`engine.atomic_writer`): вихідний файл з'являється лише після успішної перевірки (`os.replace`). Неавтентифікований відкритий текст ніколи не залишається на диску.

## 2.5. Як додати новий режим

```python
# aeslab/modes.py
@register_mode
class AesCcm(CipherMode):
    spec = ModeSpec(name="aes-ccm", title="AES-CCM", family="aead",
                    key_bits=(128, 192, 256), iv_lens=(13,), default_iv=13,
                    tag_lens=(16,), default_tag=16, aliases=("ccm",),
                    security="AEAD (SP 800-38C)", risks="двопрохідний; потрібна довжина наперед")

    def encrypt(self, fi, fo, keys, p, iv, header):
        ...  # шифрування з assoc_data(header, p.aad) як AAD

    def decrypt(self, fi, fo, keys, p, iv, header, body_len):
        ...  # перевірка тегу; при помилці — raise AuthFailed()
```

Після оголошення класу режим автоматично з'являється в `aes_cli.py modes`, у CLI/REPL, у бенчмарку та в tamper-тестах (параметризовані за `REGISTRY`). Змінювати інші модулі не потрібно.
