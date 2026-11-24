"""Глобальні параметри за замовчуванням (можна перевизначити змінними середовища)."""
import os

# --- KDF -------------------------------------------------------------------
PBKDF2_ITERATIONS = int(os.environ.get("AES_LAB_ITERATIONS", 310_000))  # OWASP 2023 для PBKDF2-HMAC-SHA256
MIN_PBKDF2_ITERATIONS = 100_000           # нижня межа політики (тести можуть знизити явно)
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1
SALT_BYTES = 16                           # >= 128 біт
MASTER_KEY_BYTES = 32                     # вихід KDF (майстер-ключ), далі HKDF
MAC_KEY_BYTES = 32                        # ключ HMAC-SHA256
VERIFIER_BYTES = 32

# --- Політика паролів -------------------------------------------------------
MIN_PASSWORD_LEN = 12
MIN_PASSWORD_CLASSES = 3                  # з 4: малі, великі, цифри, символи

# --- Політика життєвого циклу ключа ----------------------------------------
DEFAULT_KEY_BITS = 256
DEFAULT_EXPIRES_DAYS = 180
DEFAULT_MAX_USES = 1_000_000              # макс. операцій шифрування одним ключем
GCM_RANDOM_NONCE_LIMIT = 2 ** 32          # NIST SP 800-38D, п.8.3 для випадкових 96-бітних nonce
RECENT_NONCE_CACHE = 1000                 # скільки відбитків останніх nonce/IV тримати для контролю повторів

# --- Формат файлу / вводу-виводу --------------------------------------------
MAGIC = b"ALAB"
FORMAT_VERSION = 2
IO_CHUNK = 1024 * 1024                    # буфер потокової обробки (1 MiB)
DEFAULT_SEGMENT = 64 * 1024               # розмір сегмента для сегментованих AEAD (STREAM)
MAX_HEADER_LEN = 4096

# --- Шляхи -----------------------------------------------------------------
KEYSTORE_PATH = os.environ.get("AES_LAB_KEYSTORE", "keystore.json")
LOG_PATH = os.environ.get("AES_LAB_LOG", os.path.join("logs", "aes.jsonl"))
LOG_MAX_BYTES = 1 * 1024 * 1024
LOG_BACKUPS = 5
PASSWORD_ENV = "AES_LAB_PASSWORD"
