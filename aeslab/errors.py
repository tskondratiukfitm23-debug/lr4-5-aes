"""Класифікація помилок: машиночитні коди, коди виходу та повідомлення українською."""


class AesLabError(Exception):
    """Базова помилка лабораторного модуля.

    Атрибути:
        code: короткий машиночитний код (потрапляє у журнал як ``error_code``);
        exit_code: код завершення CLI;
        message: людське повідомлення українською.
    """

    code = "ERROR"
    exit_code = 1
    default_message = "Невідома помилка"

    def __init__(self, message: str | None = None, **details):
        self.message = message or self.default_message
        self.details = details
        super().__init__(self.message)

    def __str__(self) -> str:
        return f"[{self.code}] {self.message}"


class InvalidParams(AesLabError):
    code = "INVALID_PARAMS"
    exit_code = 2
    default_message = "Некоректні параметри шифрування"


class FileIOError(AesLabError):
    code = "IO_ERROR"
    exit_code = 3
    default_message = "Помилка читання/запису файлу"


class BadMagic(AesLabError):
    code = "BAD_MAGIC"
    exit_code = 10
    default_message = "Файл не є контейнером AES-Lab (неправильна сигнатура)"


class BadFormat(AesLabError):
    code = "BAD_FORMAT"
    exit_code = 11
    default_message = "Пошкоджений або непідтримуваний заголовок файлу"


class Truncated(AesLabError):
    code = "TRUNCATED"
    exit_code = 12
    default_message = "Файл обрізаний (бракує даних/тегу)"


class UnsupportedMode(AesLabError):
    code = "UNSUPPORTED_MODE"
    exit_code = 13
    default_message = "Режим шифрування не підтримується"


class TamperDetected(AesLabError):
    code = "TAMPER_DETECTED"
    exit_code = 20
    default_message = "Виявлено втручання: тег автентичності не збігся (дані/заголовок змінено або інша AAD)"


class AuthFailed(AesLabError):
    code = "AUTH_FAILED"
    exit_code = 21
    default_message = "Перевірка автентичності не пройдена (підміна даних АБО неправильний ключ — розрізнити неможливо)"


class BadPadding(AesLabError):
    code = "BAD_PADDING"
    exit_code = 22
    default_message = "Некоректне доповнення (padding)"


class KeyMismatch(AesLabError):
    code = "KEY_MISMATCH"
    exit_code = 23
    default_message = "Файл зашифровано іншим ключем (key_id не збігається)"


class WrongPassword(AesLabError):
    code = "WRONG_PASSWORD"
    exit_code = 30
    default_message = "Неправильний пароль для ключа"


class KeyNotFound(AesLabError):
    code = "KEY_NOT_FOUND"
    exit_code = 31
    default_message = "Ключ не знайдено у сховищі"


class KeyRevoked(AesLabError):
    code = "KEY_REVOKED"
    exit_code = 32
    default_message = "Ключ відкликано (компрометація) — використання заборонено"


class KeyExpired(AesLabError):
    code = "KEY_EXPIRED"
    exit_code = 33
    default_message = "Термін дії ключа минув — шифрування заборонено"


class KeyExhausted(AesLabError):
    code = "KEY_EXHAUSTED"
    exit_code = 34
    default_message = "Вичерпано ліміт використань ключа — виконайте ротацію"


class NonceLimit(AesLabError):
    code = "NONCE_LIMIT"
    exit_code = 35
    default_message = "Досягнуто ліміту nonce для GCM — виконайте ротацію ключа"


class NonceReuse(AesLabError):
    code = "NONCE_REUSE"
    exit_code = 36
    default_message = "Виявлено повторне використання nonce/IV з тим самим ключем"


class WeakPassword(AesLabError):
    code = "WEAK_PASSWORD"
    exit_code = 37
    default_message = "Пароль не відповідає політиці складності"


class KeyReuse(AesLabError):
    code = "KEY_REUSE"
    exit_code = 38
    default_message = "Заборонено повторне використання ключа/солі/пароля/мітки"


class KeyLength(AesLabError):
    code = "KEY_LENGTH"
    exit_code = 39
    default_message = "Неприпустима довжина ключа"


class KeyRetired(AesLabError):
    code = "KEY_RETIRED"
    exit_code = 40
    default_message = "Ключ виведено з обігу — дозволене лише дешифрування"


ALL_ERRORS = {c.code: c for c in AesLabError.__subclasses__()}
