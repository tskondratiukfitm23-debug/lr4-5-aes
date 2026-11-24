"""Структуроване журналювання (JSON Lines) з ротацією файлу та фільтрацією секретів."""
from __future__ import annotations

import getpass
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

from . import config

SESSION_ID = uuid.uuid4().hex[:12]
SENSITIVE = ("password", "passwd", "secret", "master", "enc_key", "mac_key", "key_bytes", "token")


def _scrub(fields: dict) -> dict:
    """Ніколи не записувати паролі/ключі: такі поля замінюються на '***'."""
    return {k: ("***" if any(s in k.lower() for s in SENSITIVE) else v) for k, v in fields.items()}


class JSONLFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc).isoformat(timespec="milliseconds")
                  .replace("+00:00", "Z"),
            "level": record.levelname,
            "event": record.getMessage(),
            "session": SESSION_ID,
            "pid": os.getpid(),
            "user": _user(),
        }
        base.update(_scrub(getattr(record, "fields", {}) or {}))
        return json.dumps(base, ensure_ascii=False, default=str)


def _user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # pragma: no cover
        return "unknown"


def get_logger(path: str | None = None) -> logging.Logger:
    """Повернути логер 'aeslab' (каталог журналу створюється автоматично)."""
    path = path or config.LOG_PATH
    logger = logging.getLogger("aeslab")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    current = getattr(logger, "_aeslab_path", None)
    if current != os.path.abspath(path):
        for h in list(logger.handlers):
            logger.removeHandler(h)
            h.close()
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        fh = RotatingFileHandler(path, maxBytes=config.LOG_MAX_BYTES, backupCount=config.LOG_BACKUPS,
                                 encoding="utf-8")
        fh.setFormatter(JSONLFormatter())
        logger.addHandler(fh)
        logger._aeslab_path = os.path.abspath(path)
    return logger


def log_event(event: str, level: int = logging.INFO, logger: logging.Logger | None = None, **fields) -> None:
    """Записати подію: ``log_event('decrypt', status='fail', error_code='AUTH_FAILED', ...)``."""
    (logger or get_logger()).log(level, event, extra={"fields": fields})
