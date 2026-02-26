"""
Logging setup for MicroPKI.

Provides ISO 8601 formatted log output to either a file or stderr.
Sensitive data (passphrases) is never logged.
"""

import logging
import sys
from datetime import datetime, timezone


class _Iso8601Formatter(logging.Formatter):
    """Кастомный форматер, генерирующий временные метки ISO 8601 с миллисекундами."""

    def formatTime(self, record, datefmt=None):
        dt = datetime.fromtimestamp(record.created, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{int(record.msecs):03d}Z"


def setup_logger(log_file: str | None = None) -> logging.Logger:
    """
    Configure and return the application logger.

    Args:
        log_file: Optional path to a log file. If None, logs go to stderr.

    Returns:
        Configured logging.Logger instance.
    """
    logger = logging.getLogger("micropki")
    logger.setLevel(logging.DEBUG)

    # Удаляем существующие обработчики, чтобы избежать дубликатов при повторной инициализации
    logger.handlers.clear()

    formatter = _Iso8601Formatter(
        fmt="%(asctime)s %(levelname)s %(message)s"
    )

    if log_file:
        handler = logging.FileHandler(log_file, encoding="utf-8")
    else:
        handler = logging.StreamHandler(sys.stderr)

    handler.setLevel(logging.DEBUG)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger
