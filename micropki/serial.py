"""
Генератор уникальных серийных номеров для MicroPKI.

Формирует 64-битные составные серийные номера:
  - Старшие 32 бита: Unix-временная метка (секунды)
  - Младшие 32 бита: случайное значение из CSPRNG

Уникальность гарантируется проверкой по базе данных.
"""

from __future__ import annotations

import os
import time

from .database import init_db, serial_exists


def generate_unique_serial(db_path: str | None = None, max_retries: int = 10) -> int:
    """
    Сгенерировать уникальный 64-битный серийный номер.

    Формат: [32 бита временной метки][32 бита случайных данных].

    Если передан db_path, инициализирует схему БД (идемпотентно) и проверяет
    уникальность, повторяя попытку при коллизии.

    Аргументы:
        db_path: Необязательный путь к БД SQLite для проверки уникальности.
        max_retries: Максимальное число попыток при коллизии.

    Возвращает:
        Положительное 64-битное целое — серийный номер.

    Вызывает исключения:
        RuntimeError: Если уникальный номер не удалось получить за max_retries попыток.
    """
    if db_path is not None:
        init_db(db_path)  # Убедиться, что схема существует (идемпотентно)

    for attempt in range(max_retries):
        ts = int(time.time()) & 0xFFFFFFFF  # 32-битная временная метка
        rand = int.from_bytes(os.urandom(4), byteorder="big")  # 32-битное случайное число
        serial = (ts << 32) | rand

        if serial <= 0:
            serial = 1  # Должно быть положительным

        if db_path is None:
            return serial

        serial_hex = format(serial, "X")
        if not serial_exists(db_path, serial_hex):
            return serial

    raise RuntimeError(
        f"Не удалось сгенерировать уникальный серийный номер за {max_retries} попыток."
    )

