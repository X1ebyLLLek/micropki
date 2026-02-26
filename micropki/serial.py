"""
Unique serial number generator for MicroPKI.

Generates 64-bit composite serial numbers:
  - High 32 bits: Unix timestamp (seconds)
  - Low 32 bits: CSPRNG random value

Checks the database to guarantee uniqueness.
"""

from __future__ import annotations

import os
import time

from .database import init_db, serial_exists


def generate_unique_serial(db_path: str | None = None, max_retries: int = 10) -> int:
    """
    Generate a unique 64-bit serial number.

    Composite format:
      [32-bit timestamp][32-bit random]

    If db_path is provided, ensures the DB schema exists and checks
    uniqueness against the database, retrying on collision.

    Args:
        db_path: Optional path to the SQLite database for uniqueness check.
        max_retries: Maximum retry attempts if collision occurs.

    Returns:
        A positive 64-bit integer serial number.

    Raises:
        RuntimeError: If a unique serial cannot be generated after max_retries.
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
        f"Failed to generate unique serial after {max_retries} attempts."
    )

