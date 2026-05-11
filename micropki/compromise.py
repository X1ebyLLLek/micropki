"""
Симуляция компрометации ключа (Sprint 7).

Реализует CTL-3 и CTL-4:
  - Помечает сертификат как отозванный с причиной keyCompromise.
  - Записывает публичный ключ в таблицу compromised_keys.
  - Блокирует повторный выпуск по тому же ключу.
"""

from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization


def hash_public_key(public_key: object) -> str:
    """
    Вычисляет SHA-256 хеш открытого ключа (DER-кодировка SPKI).

    Аргументы:
        public_key: Объект открытого ключа (RSA, ECC и т.д.).

    Возвращает:
        Строку hex SHA-256 хеша в верхнем регистре.
    """
    der = public_key.public_bytes(  # type: ignore[union-attr]
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest().upper()


def record_compromised_key(
    db_path: str,
    public_key_hash: str,
    certificate_serial: str,
    reason: str = "keyCompromise",
) -> None:
    """
    Добавляет запись о скомпрометированном ключе в БД.

    Идемпотентно: повторная вставка того же хеша игнорируется (IGNORE).

    Аргументы:
        db_path:           Путь к SQLite-базе.
        public_key_hash:   SHA-256 открытого ключа (hex).
        certificate_serial: Серийный номер сертификата (hex).
        reason:            Причина компрометации.
    """
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """INSERT OR IGNORE INTO compromised_keys
               (public_key_hash, certificate_serial, compromise_date, compromise_reason)
               VALUES (?, ?, ?, ?)""",
            (public_key_hash, certificate_serial.upper(), now, reason),
        )
        conn.commit()
    finally:
        conn.close()


def is_key_compromised(db_path: str, public_key_hash: str) -> bool:
    """
    Проверяет, скомпрометирован ли данный открытый ключ.

    Аргументы:
        db_path:         Путь к SQLite-базе.
        public_key_hash: SHA-256 открытого ключа (hex).

    Возвращает:
        True, если ключ присутствует в таблице compromised_keys.
    """
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT 1 FROM compromised_keys WHERE public_key_hash = ? COLLATE NOCASE",
            (public_key_hash.upper(),),
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def simulate_compromise(
    db_path: str,
    cert: x509.Certificate,
    reason: str = "keyCompromise",
) -> str:
    """
    Выполняет полную процедуру симуляции компрометации:
      1. Вычисляет хеш открытого ключа.
      2. Записывает в compromised_keys.
      3. Обновляет статус сертификата в certificates на 'revoked'.

    Аргументы:
        db_path: Путь к SQLite-базе.
        cert:    Объект x509.Certificate.
        reason:  Причина компрометации.

    Возвращает:
        Хеш открытого ключа (для использования в аудит-записи).
    """
    from .database import update_status  # локальный импорт для избежания циклов

    serial_hex = format(cert.serial_number, "X")
    pub_key_hash = hash_public_key(cert.public_key())

    record_compromised_key(db_path, pub_key_hash, serial_hex, reason)
    update_status(db_path, serial_hex, "revoked", reason=reason)

    return pub_key_hash
