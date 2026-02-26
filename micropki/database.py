"""
Управление базой данных SQLite для MicroPKI.

Хранит информацию о выпущенных сертификатах (серийный номер, субъект, даты,
статус отзыва) и сам файл PEM для быстрого извлечения репозиторием.
"""

from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("micropki")

# ---- Схема БД ----

DEFAULT_DB_PATH = "micropki.db"

_SCHEMA_SQL = """\
CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    serial_hex TEXT UNIQUE NOT NULL,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    cert_pem TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'valid',
    revocation_reason TEXT,
    revocation_date TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_serial_hex ON certificates (serial_hex);
CREATE INDEX IF NOT EXISTS idx_status ON certificates (status);
"""


def init_db(db_path: str = DEFAULT_DB_PATH) -> None:
    """
    Инициализирует базу данных SQLite со схемой сертификатов.

    Идемпотентно: безопасно вызывать несколько раз. Использует IF NOT EXISTS.

    Аргументы:
        db_path: Путь к файлу базы данных SQLite.
    """
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(path))
    try:
        conn.executescript(_SCHEMA_SQL)
        conn.commit()
        logger.info("База данных инициализирована по адресу: %s", path.resolve())
    finally:
        conn.close()


def _migrate_db(conn: sqlite3.Connection) -> None:
    """Выполняет миграции схемы базы данных, если требуется."""
    pass


def _connect(db_path: str) -> sqlite3.Connection:
    """Открывает соединение с включенной фабрикой строк."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    # Использование WAL (Write-Ahead Log) для лучшего параллелизма
    # (полезно, если CLI и веб-сервер работают одновременно)
    conn.execute("PRAGMA journal_mode=WAL;")
    _migrate_db(conn)
    return conn


# ---- Вставка ----

def insert_certificate(
    db_path: str,
    serial_hex: str,
    subject: str,
    issuer: str,
    not_before: str,
    not_after: str,
    cert_pem: str,
    status: str = "valid",
) -> None:
    """
    Вставить запись о сертификате в базу данных.

    Аргументы:
        db_path: Путь к базе данных SQLite.
        serial_hex: Серийный номер в виде hex-строки (например, "2A7F...").
        subject: DN субъекта в виде строки RFC 4514.
        issuer: DN издателя в виде строки RFC 4514.
        not_before: Метка времени ISO 8601.
        not_after: Метка времени ISO 8601.
        cert_pem: Полный текст сертификата в формате PEM.
        status: Статус сертификата ('valid', 'revoked', 'expired').

    Вызывает исключения:
        sqlite3.IntegrityError: Если серийный номер уже существует.
    """
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn = _connect(db_path)
    try:
        conn.execute(
            """INSERT INTO certificates
               (serial_hex, subject, issuer, not_before, not_after,
                cert_pem, status, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (serial_hex, subject, issuer, not_before, not_after,
             cert_pem, status, now),
        )
        conn.commit()
        logger.info("Сертификат добавлен в БД: serial=%s, subject=%s", serial_hex, subject)
    except sqlite3.IntegrityError as e:
        logger.error("Ошибка вставки в БД (дубликат серийного номера?): %s", e)
        raise
    finally:
        conn.close()


# ---- Запросы ----

def get_by_serial(db_path: str, serial_hex: str) -> dict[str, Any] | None:
    """
    Получить запись сертификата по его серийному номеру (hex).

    Аргументы:
        db_path: Путь к базе данных SQLite.
        serial_hex: Серийный номер в шестнадцатеричном формате (без учета регистра).

    Возвращает:
        Словарь с полями сертификата или None, если не найден.
    """
    conn = _connect(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM certificates WHERE serial_hex = ? COLLATE NOCASE",
            (serial_hex.upper(),),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def list_certificates(
    db_path: str,
    status: str | None = None,
    issuer: str | None = None,
) -> list[dict[str, Any]]:
    """
    Запрашивает сертификаты с необязательными фильтрами.

    Аргументы:
        db_path: Путь к базе данных SQLite.
        status: Фильтр по статусу ('valid', 'revoked', 'expired').
        issuer: Фильтр по DN издателя (поиск подстроки).

    Возвращает:
        Список словарей записей сертификатов.
    """
    conn = _connect(db_path)
    try:
        query = "SELECT * FROM certificates WHERE 1=1"
        params: list = []

        if status:
            query += " AND status = ?"
            params.append(status)
        if issuer:
            query += " AND issuer LIKE ?"
            params.append(f"%{issuer}%")

        query += " ORDER BY id DESC"
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ---- Обновление (заглушки для 4-го спринта) ----

def update_status(
    db_path: str,
    serial_hex: str,
    new_status: str,
    reason: str | None = None,
) -> bool:
    """
    Обновляет статус сертификата (например, для отзыва).

    Аргументы:
        db_path: Путь к базе данных SQLite.
        serial_hex: Шестнадцатеричный серийный номер.
        new_status: Новый статус ('valid', 'revoked', 'expired').
        reason: Необязательная причина отзыва.

    Возвращает:
        True, если запись была обновлена, False, если серийный номер не найден.
    """
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn = _connect(db_path)
    try:
        if new_status == "revoked":
            cursor = conn.execute(
                """UPDATE certificates
                   SET status = ?, revocation_reason = ?, revocation_date = ?
                   WHERE serial_hex = ? COLLATE NOCASE""",
                (new_status, reason, now, serial_hex.upper()),
            )
        else:
            cursor = conn.execute(
                """UPDATE certificates SET status = ?
                   WHERE serial_hex = ? COLLATE NOCASE""",
                (new_status, serial_hex.upper()),
            )
        conn.commit()
        updated = cursor.rowcount > 0
        if updated:
            logger.info("Статус сертификата %s обновлен на '%s'.", serial_hex, new_status)
        else:
            logger.warning("Попытка обновить статус для несуществующего серийного номера: %s", serial_hex)
        return updated
    finally:
        conn.close()


def get_revoked(db_path: str) -> list[dict[str, Any]]:
    """
    Получить все отозванные сертификаты (заглушка для генерации CRL в Спринте 4).

    Возвращает:
        Список словарей записей отозванных сертификатов.
    """
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM certificates WHERE status = 'revoked' ORDER BY id"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def serial_exists(db_path: str, serial_hex: str) -> bool:
    """Проверяет, существует ли уже серийный номер в базе данных."""
    conn = _connect(db_path)
    try:
        row = conn.execute(
            "SELECT 1 FROM certificates WHERE serial_hex = ? COLLATE NOCASE",
            (serial_hex.upper(),),
        ).fetchone()
        return row is not None
    finally:
        conn.close()
