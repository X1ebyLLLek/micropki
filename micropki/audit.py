"""
Система аудита для MicroPKI (Sprint 7).

Ведёт журнал всех событий безопасности в формате NDJSON (newline-delimited JSON)
с криптографической целостностью на основе цепочки SHA-256 хешей.

Формат записи:
  {
    "timestamp": "2026-05-11T10:00:00.123456Z",
    "level": "AUDIT",
    "operation": "issue_certificate",
    "status": "success",
    "message": "...",
    "metadata": {...},
    "integrity": {"prev_hash": "...", "hash": "..."}
  }
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Хеш первой записи в цепочке — 64 нуля (SHA-256 "нулевого" блока)
_GENESIS_HASH = "0" * 64

# Имя файла для хранения последнего хеша цепочки
_CHAIN_FILENAME = "chain.dat"

# Глобальная блокировка: несколько вызовов CLI не должны одновременно писать в лог
_write_lock = threading.Lock()


class AuditLogger:
    """
    Потокобезопасный журнал аудита с SHA-256 цепочкой хешей.

    Каждая запись включает `prev_hash` (хеш предыдущей записи) и `hash`
    (хеш самой записи), что позволяет обнаружить подделку или удаление.
    """

    def __init__(self, log_path: str | Path) -> None:
        self._log_path = Path(log_path)
        self._chain_path = self._log_path.parent / _CHAIN_FILENAME
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        self._prev_hash: str = self._load_prev_hash()

    # ------------------------------------------------------------------ #
    #  Публичный API                                                       #
    # ------------------------------------------------------------------ #

    def log(
        self,
        operation: str,
        status: str,
        message: str,
        level: str = "AUDIT",
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Записывает событие в журнал аудита.

        Аргументы:
            operation: Тип операции (например, "issue_certificate").
            status:    Результат ("success" или "failure").
            message:   Человекочитаемое описание события.
            level:     Уровень ("AUDIT", "INFO", "WARNING", "ERROR").
            metadata:  Дополнительные поля (serial, subject, ip и т.д.).

        Возвращает:
            Словарь записанной записи.
        """
        entry = self._build_entry(operation, status, message, level, metadata or {})
        with _write_lock:
            self._write_entry(entry)
        return entry

    def verify(self) -> tuple[bool, str]:
        """
        Перепроверяет цепочку хешей всего журнала.

        Возвращает:
            (True, "OK") если целостность не нарушена,
            (False, "<описание>") если обнаружена подделка.
        """
        if not self._log_path.exists():
            return True, "Журнал пуст или отсутствует."

        lines = [
            line for line in self._log_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        if not lines:
            return True, "Журнал пуст."

        prev_hash = _GENESIS_HASH
        for idx, line in enumerate(lines, start=1):
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                return False, f"Запись #{idx}: неверный JSON."

            stored_prev = entry.get("integrity", {}).get("prev_hash", "")
            stored_hash = entry.get("integrity", {}).get("hash", "")

            if stored_prev != prev_hash:
                return False, (
                    f"Запись #{idx}: prev_hash не совпадает. "
                    f"Ожидалось '{prev_hash[:16]}…', "
                    f"получено '{stored_prev[:16]}…'."
                )

            computed = _compute_entry_hash(entry)
            if computed != stored_hash:
                return False, (
                    f"Запись #{idx}: хеш повреждён. "
                    f"Вычислен '{computed[:16]}…', "
                    f"записан '{stored_hash[:16]}…'."
                )

            prev_hash = stored_hash

        # Сверяем последний хеш с chain.dat
        if self._chain_path.exists():
            stored_chain = self._chain_path.read_text(encoding="utf-8").strip()
            if stored_chain != prev_hash:
                return False, (
                    "chain.dat не совпадает с хешем последней записи: "
                    f"ожидалось '{prev_hash[:16]}…', в файле '{stored_chain[:16]}…'."
                )

        return True, f"Целостность проверена. Проверено записей: {len(lines)}."

    def query(
        self,
        from_ts: str | None = None,
        to_ts: str | None = None,
        level: str | None = None,
        operation: str | None = None,
        serial: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Фильтрует записи журнала по заданным критериям.

        Аргументы:
            from_ts:   Нижняя граница времени (ISO 8601).
            to_ts:     Верхняя граница времени (ISO 8601).
            level:     Фильтр по уровню (без учёта регистра).
            operation: Фильтр по типу операции (без учёта регистра).
            serial:    Фильтр по серийному номеру в metadata.

        Возвращает:
            Список совпадающих записей.
        """
        if not self._log_path.exists():
            return []

        results = []
        for line in self._log_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            ts = entry.get("timestamp", "")
            if from_ts and ts < from_ts:
                continue
            if to_ts and ts > to_ts:
                continue
            if level and entry.get("level", "").upper() != level.upper():
                continue
            if operation and entry.get("operation", "").lower() != operation.lower():
                continue
            if serial:
                meta = entry.get("metadata", {})
                if meta.get("serial", "").upper() != serial.upper():
                    continue

            results.append(entry)

        return results

    # ------------------------------------------------------------------ #
    #  Внутренние методы                                                   #
    # ------------------------------------------------------------------ #

    def _build_entry(
        self,
        operation: str,
        status: str,
        message: str,
        level: str,
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        """Собирает словарь записи и вычисляет хеши."""
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        entry: dict[str, Any] = {
            "timestamp": ts,
            "level": level,
            "operation": operation,
            "status": status,
            "message": message,
            "metadata": metadata,
            "integrity": {
                "prev_hash": self._prev_hash,
                "hash": "",  # заполняется ниже
            },
        }
        entry["integrity"]["hash"] = _compute_entry_hash(entry)
        return entry

    def _write_entry(self, entry: dict[str, Any]) -> None:
        """Дозаписывает запись в файл и обновляет chain.dat."""
        line = json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n"
        with self._log_path.open("a", encoding="utf-8") as fh:
            fh.write(line)

        new_hash = entry["integrity"]["hash"]
        self._chain_path.write_text(new_hash, encoding="utf-8")
        self._prev_hash = new_hash

    def _load_prev_hash(self) -> str:
        """Загружает последний хеш из chain.dat или возвращает генезис-хеш."""
        if self._chain_path.exists():
            data = self._chain_path.read_text(encoding="utf-8").strip()
            if data:
                return data
        return _GENESIS_HASH


# ------------------------------------------------------------------ #
#  Вспомогательные функции                                             #
# ------------------------------------------------------------------ #

def _compute_entry_hash(entry: dict[str, Any]) -> str:
    """
    Вычисляет SHA-256 хеш записи журнала.

    Для канонического представления используются сортированные ключи
    и компактный JSON (без пробелов). Поле `integrity.hash` игнорируется
    при вычислении (заменяется пустой строкой).
    """
    # Глубокая копия с обнулением вычисляемого поля
    to_hash = dict(entry)
    to_hash["integrity"] = {
        "prev_hash": entry["integrity"]["prev_hash"],
        "hash": "",
    }
    canonical = json.dumps(to_hash, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_log_file(log_path: str | Path, chain_path: str | Path | None = None) -> tuple[bool, str]:
    """
    Утилита верификации: проверяет файл журнала без создания AuditLogger.

    Аргументы:
        log_path:   Путь к файлу NDJSON-журнала.
        chain_path: Путь к chain.dat (по умолчанию рядом с лог-файлом).

    Возвращает:
        (True, "OK-сообщение") или (False, "описание ошибки").
    """
    log_path = Path(log_path)
    if chain_path is None:
        chain_path = log_path.parent / _CHAIN_FILENAME
    else:
        chain_path = Path(chain_path)

    logger_inst = AuditLogger.__new__(AuditLogger)
    logger_inst._log_path = log_path
    logger_inst._chain_path = chain_path
    logger_inst._prev_hash = _GENESIS_HASH
    return logger_inst.verify()
