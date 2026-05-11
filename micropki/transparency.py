"""
Симуляция Certificate Transparency (CT) лога (Sprint 7).

Ведёт дозаписываемый текстовый файл ct.log в директории аудита.
Формат строки: timestamp|serial|subject|sha256_fingerprint|issuer

По спецификации CTL-2:
  - Файл append-only, публично читаемый (0o644).
  - Для каждого выпущенного сертификата добавляется одна строка.
  - Команда `audit ct-verify` проверяет наличие сертификата в логе.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

_CT_FILENAME = "ct.log"
_SEP = "|"


class CTLog:
    """Симулированный Certificate Transparency лог."""

    def __init__(self, audit_dir: str | Path) -> None:
        self._ct_path = Path(audit_dir) / _CT_FILENAME
        self._ct_path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, cert: x509.Certificate) -> None:
        """
        Добавляет запись о выпущенном сертификате в CT-лог.

        Аргументы:
            cert: Объект x509.Certificate.
        """
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        serial = format(cert.serial_number, "X")
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        fingerprint = _sha256_fingerprint(cert)

        line = _SEP.join([ts, serial, subject, fingerprint, issuer]) + "\n"
        with self._ct_path.open("a", encoding="utf-8") as fh:
            fh.write(line)

        # Убедиться, что права доступа 0o644 (публично читаемый)
        try:
            self._ct_path.chmod(0o644)
        except OSError:
            pass  # на Windows chmod ограничен

    def contains(self, serial_hex: str) -> bool:
        """
        Проверяет, присутствует ли сертификат с данным серийным номером в логе.

        Аргументы:
            serial_hex: Серийный номер в hex (без учёта регистра).

        Возвращает:
            True, если сертификат найден в CT-логе.
        """
        if not self._ct_path.exists():
            return False

        needle = serial_hex.upper()
        for line in self._ct_path.read_text(encoding="utf-8").splitlines():
            parts = line.split(_SEP)
            if len(parts) >= 2 and parts[1].upper() == needle:
                return True
        return False

    def entries(self) -> list[dict[str, str]]:
        """
        Возвращает все записи CT-лога как список словарей.

        Ключи: timestamp, serial, subject, fingerprint, issuer.
        """
        if not self._ct_path.exists():
            return []

        result = []
        for line in self._ct_path.read_text(encoding="utf-8").splitlines():
            parts = line.strip().split(_SEP)
            if len(parts) < 5:
                continue
            result.append({
                "timestamp":   parts[0],
                "serial":      parts[1],
                "subject":     parts[2],
                "fingerprint": parts[3],
                "issuer":      parts[4],
            })
        return result

    @property
    def path(self) -> Path:
        """Путь к файлу CT-лога."""
        return self._ct_path


def _sha256_fingerprint(cert: x509.Certificate) -> str:
    """Вычисляет SHA-256 отпечаток сертификата в DER-кодировке (hex)."""
    der = cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest().upper()
