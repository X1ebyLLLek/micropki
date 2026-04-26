"""
Управление отзывом сертификатов для MicroPKI.
"""

from __future__ import annotations

import logging

from .database import get_by_serial, update_status

logger = logging.getLogger("micropki")

# Все допустимые коды причин из RFC 5280
RFC5280_REASONS = (
    "unspecified",
    "keyCompromise",
    "cACompromise",
    "affiliationChanged",
    "superseded",
    "cessationOfOperation",
    "certificateHold",
    "removeFromCRL",
    "privilegeWithdrawn",
    "aACompromise",
)


def revoke_certificate(
    db_path: str,
    serial_hex: str,
    reason: str = "unspecified",
) -> None:
    """
    Отозвать сертификат по серийному номеру.

    Аргументы:
        db_path: Путь к базе данных.
        serial_hex: Серийный номер в hex-формате.
        reason: Код причины отзыва согласно RFC 5280.

    Вызывает исключения:
        ValueError: Если причина неизвестна, сертификат не найден или уже отозван.
    """
    if reason not in RFC5280_REASONS:
        raise ValueError(
            f"Неизвестная причина отзыва: '{reason}'. "
            f"Допустимые значения: {', '.join(RFC5280_REASONS)}"
        )

    record = get_by_serial(db_path, serial_hex)
    if record is None:
        raise ValueError(
            f"Сертификат с серийным номером '{serial_hex}' не найден в базе данных."
        )
    if record["status"] == "revoked":
        raise ValueError(
            f"Сертификат '{serial_hex}' уже отозван "
            f"(причина: {record.get('revocation_reason', 'не указана')})."
        )

    update_status(db_path, serial_hex, "revoked", reason=reason)
    logger.info("Сертификат отозван: serial=%s, причина=%s", serial_hex, reason)
