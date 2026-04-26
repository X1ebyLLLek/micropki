"""
Генерация и хранение CRL (Certificate Revocation List) для MicroPKI.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .crypto_utils import load_encrypted_key
from .database import get_revoked

logger = logging.getLogger("micropki")

# Маппинг строковых кодов причин RFC 5280 на флаги библиотеки
_REASON_MAP: dict[str, x509.ReasonFlags] = {
    "keyCompromise":        x509.ReasonFlags.key_compromise,
    "cACompromise":         x509.ReasonFlags.ca_compromise,
    "affiliationChanged":   x509.ReasonFlags.affiliation_changed,
    "superseded":           x509.ReasonFlags.superseded,
    "cessationOfOperation": x509.ReasonFlags.cessation_of_operation,
    "certificateHold":      x509.ReasonFlags.certificate_hold,
    "removeFromCRL":        x509.ReasonFlags.remove_from_crl,
    "privilegeWithdrawn":   x509.ReasonFlags.privilege_withdrawn,
    "aACompromise":         x509.ReasonFlags.aa_compromise,
}


def generate_crl(
    ca_cert_path: str,
    ca_key_path: str,
    ca_passphrase: bytes,
    db_path: str,
    out_dir: str,
    ca_level: str = "intermediate",
    validity_days: int = 7,
) -> str:
    """
    Сгенерировать CRL для указанного CA и сохранить его в файл.

    Берёт из базы все отозванные сертификаты, выпущенные данным CA,
    строит и подписывает CRL, затем сохраняет в {out_dir}/crl/{ca_level}.crl.pem.

    Аргументы:
        ca_cert_path: Путь к сертификату CA.
        ca_key_path: Путь к зашифрованному приватному ключу CA.
        ca_passphrase: Парольная фраза для расшифровки ключа CA.
        db_path: Путь к базе данных SQLite.
        out_dir: Корневая папка PKI; CRL сохраняется в подпапке crl/.
        ca_level: Уровень CA для имени файла ('root' или 'intermediate').
        validity_days: Срок действия CRL в днях.

    Возвращает:
        Путь к сохранённому файлу CRL в виде строки.
    """
    ca_cert = x509.load_pem_x509_certificate(Path(ca_cert_path).read_bytes())
    ca_key = load_encrypted_key(Path(ca_key_path).read_bytes(), ca_passphrase)

    # Отбираем только те отозванные записи, издателем которых является данный CA
    issuer_dn = ca_cert.subject.rfc4514_string()
    all_revoked = get_revoked(db_path)
    my_revoked = [r for r in all_revoked if r["issuer"] == issuer_dn]

    now = datetime.now(tz=timezone.utc)
    next_update = now + timedelta(days=validity_days)

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(next_update)
    )

    for rec in my_revoked:
        serial_int = int(rec["serial_hex"], 16)

        # revocation_date всегда заполнен для отозванных сертификатов,
        # но на случай старых записей используем created_at как запасной вариант
        date_str = rec.get("revocation_date") or rec["created_at"]
        rev_date = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )

        rev_builder = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial_int)
            .revocation_date(rev_date)
        )

        reason_str = rec.get("revocation_reason")
        if reason_str and reason_str in _REASON_MAP:
            rev_builder = rev_builder.add_extension(
                x509.CRLReason(_REASON_MAP[reason_str]), critical=False
            )

        builder = builder.add_revoked_certificate(rev_builder.build())

    hash_alg: hashes.HashAlgorithm = (
        hashes.SHA256() if isinstance(ca_key, rsa.RSAPrivateKey) else hashes.SHA384()
    )
    crl = builder.sign(private_key=ca_key, algorithm=hash_alg)

    crl_dir = Path(out_dir) / "crl"
    crl_dir.mkdir(parents=True, exist_ok=True)

    crl_file = crl_dir / f"{ca_level}.crl.pem"
    crl_file.write_bytes(crl.public_bytes(serialization.Encoding.PEM))

    logger.info(
        "CRL сгенерирован: %s, записей об отзыве: %d, действителен до: %s",
        crl_file.resolve(), len(my_revoked), next_update.strftime("%Y-%m-%d %H:%M:%S UTC"),
    )
    return str(crl_file)
