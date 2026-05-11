"""
Операции CA (Центра Сертификации) для MicroPKI.

Оркестрирует инициализацию Корневого CA, выпуск Промежуточного CA
и конечных сертификатов с интеграцией с базой данных.

Sprint 7: добавлены проверки политик (policy.py) и аудит (audit.py).
"""

from __future__ import annotations

import logging
import os
import platform
import re
import stat
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .certificates import (
    build_end_entity_certificate,
    build_intermediate_ca_certificate,
    build_ocsp_signer_certificate,
    build_root_ca_certificate,
    certificate_to_pem,
)
from .crypto_utils import (
    PrivateKey,
    encrypt_private_key,
    generate_key,
    load_encrypted_key,
    parse_distinguished_name,
)
from .csr import csr_to_pem, generate_csr, load_csr_from_pem
from .database import insert_certificate
from .templates import (
    CertificateTemplate,
    get_template,
    parse_san_entries,
    validate_sans_for_template,
)
from .policy import (
    check_key_size,
    check_validity_days,
    check_san_policy,
)

logger = logging.getLogger("micropki")

DEFAULT_DB_PATH = "./pki/micropki.db"
DEFAULT_AUDIT_DIR = "./pki/audit"


def _get_audit_logger(audit_dir: str | None) -> "AuditLogger | None":  # type: ignore[name-defined]
    """Создаёт AuditLogger если задан audit_dir, иначе None."""
    if not audit_dir:
        return None
    from .audit import AuditLogger
    return AuditLogger(Path(audit_dir) / "audit.log")


def _insert_cert_to_db(db_path: str | None, cert: x509.Certificate, cert_pem: bytes) -> None:
    """Вставить сертификат в базу данных, если указан db_path."""
    if db_path is None:
        return
    try:
        # Убедиться, что схема существует (идемпотентно)
        from .database import init_db
        init_db(db_path)

        insert_certificate(
            db_path=db_path,
            serial_hex=format(cert.serial_number, "X"),
            subject=cert.subject.rfc4514_string(),
            issuer=cert.issuer.rfc4514_string(),
            not_before=cert.not_valid_before_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
            not_after=cert.not_valid_after_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
            cert_pem=cert_pem.decode("utf-8"),
        )
    except Exception as e:
        logger.error("Не удалось вставить сертификат в БД: %s", e)
        raise



# ---- Корневой CA ----

def init_ca(
    subject: str,
    key_type: str,
    key_size: int,
    passphrase: bytes,
    out_dir: str,
    validity_days: int,
    force: bool = False,
    db_path: str | None = None,
    audit_dir: str | None = None,
) -> None:
    """
    Инициализировать самоподписанный Корневой CA.

    Создает структуру папок, генерирует пару ключей, создает самоподписанный
    сертификат, шифрует и сохраняет приватный ключ и генерирует policy.txt.
    Опционально вставляет сертификат в базу данных.

    Sprint 7: проверяет политику (размер ключа, срок действия), ведёт аудит.
    """
    audit = _get_audit_logger(audit_dir)
    out_path = Path(out_dir)
    private_dir = out_path / "private"
    certs_dir = out_path / "certs"
    key_file = private_dir / "ca.key.pem"
    cert_file = certs_dir / "ca.cert.pem"

    if not force:
        for f in [key_file, cert_file]:
            if f.exists():
                raise FileExistsError(
                    f"Файл '{f}' уже существует. Используйте --force для перезаписи."
                )

    # Проверка политики: срок действия корневого CA
    try:
        check_validity_days(validity_days, "root")
    except ValueError as e:
        if audit:
            audit.log("ca_init", "failure", str(e), metadata={"subject": subject, "role": "root"})
        raise

    out_path.mkdir(parents=True, exist_ok=True)
    certs_dir.mkdir(parents=True, exist_ok=True)
    _create_private_dir(private_dir)

    logger.info("Парсинг subject DN: %s", subject)
    dn = parse_distinguished_name(subject)

    logger.info("Начало генерации ключа: type=%s, size=%s", key_type, key_size)
    private_key = generate_key(key_type, key_size)
    logger.info("Генерация ключа успешно завершена.")

    # Проверка политики: размер ключа для корневого CA
    try:
        check_key_size(private_key.public_key(), "root")
    except ValueError as e:
        if audit:
            audit.log("ca_init", "failure", str(e), metadata={"subject": subject, "role": "root"})
        raise

    logger.info("Начало подписи сертификата (самоподписанный Корневой CA).")
    certificate = build_root_ca_certificate(private_key, dn, validity_days, db_path=db_path)
    logger.info("Подписание сертификата успешно завершено.")

    cert_pem = certificate_to_pem(certificate)

    # Вставляем в БД перед записью файлов (атомарно: ошибка до записи на диск)
    _insert_cert_to_db(db_path, certificate, cert_pem)

    logger.info("Шифрование приватного ключа с помощью парольной фразы.")
    encrypted_key_pem = encrypt_private_key(private_key, passphrase)
    _write_key_file(key_file, encrypted_key_pem)
    logger.info("Зашифрованный приватный ключ сохранен в: %s", key_file.resolve())

    cert_file.write_bytes(cert_pem)
    logger.info("Сертификат CA сохранен в: %s", cert_file.resolve())

    policy_file = out_path / "policy.txt"
    _generate_policy_root(policy_file, certificate, key_type, key_size)
    logger.info("Сгенерирован документ политики: %s", policy_file.resolve())

    if audit:
        audit.log(
            "ca_init", "success",
            f"Инициализирован корневой CA: {subject}",
            metadata={
                "subject": subject,
                "serial": format(certificate.serial_number, "X"),
                "validity_days": validity_days,
                "key_type": key_type,
            },
        )
    logger.info("Инициализация Корневого CA успешно завершена.")


# ---- Промежуточный CA ----

def issue_intermediate(
    root_cert_path: str,
    root_key_path: str,
    root_passphrase: bytes,
    subject: str,
    key_type: str,
    key_size: int,
    passphrase: bytes,
    out_dir: str,
    validity_days: int,
    path_length: int = 0,
    db_path: str | None = None,
    audit_dir: str | None = None,
) -> None:
    """
    Выпустить сертификат Промежуточного CA, подписанный Корневым CA.
    Автоматически сохраняется в базу данных.

    Sprint 7: проверяет политику (размер ключа, срок, pathLen), ведёт аудит.
    """
    audit = _get_audit_logger(audit_dir)
    out_path = Path(out_dir)
    private_dir = out_path / "private"
    certs_dir = out_path / "certs"
    csrs_dir = out_path / "csrs"

    # Проверка политики: срок действия промежуточного CA
    try:
        check_validity_days(validity_days, "intermediate")
        from .policy import check_path_length
        check_path_length(path_length, "intermediate")
    except ValueError as e:
        if audit:
            audit.log("issue_intermediate", "failure", str(e), metadata={"subject": subject})
        raise

    out_path.mkdir(parents=True, exist_ok=True)
    certs_dir.mkdir(parents=True, exist_ok=True)
    csrs_dir.mkdir(parents=True, exist_ok=True)
    _create_private_dir(private_dir)

    logger.info("Загрузка сертификата Корневого CA из: %s", root_cert_path)
    root_cert_pem = Path(root_cert_path).read_bytes()
    root_cert = x509.load_pem_x509_certificate(root_cert_pem)

    logger.info("Загрузка приватного ключа Корневого CA (содержимое скрыто).")
    root_key_pem = Path(root_key_path).read_bytes()
    root_key = load_encrypted_key(root_key_pem, root_passphrase)

    logger.info("Парсинг subject DN Промежуточного CA: %s", subject)
    dn = parse_distinguished_name(subject)

    logger.info("Начало генерации ключа Промежуточного CA: type=%s, size=%s", key_type, key_size)
    intermediate_key = generate_key(key_type, key_size)
    logger.info("Генерация ключа Промежуточного CA завершена.")

    # Проверка политики: размер ключа для промежуточного CA
    try:
        check_key_size(intermediate_key.public_key(), "intermediate")
    except ValueError as e:
        if audit:
            audit.log("issue_intermediate", "failure", str(e), metadata={"subject": subject})
        raise

    logger.info("Генерация CSR Промежуточного CA.")
    csr = generate_csr(intermediate_key, dn, is_ca=True, path_length=path_length)
    logger.info("CSR Промежуточного CA успешно сгенерирован.")

    csr_file = csrs_dir / "intermediate.csr.pem"
    csr_file.write_bytes(csr_to_pem(csr))
    logger.info("CSR Промежуточного CA сохранен в: %s", csr_file.resolve())

    logger.info("Корневой CA подписывает сертификат Промежуточного CA.")
    intermediate_cert = build_intermediate_ca_certificate(
        csr=csr, root_key=root_key, root_cert=root_cert,
        validity_days=validity_days, path_length=path_length, db_path=db_path,
    )
    logger.info(
        "Сертификат Промежуточного CA подписан. Serial=0x%s, Subject=%s",
        format(intermediate_cert.serial_number, "X"),
        intermediate_cert.subject.rfc4514_string(),
    )

    cert_pem = certificate_to_pem(intermediate_cert)

    # Вставляем в БД перед записью файлов
    _insert_cert_to_db(db_path, intermediate_cert, cert_pem)

    cert_file = certs_dir / "intermediate.cert.pem"
    cert_file.write_bytes(cert_pem)
    logger.info("Сертификат Промежуточного CA сохранен в: %s", cert_file.resolve())

    logger.info("Шифрование приватного ключа Промежуточного CA.")
    encrypted_key_pem = encrypt_private_key(intermediate_key, passphrase)
    key_file = private_dir / "intermediate.key.pem"
    _write_key_file(key_file, encrypted_key_pem)
    logger.info("Зашифрованный ключ Промежуточного CA сохранен в: %s", key_file.resolve())

    policy_file = out_path / "policy.txt"
    _append_policy_intermediate(
        policy_file, intermediate_cert, root_cert, key_type, key_size, path_length
    )
    logger.info("Документ политики обновлен информацией о Промежуточном CA.")

    if audit:
        audit.log(
            "issue_intermediate", "success",
            f"Выпущен промежуточный CA: {subject}",
            metadata={
                "subject": subject,
                "serial": format(intermediate_cert.serial_number, "X"),
                "validity_days": validity_days,
            },
        )
    logger.info("Выпуск Промежуточного CA успешно завершен.")


# ---- Конечный сертификат ----

def sign_csr_request(
    csr_pem: bytes,
    template_name: str,
    ca_cert: x509.Certificate,
    ca_key,
    validity_days: int = 365,
    db_path: str | None = None,
) -> bytes:
    """
    Подписывает CSR ключом CA и возвращает PEM сертификата (без записи файлов).
    Используется репозиторием для обработки POST /request-cert.

    Вызывает ValueError при невалидном CSR или запросе CA=True.
    """
    csr = load_csr_from_pem(csr_pem)

    # Конечный сертификат не должен запрашивать роль CA
    try:
        bc = csr.extensions.get_extension_for_class(x509.BasicConstraints)
        if bc.value.ca:
            raise ValueError("CSR не должен запрашивать CA=True для конечного сертификата")
    except x509.ExtensionNotFound:
        pass

    template = get_template(template_name)
    dn = csr.subject

    san_entries = []
    try:
        san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_entries = list(san_ext.value)
    except x509.ExtensionNotFound:
        pass

    validate_sans_for_template(template, san_entries)

    cert = build_end_entity_certificate(
        subject=dn,
        public_key=csr.public_key(),
        ca_key=ca_key,
        ca_cert=ca_cert,
        template=template,
        san_entries=san_entries if san_entries else None,
        validity_days=validity_days,
        db_path=db_path,
    )
    cert_pem = certificate_to_pem(cert)
    _insert_cert_to_db(db_path, cert, cert_pem)

    logger.info(
        "CSR подписан (API): serial=0x%s, subject=%s, template=%s",
        format(cert.serial_number, "X"),
        cert.subject.rfc4514_string(),
        template.name,
    )
    return cert_pem


def issue_cert(
    ca_cert_path: str,
    ca_key_path: str,
    ca_passphrase: bytes,
    template_name: str,
    subject: str | None,
    san_strings: list[str] | None,
    out_dir: str,
    validity_days: int = 365,
    db_path: str | None = None,
    csr_pem: bytes | None = None,
    audit_dir: str | None = None,
    allow_wildcards: bool = False,
) -> bytes:
    """
    Выпустить конечный сертификат (end-entity) используя шаблон.
    Если csr_pem передан — публичный ключ, subject и SAN берутся из CSR.
    Автоматически сохраняется в базу данных.

    Sprint 7: проверяет политику (размер ключа, срок, SAN, скомпрометированные ключи),
    записывает в аудит и CT-лог.

    Возвращает PEM сертификата в виде байт.
    """
    audit = _get_audit_logger(audit_dir)
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    # Проверка политики: срок действия конечного сертификата
    try:
        check_validity_days(validity_days, "end_entity")
    except ValueError as e:
        if audit:
            audit.log(
                "issue_certificate", "failure", str(e),
                metadata={"template": template_name, "subject": subject or ""},
            )
        raise

    logger.info("Загрузка сертификата CA из: %s", ca_cert_path)
    ca_cert = x509.load_pem_x509_certificate(Path(ca_cert_path).read_bytes())

    logger.info("Загрузка приватного ключа CA (содержимое скрыто).")
    ca_key = load_encrypted_key(Path(ca_key_path).read_bytes(), ca_passphrase)

    template = get_template(template_name)
    logger.info("Используется шаблон сертификата: %s", template.name)

    if csr_pem is not None:
        # --- Путь через CSR ---
        csr = load_csr_from_pem(csr_pem)

        try:
            bc = csr.extensions.get_extension_for_class(x509.BasicConstraints)
            if bc.value.ca:
                raise ValueError("CSR не должен запрашивать CA=True для конечного сертификата")
        except x509.ExtensionNotFound:
            pass

        dn = csr.subject
        ee_public_key = csr.public_key()
        logger.info("CSR: публичный ключ и subject извлечены из CSR.")

        san_entries = []
        try:
            san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san_entries = list(san_ext.value)
            logger.info("CSR: извлечено %d SAN записей.", len(san_entries))
        except x509.ExtensionNotFound:
            if san_strings:
                san_entries = parse_san_entries(san_strings)
                logger.info("CSR не содержит SAN, использованы --san аргументы.")
        save_key = False
    else:
        # --- Генерация новой ключевой пары ---
        logger.info("Парсинг subject DN сертификата: %s", subject)
        dn = parse_distinguished_name(subject)  # type: ignore[arg-type]

        san_entries = []
        if san_strings:
            san_entries = parse_san_entries(san_strings)
            logger.info("Распарсено %d SAN записей: %s", len(san_entries), ", ".join(san_strings))

        logger.info("Генерация ключевой пары конечного субъекта (RSA-2048).")
        from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
        ee_key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ee_public_key = ee_key.public_key()
        logger.info("Генерация ключа конечного субъекта завершена.")
        save_key = True

    # Проверка политики: размер ключа, SAN, скомпрометированный ключ
    _subject_str = subject or (dn.rfc4514_string() if dn else "")
    try:
        check_key_size(ee_public_key, "end_entity")
        check_san_policy(san_entries, template_name, allow_wildcards=allow_wildcards)
    except ValueError as e:
        if audit:
            audit.log(
                "issue_certificate", "failure", str(e),
                metadata={"template": template_name, "subject": _subject_str},
            )
        raise

    if db_path:
        from .compromise import hash_public_key, is_key_compromised
        pub_hash = hash_public_key(ee_public_key)
        if is_key_compromised(db_path, pub_hash):
            msg = "Выпуск отклонён: публичный ключ скомпрометирован."
            if audit:
                audit.log(
                    "issue_certificate", "failure", msg,
                    metadata={"template": template_name, "subject": _subject_str, "key_hash": pub_hash},
                )
            raise ValueError(msg)

    validate_sans_for_template(template, san_entries)

    logger.info("Построение сертификата %s.", template.name)
    cert = build_end_entity_certificate(
        subject=dn, public_key=ee_public_key, ca_key=ca_key,
        ca_cert=ca_cert, template=template,
        san_entries=san_entries if san_entries else None,
        validity_days=validity_days, db_path=db_path,
    )
    logger.info(
        "Сертификат выпущен: serial=0x%s, subject=%s, template=%s",
        format(cert.serial_number, "X"),
        cert.subject.rfc4514_string(),
        template.name,
    )

    cert_pem = certificate_to_pem(cert)
    _insert_cert_to_db(db_path, cert, cert_pem)

    # Запись в CT-лог и аудит
    if audit_dir:
        from .transparency import CTLog
        CTLog(audit_dir).append(cert)
        audit.log(  # type: ignore[union-attr]
            "issue_certificate", "success",
            f"Выпущен сертификат {template_name}: {cert.subject.rfc4514_string()}",
            metadata={
                "serial": format(cert.serial_number, "X"),
                "subject": cert.subject.rfc4514_string(),
                "template": template_name,
                "validity_days": validity_days,
            },
        )

    cn_attrs = dn.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    base_name = _sanitize_filename(cn_attrs[0].value) if cn_attrs else format(cert.serial_number, "x")

    cert_file = out_path / f"{base_name}.cert.pem"
    cert_file.write_bytes(cert_pem)
    logger.info("Сертификат сохранен в: %s", cert_file.resolve())

    if save_key:
        key_file = out_path / f"{base_name}.key.pem"
        unencrypted_pem = ee_key.private_bytes(  # type: ignore[possibly-undefined]
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        _write_key_file(key_file, unencrypted_pem)
        logger.warning(
            "Приватный ключ конечного субъекта сохранён НЕЗАШИФРОВАННЫМ в: %s. "
            "Пожалуйста, обеспечьте его безопасность должным образом.", key_file.resolve(),
        )

    logger.info("Выпуск сертификата конечного субъекта успешно завершен.")
    return cert_pem


# ---- OCSP-сертификат ----

def compromise_cert(
    cert_path: str,
    db_path: str,
    reason: str = "keyCompromise",
    audit_dir: str | None = None,
    ca_cert_path: str | None = None,
    ca_key_path: str | None = None,
    ca_passphrase: bytes | None = None,
    out_dir: str | None = None,
) -> dict:
    """
    Симуляция компрометации приватного ключа (CLI-33 / CTL-3).

    Выполняет:
      1. Загружает сертификат из файла.
      2. Записывает публичный ключ в compromised_keys.
      3. Отзывает сертификат в БД (reason=keyCompromise).
      4. Опционально генерирует новый CRL (emergency update).
      5. Записывает HIGH-severity запись в аудит.

    Возвращает словарь с результатом операции.
    """
    from .compromise import simulate_compromise
    from .database import get_by_serial

    audit = _get_audit_logger(audit_dir)

    cert = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
    serial_hex = format(cert.serial_number, "X")
    subject_str = cert.subject.rfc4514_string()

    pub_hash = simulate_compromise(db_path, cert, reason)

    # Опциональная аварийная генерация CRL
    crl_path = None
    if ca_cert_path and ca_key_path and ca_passphrase and out_dir:
        try:
            from .crl import generate_crl
            from .database import get_revoked as _get_revoked
            ca_cert = x509.load_pem_x509_certificate(Path(ca_cert_path).read_bytes())
            ca_key = load_encrypted_key(Path(ca_key_path).read_bytes(), ca_passphrase)
            revoked = _get_revoked(db_path)
            crl_pem = generate_crl(ca_key, ca_cert, revoked)
            crl_file = Path(out_dir) / "crl" / "ca.crl.pem"
            crl_file.parent.mkdir(parents=True, exist_ok=True)
            crl_file.write_bytes(crl_pem)
            crl_path = str(crl_file)
            logger.info("Аварийный CRL сгенерирован: %s", crl_path)
        except Exception as exc:
            logger.error("Не удалось сгенерировать аварийный CRL: %s", exc)

    if audit:
        audit.log(
            "key_compromise", "success",
            f"[HIGH] Компрометация ключа: serial={serial_hex}, subject={subject_str}",
            level="AUDIT",
            metadata={
                "serial": serial_hex,
                "subject": subject_str,
                "reason": reason,
                "public_key_hash": pub_hash,
                "crl_updated": crl_path is not None,
            },
        )

    logger.warning(
        "КОМПРОМЕТАЦИЯ КЛЮЧА: serial=%s, subject=%s, reason=%s",
        serial_hex, subject_str, reason,
    )
    return {
        "serial": serial_hex,
        "subject": subject_str,
        "public_key_hash": pub_hash,
        "reason": reason,
        "crl_path": crl_path,
    }


def issue_ocsp_cert(
    ca_cert_path: str,
    ca_key_path: str,
    ca_passphrase: bytes,
    subject: str,
    out_dir: str,
    validity_days: int = 365,
    db_path: str | None = None,
) -> tuple[str, str]:
    """
    Выпустить OCSP-сертификат подписи (EKU = OCSPSigning), подписанный указанным CA.
    Приватный ключ сохраняется незашифрованным.

    Возвращает:
        Кортеж (путь к сертификату, путь к ключу).
    """
    out_path = Path(out_dir)
    certs_dir = out_path / "certs"
    private_dir = out_path / "private"
    certs_dir.mkdir(parents=True, exist_ok=True)
    _create_private_dir(private_dir)

    logger.info("Загрузка сертификата CA из: %s", ca_cert_path)
    ca_cert = x509.load_pem_x509_certificate(Path(ca_cert_path).read_bytes())

    logger.info("Загрузка приватного ключа CA.")
    ca_key = load_encrypted_key(Path(ca_key_path).read_bytes(), ca_passphrase)

    dn = parse_distinguished_name(subject)
    logger.info("Генерация ключевой пары OCSP-респондера (RSA-2048).")
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    ocsp_key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)

    cert = build_ocsp_signer_certificate(
        subject=dn,
        public_key=ocsp_key.public_key(),
        ca_key=ca_key,
        ca_cert=ca_cert,
        validity_days=validity_days,
        db_path=db_path,
    )
    cert_pem = certificate_to_pem(cert)

    _insert_cert_to_db(db_path, cert, cert_pem)

    cert_file = certs_dir / "ocsp.cert.pem"
    cert_file.write_bytes(cert_pem)
    logger.info("OCSP-сертификат сохранён в: %s", cert_file.resolve())

    key_pem = ocsp_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_file = private_dir / "ocsp.key.pem"
    _write_key_file(key_file, key_pem)
    logger.warning(
        "OCSP приватный ключ сохранён НЕЗАШИФРОВАННЫМ в: %s. "
        "Ограничьте доступ к файлу.", key_file.resolve(),
    )
    logger.info("Выпуск OCSP-сертификата завершён.")
    return str(cert_file), str(key_file)


# ---- Вспомогательные функции ----

def _sanitize_filename(name: str) -> str:
    """Преобразовать значение CN в безопасное имя файла."""
    name = name.strip().lower()
    name = re.sub(r"[^a-z0-9._-]", "_", name)
    return name or "cert"


def _create_private_dir(private_dir: Path) -> None:
    """Создать приватную папку с ограниченными правами (0o700)."""
    private_dir.mkdir(parents=True, exist_ok=True)
    if platform.system() != "Windows":
        try:
            os.chmod(str(private_dir), stat.S_IRWXU)
        except OSError as e:
            logger.warning("Не удалось задать права доступа для '%s': %s", private_dir, e)
    else:
        logger.warning(
            "Обнаружена Windows: невозможно задать права в стиле Unix для '%s'. "
            "Пожалуйста, ограничьте доступ вручную.", private_dir,
        )


def _write_key_file(key_file: Path, data: bytes) -> None:
    """Записать файл ключа с ограниченными правами (0o600)."""
    key_file.write_bytes(data)
    if platform.system() != "Windows":
        try:
            os.chmod(str(key_file), stat.S_IRUSR | stat.S_IWUSR)
        except OSError as e:
            logger.warning("Не удалось задать права доступа для '%s': %s", key_file, e)
    else:
        logger.warning(
            "Обнаружена Windows: невозможно задать права в стиле Unix для '%s'. "
            "Пожалуйста, ограничьте доступ вручную.", key_file,
        )


def _generate_policy_root(policy_file, certificate, key_type, key_size):
    """Сгенерировать документ policy.txt с метаданными Корневого CA."""
    now = datetime.now(tz=timezone.utc)
    serial_hex = format(certificate.serial_number, "X")
    not_before = certificate.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    not_after = certificate.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    key_algo = f"RSA-{key_size}" if key_type == "rsa" else f"ECC-P{key_size}"

    content = f"""\
================================================================================
                        Политика сертификатов MicroPKI
================================================================================

Версия политики : 1.0
Дата создания   : {now.strftime("%Y-%m-%d %H:%M:%S UTC")}

--- Корневой CA (Root CA) ---
Имя CA (Subject DN)       : {certificate.subject.rfc4514_string()}
Серийный номер сертификата: 0x{serial_hex}

Срок действия:
  Не ранее (Not Before) : {not_before}
  Не позднее (Not After) : {not_after}

Алгоритм ключа : {key_algo}

Назначение:
  Корневой CA для демонстрации MicroPKI.
  Этот сертификат является самоподписанным якорем доверия, используемым для
  выпуска сертификатов подчиненных CA и сертификатов конечных субъектов
  в рамках инфраструктуры MicroPKI.

================================================================================
"""
    policy_file.write_text(content, encoding="utf-8")


def _append_policy_intermediate(policy_file, intermediate_cert, root_cert, key_type, key_size, path_length):
    """Добавить данные Промежуточного CA в документ policy.txt."""
    now = datetime.now(tz=timezone.utc)
    serial_hex = format(intermediate_cert.serial_number, "X")
    not_before = intermediate_cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    not_after = intermediate_cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    key_algo = f"RSA-{key_size}" if key_type == "rsa" else f"ECC-P{key_size}"

    section = f"""
--- Промежуточный CA (Intermediate CA) ---
Добавлено : {now.strftime("%Y-%m-%d %H:%M:%S UTC")}

Имя CA (Subject DN)       : {intermediate_cert.subject.rfc4514_string()}
Серийный номер сертификата: 0x{serial_hex}
Издатель (Root CA)        : {root_cert.subject.rfc4514_string()}

Срок действия:
  Не ранее (Not Before) : {not_before}
  Не позднее (Not After) : {not_after}

Алгоритм ключа           : {key_algo}
Длина пути (Path Length) : {path_length}

================================================================================
"""
    with policy_file.open("a", encoding="utf-8") as f:
        f.write(section)
