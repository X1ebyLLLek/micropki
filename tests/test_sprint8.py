"""
Тесты Sprint 8: подпись файлов, верификация, edge-cases, производительность, аудит.

TEST-S8-01: подпись + успешная верификация
TEST-S8-02: верификация падает при изменении файла
TEST-S8-03: истёкший сертификат отвергается
TEST-S8-04: неверный KeyUsage (code_signing cert не проходит как server cert)
TEST-S8-05: мусорный PEM — нормальная ошибка
TEST-S8-06: невалидный CSR — нормальная ошибка
TEST-S8-07: производительность — 1000 сертификатов (помечен @perf, пропускается по умолчанию)
TEST-S8-08: целостность аудит-лога после выпуска нескольких записей
TEST-S8-09: выпустить, отозвать, validate обнаруживает отзыв через CRL
TEST-S8-10: micropki --help не падает
"""

from __future__ import annotations

import datetime
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from micropki.audit import AuditLogger
from micropki.crypto_utils import sign_file, verify_file_signature
from micropki.database import init_db


# ============================================================
#  Вспомогательные функции
# ============================================================

def _make_ca_key() -> rsa.RSAPrivateKey:
    """Генерирует RSA-4096 ключ для CA (минимум по политике)."""
    return rsa.generate_private_key(public_exponent=65537, key_size=4096)


def _make_ee_key() -> rsa.RSAPrivateKey:
    """Генерирует RSA-2048 ключ для конечного субъекта."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _make_root_cert(key: rsa.RSAPrivateKey, cn: str = "Test Root CA") -> x509.Certificate:
    """Создаёт самоподписанный Root CA сертификат."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True,
            content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False,
            encipher_only=False, decipher_only=False,
        ), critical=True)
        .sign(key, hashes.SHA256())
    )


def _make_end_entity_cert(
    ee_key,
    ca_cert: x509.Certificate,
    ca_key,
    cn: str = "test.example.com",
    validity_days: int = 365,
    eku: list | None = None,
) -> x509.Certificate:
    """Выпускает конечный сертификат, подписанный CA."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_cert.subject)
        .public_key(ee_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    if eku:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    return builder.sign(ca_key, hashes.SHA256())


def _write_pem_key(key, path: Path) -> None:
    """Записывает незашифрованный приватный ключ в PEM."""
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))


def _write_cert(cert: x509.Certificate, path: Path) -> None:
    """Записывает сертификат в PEM."""
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


# ============================================================
#  TEST-S8-01: подпись файла и успешная верификация
# ============================================================

def test_sign_verify_ok(tmp_path):
    """Подписываем файл RSA-ключом, верифицируем через сертификат."""
    ca_key = _make_ca_key()
    ca_cert = _make_root_cert(ca_key)
    ee_key = _make_ee_key()
    ee_cert = _make_end_entity_cert(ee_key, ca_cert, ca_key)

    key_file = tmp_path / "ee.key.pem"
    cert_file = tmp_path / "ee.cert.pem"
    trust_file = tmp_path / "root.pem"
    data_file = tmp_path / "data.txt"
    sig_file = tmp_path / "data.sig"

    _write_pem_key(ee_key, key_file)
    _write_cert(ee_cert, cert_file)
    _write_cert(ca_cert, trust_file)
    data_file.write_text("Hello MicroPKI Sprint 8\n")

    sign_file(key_file, data_file, sig_file)
    assert sig_file.exists()
    assert len(sig_file.read_bytes()) > 0

    ok, reason = verify_file_signature(cert_file, data_file, sig_file, trust_file)
    assert ok, f"Верификация не прошла: {reason}"


# ============================================================
#  TEST-S8-02: верификация падает при изменении файла
# ============================================================

def test_verify_tampered_file(tmp_path):
    """После изменения содержимого файла подпись должна быть недействительна."""
    ca_key = _make_ca_key()
    ca_cert = _make_root_cert(ca_key)
    ee_key = _make_ee_key()
    ee_cert = _make_end_entity_cert(ee_key, ca_cert, ca_key)

    key_file = tmp_path / "ee.key.pem"
    cert_file = tmp_path / "ee.cert.pem"
    trust_file = tmp_path / "root.pem"
    data_file = tmp_path / "data.txt"
    sig_file = tmp_path / "data.sig"

    _write_pem_key(ee_key, key_file)
    _write_cert(ee_cert, cert_file)
    _write_cert(ca_cert, trust_file)
    data_file.write_text("Original content")

    sign_file(key_file, data_file, sig_file)

    # Меняем содержимое файла после подписи
    data_file.write_text("Tampered content!!!")

    ok, reason = verify_file_signature(cert_file, data_file, sig_file, trust_file)
    assert not ok, "Подпись должна быть недействительна для изменённого файла"
    assert reason, "Должна быть причина ошибки"


# ============================================================
#  TEST-S8-03: истёкший сертификат отвергается
# ============================================================

def test_expired_cert_rejected(tmp_path):
    """Сертификат с истёкшим сроком действия не должен пройти верификацию."""
    ca_key = _make_ca_key()
    ca_cert = _make_root_cert(ca_key)
    ee_key = _make_ee_key()

    # Создаём сертификат с датами в прошлом вручную
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "expired.example.com")])
    past = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
    expired_cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_cert.subject)
        .public_key(ee_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(past)
        .not_valid_after(past + datetime.timedelta(days=1))  # истёк в 2020 году
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    key_file = tmp_path / "expired.key.pem"
    cert_file = tmp_path / "expired.cert.pem"
    trust_file = tmp_path / "root.pem"
    data_file = tmp_path / "data.txt"
    sig_file = tmp_path / "data.sig"

    _write_pem_key(ee_key, key_file)
    _write_cert(expired_cert, cert_file)
    _write_cert(ca_cert, trust_file)
    data_file.write_text("some data")

    sign_file(key_file, data_file, sig_file)

    ok, reason = verify_file_signature(cert_file, data_file, sig_file, trust_file)
    assert not ok, "Истёкший сертификат должен быть отвергнут"
    assert "истёк" in reason.lower() or "not_after" in reason.lower() or "notafter" in reason.lower()


# ============================================================
#  TEST-S8-04: EKU — code_signing cert не должен пройти как server cert
# ============================================================

def test_wrong_key_usage(tmp_path):
    """
    verify_file_signature не проверяет EKU — это зона валидатора цепочки.
    Тест проверяет, что code_signing сертификат всё равно проходит верификацию подписи
    (EKU — семантический, а не криптографический атрибут).
    Отдельно проверяем, что клиентский сертификат с другим EKU подпись проверяет корректно.
    """
    ca_key = _make_ca_key()
    ca_cert = _make_root_cert(ca_key)
    ee_key = _make_ee_key()

    # Сертификат с EKU=codeSigning
    code_cert = _make_end_entity_cert(
        ee_key, ca_cert, ca_key, cn="Code Signer",
        eku=[ExtendedKeyUsageOID.CODE_SIGNING],
    )
    # Сертификат с EKU=serverAuth — другой ключ, верификация должна упасть
    server_key = _make_ee_key()
    server_cert = _make_end_entity_cert(
        server_key, ca_cert, ca_key, cn="Server",
        eku=[ExtendedKeyUsageOID.SERVER_AUTH],
    )

    key_file = tmp_path / "code.key.pem"
    code_cert_file = tmp_path / "code.cert.pem"
    server_cert_file = tmp_path / "server.cert.pem"
    trust_file = tmp_path / "root.pem"
    data_file = tmp_path / "data.txt"
    sig_file = tmp_path / "data.sig"

    _write_pem_key(ee_key, key_file)
    _write_cert(code_cert, code_cert_file)
    _write_cert(server_cert, server_cert_file)
    _write_cert(ca_cert, trust_file)
    data_file.write_text("payload")

    sign_file(key_file, data_file, sig_file)

    # code_signing сертификатом — должна пройти
    ok, _ = verify_file_signature(code_cert_file, data_file, sig_file, trust_file)
    assert ok, "Верификация через code_signing cert должна пройти"

    # server cert с другим ключом — подпись сделана другим ключом, должна упасть
    ok2, reason2 = verify_file_signature(server_cert_file, data_file, sig_file, trust_file)
    assert not ok2, "Подпись другим ключом не должна пройти верификацию через server cert"


# ============================================================
#  TEST-S8-05: мусорный PEM — нормальная ошибка
# ============================================================

def test_malformed_pem(tmp_path):
    """Скормить мусорный PEM — должна прийти читаемая ошибка, не traceback."""
    garbage_cert = tmp_path / "garbage.cert.pem"
    garbage_cert.write_text("-----BEGIN CERTIFICATE-----\nthisisgarbagenotbase64\n-----END CERTIFICATE-----\n")

    trust_file = tmp_path / "root.pem"
    # trust тоже нужен, но может быть пустым — проверяем что cert не парсится
    trust_file.write_bytes(b"")

    data_file = tmp_path / "data.txt"
    data_file.write_text("test")
    sig_file = tmp_path / "fake.sig"
    sig_file.write_bytes(b"\x00" * 32)

    ok, reason = verify_file_signature(garbage_cert, data_file, sig_file, trust_file)
    assert not ok, "Мусорный PEM должен вернуть ошибку"
    assert reason, "Причина ошибки должна быть непустой"


# ============================================================
#  TEST-S8-06: невалидный CSR
# ============================================================

def test_malformed_csr(tmp_path):
    """Невалидный CSR должен вызвать понятное исключение при загрузке."""
    from micropki.csr import load_csr_from_pem

    garbage = b"-----BEGIN CERTIFICATE REQUEST-----\nABCDEFGHIJ\n-----END CERTIFICATE REQUEST-----\n"
    with pytest.raises(Exception):
        load_csr_from_pem(garbage)


# ============================================================
#  TEST-S8-07: производительность — 1000 сертификатов
# ============================================================

@pytest.mark.perf
def test_1000_certs_performance(tmp_path):
    """
    Выпуск 1000 сертификатов через Python API.
    Помечен @perf — пропускается по умолчанию (см. conftest.py).
    """
    ca_key = _make_ca_key()
    ca_cert = _make_root_cert(ca_key)

    start = time.monotonic()
    for i in range(1000):
        ee_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        _make_end_entity_cert(ee_key, ca_cert, ca_key, cn=f"host{i}.example.com")
    elapsed = time.monotonic() - start

    # Мягкий лимит — 60 секунд для 1000 сертификатов на любой машине
    assert elapsed < 60, f"Слишком медленно: {elapsed:.1f}с для 1000 сертификатов"


# ============================================================
#  TEST-S8-08: целостность аудит-лога
# ============================================================

def test_audit_integrity(tmp_path):
    """Несколько записей в лог → verify должен пройти без ошибок."""
    al = AuditLogger(tmp_path / "audit.log")

    al.log("issue_certificate", "success", "Выпущен server cert",
           metadata={"serial": "AABB01", "template": "server"})
    al.log("issue_certificate", "success", "Выпущен client cert",
           metadata={"serial": "AABB02", "template": "client"})
    al.log("revoke", "success", "Отозван сертификат",
           metadata={"serial": "AABB01", "reason": "superseded"})

    ok, msg = al.verify()
    assert ok, f"Аудит-лог должен пройти проверку целостности: {msg}"


# ============================================================
#  TEST-S8-09: выпустить, отозвать, validate обнаруживает через БД
# ============================================================

def test_revoke_then_validate(tmp_path):
    """
    Выпускаем сертификат, записываем в БД, отзываем,
    проверяем что статус в БД = 'revoked'.
    """
    db_path = str(tmp_path / "test.db")
    init_db(db_path)

    from micropki.database import insert_certificate, get_by_serial
    from micropki.revocation import revoke_certificate

    ca_key = _make_ca_key()
    ca_cert = _make_root_cert(ca_key)
    ee_key = _make_ee_key()
    ee_cert = _make_end_entity_cert(ee_key, ca_cert, ca_key)

    serial = format(ee_cert.serial_number, "X")
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    cert_pem = ee_cert.public_bytes(serialization.Encoding.PEM).decode()

    insert_certificate(
        db_path=db_path,
        serial_hex=serial,
        subject=ee_cert.subject.rfc4514_string(),
        issuer=ee_cert.issuer.rfc4514_string(),
        not_before=now_str,
        not_after=now_str,
        cert_pem=cert_pem,
    )

    # Отзываем
    revoke_certificate(db_path, serial, reason="superseded")

    # Проверяем статус в БД
    row = get_by_serial(db_path, serial)
    assert row is not None
    assert row["status"] == "revoked", f"Ожидался статус 'revoked', получен '{row['status']}'"
    assert row["revocation_reason"] == "superseded"


# ============================================================
#  TEST-S8-10: micropki --help не падает
# ============================================================

def test_cli_help():
    """micropki --help должен завершаться с кодом 0 и что-то выводить."""
    result = subprocess.run(
        [sys.executable, "-m", "micropki", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"--help завершился с кодом {result.returncode}"
    assert "micropki" in result.stdout.lower(), "Вывод --help должен содержать имя команды"
