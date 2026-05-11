"""
Тесты Sprint 7: аудит, политики, CT-лог, компрометация ключа, rate limiting.

Покрывает требования:
  TEST-51: политика — слабый ключ
  TEST-52: политика — превышение срока
  TEST-53: политика — wildcard SAN
  TEST-54: политика — запрещённый тип SAN
  TEST-55: аудит — обнаружение подделки
  TEST-56: аудит — обнаружение удалённой записи
  TEST-57: компрометация — блокировка повторного выпуска
  TEST-59: CT-лог — наличие записи после выпуска
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from micropki.audit import AuditLogger, verify_log_file
from micropki.compromise import (
    hash_public_key,
    is_key_compromised,
    record_compromised_key,
    simulate_compromise,
)
from micropki.database import init_db
from micropki.policy import (
    check_key_size,
    check_san_policy,
    check_validity_days,
)
from micropki.ratelimit import RateLimiter
from micropki.transparency import CTLog


# ============================================================
#  Вспомогательные фикстуры
# ============================================================

@pytest.fixture
def tmp_audit(tmp_path):
    """Возвращает AuditLogger с временным файлом."""
    return AuditLogger(tmp_path / "audit" / "audit.log")


@pytest.fixture
def tmp_db(tmp_path):
    """Создаёт пустую БД и возвращает путь к ней."""
    db = str(tmp_path / "test.db")
    init_db(db)
    return db


@pytest.fixture
def rsa_2048_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def rsa_1024_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)


@pytest.fixture
def rsa_4096_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=4096)


@pytest.fixture
def ecc_p256_key():
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture
def ecc_p384_key():
    return ec.generate_private_key(ec.SECP384R1())


def _make_self_signed_cert(private_key, common_name: str = "test.example.com"):
    """Создаёт самоподписанный сертификат для тестов компрометации."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID
    import datetime

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(private_key, hashes.SHA256())
    )


# ============================================================
#  TEST-51: политика — слабый ключ (RSA < 2048)
# ============================================================

class TestPolicyKeySize:

    def test_rsa_1024_rejected_for_end_entity(self, rsa_1024_key):
        with pytest.raises(ValueError, match="2048"):
            check_key_size(rsa_1024_key.public_key(), "end_entity")

    def test_rsa_2048_accepted_for_end_entity(self, rsa_2048_key):
        check_key_size(rsa_2048_key.public_key(), "end_entity")  # не должно бросать

    def test_rsa_2048_rejected_for_root(self, rsa_2048_key):
        with pytest.raises(ValueError, match="4096"):
            check_key_size(rsa_2048_key.public_key(), "root")

    def test_rsa_4096_accepted_for_root(self, rsa_4096_key):
        check_key_size(rsa_4096_key.public_key(), "root")

    def test_ecc_p256_rejected_for_root(self, ecc_p256_key):
        with pytest.raises(ValueError, match="P-256"):
            check_key_size(ecc_p256_key.public_key(), "root")

    def test_ecc_p256_accepted_for_end_entity(self, ecc_p256_key):
        check_key_size(ecc_p256_key.public_key(), "end_entity")

    def test_ecc_p384_accepted_for_root(self, ecc_p384_key):
        check_key_size(ecc_p384_key.public_key(), "root")

    def test_ecc_p384_accepted_for_intermediate(self, ecc_p384_key):
        check_key_size(ecc_p384_key.public_key(), "intermediate")


# ============================================================
#  TEST-52: политика — превышение срока действия
# ============================================================

class TestPolicyValidity:

    def test_end_entity_366_days_rejected(self):
        with pytest.raises(ValueError, match="365"):
            check_validity_days(366, "end_entity")

    def test_end_entity_365_days_accepted(self):
        check_validity_days(365, "end_entity")

    def test_root_3651_days_rejected(self):
        with pytest.raises(ValueError, match="3650"):
            check_validity_days(3651, "root")

    def test_root_3650_days_accepted(self):
        check_validity_days(3650, "root")

    def test_intermediate_1826_days_rejected(self):
        with pytest.raises(ValueError, match="1825"):
            check_validity_days(1826, "intermediate")

    def test_intermediate_1825_days_accepted(self):
        check_validity_days(1825, "intermediate")


# ============================================================
#  TEST-53/54: политика — SAN (wildcard и запрещённые типы)
# ============================================================

class TestPolicySAN:

    def test_wildcard_server_rejected_by_default(self):
        san = [x509.DNSName("*.example.com")]
        with pytest.raises(ValueError, match="[Ww]ildcard"):
            check_san_policy(san, "server", allow_wildcards=False)

    def test_wildcard_server_allowed_when_flag_set(self):
        san = [x509.DNSName("*.example.com")]
        check_san_policy(san, "server", allow_wildcards=True)  # не должно бросать

    def test_email_san_rejected_for_server(self):
        san = [x509.RFC822Name("user@example.com")]
        with pytest.raises(ValueError, match="email"):
            check_san_policy(san, "server")

    def test_uri_san_rejected_for_server(self):
        san = [x509.UniformResourceIdentifier("https://example.com")]
        with pytest.raises(ValueError, match="uri"):
            check_san_policy(san, "server")

    def test_dns_san_accepted_for_server(self):
        san = [x509.DNSName("example.com")]
        check_san_policy(san, "server")

    def test_ip_san_accepted_for_server(self):
        import ipaddress
        san = [x509.IPAddress(ipaddress.IPv4Address("1.2.3.4"))]
        check_san_policy(san, "server")

    def test_email_san_rejected_for_code_signing(self):
        san = [x509.RFC822Name("signer@example.com")]
        with pytest.raises(ValueError, match="email"):
            check_san_policy(san, "code_signing")

    def test_ip_san_rejected_for_code_signing(self):
        import ipaddress
        san = [x509.IPAddress(ipaddress.IPv4Address("10.0.0.1"))]
        with pytest.raises(ValueError, match="ip"):
            check_san_policy(san, "code_signing")

    def test_dns_san_accepted_for_code_signing(self):
        san = [x509.DNSName("example.com")]
        check_san_policy(san, "code_signing")

    def test_empty_san_accepted_when_no_wildcard(self):
        check_san_policy([], "server")


# ============================================================
#  Тесты AuditLogger
# ============================================================

class TestAuditLogger:

    def test_log_creates_file(self, tmp_audit, tmp_path):
        tmp_audit.log("test_op", "success", "Тестовое сообщение")
        assert (tmp_path / "audit" / "audit.log").exists()

    def test_log_entry_has_required_fields(self, tmp_audit):
        entry = tmp_audit.log("issue_certificate", "success", "Выпущен сертификат")
        for field in ("timestamp", "level", "operation", "status", "message", "integrity"):
            assert field in entry

    def test_log_entry_has_hash_chain(self, tmp_audit):
        e1 = tmp_audit.log("op1", "success", "первая запись")
        e2 = tmp_audit.log("op2", "success", "вторая запись")
        # prev_hash второй записи равен hash первой
        assert e2["integrity"]["prev_hash"] == e1["integrity"]["hash"]

    def test_verify_clean_log_passes(self, tmp_audit):
        tmp_audit.log("op1", "success", "сообщение 1")
        tmp_audit.log("op2", "failure", "сообщение 2")
        ok, msg = tmp_audit.verify()
        assert ok, msg

    def test_verify_empty_log_passes(self, tmp_audit):
        ok, _ = tmp_audit.verify()
        assert ok

    def test_genesis_hash_is_zeros(self, tmp_audit):
        e = tmp_audit.log("first", "success", "первая запись")
        assert e["integrity"]["prev_hash"] == "0" * 64

    def test_metadata_stored(self, tmp_audit):
        entry = tmp_audit.log("issue_certificate", "success", "msg",
                               metadata={"serial": "ABCD", "template": "server"})
        assert entry["metadata"]["serial"] == "ABCD"

    def test_query_by_operation(self, tmp_audit):
        tmp_audit.log("issue_certificate", "success", "выпуск")
        tmp_audit.log("revoke", "success", "отзыв")
        results = tmp_audit.query(operation="issue_certificate")
        assert len(results) == 1
        assert results[0]["operation"] == "issue_certificate"

    def test_query_by_level(self, tmp_audit):
        tmp_audit.log("op", "success", "info", level="INFO")
        tmp_audit.log("op", "success", "audit", level="AUDIT")
        results = tmp_audit.query(level="AUDIT")
        assert all(e["level"] == "AUDIT" for e in results)

    def test_query_by_serial(self, tmp_audit):
        tmp_audit.log("issue", "success", "msg", metadata={"serial": "AA11"})
        tmp_audit.log("issue", "success", "msg", metadata={"serial": "BB22"})
        results = tmp_audit.query(serial="AA11")
        assert len(results) == 1


# ============================================================
#  TEST-55: обнаружение подделки журнала
# ============================================================

class TestAuditTamperDetection:

    def test_modified_entry_detected(self, tmp_path):
        al = AuditLogger(tmp_path / "audit.log")
        al.log("op1", "success", "первая")
        al.log("op2", "success", "вторая")

        # Модифицируем байт в файле журнала
        log_path = tmp_path / "audit.log"
        content = log_path.read_text(encoding="utf-8")
        # Заменяем "success" на "failure" в первой строке
        tampered = content.replace('"success"', '"hacked__"', 1)
        log_path.write_text(tampered, encoding="utf-8")

        ok, msg = al.verify()
        assert not ok
        assert "хеш" in msg.lower() or "повреждён" in msg.lower() or "hash" in msg.lower()

    def test_deleted_entry_detected(self, tmp_path):
        """TEST-56: удалённая строка нарушает цепочку."""
        al = AuditLogger(tmp_path / "audit.log")
        al.log("op_A", "success", "запись A")
        al.log("op_B", "success", "запись B")
        al.log("op_C", "success", "запись C")

        log_path = tmp_path / "audit.log"
        lines = log_path.read_text(encoding="utf-8").splitlines()
        # Удаляем вторую запись (B)
        del lines[1]
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        ok, msg = al.verify()
        assert not ok

    def test_unmodified_log_passes_verify_log_file(self, tmp_path):
        al = AuditLogger(tmp_path / "audit.log")
        al.log("op", "success", "ok")
        ok, _ = verify_log_file(tmp_path / "audit.log")
        assert ok


# ============================================================
#  TEST-57: компрометация ключа и блокировка повторного выпуска
# ============================================================

class TestCompromise:

    def test_hash_public_key_returns_hex_string(self, rsa_2048_key):
        h = hash_public_key(rsa_2048_key.public_key())
        assert len(h) == 64
        assert h == h.upper()

    def test_same_key_same_hash(self, rsa_2048_key):
        h1 = hash_public_key(rsa_2048_key.public_key())
        h2 = hash_public_key(rsa_2048_key.public_key())
        assert h1 == h2

    def test_different_keys_different_hashes(self, rsa_2048_key):
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        h1 = hash_public_key(rsa_2048_key.public_key())
        h2 = hash_public_key(other.public_key())
        assert h1 != h2

    def test_record_and_detect_compromised_key(self, tmp_db, rsa_2048_key):
        pub_hash = hash_public_key(rsa_2048_key.public_key())
        assert not is_key_compromised(tmp_db, pub_hash)

        record_compromised_key(tmp_db, pub_hash, "DEADBEEF")
        assert is_key_compromised(tmp_db, pub_hash)

    def test_record_idempotent(self, tmp_db, rsa_2048_key):
        pub_hash = hash_public_key(rsa_2048_key.public_key())
        # Повторная запись не должна падать
        record_compromised_key(tmp_db, pub_hash, "SER1")
        record_compromised_key(tmp_db, pub_hash, "SER1")
        assert is_key_compromised(tmp_db, pub_hash)

    def test_simulate_compromise_marks_key(self, tmp_db, rsa_2048_key):
        # Добавляем запись о сертификате в БД
        from micropki.database import insert_certificate
        import datetime
        cert = _make_self_signed_cert(rsa_2048_key)
        serial = format(cert.serial_number, "X")
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        insert_certificate(
            db_path=tmp_db,
            serial_hex=serial,
            subject=cert.subject.rfc4514_string(),
            issuer=cert.issuer.rfc4514_string(),
            not_before=now, not_after=now,
            cert_pem="",
        )

        pub_hash = simulate_compromise(tmp_db, cert)
        assert is_key_compromised(tmp_db, pub_hash)

        # Статус в БД должен быть 'revoked'
        from micropki.database import get_by_serial
        row = get_by_serial(tmp_db, serial)
        assert row["status"] == "revoked"
        assert row["revocation_reason"] == "keyCompromise"


# ============================================================
#  TEST-59: CT-лог
# ============================================================

class TestCTLog:

    def test_append_creates_ct_log(self, tmp_path, rsa_2048_key):
        ct = CTLog(tmp_path)
        cert = _make_self_signed_cert(rsa_2048_key)
        ct.append(cert)
        assert ct.path.exists()

    def test_contains_after_append(self, tmp_path, rsa_2048_key):
        ct = CTLog(tmp_path)
        cert = _make_self_signed_cert(rsa_2048_key)
        ct.append(cert)
        serial = format(cert.serial_number, "X")
        assert ct.contains(serial)

    def test_not_contains_unknown_serial(self, tmp_path, rsa_2048_key):
        ct = CTLog(tmp_path)
        assert not ct.contains("DEADBEEFDEADBEEF")

    def test_entries_returns_list(self, tmp_path, rsa_2048_key):
        ct = CTLog(tmp_path)
        cert = _make_self_signed_cert(rsa_2048_key)
        ct.append(cert)
        entries = ct.entries()
        assert len(entries) == 1
        assert "serial" in entries[0]
        assert "fingerprint" in entries[0]

    def test_multiple_certs_in_ct_log(self, tmp_path):
        ct = CTLog(tmp_path)
        for i in range(3):
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            cert = _make_self_signed_cert(key, f"host{i}.example.com")
            ct.append(cert)
        assert len(ct.entries()) == 3


# ============================================================
#  Тесты Rate Limiter
# ============================================================

class TestRateLimiter:

    def test_allows_within_burst(self):
        limiter = RateLimiter(rate=10, burst=5)
        for _ in range(5):
            allowed, _ = limiter.consume("1.2.3.4")
            assert allowed

    def test_rejects_after_burst(self):
        limiter = RateLimiter(rate=1, burst=2)
        limiter.consume("1.2.3.4")
        limiter.consume("1.2.3.4")
        allowed, retry_after = limiter.consume("1.2.3.4")
        assert not allowed
        assert retry_after > 0

    def test_retry_after_positive(self):
        limiter = RateLimiter(rate=1, burst=1)
        limiter.consume("10.0.0.1")
        allowed, retry_after = limiter.consume("10.0.0.1")
        assert not allowed
        assert retry_after > 0

    def test_different_clients_independent(self):
        limiter = RateLimiter(rate=1, burst=1)
        limiter.consume("1.1.1.1")
        # Второй клиент не должен быть затронут
        allowed, _ = limiter.consume("2.2.2.2")
        assert allowed

    def test_reset_restores_bucket(self):
        limiter = RateLimiter(rate=1, burst=1)
        limiter.consume("3.3.3.3")
        limiter.reset("3.3.3.3")
        allowed, _ = limiter.consume("3.3.3.3")
        assert allowed

    def test_invalid_rate_raises(self):
        with pytest.raises(ValueError):
            RateLimiter(rate=0, burst=5)

    def test_invalid_burst_raises(self):
        with pytest.raises(ValueError):
            RateLimiter(rate=5, burst=0)
