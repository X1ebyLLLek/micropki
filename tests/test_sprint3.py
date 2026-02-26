"""
Интеграционные тесты для Выпуска 3 (Sprint 3):
  - Интеграция базы данных SQLite (хранение, запросы)
  - Генерация уникальных серийных номеров
  - Выпуск сертификатов с авто-вставкой в БД
  - HTTP-сервер репозитория (Repository Server)
"""

import json
import sqlite3
import threading
import time
import urllib.request
import urllib.error

import pytest

from cryptography import x509

from micropki.ca import init_ca, issue_cert, issue_intermediate
from micropki.database import (
    get_by_serial,
    get_revoked,
    init_db,
    insert_certificate,
    list_certificates,
    serial_exists,
    update_status,
)
from micropki.logger import setup_logger
from micropki.repository import run_server
from micropki.serial import generate_unique_serial


@pytest.fixture(autouse=True)
def _setup_logger():
    setup_logger()


@pytest.fixture
def db_path(tmp_path):
    """Создать и вернуть путь к временной базе данных."""
    path = str(tmp_path / "test.db")
    init_db(path)
    return path


@pytest.fixture
def root_passphrase():
    return b"test-root-pass"


@pytest.fixture
def inter_passphrase():
    return b"test-inter-pass"


@pytest.fixture
def full_pki(tmp_path, db_path, root_passphrase, inter_passphrase):
    """Настроить полную PKI с Корневым и Промежуточным CA в базе данных."""
    out_dir = str(tmp_path / "pki")

    init_ca(
        subject="/CN=Test Root CA/O=TestOrg",
        key_type="rsa", key_size=4096,
        passphrase=root_passphrase,
        out_dir=out_dir, validity_days=3650,
        db_path=db_path,
    )

    issue_intermediate(
        root_cert_path=str(tmp_path / "pki" / "certs" / "ca.cert.pem"),
        root_key_path=str(tmp_path / "pki" / "private" / "ca.key.pem"),
        root_passphrase=root_passphrase,
        subject="CN=Test Intermediate CA,O=TestOrg",
        key_type="rsa", key_size=4096,
        passphrase=inter_passphrase,
        out_dir=out_dir, validity_days=1825,
        db_path=db_path,
    )

    return tmp_path / "pki"


class TestDatabaseInit:
    """Тесты инициализации базы данных."""

    def test_init_creates_db_file(self, tmp_path):
        path = str(tmp_path / "new.db")
        init_db(path)
        assert (tmp_path / "new.db").exists()

    def test_init_idempotent(self, db_path):
        # При повторном вызове не должно быть исключений
        init_db(db_path)

    def test_schema_has_certificates_table(self, db_path):
        conn = sqlite3.connect(db_path)
        result = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='certificates'"
        ).fetchone()
        conn.close()
        assert result is not None


class TestDatabaseCRUD:
    """Тесты CRUD-операций с базой данных."""

    def test_insert_and_retrieve(self, db_path):
        insert_certificate(
            db_path, serial_hex="ABCD1234",
            subject="CN=test", issuer="CN=issuer",
            not_before="2024-01-01T00:00:00Z",
            not_after="2025-01-01T00:00:00Z",
            cert_pem="-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
        )

        record = get_by_serial(db_path, "ABCD1234")
        assert record is not None
        assert record["subject"] == "CN=test"
        assert record["status"] == "valid"

    def test_serial_case_insensitive(self, db_path):
        insert_certificate(
            db_path, serial_hex="AABB",
            subject="CN=t", issuer="CN=i",
            not_before="2024-01-01T00:00:00Z",
            not_after="2025-01-01T00:00:00Z",
            cert_pem="pem",
        )
        assert get_by_serial(db_path, "aabb") is not None
        assert get_by_serial(db_path, "AABB") is not None

    def test_duplicate_serial_raises(self, db_path):
        insert_certificate(
            db_path, serial_hex="DUP1",
            subject="CN=a", issuer="CN=i",
            not_before="2024-01-01T00:00:00Z",
            not_after="2025-01-01T00:00:00Z",
            cert_pem="pem",
        )
        with pytest.raises(sqlite3.IntegrityError):
            insert_certificate(
                db_path, serial_hex="DUP1",
                subject="CN=b", issuer="CN=i",
                not_before="2024-01-01T00:00:00Z",
                not_after="2025-01-01T00:00:00Z",
                cert_pem="pem2",
            )

    def test_list_certificates_all(self, db_path):
        for i in range(3):
            insert_certificate(
                db_path, serial_hex=f"LIST{i}",
                subject=f"CN=cert{i}", issuer="CN=ca",
                not_before="2024-01-01T00:00:00Z",
                not_after="2025-01-01T00:00:00Z",
                cert_pem=f"pem{i}",
            )
        certs = list_certificates(db_path)
        assert len(certs) == 3

    def test_list_certificates_filter_status(self, db_path):
        insert_certificate(
            db_path, serial_hex="VALID1",
            subject="CN=valid", issuer="CN=ca",
            not_before="2024-01-01T00:00:00Z",
            not_after="2025-01-01T00:00:00Z",
            cert_pem="pem", status="valid",
        )
        insert_certificate(
            db_path, serial_hex="REV1",
            subject="CN=revoked", issuer="CN=ca",
            not_before="2024-01-01T00:00:00Z",
            not_after="2025-01-01T00:00:00Z",
            cert_pem="pem", status="revoked",
        )
        valid = list_certificates(db_path, status="valid")
        assert len(valid) == 1
        assert valid[0]["serial_hex"] == "VALID1"

    def test_update_status(self, db_path):
        insert_certificate(
            db_path, serial_hex="UPD1",
            subject="CN=test", issuer="CN=ca",
            not_before="2024-01-01T00:00:00Z",
            not_after="2025-01-01T00:00:00Z",
            cert_pem="pem",
        )
        result = update_status(db_path, "UPD1", "revoked", reason="keyCompromise")
        assert result is True

        record = get_by_serial(db_path, "UPD1")
        assert record["status"] == "revoked"
        assert record["revocation_reason"] == "keyCompromise"

    def test_get_revoked(self, db_path):
        insert_certificate(
            db_path, serial_hex="R1",
            subject="CN=a", issuer="CN=ca",
            not_before="2024-01-01T00:00:00Z",
            not_after="2025-01-01T00:00:00Z",
            cert_pem="pem", status="revoked",
        )
        revoked = get_revoked(db_path)
        assert len(revoked) == 1

    def test_serial_exists(self, db_path):
        assert serial_exists(db_path, "NONEXIST") is False
        insert_certificate(
            db_path, serial_hex="EXISTS1",
            subject="CN=x", issuer="CN=ca",
            not_before="2024-01-01T00:00:00Z",
            not_after="2025-01-01T00:00:00Z",
            cert_pem="pem",
        )
        assert serial_exists(db_path, "EXISTS1") is True

    def test_not_found_returns_none(self, db_path):
        assert get_by_serial(db_path, "NOPE") is None


class TestSerialGenerator:
    """Тесты генерации уникального серийного номера."""

    def test_generates_positive_int(self):
        serial = generate_unique_serial()
        assert serial > 0

    def test_generates_unique_serials(self):
        serials = set()
        for _ in range(100):
            s = generate_unique_serial()
            serials.add(s)
        assert len(serials) == 100  # Все уникальны

    def test_checks_db_for_uniqueness(self, db_path):
        serial = generate_unique_serial(db_path)
        assert serial > 0
        # Серийника ещё не должно быть в БД (мы его только сгенерировали)
        serial_hex = format(serial, "X")
        assert serial_exists(db_path, serial_hex) is False


class TestAutoInsertionOnIssuance:
    """Тесты автоматической вставки в БД при выпуске сертификатов."""

    def test_root_ca_inserted_into_db(self, full_pki, db_path):
        certs = list_certificates(db_path)
        # Должны быть корневой CA и промежуточный CA
        assert len(certs) >= 2

    def test_issued_certs_have_correct_fields(self, full_pki, db_path):
        certs = list_certificates(db_path)
        for c in certs:
            assert c["serial_hex"]
            assert c["subject"]
            assert c["issuer"]
            assert c["not_before"]
            assert c["not_after"]
            assert c["cert_pem"].startswith("-----BEGIN CERTIFICATE-----")
            assert c["status"] == "valid"

    def test_issue_5_leaf_certs_all_in_db(self, full_pki, db_path, inter_passphrase):
        """Выпустить 5 конечных сертификатов и проверить, что все они в БД."""
        templates = ["server", "client", "code_signing", "server", "client"]
        sans = [
            ["dns:s1.example.com"], None, None,
            ["dns:s2.example.com"], ["email:test@test.com"],
        ]
        for i, (tmpl, san) in enumerate(zip(templates, sans)):
            issue_cert(
                ca_cert_path=str(full_pki / "certs" / "intermediate.cert.pem"),
                ca_key_path=str(full_pki / "private" / "intermediate.key.pem"),
                ca_passphrase=inter_passphrase,
                template_name=tmpl,
                subject=f"/CN=leaf{i}.test",
                san_strings=san,
                out_dir=str(full_pki / "certs"),
                db_path=db_path,
            )

        # 2 (корневой + промежуточный) + 5 конечных = 7
        all_certs = list_certificates(db_path)
        assert len(all_certs) == 7

        # Все серийники должны быть уникальными
        serials = [c["serial_hex"] for c in all_certs]
        assert len(set(serials)) == 7


class TestSerialUniquenessStress:
    """Стресс-тест: выпустить 50 сертификатов и проверить уникальность серийников."""

    def test_50_certs_unique_serials(self, full_pki, db_path, inter_passphrase):
        for i in range(50):
            issue_cert(
                ca_cert_path=str(full_pki / "certs" / "intermediate.cert.pem"),
                ca_key_path=str(full_pki / "private" / "intermediate.key.pem"),
                ca_passphrase=inter_passphrase,
                template_name="client",
                subject=f"/CN=stress{i}.test",
                san_strings=None,
                out_dir=str(full_pki / "certs"),
                db_path=db_path,
            )

        all_certs = list_certificates(db_path)
        # 2 (сертификаты CA) + 50 конечных = 52
        assert len(all_certs) == 52
        serials = [c["serial_hex"] for c in all_certs]
        assert len(set(serials)) == 52


class TestHTTPRepository:
    """Тесты HTTP-репозитория сертификатов."""

    @pytest.fixture
    def server_with_data(self, full_pki, db_path, inter_passphrase):
        """Запустить сервер в фоновом потоке и вернуть (port, pki_dir)."""
        # Выпустить тестовый сертификат, чтобы было что запрашивать
        issue_cert(
            ca_cert_path=str(full_pki / "certs" / "intermediate.cert.pem"),
            ca_key_path=str(full_pki / "private" / "intermediate.key.pem"),
            ca_passphrase=inter_passphrase,
            template_name="server",
            subject="/CN=api-test.com",
            san_strings=["dns:api-test.com"],
            out_dir=str(full_pki / "certs"),
            db_path=db_path,
        )

        # Найти свободный порт
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]

        from http.server import HTTPServer
        from functools import partial
        from micropki.repository import RepositoryHandler

        handler = partial(RepositoryHandler, db_path, str(full_pki / "certs"))
        server = HTTPServer(("127.0.0.1", port), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        time.sleep(0.3)  # Дать серверу время на запуск

        yield port, full_pki, db_path

        server.shutdown()

    def test_get_certificate_by_serial(self, server_with_data, db_path):
        port, pki_dir, _ = server_with_data

        # Получить серийник из БД
        certs = list_certificates(db_path)
        leaf = [c for c in certs if "api-test" in c["subject"]][0]
        serial = leaf["serial_hex"]

        url = f"http://127.0.0.1:{port}/certificate/{serial}"
        resp = urllib.request.urlopen(url)
        assert resp.status == 200
        body = resp.read().decode()
        assert "BEGIN CERTIFICATE" in body

    def test_get_ca_root(self, server_with_data):
        port, pki_dir, _ = server_with_data
        url = f"http://127.0.0.1:{port}/ca/root"
        resp = urllib.request.urlopen(url)
        assert resp.status == 200
        body = resp.read().decode()
        assert "BEGIN CERTIFICATE" in body

    def test_get_ca_intermediate(self, server_with_data):
        port, pki_dir, _ = server_with_data
        url = f"http://127.0.0.1:{port}/ca/intermediate"
        resp = urllib.request.urlopen(url)
        assert resp.status == 200

    def test_crl_returns_501(self, server_with_data):
        port, _, _ = server_with_data
        url = f"http://127.0.0.1:{port}/crl"
        try:
            urllib.request.urlopen(url)
            assert False, "Should have raised"
        except urllib.error.HTTPError as e:
            assert e.code == 501

    def test_invalid_serial_returns_400(self, server_with_data):
        port, _, _ = server_with_data
        url = f"http://127.0.0.1:{port}/certificate/XYZ-NOT-HEX"
        try:
            urllib.request.urlopen(url)
            assert False, "Should have raised"
        except urllib.error.HTTPError as e:
            assert e.code == 400

    def test_nonexistent_serial_returns_404(self, server_with_data):
        port, _, _ = server_with_data
        url = f"http://127.0.0.1:{port}/certificate/DEADBEEF12345678"
        try:
            urllib.request.urlopen(url)
            assert False, "Should have raised"
        except urllib.error.HTTPError as e:
            assert e.code == 404

    def test_cert_matches_db_content(self, server_with_data, db_path):
        """Проверить, что ответ API совпадает с PEM, сохраненным в БД."""
        port, _, _ = server_with_data

        certs = list_certificates(db_path)
        leaf = [c for c in certs if "api-test" in c["subject"]][0]

        url = f"http://127.0.0.1:{port}/certificate/{leaf['serial_hex']}"
        resp = urllib.request.urlopen(url)
        api_pem = resp.read().decode()

        assert api_pem.strip() == leaf["cert_pem"].strip()
