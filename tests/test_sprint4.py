"""
Интеграционные тесты для Спринта 4:
  - Отзыв сертификатов (revocation)
  - Генерация CRL
  - HTTP-раздача CRL через репозиторий
"""

import socket
import threading
import time
import urllib.error
import urllib.request
from functools import partial
from http.server import HTTPServer

import pytest
from cryptography import x509

from micropki.ca import init_ca, issue_cert, issue_intermediate
from micropki.crl import generate_crl
from micropki.database import get_by_serial, init_db, list_certificates
from micropki.logger import setup_logger
from micropki.repository import RepositoryHandler
from micropki.revocation import RFC5280_REASONS, revoke_certificate


@pytest.fixture(autouse=True)
def _setup_logger():
    setup_logger()


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "test.db")
    init_db(path)
    return path


@pytest.fixture
def root_pass():
    return b"test-root-pass"


@pytest.fixture
def inter_pass():
    return b"test-inter-pass"


@pytest.fixture
def full_pki(tmp_path, db_path, root_pass, inter_pass):
    """Полная PKI: корневой + промежуточный CA."""
    out_dir = str(tmp_path / "pki")
    init_ca(
        subject="/CN=Sprint4 Root CA/O=TestOrg",
        key_type="rsa", key_size=4096,
        passphrase=root_pass,
        out_dir=out_dir, validity_days=3650,
        db_path=db_path,
    )
    issue_intermediate(
        root_cert_path=str(tmp_path / "pki" / "certs" / "ca.cert.pem"),
        root_key_path=str(tmp_path / "pki" / "private" / "ca.key.pem"),
        root_passphrase=root_pass,
        subject="CN=Sprint4 Intermediate CA,O=TestOrg",
        key_type="rsa", key_size=4096,
        passphrase=inter_pass,
        out_dir=out_dir, validity_days=1825,
        db_path=db_path,
    )
    return tmp_path / "pki"


def _issue_leaf(full_pki, db_path, inter_pass, cn):
    """Выпустить клиентский сертификат и вернуть его запись из БД."""
    issue_cert(
        ca_cert_path=str(full_pki / "certs" / "intermediate.cert.pem"),
        ca_key_path=str(full_pki / "private" / "intermediate.key.pem"),
        ca_passphrase=inter_pass,
        template_name="client",
        subject=f"/CN={cn}",
        san_strings=None,
        out_dir=str(full_pki / "certs"),
        db_path=db_path,
    )
    certs = list_certificates(db_path)
    return next(c for c in certs if cn in c["subject"])


# ─────────────────────────────────────────────
#  Тесты отзыва сертификатов
# ─────────────────────────────────────────────

class TestRevocation:

    def test_revoke_меняет_статус(self, full_pki, db_path, inter_pass):
        leaf = _issue_leaf(full_pki, db_path, inter_pass, "revoke-status.local")
        revoke_certificate(db_path, leaf["serial_hex"], reason="keyCompromise")
        record = get_by_serial(db_path, leaf["serial_hex"])
        assert record["status"] == "revoked"
        assert record["revocation_reason"] == "keyCompromise"

    def test_revoke_записывает_дату(self, full_pki, db_path, inter_pass):
        leaf = _issue_leaf(full_pki, db_path, inter_pass, "revoke-date.local")
        revoke_certificate(db_path, leaf["serial_hex"])
        record = get_by_serial(db_path, leaf["serial_hex"])
        assert record["revocation_date"] is not None

    def test_несуществующий_серийник_вызывает_ошибку(self, db_path):
        with pytest.raises(ValueError, match="не найден"):
            revoke_certificate(db_path, "DEADBEEF00000000")

    def test_повторный_отзыв_вызывает_ошибку(self, full_pki, db_path, inter_pass):
        leaf = _issue_leaf(full_pki, db_path, inter_pass, "double-revoke.local")
        revoke_certificate(db_path, leaf["serial_hex"])
        with pytest.raises(ValueError, match="уже отозван"):
            revoke_certificate(db_path, leaf["serial_hex"])

    def test_неверная_причина_вызывает_ошибку(self, full_pki, db_path, inter_pass):
        leaf = _issue_leaf(full_pki, db_path, inter_pass, "bad-reason.local")
        with pytest.raises(ValueError, match="Неизвестная причина"):
            revoke_certificate(db_path, leaf["serial_hex"], reason="несуществующаяПричина")

    def test_все_коды_причин_rfc5280_принимаются(self, full_pki, db_path, inter_pass):
        for i, reason in enumerate(RFC5280_REASONS):
            leaf = _issue_leaf(full_pki, db_path, inter_pass, f"reason-{i}.local")
            revoke_certificate(db_path, leaf["serial_hex"], reason=reason)
            record = get_by_serial(db_path, leaf["serial_hex"])
            assert record["status"] == "revoked"


# ─────────────────────────────────────────────
#  Тесты генерации CRL
# ─────────────────────────────────────────────

class TestCRLGeneration:

    def test_файл_crl_создаётся(self, full_pki, db_path, inter_pass):
        generate_crl(
            ca_cert_path=str(full_pki / "certs" / "intermediate.cert.pem"),
            ca_key_path=str(full_pki / "private" / "intermediate.key.pem"),
            ca_passphrase=inter_pass,
            db_path=db_path,
            out_dir=str(full_pki),
            ca_level="intermediate",
        )
        assert (full_pki / "crl" / "intermediate.crl.pem").exists()

    def test_crl_валидный_pem(self, full_pki, db_path, inter_pass):
        generate_crl(
            ca_cert_path=str(full_pki / "certs" / "intermediate.cert.pem"),
            ca_key_path=str(full_pki / "private" / "intermediate.key.pem"),
            ca_passphrase=inter_pass,
            db_path=db_path,
            out_dir=str(full_pki),
            ca_level="intermediate",
        )
        pem = (full_pki / "crl" / "intermediate.crl.pem").read_bytes()
        crl = x509.load_pem_x509_crl(pem)
        assert crl is not None

    def test_crl_подписан_промежуточным_ca(self, full_pki, db_path, inter_pass):
        generate_crl(
            ca_cert_path=str(full_pki / "certs" / "intermediate.cert.pem"),
            ca_key_path=str(full_pki / "private" / "intermediate.key.pem"),
            ca_passphrase=inter_pass,
            db_path=db_path,
            out_dir=str(full_pki),
            ca_level="intermediate",
        )
        pem = (full_pki / "crl" / "intermediate.crl.pem").read_bytes()
        crl = x509.load_pem_x509_crl(pem)
        ca_cert = x509.load_pem_x509_certificate(
            (full_pki / "certs" / "intermediate.cert.pem").read_bytes()
        )
        assert crl.issuer == ca_cert.subject

    def test_отозванный_сертификат_попадает_в_crl(self, full_pki, db_path, inter_pass):
        leaf = _issue_leaf(full_pki, db_path, inter_pass, "in-crl.local")
        revoke_certificate(db_path, leaf["serial_hex"], reason="superseded")

        generate_crl(
            ca_cert_path=str(full_pki / "certs" / "intermediate.cert.pem"),
            ca_key_path=str(full_pki / "private" / "intermediate.key.pem"),
            ca_passphrase=inter_pass,
            db_path=db_path,
            out_dir=str(full_pki),
            ca_level="intermediate",
        )
        pem = (full_pki / "crl" / "intermediate.crl.pem").read_bytes()
        crl = x509.load_pem_x509_crl(pem)
        serial_int = int(leaf["serial_hex"], 16)
        assert crl.get_revoked_certificate_by_serial_number(serial_int) is not None

    def test_действующий_сертификат_не_попадает_в_crl(self, full_pki, db_path, inter_pass):
        leaf = _issue_leaf(full_pki, db_path, inter_pass, "valid-not-in-crl.local")

        generate_crl(
            ca_cert_path=str(full_pki / "certs" / "intermediate.cert.pem"),
            ca_key_path=str(full_pki / "private" / "intermediate.key.pem"),
            ca_passphrase=inter_pass,
            db_path=db_path,
            out_dir=str(full_pki),
            ca_level="intermediate",
        )
        pem = (full_pki / "crl" / "intermediate.crl.pem").read_bytes()
        crl = x509.load_pem_x509_crl(pem)
        serial_int = int(leaf["serial_hex"], 16)
        assert crl.get_revoked_certificate_by_serial_number(serial_int) is None

    def test_срок_действия_crl(self, full_pki, db_path, inter_pass):
        generate_crl(
            ca_cert_path=str(full_pki / "certs" / "intermediate.cert.pem"),
            ca_key_path=str(full_pki / "private" / "intermediate.key.pem"),
            ca_passphrase=inter_pass,
            db_path=db_path,
            out_dir=str(full_pki),
            ca_level="intermediate",
            validity_days=14,
        )
        pem = (full_pki / "crl" / "intermediate.crl.pem").read_bytes()
        crl = x509.load_pem_x509_crl(pem)
        delta = crl.next_update_utc - crl.last_update_utc
        assert delta.days == 14

    def test_корневой_crl_генерируется(self, full_pki, db_path, root_pass):
        generate_crl(
            ca_cert_path=str(full_pki / "certs" / "ca.cert.pem"),
            ca_key_path=str(full_pki / "private" / "ca.key.pem"),
            ca_passphrase=root_pass,
            db_path=db_path,
            out_dir=str(full_pki),
            ca_level="root",
        )
        assert (full_pki / "crl" / "root.crl.pem").exists()

    def test_crl_промежуточного_не_содержит_записи_корневого(
        self, full_pki, db_path, inter_pass, root_pass
    ):
        """Конечный сертификат выпущен промежуточным CA — в CRL корневого его быть не должно."""
        leaf = _issue_leaf(full_pki, db_path, inter_pass, "issuer-check.local")
        revoke_certificate(db_path, leaf["serial_hex"])

        generate_crl(
            ca_cert_path=str(full_pki / "certs" / "ca.cert.pem"),
            ca_key_path=str(full_pki / "private" / "ca.key.pem"),
            ca_passphrase=root_pass,
            db_path=db_path,
            out_dir=str(full_pki),
            ca_level="root",
        )
        pem = (full_pki / "crl" / "root.crl.pem").read_bytes()
        crl = x509.load_pem_x509_crl(pem)
        serial_int = int(leaf["serial_hex"], 16)
        assert crl.get_revoked_certificate_by_serial_number(serial_int) is None

    def test_повторная_генерация_обновляет_файл(self, full_pki, db_path, inter_pass):
        def _gen():
            return generate_crl(
                ca_cert_path=str(full_pki / "certs" / "intermediate.cert.pem"),
                ca_key_path=str(full_pki / "private" / "intermediate.key.pem"),
                ca_passphrase=inter_pass,
                db_path=db_path,
                out_dir=str(full_pki),
                ca_level="intermediate",
            )

        _gen()
        mtime1 = (full_pki / "crl" / "intermediate.crl.pem").stat().st_mtime
        time.sleep(0.05)
        _gen()
        mtime2 = (full_pki / "crl" / "intermediate.crl.pem").stat().st_mtime
        assert mtime2 >= mtime1


# ─────────────────────────────────────────────
#  Тесты HTTP-раздачи CRL
# ─────────────────────────────────────────────

class TestCRLHTTPEndpoint:

    @pytest.fixture
    def server_with_crl(self, full_pki, db_path, inter_pass):
        """Запустить сервер с уже сгенерированным CRL для промежуточного CA."""
        leaf = _issue_leaf(full_pki, db_path, inter_pass, "http-crl-test.local")
        revoke_certificate(db_path, leaf["serial_hex"], reason="cessationOfOperation")

        generate_crl(
            ca_cert_path=str(full_pki / "certs" / "intermediate.cert.pem"),
            ca_key_path=str(full_pki / "private" / "intermediate.key.pem"),
            ca_passphrase=inter_pass,
            db_path=db_path,
            out_dir=str(full_pki),
            ca_level="intermediate",
        )

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]

        handler = partial(RepositoryHandler, db_path, str(full_pki / "certs"))
        server = HTTPServer(("127.0.0.1", port), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        time.sleep(0.2)

        yield port, full_pki, db_path

        server.shutdown()

    def test_get_crl_без_параметров_возвращает_200(self, server_with_crl):
        port, _, _ = server_with_crl
        resp = urllib.request.urlopen(f"http://127.0.0.1:{port}/crl")
        assert resp.status == 200

    def test_content_type_application_pkix_crl(self, server_with_crl):
        port, _, _ = server_with_crl
        resp = urllib.request.urlopen(f"http://127.0.0.1:{port}/crl")
        assert resp.headers["Content-Type"] == "application/pkix-crl"

    def test_get_crl_с_параметром_intermediate(self, server_with_crl):
        port, _, _ = server_with_crl
        resp = urllib.request.urlopen(f"http://127.0.0.1:{port}/crl?ca=intermediate")
        assert resp.status == 200
        body = resp.read()
        crl = x509.load_pem_x509_crl(body)
        assert crl is not None

    def test_отсутствующий_crl_возвращает_404(self, server_with_crl):
        port, _, _ = server_with_crl
        # CRL для root не генерировали
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/crl?ca=root")
        assert exc_info.value.code == 404

    def test_неверный_параметр_ca_возвращает_400(self, server_with_crl):
        port, _, _ = server_with_crl
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/crl?ca=unknown")
        assert exc_info.value.code == 400

    def test_crl_содержит_отозванную_запись(self, server_with_crl):
        port, _, _ = server_with_crl
        resp = urllib.request.urlopen(f"http://127.0.0.1:{port}/crl")
        crl = x509.load_pem_x509_crl(resp.read())
        assert len(list(crl)) >= 1

    def test_содержимое_crl_совпадает_с_файлом(self, server_with_crl):
        port, full_pki, _ = server_with_crl
        resp = urllib.request.urlopen(f"http://127.0.0.1:{port}/crl")
        api_data = resp.read()
        file_data = (full_pki / "crl" / "intermediate.crl.pem").read_bytes()
        assert api_data.strip() == file_data.strip()
