"""
Интеграционные тесты для Спринта 6:
  - TEST-38: Генерация CSR (gen_csr)
  - TEST-39: Выпуск через API (POST /request-cert)
  - TEST-40: Валидация цепочки — успех
  - TEST-41: Валидация — истёкший сертификат
  - TEST-43: Проверка отзыва через CRL
  - TEST-44: Проверка отзыва через OCSP
  - TEST-45: Откат OCSP → CRL
  - TEST-46: Валидация — отсутствует промежуточный CA
  - TEST-49: Отклонение CSR с повреждённой подписью
  - TEST-50: Отклонение CSR с CA=True
"""

import base64
import socket
import threading
import time
from datetime import datetime, timedelta, timezone
from functools import partial
from http.server import HTTPServer
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import ocsp

from micropki.ca import init_ca, issue_cert, issue_intermediate, issue_ocsp_cert, sign_csr_request
from micropki.client import (
    _load_pem_bundle,
    check_cert_status,
    gen_csr,
    request_cert,
    validate_cert,
)
from micropki.crl import generate_crl
from micropki.csr import load_csr_from_pem
from micropki.database import init_db, list_certificates
from micropki.logger import setup_logger
from micropki.ocsp_responder import OCSPHandler
from micropki.repository import RepositoryHandler
from micropki.revocation import revoke_certificate
from micropki.revocation_check import (
    check_crl,
    check_ocsp,
    check_revocation,
    extract_cdp_urls,
    extract_ocsp_url,
)
from micropki.validation import ValidationResult, build_chain, validate_chain


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
    return b"sprint6-root-pass"


@pytest.fixture
def inter_pass():
    return b"sprint6-inter-pass"


@pytest.fixture
def full_pki(tmp_path, db_path, root_pass, inter_pass):
    """Полная PKI: корневой CA + промежуточный CA."""
    out_dir = str(tmp_path / "pki")
    init_ca(
        subject="/CN=Sprint6 Root CA/O=TestOrg",
        key_type="rsa", key_size=4096,
        passphrase=root_pass, out_dir=out_dir,
        validity_days=3650, db_path=db_path,
    )
    issue_intermediate(
        root_cert_path=str(tmp_path / "pki" / "certs" / "ca.cert.pem"),
        root_key_path=str(tmp_path / "pki" / "private" / "ca.key.pem"),
        root_passphrase=root_pass,
        subject="CN=Sprint6 Intermediate CA,O=TestOrg",
        key_type="rsa", key_size=4096,
        passphrase=inter_pass,
        out_dir=out_dir, validity_days=1825, db_path=db_path,
    )
    return tmp_path / "pki"


def _issue_leaf(full_pki, db_path, inter_pass, cn, template="client", sans=None):
    issue_cert(
        ca_cert_path=str(full_pki / "certs" / "intermediate.cert.pem"),
        ca_key_path=str(full_pki / "private" / "intermediate.key.pem"),
        ca_passphrase=inter_pass,
        template_name=template,
        subject=f"/CN={cn}",
        san_strings=sans,
        out_dir=str(full_pki / "certs"),
        db_path=db_path,
    )
    certs = list_certificates(db_path)
    record = next(c for c in certs if cn in c["subject"])
    cert_obj = x509.load_pem_x509_certificate(record["cert_pem"].encode())
    return record, cert_obj


# ─────────────────────────────────────────────
#  TEST-38: Генерация CSR
# ─────────────────────────────────────────────

class TestCSRGeneration:

    def test_rsa_csr_создаётся(self, tmp_path):
        key_p = str(tmp_path / "key.pem")
        csr_p = str(tmp_path / "req.csr.pem")
        gen_csr("CN=test.local,O=Test", "rsa", 2048, None, key_p, csr_p)
        assert Path(key_p).exists()
        assert Path(csr_p).exists()

    def test_ecc_csr_создаётся(self, tmp_path):
        key_p = str(tmp_path / "key.pem")
        csr_p = str(tmp_path / "req.csr.pem")
        gen_csr("CN=ecc.local,O=Test", "ecc", 256, None, key_p, csr_p)
        csr = x509.load_pem_x509_csr(Path(csr_p).read_bytes())
        assert isinstance(csr.public_key(), ec.EllipticCurvePublicKey)

    def test_ключ_незашифрован(self, tmp_path):
        key_p = str(tmp_path / "key.pem")
        csr_p = str(tmp_path / "req.csr.pem")
        gen_csr("CN=plain.local", "rsa", 2048, None, key_p, csr_p)
        key = serialization.load_pem_private_key(Path(key_p).read_bytes(), password=None)
        assert key is not None

    def test_csr_подпись_верна(self, tmp_path):
        key_p = str(tmp_path / "key.pem")
        csr_p = str(tmp_path / "req.csr.pem")
        gen_csr("CN=sig.local", "rsa", 2048, None, key_p, csr_p)
        csr = x509.load_pem_x509_csr(Path(csr_p).read_bytes())
        assert csr.is_signature_valid

    def test_csr_содержит_subject(self, tmp_path):
        key_p = str(tmp_path / "key.pem")
        csr_p = str(tmp_path / "req.csr.pem")
        gen_csr("CN=subj.local,O=MegaCorp", "rsa", 2048, None, key_p, csr_p)
        csr = x509.load_pem_x509_csr(Path(csr_p).read_bytes())
        assert "subj.local" in csr.subject.rfc4514_string()
        assert "MegaCorp" in csr.subject.rfc4514_string()

    def test_csr_содержит_san(self, tmp_path):
        key_p = str(tmp_path / "key.pem")
        csr_p = str(tmp_path / "req.csr.pem")
        gen_csr(
            "CN=app.local", "rsa", 2048,
            ["dns:app.local", "dns:api.local"],
            key_p, csr_p,
        )
        csr = x509.load_pem_x509_csr(Path(csr_p).read_bytes())
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        values = [n.value for n in san.value]
        assert "app.local" in values
        assert "api.local" in values

    def test_неверный_тип_ключа_вызывает_ошибку(self, tmp_path):
        with pytest.raises(ValueError, match="тип ключа"):
            gen_csr("CN=x", "dsa", 2048, None, str(tmp_path / "k"), str(tmp_path / "c"))

    def test_неверный_размер_rsa_вызывает_ошибку(self, tmp_path):
        with pytest.raises(ValueError):
            gen_csr("CN=x", "rsa", 1024, None, str(tmp_path / "k"), str(tmp_path / "c"))


# ─────────────────────────────────────────────
#  TEST-39 (часть): Выпуск через CSR (библиотечный)
# ─────────────────────────────────────────────

class TestIssueCertFromCSR:

    def test_выпуск_из_csr(self, full_pki, db_path, inter_pass, tmp_path):
        key_p = str(tmp_path / "key.pem")
        csr_p = str(tmp_path / "req.csr.pem")
        gen_csr("CN=csr-client.local,O=Test", "rsa", 2048, None, key_p, csr_p)

        cert_pem = issue_cert(
            ca_cert_path=str(full_pki / "certs" / "intermediate.cert.pem"),
            ca_key_path=str(full_pki / "private" / "intermediate.key.pem"),
            ca_passphrase=inter_pass,
            template_name="client",
            subject=None,
            san_strings=None,
            out_dir=str(tmp_path / "out"),
            db_path=db_path,
            csr_pem=Path(csr_p).read_bytes(),
        )
        cert = x509.load_pem_x509_certificate(cert_pem)
        assert "csr-client.local" in cert.subject.rfc4514_string()
        # Публичный ключ из сертификата совпадает с ключом CSR
        csr_key = x509.load_pem_x509_csr(Path(csr_p).read_bytes()).public_key()
        cert_key = cert.public_key()
        assert (
            csr_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            == cert_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        )

    def test_san_из_csr_переносится_в_сертификат(self, full_pki, db_path, inter_pass, tmp_path):
        key_p = str(tmp_path / "key.pem")
        csr_p = str(tmp_path / "req.csr.pem")
        gen_csr(
            "CN=server.local", "rsa", 2048,
            ["dns:server.local", "dns:www.server.local"],
            key_p, csr_p,
        )
        cert_pem = issue_cert(
            ca_cert_path=str(full_pki / "certs" / "intermediate.cert.pem"),
            ca_key_path=str(full_pki / "private" / "intermediate.key.pem"),
            ca_passphrase=inter_pass,
            template_name="server",
            subject=None, san_strings=None,
            out_dir=str(tmp_path / "out"),
            db_path=db_path,
            csr_pem=Path(csr_p).read_bytes(),
        )
        cert = x509.load_pem_x509_certificate(cert_pem)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names = [n.value for n in san.value]
        assert "server.local" in names
        assert "www.server.local" in names

    def test_sign_csr_request_без_записи_файлов(self, full_pki, inter_pass, db_path, tmp_path):
        key_p = str(tmp_path / "key.pem")
        csr_p = str(tmp_path / "req.csr.pem")
        gen_csr("CN=nosave.local", "rsa", 2048, None, key_p, csr_p)

        ca_cert = x509.load_pem_x509_certificate(
            (full_pki / "certs" / "intermediate.cert.pem").read_bytes()
        )
        from micropki.crypto_utils import load_encrypted_key
        ca_key = load_encrypted_key(
            (full_pki / "private" / "intermediate.key.pem").read_bytes(), inter_pass
        )
        cert_pem = sign_csr_request(
            csr_pem=Path(csr_p).read_bytes(),
            template_name="client",
            ca_cert=ca_cert, ca_key=ca_key,
            db_path=db_path,
        )
        cert = x509.load_pem_x509_certificate(cert_pem)
        assert "nosave.local" in cert.subject.rfc4514_string()


# ─────────────────────────────────────────────
#  TEST-49, TEST-50: Негативные сценарии CSR
# ─────────────────────────────────────────────

class TestCSRNegative:

    def test_повреждённый_csr_отклоняется(self, full_pki, db_path, inter_pass, tmp_path):
        """TEST-49: CSR с повреждённой подписью должен быть отклонён."""
        key_p = str(tmp_path / "key.pem")
        csr_p = str(tmp_path / "req.csr.pem")
        gen_csr("CN=tamper.local", "rsa", 2048, None, key_p, csr_p)

        csr_pem = Path(csr_p).read_bytes()
        # Декодируем DER, меняем один байт в конце (область подписи)
        csr_obj = x509.load_pem_x509_csr(csr_pem)
        csr_der = bytearray(csr_obj.public_bytes(serialization.Encoding.DER))
        csr_der[-5] ^= 0xFF  # портим последние байты (подпись)
        b64 = base64.b64encode(bytes(csr_der)).decode()
        lines = "\n".join(b64[i:i+64] for i in range(0, len(b64), 64))
        tampered = f"-----BEGIN CERTIFICATE REQUEST-----\n{lines}\n-----END CERTIFICATE REQUEST-----\n".encode()

        with pytest.raises(Exception):
            load_csr_from_pem(tampered)

    def test_csr_ca_true_отклоняется(self, full_pki, db_path, inter_pass, tmp_path):
        """TEST-50: CSR с CA=True должен быть отклонён."""
        from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
        from micropki.crypto_utils import get_signature_algorithm

        key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
        dn = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "bad-ca.local")])
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(dn)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(key, hashes.SHA256())
        )
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)

        with pytest.raises(ValueError, match="CA=True"):
            issue_cert(
                ca_cert_path=str(full_pki / "certs" / "intermediate.cert.pem"),
                ca_key_path=str(full_pki / "private" / "intermediate.key.pem"),
                ca_passphrase=inter_pass,
                template_name="client",
                subject=None, san_strings=None,
                out_dir=str(tmp_path / "out"),
                db_path=db_path,
                csr_pem=csr_pem,
            )


# ─────────────────────────────────────────────
#  TEST-40, TEST-41, TEST-46: Валидация цепочки
# ─────────────────────────────────────────────

class TestChainValidation:

    def test_valid_chain(self, full_pki, db_path, inter_pass, tmp_path):
        """TEST-40: Валидная цепочка должна пройти проверку."""
        _issue_leaf(full_pki, db_path, inter_pass, "valid-chain.local")

        certs = list_certificates(db_path)
        record = next(c for c in certs if "valid-chain.local" in c["subject"])
        cert_file = tmp_path / "leaf.pem"
        cert_file.write_text(record["cert_pem"])

        result = validate_cert(
            cert_path=str(cert_file),
            untrusted_paths=[str(full_pki / "certs" / "intermediate.cert.pem")],
            trusted_path=str(full_pki / "certs" / "ca.cert.pem"),
            mode="chain",
        )
        assert result.valid, f"Ожидался успех. Шаги: {[(s.name, s.detail) for s in result.steps]}"

    def test_все_шаги_пройдены(self, full_pki, db_path, inter_pass, tmp_path):
        _issue_leaf(full_pki, db_path, inter_pass, "all-steps.local")
        certs = list_certificates(db_path)
        record = next(c for c in certs if "all-steps.local" in c["subject"])
        cert_file = tmp_path / "leaf.pem"
        cert_file.write_text(record["cert_pem"])

        result = validate_cert(
            cert_path=str(cert_file),
            untrusted_paths=[str(full_pki / "certs" / "intermediate.cert.pem")],
            trusted_path=str(full_pki / "certs" / "ca.cert.pem"),
            mode="chain",
        )
        failed = [s for s in result.steps if not s.passed]
        assert not failed, f"Провалившиеся шаги: {[(s.name, s.detail) for s in failed]}"

    def test_истёкший_сертификат(self, full_pki, db_path, inter_pass, tmp_path):
        """TEST-41: Сертификат с истёкшим сроком действия."""
        issue_cert(
            ca_cert_path=str(full_pki / "certs" / "intermediate.cert.pem"),
            ca_key_path=str(full_pki / "private" / "intermediate.key.pem"),
            ca_passphrase=inter_pass,
            template_name="client",
            subject="/CN=expired.local",
            san_strings=None,
            out_dir=str(full_pki / "certs"),
            validity_days=1,
            db_path=db_path,
        )
        certs = list_certificates(db_path)
        record = next(c for c in certs if "expired.local" in c["subject"])
        cert_file = tmp_path / "expired.pem"
        cert_file.write_text(record["cert_pem"])

        # Проверяем с временем 5 дней вперёд (сертификат уже истёк)
        future = datetime.now(tz=timezone.utc) + timedelta(days=5)
        result = validate_cert(
            cert_path=str(cert_file),
            untrusted_paths=[str(full_pki / "certs" / "intermediate.cert.pem")],
            trusted_path=str(full_pki / "certs" / "ca.cert.pem"),
            mode="chain",
            validation_time=future,
        )
        assert not result.valid
        assert any("срок действия" in s.name and not s.passed for s in result.steps)

    def test_отсутствует_промежуточный_ca_ошибка(self, full_pki, db_path, inter_pass, tmp_path):
        """TEST-46 (часть 1): без промежуточного CA цепочка не строится."""
        _issue_leaf(full_pki, db_path, inter_pass, "no-inter.local")
        certs = list_certificates(db_path)
        record = next(c for c in certs if "no-inter.local" in c["subject"])
        cert_file = tmp_path / "leaf.pem"
        cert_file.write_text(record["cert_pem"])

        result = validate_cert(
            cert_path=str(cert_file),
            untrusted_paths=[],  # промежуточный не передан
            trusted_path=str(full_pki / "certs" / "ca.cert.pem"),
            mode="chain",
        )
        assert not result.valid
        assert "цепочк" in result.error.lower() or "построить" in result.error.lower()

    def test_с_промежуточным_ca_успех(self, full_pki, db_path, inter_pass, tmp_path):
        """TEST-46 (часть 2): с промежуточным CA цепочка строится."""
        _issue_leaf(full_pki, db_path, inter_pass, "with-inter.local")
        certs = list_certificates(db_path)
        record = next(c for c in certs if "with-inter.local" in c["subject"])
        cert_file = tmp_path / "leaf.pem"
        cert_file.write_text(record["cert_pem"])

        result = validate_cert(
            cert_path=str(cert_file),
            untrusted_paths=[str(full_pki / "certs" / "intermediate.cert.pem")],
            trusted_path=str(full_pki / "certs" / "ca.cert.pem"),
            mode="chain",
        )
        assert result.valid

    def test_build_chain_возвращает_none_без_root(self, full_pki, db_path, inter_pass):
        """Если trusted пуст — цепочка не строится."""
        _issue_leaf(full_pki, db_path, inter_pass, "no-root.local")
        certs = list_certificates(db_path)
        record = next(c for c in certs if "no-root.local" in c["subject"])
        leaf = x509.load_pem_x509_certificate(record["cert_pem"].encode())
        inter = x509.load_pem_x509_certificate(
            (full_pki / "certs" / "intermediate.cert.pem").read_bytes()
        )
        result = build_chain(leaf, [inter], [])
        assert result is None


# ─────────────────────────────────────────────
#  TEST-43: Проверка отзыва через CRL
# ─────────────────────────────────────────────

class TestCRLCheck:

    def test_crl_отозван(self, full_pki, db_path, inter_pass, tmp_path):
        """TEST-43: Отозванный сертификат должен быть найден в CRL."""
        record, leaf_cert = _issue_leaf(full_pki, db_path, inter_pass, "crl-revoked.local")
        revoke_certificate(db_path, record["serial_hex"], reason="keyCompromise")

        crl_path = generate_crl(
            ca_cert_path=str(full_pki / "certs" / "intermediate.cert.pem"),
            ca_key_path=str(full_pki / "private" / "intermediate.key.pem"),
            ca_passphrase=inter_pass,
            db_path=db_path,
            out_dir=str(full_pki),
            ca_level="intermediate",
            validity_days=7,
        )

        issuer = x509.load_pem_x509_certificate(
            (full_pki / "certs" / "intermediate.cert.pem").read_bytes()
        )
        status = check_crl(leaf_cert, issuer, crl_path)
        assert status.status == "revoked"
        assert status.reason is not None

    def test_crl_good(self, full_pki, db_path, inter_pass, tmp_path):
        record, leaf_cert = _issue_leaf(full_pki, db_path, inter_pass, "crl-good.local")

        crl_path = generate_crl(
            ca_cert_path=str(full_pki / "certs" / "intermediate.cert.pem"),
            ca_key_path=str(full_pki / "private" / "intermediate.key.pem"),
            ca_passphrase=inter_pass,
            db_path=db_path,
            out_dir=str(full_pki),
            ca_level="intermediate",
        )

        issuer = x509.load_pem_x509_certificate(
            (full_pki / "certs" / "intermediate.cert.pem").read_bytes()
        )
        status = check_crl(leaf_cert, issuer, crl_path)
        assert status.status == "good"

    def test_check_cert_status_через_crl(self, full_pki, db_path, inter_pass, tmp_path):
        """check_cert_status с файлом CRL."""
        record, _ = _issue_leaf(full_pki, db_path, inter_pass, "status-crl.local")
        revoke_certificate(db_path, record["serial_hex"], reason="superseded")

        crl_path = generate_crl(
            ca_cert_path=str(full_pki / "certs" / "intermediate.cert.pem"),
            ca_key_path=str(full_pki / "private" / "intermediate.key.pem"),
            ca_passphrase=inter_pass,
            db_path=db_path, out_dir=str(full_pki),
            ca_level="intermediate",
        )

        certs = list_certificates(db_path)
        rec = next(c for c in certs if "status-crl.local" in c["subject"])
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(rec["cert_pem"])

        result = check_cert_status(
            cert_path=str(cert_file),
            ca_cert_path=str(full_pki / "certs" / "intermediate.cert.pem"),
            crl_source=crl_path,
        )
        assert result.status == "revoked"
        assert result.reason == "superseded"


# ─────────────────────────────────────────────
#  TEST-44: Проверка через OCSP
# ─────────────────────────────────────────────

@pytest.fixture
def ocsp_setup(full_pki, db_path, inter_pass):
    cert_path, key_path = issue_ocsp_cert(
        ca_cert_path=str(full_pki / "certs" / "intermediate.cert.pem"),
        ca_key_path=str(full_pki / "private" / "intermediate.key.pem"),
        ca_passphrase=inter_pass,
        subject="/CN=Sprint6 OCSP/O=TestOrg",
        out_dir=str(full_pki),
        validity_days=365,
        db_path=db_path,
    )
    issuer_cert = x509.load_pem_x509_certificate(
        (full_pki / "certs" / "intermediate.cert.pem").read_bytes()
    )
    responder_cert = x509.load_pem_x509_certificate(
        (full_pki / "certs" / "ocsp.cert.pem").read_bytes()
    )
    responder_key = serialization.load_pem_private_key(
        (full_pki / "private" / "ocsp.key.pem").read_bytes(), password=None
    )
    return {
        "issuer_cert": issuer_cert,
        "responder_cert": responder_cert,
        "responder_key": responder_key,
        "db_path": db_path,
        "full_pki": full_pki,
    }


@pytest.fixture
def ocsp_server(ocsp_setup):
    """Запускает OCSP-сервер на случайном порту."""
    stub_key = ec.generate_private_key(ec.SECP256R1())
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    handler = partial(
        OCSPHandler,
        ocsp_setup["issuer_cert"],
        ocsp_setup["responder_cert"],
        ocsp_setup["responder_key"],
        ocsp_setup["db_path"],
        stub_key,
    )
    srv = HTTPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.05)
    yield port, ocsp_setup
    srv.shutdown()


class TestOCSPCheck:

    def test_ocsp_good(self, ocsp_server, inter_pass):
        """TEST-44 (good): действительный сертификат → good."""
        port, setup = ocsp_server
        record, leaf_cert = _issue_leaf(
            setup["full_pki"], setup["db_path"], inter_pass, "ocsp-good6.local"
        )
        ocsp_url = f"http://127.0.0.1:{port}"
        result = check_ocsp(leaf_cert, setup["issuer_cert"], ocsp_url)
        assert result.status == "good"
        assert result.method == "ocsp"

    def test_ocsp_revoked(self, ocsp_server, inter_pass):
        """TEST-44 (revoked): отозванный сертификат → revoked."""
        port, setup = ocsp_server
        record, leaf_cert = _issue_leaf(
            setup["full_pki"], setup["db_path"], inter_pass, "ocsp-rev6.local"
        )
        revoke_certificate(setup["db_path"], record["serial_hex"], reason="keyCompromise")
        ocsp_url = f"http://127.0.0.1:{port}"
        result = check_ocsp(leaf_cert, setup["issuer_cert"], ocsp_url)
        assert result.status == "revoked"
        assert result.revocation_time is not None


# ─────────────────────────────────────────────
#  TEST-45: Откат OCSP → CRL
# ─────────────────────────────────────────────

class TestRevocationFallback:

    def test_ocsp_недоступен_откат_на_crl(self, full_pki, db_path, inter_pass, tmp_path):
        """TEST-45: OCSP недоступен → откат на CRL → статус revoked."""
        record, leaf_cert = _issue_leaf(full_pki, db_path, inter_pass, "fallback.local")
        revoke_certificate(db_path, record["serial_hex"], reason="cessationOfOperation")

        crl_path = generate_crl(
            ca_cert_path=str(full_pki / "certs" / "intermediate.cert.pem"),
            ca_key_path=str(full_pki / "private" / "intermediate.key.pem"),
            ca_passphrase=inter_pass,
            db_path=db_path, out_dir=str(full_pki),
            ca_level="intermediate",
        )

        issuer = x509.load_pem_x509_certificate(
            (full_pki / "certs" / "intermediate.cert.pem").read_bytes()
        )
        # Несуществующий OCSP-сервер → откат на CRL
        result = check_revocation(
            cert=leaf_cert,
            issuer_cert=issuer,
            crl_source=crl_path,
            ocsp_url="http://127.0.0.1:19999",  # порт никем не занят
        )
        # OCSP должен был вернуть unknown, CRL — revoked
        assert result.status == "revoked"
        assert result.method == "crl"

    def test_ocsp_и_crl_недоступны_unknown(self, full_pki, db_path, inter_pass):
        """Если ни OCSP ни CRL не настроены — статус unknown."""
        record, leaf_cert = _issue_leaf(full_pki, db_path, inter_pass, "unknown-rev.local")
        issuer = x509.load_pem_x509_certificate(
            (full_pki / "certs" / "intermediate.cert.pem").read_bytes()
        )
        result = check_revocation(leaf_cert, issuer, crl_source=None, ocsp_url=None)
        assert result.status == "unknown"
        assert result.method == "none"


# ─────────────────────────────────────────────
#  TEST-39 (HTTP): POST /request-cert
# ─────────────────────────────────────────────

@pytest.fixture
def repo_server(full_pki, db_path, inter_pass):
    """Запускает репозиторий с CA, поддерживающий /request-cert."""
    from micropki.crypto_utils import load_encrypted_key
    ca_cert = x509.load_pem_x509_certificate(
        (full_pki / "certs" / "intermediate.cert.pem").read_bytes()
    )
    ca_key = load_encrypted_key(
        (full_pki / "private" / "intermediate.key.pem").read_bytes(), inter_pass
    )

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    handler = partial(
        RepositoryHandler,
        db_path,
        str(full_pki / "certs"),
        ca_cert=ca_cert,
        ca_key=ca_key,
        api_key="test-api-key",
    )
    srv = HTTPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.05)
    yield port, full_pki, db_path
    srv.shutdown()


class TestRequestCertEndpoint:

    def test_запрос_клиентского_сертификата(self, repo_server, tmp_path):
        """TEST-39: gen-csr + POST /request-cert → получаем сертификат."""
        port, full_pki, db_path = repo_server
        key_p = str(tmp_path / "key.pem")
        csr_p = str(tmp_path / "req.csr.pem")
        gen_csr("CN=api-client.local,O=Test", "rsa", 2048, None, key_p, csr_p)

        out_cert = str(tmp_path / "cert.pem")
        cert_path = request_cert(
            csr_path=csr_p,
            template="client",
            ca_url=f"http://127.0.0.1:{port}",
            out_cert=out_cert,
            api_key="test-api-key",
        )
        cert = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
        assert "api-client.local" in cert.subject.rfc4514_string()

    def test_публичный_ключ_совпадает_с_csr(self, repo_server, tmp_path):
        port, full_pki, db_path = repo_server
        key_p = str(tmp_path / "key.pem")
        csr_p = str(tmp_path / "req.csr.pem")
        gen_csr("CN=key-match.local", "rsa", 2048, None, key_p, csr_p)

        out_cert = str(tmp_path / "cert.pem")
        cert_path = request_cert(
            csr_path=csr_p,
            template="client",
            ca_url=f"http://127.0.0.1:{port}",
            out_cert=out_cert,
            api_key="test-api-key",
        )
        csr_pub = x509.load_pem_x509_csr(Path(csr_p).read_bytes()).public_key()
        cert_pub = x509.load_pem_x509_certificate(Path(cert_path).read_bytes()).public_key()
        assert (
            csr_pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            == cert_pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        )

    def test_неверный_api_ключ_возвращает_401(self, repo_server, tmp_path):
        import urllib.error
        port, _, _ = repo_server
        key_p = str(tmp_path / "key.pem")
        csr_p = str(tmp_path / "req.csr.pem")
        gen_csr("CN=bad-key.local", "rsa", 2048, None, key_p, csr_p)

        with pytest.raises(RuntimeError, match="401"):
            request_cert(
                csr_path=csr_p,
                template="client",
                ca_url=f"http://127.0.0.1:{port}",
                out_cert=str(tmp_path / "cert.pem"),
                api_key="wrong-key",
            )

    def test_csr_ca_true_через_api_отклоняется(self, repo_server, tmp_path):
        port, _, _ = repo_server
        from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
        key = _rsa.generate_private_key(65537, 2048)
        dn = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "bad-api-ca.local")])
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(dn)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(key, hashes.SHA256())
        )
        csr_file = tmp_path / "bad.csr.pem"
        csr_file.write_bytes(csr.public_bytes(serialization.Encoding.PEM))

        with pytest.raises(RuntimeError, match="400|CA=True"):
            request_cert(
                csr_path=str(csr_file),
                template="client",
                ca_url=f"http://127.0.0.1:{port}",
                out_cert=str(tmp_path / "cert.pem"),
                api_key="test-api-key",
            )


# ─────────────────────────────────────────────
#  Вспомогательные функции и утилиты
# ─────────────────────────────────────────────

class TestUtilities:

    def test_load_pem_bundle_один_сертификат(self, full_pki):
        data = (full_pki / "certs" / "ca.cert.pem").read_bytes()
        certs = _load_pem_bundle(data)
        assert len(certs) == 1

    def test_load_pem_bundle_несколько_сертификатов(self, full_pki):
        root = (full_pki / "certs" / "ca.cert.pem").read_bytes()
        inter = (full_pki / "certs" / "intermediate.cert.pem").read_bytes()
        bundle = root + inter
        certs = _load_pem_bundle(bundle)
        assert len(certs) == 2

    def test_extract_ocsp_url_нет_aia(self, full_pki):
        cert = x509.load_pem_x509_certificate(
            (full_pki / "certs" / "ca.cert.pem").read_bytes()
        )
        assert extract_ocsp_url(cert) is None

    def test_extract_cdp_urls_нет_cdp(self, full_pki):
        cert = x509.load_pem_x509_certificate(
            (full_pki / "certs" / "ca.cert.pem").read_bytes()
        )
        assert extract_cdp_urls(cert) == []

    def test_validate_chain_пустая_цепочка(self, full_pki):
        root = x509.load_pem_x509_certificate(
            (full_pki / "certs" / "ca.cert.pem").read_bytes()
        )
        result = validate_chain([root])
        assert not result.valid

    def test_validate_chain_минимальная(self, full_pki):
        root = x509.load_pem_x509_certificate(
            (full_pki / "certs" / "ca.cert.pem").read_bytes()
        )
        inter = x509.load_pem_x509_certificate(
            (full_pki / "certs" / "intermediate.cert.pem").read_bytes()
        )
        result = validate_chain([inter, root])
        assert result.valid, [(s.name, s.detail) for s in result.steps]
