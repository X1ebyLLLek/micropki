"""
Интеграционные тесты для Выпуска 2 (Sprint 2):
  - Выпуск Промежуточного CA
  - Выпуск сертификатов конечных субъектов (Server, Client, Code Signing)
  - Проверка совместимости SAN и профилей расширений.
  - Проверка цепочки сертификатов от конечного до корневого.
"""

import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

from micropki.ca import init_ca, issue_cert, issue_intermediate
from micropki.crypto_utils import load_encrypted_key
from micropki.logger import setup_logger


@pytest.fixture(autouse=True)
def _setup_logger():
    setup_logger()


@pytest.fixture
def root_passphrase() -> bytes:
    return b"root-passphrase-test"


@pytest.fixture
def intermediate_passphrase() -> bytes:
    return b"intermediate-passphrase-test"


@pytest.fixture
def root_pki(tmp_path, root_passphrase):
    """Создать Корневой CA и вернуть пути к выходному каталогу."""
    out_dir = tmp_path / "pki"
    init_ca(
        subject="/CN=Test Root CA/O=TestOrg",
        key_type="rsa",
        key_size=4096,
        passphrase=root_passphrase,
        out_dir=str(out_dir),
        validity_days=3650,
    )
    return out_dir


@pytest.fixture
def intermediate_pki(root_pki, root_passphrase, intermediate_passphrase):
    """Создать Промежуточный CA и вернуть пути к каталогу."""
    issue_intermediate(
        root_cert_path=str(root_pki / "certs" / "ca.cert.pem"),
        root_key_path=str(root_pki / "private" / "ca.key.pem"),
        root_passphrase=root_passphrase,
        subject="CN=Test Intermediate CA,O=TestOrg",
        key_type="rsa",
        key_size=4096,
        passphrase=intermediate_passphrase,
        out_dir=str(root_pki),
        validity_days=1825,
        path_length=0,
    )
    return root_pki


class TestIntermediateCA:
    """Тесты выпуска Промежуточного CA."""

    def test_intermediate_files_created(self, intermediate_pki):
        assert (intermediate_pki / "private" / "intermediate.key.pem").exists()
        assert (intermediate_pki / "certs" / "intermediate.cert.pem").exists()
        assert (intermediate_pki / "csrs" / "intermediate.csr.pem").exists()

    def test_intermediate_cert_properties(self, intermediate_pki):
        cert_pem = (intermediate_pki / "certs" / "intermediate.cert.pem").read_bytes()
        cert = x509.load_pem_x509_certificate(cert_pem)

        # Проверить CA=TRUE
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.critical is True
        assert bc.value.ca is True
        assert bc.value.path_length == 0

        # Проверить Key Usage
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku.critical is True
        assert ku.value.key_cert_sign is True
        assert ku.value.crl_sign is True

        # Проверить issuer != subject (не самоподписанный)
        assert cert.issuer != cert.subject

        # Проверить субъект
        cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        assert cn[0].value == "Test Intermediate CA"

    def test_intermediate_key_encrypted(self, intermediate_pki, intermediate_passphrase):
        key_pem = (intermediate_pki / "private" / "intermediate.key.pem").read_bytes()
        assert b"ENCRYPTED" in key_pem

        key = load_encrypted_key(key_pem, intermediate_passphrase)
        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 4096

    def test_policy_updated(self, intermediate_pki):
        policy = (intermediate_pki / "policy.txt").read_text(encoding="utf-8")
        assert "Intermediate CA" in policy
        assert "Root CA" in policy or "Issuer" in policy
        assert "Path Length" in policy

    def test_ski_aki_correct(self, intermediate_pki):
        """AKI промежуточного должен совпадать с SKI корневого."""
        root_pem = (intermediate_pki / "certs" / "ca.cert.pem").read_bytes()
        root_cert = x509.load_pem_x509_certificate(root_pem)
        root_ski = root_cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        )

        inter_pem = (intermediate_pki / "certs" / "intermediate.cert.pem").read_bytes()
        inter_cert = x509.load_pem_x509_certificate(inter_pem)
        inter_aki = inter_cert.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier
        )

        assert inter_aki.value.key_identifier == root_ski.value.digest


class TestServerCertificate:
    """Тесты выпуска сертификата сервера."""

    def test_issue_server_cert(self, intermediate_pki, intermediate_passphrase):
        issue_cert(
            ca_cert_path=str(intermediate_pki / "certs" / "intermediate.cert.pem"),
            ca_key_path=str(intermediate_pki / "private" / "intermediate.key.pem"),
            ca_passphrase=intermediate_passphrase,
            template_name="server",
            subject="/CN=example.com/O=TestOrg",
            san_strings=["dns:example.com", "dns:www.example.com", "ip:192.168.1.10"],
            out_dir=str(intermediate_pki / "certs"),
            validity_days=365,
        )

        cert_file = intermediate_pki / "certs" / "example.com.cert.pem"
        key_file = intermediate_pki / "certs" / "example.com.key.pem"
        assert cert_file.exists()
        assert key_file.exists()

        # Загрузить и проверить сертификат
        cert = x509.load_pem_x509_certificate(cert_file.read_bytes())

        # CA=FALSE
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is False

        # EKU = serverAuth
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        assert ExtendedKeyUsageOID.SERVER_AUTH in eku.value

        # Присутствует SAN
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san.value.get_values_for_type(x509.DNSName)
        assert "example.com" in dns_names
        assert "www.example.com" in dns_names

    def test_server_cert_without_san_fails(self, intermediate_pki, intermediate_passphrase):
        with pytest.raises(ValueError, match="Шаблон .+ требует как минимум одну запись SAN"):
            issue_cert(
                ca_cert_path=str(intermediate_pki / "certs" / "intermediate.cert.pem"),
                ca_key_path=str(intermediate_pki / "private" / "intermediate.key.pem"),
                ca_passphrase=intermediate_passphrase,
                template_name="server",
                subject="/CN=no-san.com",
                san_strings=None,
                out_dir=str(intermediate_pki / "certs"),
            )


class TestClientCertificate:
    """Тесты выпуска сертификата клиента."""

    def test_issue_client_cert(self, intermediate_pki, intermediate_passphrase):
        issue_cert(
            ca_cert_path=str(intermediate_pki / "certs" / "intermediate.cert.pem"),
            ca_key_path=str(intermediate_pki / "private" / "intermediate.key.pem"),
            ca_passphrase=intermediate_passphrase,
            template_name="client",
            subject="/CN=Alice Smith",
            san_strings=["email:alice@example.com"],
            out_dir=str(intermediate_pki / "certs"),
            validity_days=365,
        )

        cert_file = intermediate_pki / "certs" / "alice_smith.cert.pem"
        assert cert_file.exists()

        cert = x509.load_pem_x509_certificate(cert_file.read_bytes())
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        assert ExtendedKeyUsageOID.CLIENT_AUTH in eku.value


class TestCodeSigningCertificate:
    """Тесты выпуска сертификата для подписи кода."""

    def test_issue_code_signing_cert(self, intermediate_pki, intermediate_passphrase):
        issue_cert(
            ca_cert_path=str(intermediate_pki / "certs" / "intermediate.cert.pem"),
            ca_key_path=str(intermediate_pki / "private" / "intermediate.key.pem"),
            ca_passphrase=intermediate_passphrase,
            template_name="code_signing",
            subject="/CN=MicroPKI Code Signer",
            san_strings=None,
            out_dir=str(intermediate_pki / "certs"),
            validity_days=365,
        )

        cert_file = intermediate_pki / "certs" / "micropki_code_signer.cert.pem"
        assert cert_file.exists()

        cert = x509.load_pem_x509_certificate(cert_file.read_bytes())

        # CA=FALSE
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is False

        # EKU = codeSigning
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        assert ExtendedKeyUsageOID.CODE_SIGNING in eku.value

        # Использование ключа (Key Usage): только digital_signature
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku.value.digital_signature is True
        assert ku.value.key_encipherment is False


class TestChainValidation:
    """Тесты проверки цепочки сертификатов (leaf -> intermediate -> root)."""

    def test_full_chain(self, intermediate_pki, intermediate_passphrase):
        # Выпустить сертификат сервера
        issue_cert(
            ca_cert_path=str(intermediate_pki / "certs" / "intermediate.cert.pem"),
            ca_key_path=str(intermediate_pki / "private" / "intermediate.key.pem"),
            ca_passphrase=intermediate_passphrase,
            template_name="server",
            subject="/CN=chain-test.example.com",
            san_strings=["dns:chain-test.example.com"],
            out_dir=str(intermediate_pki / "certs"),
            validity_days=365,
        )

        # Загрузить все три сертификата
        root_cert = x509.load_pem_x509_certificate(
            (intermediate_pki / "certs" / "ca.cert.pem").read_bytes()
        )
        inter_cert = x509.load_pem_x509_certificate(
            (intermediate_pki / "certs" / "intermediate.cert.pem").read_bytes()
        )
        leaf_cert = x509.load_pem_x509_certificate(
            (intermediate_pki / "certs" / "chain-test.example.com.cert.pem").read_bytes()
        )

        # Проверка: issuer конечного узла == subject промежуточного
        assert leaf_cert.issuer == inter_cert.subject

        # Проверка: issuer промежуточного == subject корневого
        assert inter_cert.issuer == root_cert.subject

        # Проверка: корневой является самоподписанным
        assert root_cert.issuer == root_cert.subject

        # Проверка подписей
        # конечный сертификат подписан промежуточным
        inter_cert.public_key().verify(
            leaf_cert.signature,
            leaf_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            leaf_cert.signature_hash_algorithm,
        )

        # промежуточный подписан корневым
        root_cert.public_key().verify(
            inter_cert.signature,
            inter_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            inter_cert.signature_hash_algorithm,
        )

        # корневой самоподписанный
        root_cert.public_key().verify(
            root_cert.signature,
            root_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            root_cert.signature_hash_algorithm,
        )


class TestNegativeCases:
    """Негативные тесты для Sprint 2."""

    def test_unsupported_san_type_for_template(self, intermediate_pki, intermediate_passphrase):
        """code_signing должен отклонять SAN типа IP."""
        with pytest.raises(ValueError, match="не разрешен"):
            issue_cert(
                ca_cert_path=str(intermediate_pki / "certs" / "intermediate.cert.pem"),
                ca_key_path=str(intermediate_pki / "private" / "intermediate.key.pem"),
                ca_passphrase=intermediate_passphrase,
                template_name="code_signing",
                subject="/CN=Bad Code Signer",
                san_strings=["ip:1.2.3.4"],
                out_dir=str(intermediate_pki / "certs"),
            )

    def test_wrong_passphrase_for_intermediate(self, intermediate_pki):
        """Неверная парольная фраза для промежуточного ключа должна вызывать ошибку."""
        with pytest.raises(Exception):
            issue_cert(
                ca_cert_path=str(intermediate_pki / "certs" / "intermediate.cert.pem"),
                ca_key_path=str(intermediate_pki / "private" / "intermediate.key.pem"),
                ca_passphrase=b"wrong-passphrase",
                template_name="server",
                subject="/CN=test.com",
                san_strings=["dns:test.com"],
                out_dir=str(intermediate_pki / "certs"),
            )

    def test_server_with_email_san_fails(self, intermediate_pki, intermediate_passphrase):
        """Шаблон server не должен принимать SAN типа email."""
        with pytest.raises(ValueError, match="не разрешен"):
            issue_cert(
                ca_cert_path=str(intermediate_pki / "certs" / "intermediate.cert.pem"),
                ca_key_path=str(intermediate_pki / "private" / "intermediate.key.pem"),
                ca_passphrase=intermediate_passphrase,
                template_name="server",
                subject="/CN=bad-server.com",
                san_strings=["email:admin@bad-server.com"],
                out_dir=str(intermediate_pki / "certs"),
            )

    def test_unencrypted_ee_key(self, intermediate_pki, intermediate_passphrase):
        """Ключ конечного субъекта должен быть сохранен в незашифрованном виде."""
        issue_cert(
            ca_cert_path=str(intermediate_pki / "certs" / "intermediate.cert.pem"),
            ca_key_path=str(intermediate_pki / "private" / "intermediate.key.pem"),
            ca_passphrase=intermediate_passphrase,
            template_name="client",
            subject="/CN=Unencrypted Key Test",
            san_strings=None,
            out_dir=str(intermediate_pki / "certs"),
            validity_days=365,
        )

        key_pem = (intermediate_pki / "certs" / "unencrypted_key_test.key.pem").read_bytes()
        assert b"ENCRYPTED" not in key_pem
        # Должен загружаться без пароля
        key = serialization.load_pem_private_key(key_pem, password=None)
        assert isinstance(key, rsa.RSAPrivateKey)
