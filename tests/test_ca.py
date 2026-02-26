"""Интеграционные тесты для инициализации CA и проверки сертификатов."""

import os
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

from micropki.ca import init_ca
from micropki.crypto_utils import load_encrypted_key
from micropki.logger import setup_logger


@pytest.fixture(autouse=True)
def _setup_logger():
    """Убедиться, что логгер настроен для тестов."""
    setup_logger()


@pytest.fixture
def passphrase() -> bytes:
    return b"test-ca-passphrase-2024"


@pytest.fixture
def passphrase_file(tmp_path, passphrase) -> Path:
    """Создать временный файл с парольной фразой."""
    p = tmp_path / "ca.pass"
    p.write_bytes(passphrase + b"\n")  # с завершающим переносом строки
    return p


class TestCAInitRSA:
    """Интеграционные тесты для инициализации CA на базе RSA."""

    def test_full_ca_init_rsa(self, tmp_path, passphrase):
        """Полная инициализация RSA CA создает все ожидаемые файлы с корректным содержимым."""
        out_dir = tmp_path / "pki"

        init_ca(
            subject="/CN=Test RSA Root CA/O=TestOrg/C=US",
            key_type="rsa",
            key_size=4096,
            passphrase=passphrase,
            out_dir=str(out_dir),
            validity_days=365,
        )

        # Проверить структуру директорий
        assert (out_dir / "private" / "ca.key.pem").exists()
        assert (out_dir / "certs" / "ca.cert.pem").exists()
        assert (out_dir / "policy.txt").exists()

        # Загрузить и проверить сертификат
        cert_pem = (out_dir / "certs" / "ca.cert.pem").read_bytes()
        cert = x509.load_pem_x509_certificate(cert_pem)

        # Проверить субъект
        cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        assert cn[0].value == "Test RSA Root CA"

        # Проверить issuer == subject (самоподписанный)
        assert cert.subject == cert.issuer

        # Проверить расширения
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.critical is True
        assert bc.value.ca is True
        assert bc.value.path_length is None

        ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku.critical is True
        assert ku.value.key_cert_sign is True
        assert ku.value.crl_sign is True

        # Проверить, что SKI и AKI существуют
        ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        assert ski.value.digest == aki.value.key_identifier

        # Проверить алгоритм подписи
        assert isinstance(cert.signature_hash_algorithm, hashes.SHA256)

    def test_key_cert_matching_rsa(self, tmp_path, passphrase):
        """Приватный ключ RSA должен соответствовать публичному ключу сертификата."""
        out_dir = tmp_path / "pki"

        init_ca(
            subject="/CN=Key Match Test",
            key_type="rsa",
            key_size=4096,
            passphrase=passphrase,
            out_dir=str(out_dir),
            validity_days=365,
        )

        # Загрузить зашифрованный ключ
        key_pem = (out_dir / "private" / "ca.key.pem").read_bytes()
        private_key = load_encrypted_key(key_pem, passphrase)

        # Загрузить сертификат
        cert_pem = (out_dir / "certs" / "ca.cert.pem").read_bytes()
        cert = x509.load_pem_x509_certificate(cert_pem)

        # Подписать и проверить для доказательства соответствия ключа и сертификата
        test_data = b"Hello, MicroPKI!"
        signature = private_key.sign(
            test_data,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )

        # Вызовет исключение, если ключ не совпадает
        cert.public_key().verify(
            signature,
            test_data,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )


class TestCAInitECC:
    """Интеграционные тесты для инициализации CA на базе ECC."""

    def test_full_ca_init_ecc(self, tmp_path, passphrase):
        """Полная инициализация ECC CA создает все ожидаемые файлы с корректным содержимым."""
        out_dir = tmp_path / "pki-ecc"

        init_ca(
            subject="CN=ECC Root CA,O=MicroPKI",
            key_type="ecc",
            key_size=384,
            passphrase=passphrase,
            out_dir=str(out_dir),
            validity_days=365,
        )

        # Проверить существование файлов
        assert (out_dir / "private" / "ca.key.pem").exists()
        assert (out_dir / "certs" / "ca.cert.pem").exists()
        assert (out_dir / "policy.txt").exists()

        # Загрузить сертификат
        cert_pem = (out_dir / "certs" / "ca.cert.pem").read_bytes()
        cert = x509.load_pem_x509_certificate(cert_pem)

        # ECC должен использовать SHA-384
        assert isinstance(cert.signature_hash_algorithm, hashes.SHA384)

        # Проверить, что это CA
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is True

    def test_key_cert_matching_ecc(self, tmp_path, passphrase):
        """Приватный ключ ECC должен соответствовать публичному ключу сертификата."""
        out_dir = tmp_path / "pki-ecc"

        init_ca(
            subject="CN=ECC Key Match",
            key_type="ecc",
            key_size=384,
            passphrase=passphrase,
            out_dir=str(out_dir),
            validity_days=365,
        )

        # Загрузить ключ и сертификат
        key_pem = (out_dir / "private" / "ca.key.pem").read_bytes()
        private_key = load_encrypted_key(key_pem, passphrase)

        cert_pem = (out_dir / "certs" / "ca.cert.pem").read_bytes()
        cert = x509.load_pem_x509_certificate(cert_pem)

        # Подписать и проверить
        test_data = b"ECC test data"
        signature = private_key.sign(
            test_data,
            ec.ECDSA(hashes.SHA384()),
        )

        cert.public_key().verify(
            signature,
            test_data,
            ec.ECDSA(hashes.SHA384()),
        )


class TestPolicyDocument:
    """Тесты содержимого policy.txt."""

    def test_policy_contains_required_info(self, tmp_path, passphrase):
        """policy.txt должен содержать имя CA, серийный номер, срок действия, информацию о ключе и назначение."""
        out_dir = tmp_path / "pki"

        init_ca(
            subject="/CN=Policy Test CA",
            key_type="rsa",
            key_size=4096,
            passphrase=passphrase,
            out_dir=str(out_dir),
            validity_days=365,
        )

        policy = (out_dir / "policy.txt").read_text(encoding="utf-8")

        assert "Policy Test CA" in policy
        assert "RSA-4096" in policy
        assert "Не ранее (Not Before)" in policy
        assert "Не позднее (Not After)" in policy
        assert "Серийный номер" in policy
        assert "Корневой CA" in policy or "Назначение" in policy
        assert "1.0" in policy


class TestCAInitErrors:
    """Тесты на ошибочные ситуации при инициализации CA."""

    def test_overwrite_without_force(self, tmp_path, passphrase):
        """Повторная инициализация без параметра --force должна завершиться ошибкой."""
        out_dir = tmp_path / "pki"

        init_ca(
            subject="/CN=Test CA",
            key_type="rsa",
            key_size=4096,
            passphrase=passphrase,
            out_dir=str(out_dir),
            validity_days=365,
        )

        with pytest.raises(FileExistsError, match="уже существует"):
            init_ca(
                subject="/CN=Test CA",
                key_type="rsa",
                key_size=4096,
                passphrase=passphrase,
                out_dir=str(out_dir),
                validity_days=365,
            )

    def test_overwrite_with_force(self, tmp_path, passphrase):
        """Повторная инициализация с параметром force=True должна завершиться успешно."""
        out_dir = tmp_path / "pki"

        init_ca(
            subject="/CN=Test CA",
            key_type="rsa",
            key_size=4096,
            passphrase=passphrase,
            out_dir=str(out_dir),
            validity_days=365,
        )

        # Не должно вызывать исключений
        init_ca(
            subject="/CN=Test CA v2",
            key_type="rsa",
            key_size=4096,
            passphrase=passphrase,
            out_dir=str(out_dir),
            validity_days=365,
            force=True,
        )

        # Проверить новый сертификат
        cert_pem = (out_dir / "certs" / "ca.cert.pem").read_bytes()
        cert = x509.load_pem_x509_certificate(cert_pem)
        cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        assert cn[0].value == "Test CA v2"


class TestSelfVerification:
    """Тесты на целостность сгенерированных сертификатов."""

    def test_certificate_self_signed_verification(self, tmp_path, passphrase):
        """Сертификат должен проходить проверку как самоподписанный."""
        out_dir = tmp_path / "pki"

        init_ca(
            subject="/CN=Self Verify Test",
            key_type="rsa",
            key_size=4096,
            passphrase=passphrase,
            out_dir=str(out_dir),
            validity_days=365,
        )

        cert_pem = (out_dir / "certs" / "ca.cert.pem").read_bytes()
        cert = x509.load_pem_x509_certificate(cert_pem)

        # Проверить самоподписанный: subject == issuer
        assert cert.subject == cert.issuer

        # Проверить подпись, используя собственный публичный ключ сертификата
        public_key = cert.public_key()
        public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
