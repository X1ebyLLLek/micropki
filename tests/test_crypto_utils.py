"""Юнит-тесты для модуля crypto_utils."""

import pytest

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import Name

from micropki.crypto_utils import (
    encrypt_private_key,
    generate_ecc_key,
    generate_key,
    generate_rsa_key,
    get_signature_algorithm,
    load_encrypted_key,
    parse_distinguished_name,
)


class TestKeyGeneration:
    """Тесты функций генерации ключей."""

    def test_generate_rsa_key_4096(self):
        """Ключ RSA должен быть 4096-битным."""
        key = generate_rsa_key(4096)
        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 4096

    def test_generate_ecc_key_p384(self):
        """Ключ ECC должен использовать кривую NIST P-384."""
        key = generate_ecc_key()
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert isinstance(key.curve, ec.SECP384R1)

    def test_generate_key_rsa(self):
        """generate_key с type='rsa' возвращает ключ RSA."""
        key = generate_key("rsa", 4096)
        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 4096

    def test_generate_key_ecc(self):
        """generate_key с type='ecc' возвращает ключ ECC."""
        key = generate_key("ecc", 384)
        assert isinstance(key, ec.EllipticCurvePrivateKey)


class TestPEMEncryption:
    """Тесты шифрования/дешифрования приватного ключа."""

    def test_rsa_encrypt_decrypt_roundtrip(self):
        """Ключ RSA может быть зашифрован и расшифрован."""
        key = generate_rsa_key(4096)
        passphrase = b"test-passphrase-123"

        pem_data = encrypt_private_key(key, passphrase)
        assert b"ENCRYPTED" in pem_data

        loaded = load_encrypted_key(pem_data, passphrase)
        assert isinstance(loaded, rsa.RSAPrivateKey)
        assert loaded.key_size == 4096

    def test_ecc_encrypt_decrypt_roundtrip(self):
        """Ключ ECC может быть зашифрован и расшифрован."""
        key = generate_ecc_key()
        passphrase = b"ecc-passphrase"

        pem_data = encrypt_private_key(key, passphrase)
        assert b"ENCRYPTED" in pem_data

        loaded = load_encrypted_key(pem_data, passphrase)
        assert isinstance(loaded, ec.EllipticCurvePrivateKey)

    def test_wrong_passphrase_fails(self):
        """Загрузка с неверной парольной фразой должна вызывать ошибку."""
        key = generate_rsa_key(4096)
        pem_data = encrypt_private_key(key, b"correct-pass")

        with pytest.raises(Exception):
            load_encrypted_key(pem_data, b"wrong-pass")


class TestDNParsing:
    """Тесты синтаксического анализа Distinguished Name (DN)."""

    def test_slash_notation_single(self):
        """Парсинг /CN=My Root CA."""
        name = parse_distinguished_name("/CN=My Root CA")
        assert isinstance(name, Name)
        attrs = list(name)
        assert len(attrs) == 1
        assert attrs[0].value == "My Root CA"

    def test_slash_notation_multiple(self):
        """Парсинг /CN=Test/O=Org/C=US."""
        name = parse_distinguished_name("/CN=Test/O=Org/C=US")
        attrs = {a.oid._name: a.value for a in name}
        assert attrs["commonName"] == "Test"
        assert attrs["organizationName"] == "Org"
        assert attrs["countryName"] == "US"

    def test_comma_notation_single(self):
        """Парсинг CN=My Root CA."""
        name = parse_distinguished_name("CN=My Root CA")
        attrs = list(name)
        assert len(attrs) == 1
        assert attrs[0].value == "My Root CA"

    def test_comma_notation_multiple(self):
        """Парсинг CN=Test,O=Org,C=US."""
        name = parse_distinguished_name("CN=Test,O=Org,C=US")
        attrs = {a.oid._name: a.value for a in name}
        assert attrs["commonName"] == "Test"
        assert attrs["organizationName"] == "Org"
        assert attrs["countryName"] == "US"

    def test_empty_dn_raises(self):
        """Пустой DN должен вызывать ValueError."""
        with pytest.raises(ValueError, match="не должно быть пустым"):
            parse_distinguished_name("")

    def test_invalid_dn_syntax_raises(self):
        """DN без '=' должен вызывать ValueError."""
        with pytest.raises(ValueError, match="Неверный формат DN"):
            parse_distinguished_name("invalid-dn")

    def test_unknown_attribute_raises(self):
        """Неизвестный атрибут DN должен вызывать ValueError."""
        with pytest.raises(ValueError, match="Неизвестный атрибут DN"):
            parse_distinguished_name("UNKNOWN=Test")


class TestSignatureAlgorithm:
    """Тесты выбора алгоритма подписи."""

    def test_rsa_uses_sha256(self):
        """Ключ RSA -> SHA256."""
        from cryptography.hazmat.primitives import hashes

        key = generate_rsa_key(4096)
        algo = get_signature_algorithm(key)
        assert isinstance(algo, hashes.SHA256)

    def test_ecc_uses_sha384(self):
        """Ключ ECC -> SHA384."""
        from cryptography.hazmat.primitives import hashes

        key = generate_ecc_key()
        algo = get_signature_algorithm(key)
        assert isinstance(algo, hashes.SHA384)
