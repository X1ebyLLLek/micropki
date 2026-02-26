"""
Криптографические утилиты для MicroPKI.

Обрабатывает генерацию ключей (RSA-4096 / ECC P-384), шифрование/расшифрование PEM,
и парсинг Отличительных Имен (Distinguished Name).
"""

from __future__ import annotations

import re
from typing import Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import Name, NameAttribute
from cryptography.x509.oid import NameOID

PrivateKey = Union[RSAPrivateKey, EllipticCurvePrivateKey]

# Маппинг общих сокращений атрибутов DN на OID
_DN_OID_MAP = {
    "CN": NameOID.COMMON_NAME,
    "O": NameOID.ORGANIZATION_NAME,
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "C": NameOID.COUNTRY_NAME,
    "ST": NameOID.STATE_OR_PROVINCE_NAME,
    "L": NameOID.LOCALITY_NAME,
    "E": NameOID.EMAIL_ADDRESS,
    "SERIALNUMBER": NameOID.SERIAL_NUMBER,
}


def generate_rsa_key(bits: int = 4096) -> RSAPrivateKey:
    """Генерирует приватный RSA ключ с указанной длиной в битах."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
    )


def generate_ecc_key() -> EllipticCurvePrivateKey:
    """Генерирует приватный ECC ключ на кривой NIST P-384 (secp384r1)."""
    return ec.generate_private_key(ec.SECP384R1())


def generate_key(key_type: str, key_size: int) -> PrivateKey:
    """
    Сгенерировать приватный ключ на основе запрошенного типа.

    Аргументы:
        key_type: 'rsa' или 'ecc'.
        key_size: 4096 для RSA, 384 для ECC.

    Возвращает:
        Сгенерированный приватный ключ.
    """
    if key_type == "rsa":
        return generate_rsa_key(key_size)
    else:
        return generate_ecc_key()


def encrypt_private_key(key: PrivateKey, passphrase: bytes) -> bytes:
    """
    Сериализовать приватный ключ в зашифрованный формат PKCS#8 PEM.

    Использует BestAvailableEncryption (AES-256-CBC + PBKDF2).

    Аргументы:
        key: Приватный ключ для шифрования.
        passphrase: Парольная фраза в виде байт.

    Возвращает:
        Закодированные в PEM байты зашифрованного приватного ключа.
    """
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )


def load_encrypted_key(pem_data: bytes, passphrase: bytes) -> PrivateKey:
    """
    Загрузить зашифрованный приватный ключ PEM из байт.

    Аргументы:
        pem_data: Закодированный в PEM зашифрованный приватный ключ.
        passphrase: Парольная фраза для расшифровки.

    Возвращает:
        Загруженный объект приватного ключа.
    """
    return serialization.load_pem_private_key(pem_data, password=passphrase)


def serialize_public_key_der(key: PrivateKey) -> bytes:
    """Получить закодированный в DER SubjectPublicKeyInfo для вычисления SKI."""
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def parse_distinguished_name(dn_string: str) -> Name:
    """
    Распарсить строку Отличительного Имени (Distinguished Name) в объект x509.Name.

    Поддерживает два распространенных формата:
      - Через слеш:       /CN=My Root CA/O=Demo/C=US
      - Через запятую:    CN=My Root CA,O=Demo,C=US

    Аргументы:
        dn_string: Строка DN для парсинга.

    Возвращает:
        x509.Name с распарсенными атрибутами.

    Вызывает исключения:
        ValueError: Если строка DN пуста или имеет неверный синтаксис.
    """
    if not dn_string or not dn_string.strip():
        raise ValueError("Отличительное имя (Distinguished Name) не должно быть пустым.")

    dn_string = dn_string.strip()

    # Определение формата и разбиение на части
    if dn_string.startswith("/"):
        # Формат через слеш: /CN=xxx/O=yyy
        parts = [p for p in dn_string.split("/") if p.strip()]
    else:
        # Формат через запятую: CN=xxx,O=yyy
        # Используем regex для разбиения по запятым, которые НЕ находятся внутри значений
        parts = [p.strip() for p in re.split(r",(?=\s*[A-Za-z]+=)", dn_string) if p.strip()]

    if not parts:
        raise ValueError(f"Неверный синтаксис DN: '{dn_string}'")

    attributes = []
    for part in parts:
        if "=" not in part:
            raise ValueError(f"Неверный формат DN (отсутствует '='): '{part}'")

        key, _, value = part.partition("=")
        key = key.strip().upper()
        value = value.strip()

        if not value:
            raise ValueError(f"Пустое значение для атрибута DN '{key}'")

        oid = _DN_OID_MAP.get(key)
        if oid is None:
            raise ValueError(
                f"Неизвестный атрибут DN '{key}'. "
                f"Поддерживаемые: {', '.join(sorted(_DN_OID_MAP.keys()))}"
            )

        attributes.append(NameAttribute(oid, value))

    return Name(attributes)


def get_signature_algorithm(key: PrivateKey) -> hashes.HashAlgorithm:
    """
    Возвращает подходящий алгоритм хеширования для подписи на основе типа ключа.

    RSA → SHA-256, ECC P-384 → SHA-384.
    """
    if isinstance(key, RSAPrivateKey):
        return hashes.SHA256()
    else:
        return hashes.SHA384()
