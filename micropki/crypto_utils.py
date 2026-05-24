"""
Криптографические утилиты для MicroPKI.

Обрабатывает генерацию ключей (RSA-4096 / ECC P-384), шифрование/расшифрование PEM,
парсинг Отличительных Имен (Distinguished Name), а также подпись и верификацию файлов.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Union

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
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


def sign_file(key_path: str | Path, file_path: str | Path, out_path: str | Path) -> None:
    """
    Подписывает файл приватным ключом (RSA PKCS#1v15 SHA-256 или ECDSA SHA-256).

    Подпись сохраняется как бинарный detached-файл (DER-байты подписи).

    Аргументы:
        key_path:  путь к незашифрованному PEM-ключу
        file_path: путь к подписываемому файлу
        out_path:  путь для сохранения файла подписи (.sig)

    Вызывает исключения:
        ValueError: если ключ не поддерживается
        FileNotFoundError: если файлы не найдены
    """
    key_pem = Path(key_path).read_bytes()
    # Незашифрованный ключ — password=None
    private_key = serialization.load_pem_private_key(key_pem, password=None)

    data = Path(file_path).read_bytes()

    if isinstance(private_key, RSAPrivateKey):
        signature = private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    elif isinstance(private_key, EllipticCurvePrivateKey):
        signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    else:
        raise ValueError(f"Неподдерживаемый тип ключа: {type(private_key).__name__}")

    Path(out_path).write_bytes(signature)


def verify_file_signature(
    cert_path: str | Path,
    file_path: str | Path,
    sig_path: str | Path,
    trusted_path: str | Path,
) -> tuple[bool, str]:
    """
    Проверяет detached-подпись файла.

    Дополнительно проверяет цепочку сертификата до доверенного корня.

    Аргументы:
        cert_path:    путь к сертификату подписанта (PEM)
        file_path:    путь к файлу, подпись которого проверяем
        sig_path:     путь к файлу подписи (бинарный .sig)
        trusted_path: PEM-файл с доверенными корневыми сертификатами (bundle)

    Возвращает:
        (True, "") если всё ок
        (False, "причина") при ошибке
    """
    # Загружаем сертификат подписанта
    try:
        cert_pem = Path(cert_path).read_bytes()
        cert = x509.load_pem_x509_certificate(cert_pem)
    except Exception as e:
        return False, f"Не удалось загрузить сертификат: {e}"

    # Проверяем срок действия сертификата
    from datetime import datetime, timezone
    now = datetime.now(tz=timezone.utc)
    if now < cert.not_valid_before_utc:
        return False, f"Сертификат ещё не действителен (notBefore={cert.not_valid_before_utc})"
    if now > cert.not_valid_after_utc:
        return False, f"Сертификат истёк (notAfter={cert.not_valid_after_utc})"

    # Простая проверка цепочки до доверенного корня
    trusted_pem_data = Path(trusted_path).read_bytes()
    # Разбиваем bundle на отдельные PEM-блоки
    trusted_certs: list[x509.Certificate] = []
    pem_blocks = _split_pem_bundle(trusted_pem_data)
    for block in pem_blocks:
        try:
            trusted_certs.append(x509.load_pem_x509_certificate(block))
        except Exception:
            continue

    if not trusted_certs:
        return False, "Нет доверенных сертификатов в bundle"

    # Ищем хоть один доверенный сертификат, который подписал наш cert
    chain_ok = False
    cert_issuer = cert.issuer.rfc4514_string()
    for tc in trusted_certs:
        if tc.subject.rfc4514_string() == cert_issuer:
            pub = tc.public_key()
            try:
                if isinstance(pub, rsa.RSAPublicKey):
                    pub.verify(cert.signature, cert.tbs_certificate_bytes,
                               padding.PKCS1v15(), cert.signature_hash_algorithm)
                elif isinstance(pub, ec.EllipticCurvePublicKey):
                    pub.verify(cert.signature, cert.tbs_certificate_bytes,
                               ec.ECDSA(cert.signature_hash_algorithm))
                chain_ok = True
                break
            except InvalidSignature:
                continue

    if not chain_ok:
        return False, "Сертификат не прошёл проверку цепочки до доверенного корня"

    # Проверяем саму подпись файла
    data = Path(file_path).read_bytes()
    signature = Path(sig_path).read_bytes()
    pub_key = cert.public_key()

    try:
        if isinstance(pub_key, rsa.RSAPublicKey):
            pub_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            pub_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        else:
            return False, f"Неподдерживаемый тип публичного ключа: {type(pub_key).__name__}"
    except InvalidSignature:
        return False, "Подпись недействительна (файл изменён или неверный ключ)"

    return True, ""


def _split_pem_bundle(pem_data: bytes) -> list[bytes]:
    """Разбивает PEM-bundle с несколькими сертификатами на список отдельных PEM-блоков."""
    blocks = []
    current: list[bytes] = []
    for line in pem_data.splitlines(keepends=True):
        if line.strip().startswith(b"-----BEGIN"):
            current = [line]
        elif line.strip().startswith(b"-----END") and current:
            current.append(line)
            blocks.append(b"".join(current))
            current = []
        elif current:
            current.append(line)
    return blocks
