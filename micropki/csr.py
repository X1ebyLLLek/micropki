"""
Генерация и загрузка Certificate Signing Request (CSR) для MicroPKI.

Включает расширения BasicConstraints в зависимости от того,
предназначен ли запрос для CA или для конечного субъекта.
"""

from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import CertificateSigningRequest, CertificateSigningRequestBuilder

from .crypto_utils import PrivateKey, get_signature_algorithm


def generate_csr(
    private_key: PrivateKey,
    subject: x509.Name,
    is_ca: bool = False,
    path_length: int | None = None,
) -> CertificateSigningRequest:
    """
    Генерирует PKCS#10 Certificate Signing Request (CSR).

    Аргументы:
        private_key: Приватный ключ для подписи CSR.
        subject: Отличительное имя (Distinguished Name) субъекта.
        is_ca: Если True, добавляет BasicConstraints cCA=True.
        path_length: Ограничение длины пути для CA (игнорируется, если is_ca=False).

    Возвращает:
        Сгенерированный X.509 CSR.
    """
    builder = CertificateSigningRequestBuilder().subject_name(subject)

    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length),
            critical=True,
        )

    hash_algo = get_signature_algorithm(private_key)
    return builder.sign(private_key, hash_algo)


def load_csr_from_pem(pem_data: bytes) -> CertificateSigningRequest:
    """
    Загружает CSR из PEM закодированных байт.

    Аргументы:
        pem_data: Данные CSR в формате PEM.

    Возвращает:
        Загруженный объект CSR.

    Вызывает исключения:
        ValueError: Если данные не являются валидным CSR.
    """
    csr = x509.load_pem_x509_csr(pem_data)
    if not csr.is_signature_valid:
        raise ValueError("Подпись CSR недействительна.")
    return csr


def csr_to_pem(csr: CertificateSigningRequest) -> bytes:
    """Сериализует CSR в формат PEM."""
    from cryptography.hazmat.primitives.serialization import Encoding

    return csr.public_bytes(Encoding.PEM)
