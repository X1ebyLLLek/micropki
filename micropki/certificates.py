"""l
Генерация сертификатов X.509v3 для MicroPKI.

Обрабатывает создание Корневого CA, Промежуточного CA
и конечных сертификатов с соответствующими расширениями (KeyUsage,
BasicConstraints и т.д.).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import (
    AuthorityKeyIdentifier,
    BasicConstraints,
    CertificateBuilder,
    SubjectKeyIdentifier,
)

from .crypto_utils import PrivateKey, get_signature_algorithm
from .serial import generate_unique_serial
from .templates import CertificateTemplate

from cryptography.x509.oid import ExtendedKeyUsageOID


def build_root_ca_certificate(
    private_key: PrivateKey,
    subject: x509.Name,
    validity_days: int,
    db_path: str | None = None,
) -> x509.Certificate:
    """
    Создает самоподписанный X.509v3 сертификат Корневого CA.

    Серийный номер: уникальный 64-битный композитный (timestamp + CSPRNG).
    """
    now = datetime.now(tz=timezone.utc)
    serial_number = generate_unique_serial(db_path)
    public_key = private_key.public_key()
    ski = SubjectKeyIdentifier.from_public_key(public_key)

    builder = (
        CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(public_key)
        .serial_number(serial_number)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(ski, critical=False)
        .add_extension(
            AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski),
            critical=False,
        )
    )

    hash_algo = get_signature_algorithm(private_key)
    return builder.sign(private_key=private_key, algorithm=hash_algo)


def build_intermediate_ca_certificate(
    csr: x509.CertificateSigningRequest,
    root_key: PrivateKey,
    root_cert: x509.Certificate,
    validity_days: int,
    path_length: int = 0,
    db_path: str | None = None,
) -> x509.Certificate:
    """Подписывает CSR Промежуточного CA ключом Корневого CA."""
    now = datetime.now(tz=timezone.utc)
    serial_number = generate_unique_serial(db_path)
    intermediate_public_key = csr.public_key()
    ski = SubjectKeyIdentifier.from_public_key(intermediate_public_key)
    root_ski = root_cert.extensions.get_extension_for_class(SubjectKeyIdentifier)

    builder = (
        CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(root_cert.subject)
        .public_key(intermediate_public_key)
        .serial_number(serial_number)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(
            BasicConstraints(ca=True, path_length=path_length), critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(ski, critical=False)
        .add_extension(
            AuthorityKeyIdentifier.from_issuer_subject_key_identifier(root_ski.value),
            critical=False,
        )
    )

    hash_algo = get_signature_algorithm(root_key)
    return builder.sign(private_key=root_key, algorithm=hash_algo)


def _build_base_certificate(subject: x509.Name, issuer: x509.Name, public_key, validity_days: int):
    """Строитель X.509 общего назначения с субъектом, издателем, валидностью и публичным ключом."""


def build_end_entity_certificate(
    subject: x509.Name,
    public_key,
    ca_key: PrivateKey,
    ca_cert: x509.Certificate,
    template: CertificateTemplate,
    san_entries: list[x509.GeneralName] | None = None,
    validity_days: int = 365,
    db_path: str | None = None,
) -> x509.Certificate:
    """Создает конечный сертификат используя шаблон."""
    now = datetime.now(tz=timezone.utc)
    serial_number = generate_unique_serial(db_path)
    ski = SubjectKeyIdentifier.from_public_key(public_key)
    ca_ski = ca_cert.extensions.get_extension_for_class(SubjectKeyIdentifier)

    key_encipherment = template.key_encipherment
    if key_encipherment and isinstance(public_key, ec.EllipticCurvePublicKey):
        key_encipherment = False

    builder = (
        CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(serial_number)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=template.digital_signature,
                content_commitment=False,
                key_encipherment=key_encipherment,
                data_encipherment=False,
                key_agreement=template.key_agreement,
                key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(template.extended_key_usages), critical=False,
        )
        .add_extension(ski, critical=False)
        .add_extension(
            AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski.value),
            critical=False,
        )
    )

    if san_entries:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_entries), critical=False,
        )

    hash_algo = get_signature_algorithm(ca_key)
    return builder.sign(private_key=ca_key, algorithm=hash_algo)


def build_ocsp_signer_certificate(
    subject: x509.Name,
    public_key,
    ca_key: PrivateKey,
    ca_cert: x509.Certificate,
    validity_days: int = 365,
    db_path: str | None = None,
) -> x509.Certificate:
    """
    Создаёт OCSP-сертификат подписи (EKU = OCSPSigning, KeyUsage = digitalSignature).

    Включает расширение OCSPNoCheck (RFC 6960 §4.2.2.2.1), чтобы клиенты не
    проверяли статус самого OCSP-сертификата через OCSP (бесконечная рекурсия).
    """
    now = datetime.now(tz=timezone.utc)
    serial_number = generate_unique_serial(db_path)
    ski = SubjectKeyIdentifier.from_public_key(public_key)
    ca_ski = ca_cert.extensions.get_extension_for_class(SubjectKeyIdentifier)

    builder = (
        CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(serial_number)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]),
            critical=False,
        )
        .add_extension(ski, critical=False)
        .add_extension(
            AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski.value),
            critical=False,
        )
        .add_extension(x509.OCSPNoCheck(), critical=False)
    )

    hash_algo = get_signature_algorithm(ca_key)
    return builder.sign(private_key=ca_key, algorithm=hash_algo)


def certificate_to_pem(cert: x509.Certificate) -> bytes:
    """Сериализует сертификат X.509 в формат PEM."""
    return cert.public_bytes(serialization.Encoding.PEM)
