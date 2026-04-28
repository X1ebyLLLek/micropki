"""
Клиентские операции MicroPKI: генерация CSR, запрос сертификата через API,
проверка цепочки и статуса отзыва.
"""
from __future__ import annotations

import logging
import os
import platform
import stat
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from .crypto_utils import get_signature_algorithm, parse_distinguished_name
from .csr import csr_to_pem
from .revocation_check import RevocationStatus, check_crl, check_ocsp, check_revocation
from .templates import parse_san_entries
from .validation import ValidationResult, build_chain, validate_chain

logger = logging.getLogger("micropki")


# ---- Генерация CSR ----

def gen_csr(
    subject: str,
    key_type: str,
    key_size: int,
    san_strings: list[str] | None,
    out_key: str,
    out_csr: str,
) -> tuple[str, str]:
    """
    Генерирует приватный ключ и PKCS#10 CSR.
    Ключ сохраняется НЕЗАШИФРОВАННЫМ (выводится предупреждение).

    Возвращает (путь_к_ключу, путь_к_csr).
    """
    if key_type == "rsa":
        if key_size not in (2048, 4096):
            raise ValueError(f"Размер RSA-ключа должен быть 2048 или 4096, получено {key_size}")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    elif key_type == "ecc":
        if key_size not in (256, 384):
            raise ValueError(f"Размер ECC-ключа должен быть 256 или 384, получено {key_size}")
        curve = ec.SECP256R1() if key_size == 256 else ec.SECP384R1()
        private_key = ec.generate_private_key(curve)
    else:
        raise ValueError(f"Неизвестный тип ключа: '{key_type}'. Используйте 'rsa' или 'ecc'")

    dn = parse_distinguished_name(subject)
    builder = x509.CertificateSigningRequestBuilder().subject_name(dn)

    if san_strings:
        san_entries = parse_san_entries(san_strings)
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_entries), critical=False
        )

    hash_algo = get_signature_algorithm(private_key)
    csr = builder.sign(private_key, hash_algo)

    key_path = Path(out_key)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path.write_bytes(key_pem)
    if platform.system() != "Windows":
        os.chmod(str(key_path), stat.S_IRUSR | stat.S_IWUSR)
    logger.warning(
        "ВНИМАНИЕ: приватный ключ сохранён НЕЗАШИФРОВАННЫМ в '%s'. "
        "Обеспечьте защиту файла.", key_path
    )

    csr_path = Path(out_csr)
    csr_path.parent.mkdir(parents=True, exist_ok=True)
    csr_path.write_bytes(csr_to_pem(csr))
    logger.info("CSR сохранён: %s", csr_path)

    return str(key_path), str(csr_path)


# ---- Запрос сертификата через API ----

def request_cert(
    csr_path: str,
    template: str,
    ca_url: str,
    out_cert: str,
    api_key: str | None = None,
) -> str:
    """
    Отправляет CSR на POST /request-cert репозитория и сохраняет полученный сертификат.

    Возвращает путь к сохранённому сертификату.
    """
    csr_pem = Path(csr_path).read_bytes()
    url = f"{ca_url.rstrip('/')}/request-cert?template={template}"

    headers: dict[str, str] = {"Content-Type": "application/x-pem-file"}
    if api_key:
        headers["X-API-Key"] = api_key

    try:
        req = urllib.request.Request(url, data=csr_pem, headers=headers, method="POST")
        resp = urllib.request.urlopen(req)
        cert_pem = resp.read()
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code} от сервера: {body}") from exc
    except Exception as exc:
        raise RuntimeError(f"Ошибка запроса сертификата: {exc}") from exc

    cert_file = Path(out_cert)
    cert_file.parent.mkdir(parents=True, exist_ok=True)
    cert_file.write_bytes(cert_pem)
    logger.info("Сертификат получен от '%s' и сохранён: %s", ca_url, cert_file)
    return str(cert_file)


# ---- Проверка цепочки ----

def validate_cert(
    cert_path: str,
    untrusted_paths: list[str],
    trusted_path: str,
    crl_source: str | None = None,
    check_ocsp_flag: bool = False,
    mode: str = "full",
    validation_time: datetime | None = None,
) -> ValidationResult:
    """
    Проверяет цепочку сертификатов.

    mode='chain' — только подписи/срок; mode='full' — включает проверку отзыва.
    """
    leaf = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())

    untrusted: list[x509.Certificate] = []
    for p in untrusted_paths:
        untrusted.extend(_load_pem_bundle(Path(p).read_bytes()))

    trusted = _load_pem_bundle(Path(trusted_path).read_bytes())

    chain = build_chain(leaf, untrusted, trusted)
    if chain is None:
        result = ValidationResult(valid=False)
        result.add_step(
            "построение цепочки", False,
            "Не удалось построить цепочку до доверенного корня. "
            "Убедитесь, что промежуточный CA передан через --untrusted.",
        )
        return result

    logger.info(
        "Цепочка построена: %s",
        " → ".join(c.subject.rfc4514_string() for c in chain),
    )
    result = validate_chain(chain, validation_time=validation_time)

    if mode == "full" and (crl_source or check_ocsp_flag) and len(chain) >= 2:
        issuer = chain[1]
        if check_ocsp_flag:
            rev = check_revocation(leaf, issuer, crl_source, None)
        else:
            rev = check_crl(leaf, issuer, crl_source)  # type: ignore[arg-type]

        rev_ok = rev.status != "revoked"
        result.add_step("проверка отзыва", rev_ok, rev.detail)
        if not rev_ok:
            result.valid = False

    return result


# ---- Проверка статуса отзыва ----

def check_cert_status(
    cert_path: str,
    ca_cert_path: str,
    crl_source: str | None = None,
    ocsp_url: str | None = None,
) -> RevocationStatus:
    """
    Проверяет статус отзыва сертификата.
    OCSP первым (из AIA или явного URL), затем откат на CRL.
    """
    cert = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
    issuer = x509.load_pem_x509_certificate(Path(ca_cert_path).read_bytes())
    return check_revocation(cert, issuer, crl_source, ocsp_url)


# ---- Вспомогательные ----

def _load_pem_bundle(data: bytes) -> list[x509.Certificate]:
    """Загружает один или несколько X.509 сертификатов из PEM-данных."""
    certs: list[x509.Certificate] = []
    marker = b"-----BEGIN CERTIFICATE-----"
    end_marker = b"-----END CERTIFICATE-----"
    parts = data.split(marker)
    for part in parts[1:]:
        end_idx = part.find(end_marker)
        if end_idx == -1:
            continue
        pem = marker + part[: end_idx + len(end_marker)] + b"\n"
        try:
            certs.append(x509.load_pem_x509_certificate(pem))
        except Exception:
            pass
    return certs
