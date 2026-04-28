"""
Проверка статуса отзыва сертификатов через CRL и OCSP для MicroPKI.
Реализует логику OCSP-первым с откатом на CRL (RFC 5280 / RFC 6960).
"""
from __future__ import annotations

import logging
import os
import urllib.request
import urllib.error
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509 import ocsp

logger = logging.getLogger("micropki")


@dataclass
class RevocationStatus:
    status: str  # "good" | "revoked" | "unknown"
    method: str  # "ocsp" | "crl" | "none"
    revocation_time: datetime | None = None
    reason: str | None = None
    detail: str = ""


def extract_ocsp_url(cert: x509.Certificate) -> str | None:
    """Извлекает URL OCSP-респондера из расширения AIA сертификата."""
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
        for access in aia.value:
            if access.access_method == x509.AuthorityInformationAccessOID.OCSP:
                return access.access_location.value
    except x509.ExtensionNotFound:
        pass
    return None


def extract_cdp_urls(cert: x509.Certificate) -> list[str]:
    """Извлекает URLs точек распространения CRL из расширения CDP."""
    try:
        cdp_ext = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
        urls = []
        for dp in cdp_ext.value:
            if dp.full_name:
                for name in dp.full_name:
                    if isinstance(name, x509.UniformResourceIdentifier):
                        urls.append(name.value)
        return urls
    except x509.ExtensionNotFound:
        return []


def _load_crl(source: str) -> x509.CertificateRevocationList:
    """Загружает CRL из файла (PEM/DER) или по HTTP(S) URL."""
    if source.startswith("http://") or source.startswith("https://"):
        try:
            resp = urllib.request.urlopen(source, timeout=10)
            data = resp.read()
        except Exception as exc:
            raise ValueError(f"Не удалось получить CRL по URL {source}: {exc}") from exc
    else:
        try:
            data = Path(source).read_bytes()
        except OSError as exc:
            raise ValueError(f"Не удалось прочитать файл CRL '{source}': {exc}") from exc

    try:
        return x509.load_pem_x509_crl(data)
    except Exception:
        pass
    try:
        return x509.load_der_x509_crl(data)
    except Exception as exc:
        raise ValueError(f"Не удалось разобрать CRL из '{source}': {exc}") from exc


def _verify_crl_signature(
    crl: x509.CertificateRevocationList,
    issuer_cert: x509.Certificate,
) -> bool:
    """Верифицирует подпись CRL открытым ключом издателя."""
    pub = issuer_cert.public_key()
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(
                crl.signature,
                crl.tbs_certlist_bytes,
                padding.PKCS1v15(),
                crl.signature_hash_algorithm,
            )
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(
                crl.signature,
                crl.tbs_certlist_bytes,
                ec.ECDSA(crl.signature_hash_algorithm),
            )
        else:
            return False
        return True
    except (InvalidSignature, Exception):
        return False


def check_crl(
    cert: x509.Certificate,
    issuer_cert: x509.Certificate,
    crl_source: str,
) -> RevocationStatus:
    """Проверяет статус сертификата по CRL (файл или URL)."""
    try:
        crl = _load_crl(crl_source)
    except ValueError as exc:
        logger.warning("Ошибка загрузки CRL: %s", exc)
        return RevocationStatus(status="unknown", method="crl", detail=str(exc))

    if not _verify_crl_signature(crl, issuer_cert):
        msg = f"Недействительная подпись CRL из '{crl_source}'"
        logger.warning(msg)
        return RevocationStatus(status="unknown", method="crl", detail=msg)

    now = datetime.now(tz=timezone.utc)
    if crl.next_update_utc and now > crl.next_update_utc:
        logger.warning(
            "CRL устарел: nextUpdate=%s (сейчас %s)",
            crl.next_update_utc.isoformat(), now.isoformat(),
        )

    revoked = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
    if revoked is not None:
        rev_time = revoked.revocation_date_utc
        reason: str | None = None
        try:
            r_ext = revoked.extensions.get_extension_for_class(x509.CRLReason)
            reason = r_ext.value.reason.name
        except x509.ExtensionNotFound:
            pass
        detail = f"Отозван {rev_time.isoformat()}, причина: {reason or 'unspecified'}"
        logger.info("CRL: сертификат отозван — serial=%s, %s", format(cert.serial_number, "X"), detail)
        return RevocationStatus(
            status="revoked", method="crl",
            revocation_time=rev_time, reason=reason, detail=detail,
        )

    logger.info("CRL: сертификат не отозван — serial=%s", format(cert.serial_number, "X"))
    return RevocationStatus(status="good", method="crl", detail="Серийный номер не найден в CRL")


def check_ocsp(
    cert: x509.Certificate,
    issuer_cert: x509.Certificate,
    ocsp_url: str | None = None,
) -> RevocationStatus:
    """Проверяет статус сертификата через OCSP-запрос."""
    url = ocsp_url or extract_ocsp_url(cert)
    if not url:
        return RevocationStatus(
            status="unknown", method="ocsp",
            detail="URL OCSP-респондера не найден в AIA и не указан вручную",
        )

    nonce = os.urandom(16)
    try:
        req = (
            ocsp.OCSPRequestBuilder()
            .add_certificate(cert, issuer_cert, hashes.SHA256())
            .add_extension(x509.OCSPNonce(nonce), critical=False)
            .build()
        )
        req_der = req.public_bytes(serialization.Encoding.DER)
    except Exception as exc:
        logger.warning("Ошибка формирования OCSP-запроса: %s", exc)
        return RevocationStatus(
            status="unknown", method="ocsp",
            detail=f"Ошибка формирования OCSP-запроса: {exc}",
        )

    try:
        http_req = urllib.request.Request(
            url,
            data=req_der,
            headers={"Content-Type": "application/ocsp-request"},
            method="POST",
        )
        http_resp = urllib.request.urlopen(http_req, timeout=10)
        resp_data = http_resp.read()
    except Exception as exc:
        logger.info("OCSP недоступен (%s): %s", url, exc)
        return RevocationStatus(
            status="unknown", method="ocsp",
            detail=f"OCSP-респондер недоступен ({url}): {exc}",
        )

    try:
        resp = ocsp.load_der_ocsp_response(resp_data)
    except Exception as exc:
        logger.warning("Ошибка разбора OCSP-ответа: %s", exc)
        return RevocationStatus(
            status="unknown", method="ocsp",
            detail=f"Ошибка разбора OCSP-ответа: {exc}",
        )

    if resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        msg = f"OCSP-ответ не успешен: {resp.response_status.name}"
        logger.warning(msg)
        return RevocationStatus(status="unknown", method="ocsp", detail=msg)

    # Проверка nonce
    try:
        resp_nonce = resp.extensions.get_extension_for_class(x509.OCSPNonce)
        if resp_nonce.value.nonce != nonce:
            msg = "Несоответствие nonce в OCSP-ответе"
            logger.warning(msg)
            return RevocationStatus(status="unknown", method="ocsp", detail=msg)
    except x509.ExtensionNotFound:
        pass

    cert_status = resp.certificate_status
    if cert_status == ocsp.OCSPCertStatus.GOOD:
        logger.info("OCSP: сертификат действителен — serial=%s", format(cert.serial_number, "X"))
        return RevocationStatus(status="good", method="ocsp", detail="OCSP: сертификат действителен")
    elif cert_status == ocsp.OCSPCertStatus.REVOKED:
        rev_time = resp.revocation_time_utc
        reason = resp.revocation_reason
        reason_str = reason.name if reason else "unspecified"
        detail = f"OCSP: отозван {rev_time.isoformat() if rev_time else 'неизвестно'}, причина: {reason_str}"
        logger.info(detail)
        return RevocationStatus(
            status="revoked", method="ocsp",
            revocation_time=rev_time, reason=reason_str, detail=detail,
        )
    else:
        return RevocationStatus(
            status="unknown", method="ocsp", detail="OCSP: статус unknown"
        )


def check_revocation(
    cert: x509.Certificate,
    issuer_cert: x509.Certificate,
    crl_source: str | None = None,
    ocsp_url: str | None = None,
) -> RevocationStatus:
    """
    Проверяет статус отзыва: OCSP первым, при неудаче — CRL.
    URL-адреса автоматически извлекаются из AIA/CDP расширений, если не указаны явно.
    """
    effective_ocsp = ocsp_url or extract_ocsp_url(cert)
    if effective_ocsp:
        result = check_ocsp(cert, issuer_cert, effective_ocsp)
        if result.status in ("good", "revoked"):
            return result
        logger.info(
            "OCSP недоступен или вернул unknown — переходим к CRL. Причина: %s",
            result.detail,
        )

    effective_crl = crl_source
    if not effective_crl:
        cdp_urls = extract_cdp_urls(cert)
        if cdp_urls:
            effective_crl = cdp_urls[0]
            logger.info("Используем CDP URL из сертификата: %s", effective_crl)

    if effective_crl:
        return check_crl(cert, issuer_cert, effective_crl)

    return RevocationStatus(
        status="unknown", method="none",
        detail="Нет доступных источников данных об отзыве (OCSP и CRL не настроены)",
    )
