"""
OCSP-респондер для MicroPKI (RFC 6960).

Реализует парсинг DER-запросов, формирование подписанных ответов
(good/revoked/unknown), поддержку nonce и HTTP-транспорт (POST).
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from functools import partial
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp

from .crypto_utils import get_signature_algorithm
from .database import get_by_serial

logger = logging.getLogger("micropki")

# Маппинг строковых причин отзыва → флаги x509.ReasonFlags
_REASON_FLAG_MAP: dict[str, x509.ReasonFlags] = {
    "keyCompromise":        x509.ReasonFlags.key_compromise,
    "cACompromise":         x509.ReasonFlags.ca_compromise,
    "affiliationChanged":   x509.ReasonFlags.affiliation_changed,
    "superseded":           x509.ReasonFlags.superseded,
    "cessationOfOperation": x509.ReasonFlags.cessation_of_operation,
    "certificateHold":      x509.ReasonFlags.certificate_hold,
    "removeFromCRL":        x509.ReasonFlags.remove_from_crl,
    "privilegeWithdrawn":   x509.ReasonFlags.privilege_withdrawn,
    "aACompromise":         x509.ReasonFlags.aa_compromise,
}


def _make_stub_cert(serial: int, issuer_cert: x509.Certificate, key) -> x509.Certificate:
    """
    Создаёт минимальный сертификат-заглушку для формирования корректного certID
    в OCSP-ответе со статусом unknown. Заглушка нигде не сохраняется.
    """
    now = datetime.now(tz=timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(issuer_cert.subject)
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )


def process_ocsp_request(
    request_der: bytes,
    issuer_cert: x509.Certificate,
    responder_cert: x509.Certificate,
    responder_key,
    db_path: str,
    stub_key=None,
    next_update_hours: int = 1,
) -> bytes:
    """
    Обработать DER-закодированный OCSP-запрос и вернуть DER-закодированный ответ.

    При невалидном DER возвращает malformedRequest; при внутренней ошибке — internalError.
    """
    try:
        req = ocsp.load_der_ocsp_request(request_der)
    except Exception:
        resp = ocsp.OCSPResponseBuilder.build_unsuccessful(
            ocsp.OCSPResponseStatus.MALFORMED_REQUEST
        )
        return resp.public_bytes(serialization.Encoding.DER)

    try:
        return _build_signed_response(
            req=req,
            issuer_cert=issuer_cert,
            responder_cert=responder_cert,
            responder_key=responder_key,
            db_path=db_path,
            stub_key=stub_key,
            next_update_hours=next_update_hours,
        )
    except Exception as exc:
        logger.error("Ошибка формирования OCSP-ответа: %s", exc)
        resp = ocsp.OCSPResponseBuilder.build_unsuccessful(
            ocsp.OCSPResponseStatus.INTERNAL_ERROR
        )
        return resp.public_bytes(serialization.Encoding.DER)


def _build_signed_response(
    req: ocsp.OCSPRequest,
    issuer_cert: x509.Certificate,
    responder_cert: x509.Certificate,
    responder_key,
    db_path: str,
    stub_key=None,
    next_update_hours: int = 1,
) -> bytes:
    """Строит и подписывает OCSP-ответ по уже распарсенному запросу."""
    serial_hex = format(req.serial_number, "X")
    record = get_by_serial(db_path, serial_hex)

    now = datetime.now(tz=timezone.utc)
    next_update = now + timedelta(hours=next_update_hours)

    if record is None:
        # Серийный номер отсутствует в базе — статус unknown
        if stub_key is None:
            stub_key = ec.generate_private_key(ec.SECP256R1())
        cert_obj = _make_stub_cert(req.serial_number, issuer_cert, stub_key)
        cert_status = ocsp.OCSPCertStatus.UNKNOWN
        revocation_time = None
        revocation_reason = None
    elif record["status"] == "revoked":
        cert_obj = x509.load_pem_x509_certificate(record["cert_pem"].encode())
        cert_status = ocsp.OCSPCertStatus.REVOKED
        date_str = record.get("revocation_date") or record["created_at"]
        revocation_time = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
        revocation_reason = _REASON_FLAG_MAP.get(record.get("revocation_reason") or "")
    else:
        # valid или expired — с точки зрения OCSP текущий статус good
        cert_obj = x509.load_pem_x509_certificate(record["cert_pem"].encode())
        cert_status = ocsp.OCSPCertStatus.GOOD
        revocation_time = None
        revocation_reason = None

    builder = (
        ocsp.OCSPResponseBuilder()
        .add_response(
            cert=cert_obj,
            issuer=issuer_cert,
            algorithm=req.hash_algorithm,
            cert_status=cert_status,
            this_update=now,
            next_update=next_update,
            revocation_time=revocation_time,
            revocation_reason=revocation_reason,
        )
        .responder_id(ocsp.OCSPResponderEncoding.HASH, responder_cert)
    )

    # Зеркально отражаем nonce из запроса в ответе (RFC 6960 §4.4.1)
    try:
        nonce_ext = req.extensions.get_extension_for_class(x509.OCSPNonce)
        builder = builder.add_extension(
            x509.OCSPNonce(nonce_ext.value.nonce), critical=False
        )
    except x509.ExtensionNotFound:
        pass

    sign_hash = get_signature_algorithm(responder_key)
    response = builder.sign(responder_key, sign_hash)
    return response.public_bytes(serialization.Encoding.DER)


class OCSPHandler(BaseHTTPRequestHandler):
    """HTTP-обработчик OCSP-запросов (RFC 6960, HTTP-транспорт)."""

    def __init__(
        self,
        issuer_cert: x509.Certificate,
        responder_cert: x509.Certificate,
        responder_key,
        db_path: str,
        stub_key,
        *args,
        **kwargs,
    ):
        self.issuer_cert = issuer_cert
        self.responder_cert = responder_cert
        self.responder_key = responder_key
        self.db_path = db_path
        self.stub_key = stub_key
        super().__init__(*args, **kwargs)

    def log_message(self, format: str, *args) -> None:
        logger.info("[OCSP] %s %s", self.client_address[0], self.requestline)

    def do_POST(self) -> None:
        """Обрабатывает HTTP POST с OCSP-запросом."""
        content_type = self.headers.get("Content-Type", "")
        if content_type != "application/ocsp-request":
            self._send_plain_error(
                HTTPStatus.BAD_REQUEST,
                "Ожидается Content-Type: application/ocsp-request",
            )
            return

        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            self._send_plain_error(HTTPStatus.BAD_REQUEST, "Неверный Content-Length")
            return

        if length == 0:
            self._send_plain_error(HTTPStatus.BAD_REQUEST, "Пустое тело запроса")
            return

        body = self.rfile.read(length)
        response_der = process_ocsp_request(
            request_der=body,
            issuer_cert=self.issuer_cert,
            responder_cert=self.responder_cert,
            responder_key=self.responder_key,
            db_path=self.db_path,
            stub_key=self.stub_key,
        )

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/ocsp-response")
        self.send_header("Content-Length", str(len(response_der)))
        self.end_headers()
        self.wfile.write(response_der)

    def _send_plain_error(self, status: HTTPStatus, message: str) -> None:
        body = message.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run_ocsp_server(
    host: str,
    port: int,
    issuer_cert_path: str,
    responder_cert_path: str,
    responder_key_path: str,
    db_path: str,
) -> None:
    """
    Запустить HTTP OCSP-респондер.

    Аргументы:
        host: IP-адрес для привязки.
        port: TCP-порт.
        issuer_cert_path: Путь к сертификату CA, выпустившего проверяемые сертификаты.
        responder_cert_path: Путь к OCSP-сертификату подписи.
        responder_key_path: Путь к незашифрованному приватному ключу OCSP-респондера.
        db_path: Путь к базе данных сертификатов.
    """
    issuer_cert = x509.load_pem_x509_certificate(Path(issuer_cert_path).read_bytes())
    responder_cert = x509.load_pem_x509_certificate(Path(responder_cert_path).read_bytes())
    responder_key = serialization.load_pem_private_key(
        Path(responder_key_path).read_bytes(), password=None
    )
    # Один stub-ключ на всё время работы сервера — для ответов unknown
    stub_key = ec.generate_private_key(ec.SECP256R1())

    handler = partial(
        OCSPHandler, issuer_cert, responder_cert, responder_key, db_path, stub_key
    )
    server = HTTPServer((host, port), handler)
    logger.info("OCSP-респондер запущен на http://%s:%d", host, port)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("OCSP-сервер останавливается.")
    finally:
        server.server_close()
