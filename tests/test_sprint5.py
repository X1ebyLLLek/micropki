"""
Интеграционные тесты для Спринта 5:
  - OCSP-ответы: статусы good / revoked / unknown
  - Поддержка nonce
  - Верификация подписи ответа
  - Отказ на невалидный запрос
  - HTTP-транспорт OCSP
"""

import os
import socket
import threading
import time
import urllib.error
import urllib.request
from functools import partial
from http.server import HTTPServer

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.x509 import ocsp

from micropki.ca import init_ca, issue_cert, issue_intermediate, issue_ocsp_cert
from micropki.database import get_by_serial, init_db, list_certificates
from micropki.logger import setup_logger
from micropki.ocsp_responder import OCSPHandler, process_ocsp_request
from micropki.revocation import revoke_certificate


@pytest.fixture(autouse=True)
def _setup_logger():
    setup_logger()


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "test.db")
    init_db(path)
    return path


@pytest.fixture
def root_pass():
    return b"test-root-pass"


@pytest.fixture
def inter_pass():
    return b"test-inter-pass"


@pytest.fixture
def full_pki(tmp_path, db_path, root_pass, inter_pass):
    """Полная PKI: корневой + промежуточный CA."""
    out_dir = str(tmp_path / "pki")
    init_ca(
        subject="/CN=Sprint5 Root CA/O=TestOrg",
        key_type="rsa", key_size=4096,
        passphrase=root_pass,
        out_dir=out_dir, validity_days=3650,
        db_path=db_path,
    )
    issue_intermediate(
        root_cert_path=str(tmp_path / "pki" / "certs" / "ca.cert.pem"),
        root_key_path=str(tmp_path / "pki" / "private" / "ca.key.pem"),
        root_passphrase=root_pass,
        subject="CN=Sprint5 Intermediate CA,O=TestOrg",
        key_type="rsa", key_size=4096,
        passphrase=inter_pass,
        out_dir=out_dir, validity_days=1825,
        db_path=db_path,
    )
    return tmp_path / "pki"


@pytest.fixture
def ocsp_setup(full_pki, db_path, inter_pass):
    """Выпускает OCSP-сертификат и возвращает словарь со всем необходимым для тестов."""
    cert_path, key_path = issue_ocsp_cert(
        ca_cert_path=str(full_pki / "certs" / "intermediate.cert.pem"),
        ca_key_path=str(full_pki / "private" / "intermediate.key.pem"),
        ca_passphrase=inter_pass,
        subject="/CN=Sprint5 OCSP Responder/O=TestOrg",
        out_dir=str(full_pki),
        validity_days=365,
        db_path=db_path,
    )
    issuer_cert = x509.load_pem_x509_certificate(
        (full_pki / "certs" / "intermediate.cert.pem").read_bytes()
    )
    responder_cert = x509.load_pem_x509_certificate(
        (full_pki / "certs" / "ocsp.cert.pem").read_bytes()
    )
    responder_key = serialization.load_pem_private_key(
        (full_pki / "private" / "ocsp.key.pem").read_bytes(), password=None
    )
    return {
        "issuer_cert": issuer_cert,
        "responder_cert": responder_cert,
        "responder_key": responder_key,
        "db_path": db_path,
        "full_pki": full_pki,
    }


def _issue_leaf(full_pki, db_path, inter_pass, cn):
    """Выпустить клиентский сертификат, вернуть запись из БД и объект x509.Certificate."""
    issue_cert(
        ca_cert_path=str(full_pki / "certs" / "intermediate.cert.pem"),
        ca_key_path=str(full_pki / "private" / "intermediate.key.pem"),
        ca_passphrase=inter_pass,
        template_name="client",
        subject=f"/CN={cn}",
        san_strings=None,
        out_dir=str(full_pki / "certs"),
        db_path=db_path,
    )
    certs = list_certificates(db_path)
    record = next(c for c in certs if cn in c["subject"])
    cert_obj = x509.load_pem_x509_certificate(record["cert_pem"].encode())
    return record, cert_obj


def _build_ocsp_req(leaf_cert, issuer_cert, nonce: bytes | None = None) -> bytes:
    """Сформировать DER OCSP-запрос."""
    builder = (
        ocsp.OCSPRequestBuilder()
        .add_certificate(leaf_cert, issuer_cert, hashes.SHA256())
    )
    if nonce is not None:
        builder = builder.add_extension(x509.OCSPNonce(nonce), critical=False)
    return builder.build().public_bytes(serialization.Encoding.DER)


# ─────────────────────────────────────────────
#  Тесты выпуска OCSP-сертификата
# ─────────────────────────────────────────────

class TestOCSPCertIssuance:

    def test_файлы_создаются(self, full_pki, db_path, inter_pass):
        issue_ocsp_cert(
            ca_cert_path=str(full_pki / "certs" / "intermediate.cert.pem"),
            ca_key_path=str(full_pki / "private" / "intermediate.key.pem"),
            ca_passphrase=inter_pass,
            subject="/CN=OCSP Test/O=TestOrg",
            out_dir=str(full_pki),
            db_path=db_path,
        )
        assert (full_pki / "certs" / "ocsp.cert.pem").exists()
        assert (full_pki / "private" / "ocsp.key.pem").exists()

    def test_eku_содержит_ocsp_signing(self, full_pki, db_path, inter_pass):
        issue_ocsp_cert(
            ca_cert_path=str(full_pki / "certs" / "intermediate.cert.pem"),
            ca_key_path=str(full_pki / "private" / "intermediate.key.pem"),
            ca_passphrase=inter_pass,
            subject="/CN=OCSP EKU Check/O=TestOrg",
            out_dir=str(full_pki),
            db_path=db_path,
        )
        cert = x509.load_pem_x509_certificate(
            (full_pki / "certs" / "ocsp.cert.pem").read_bytes()
        )
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        assert x509.oid.ExtendedKeyUsageOID.OCSP_SIGNING in eku.value

    def test_key_usage_только_digital_signature(self, full_pki, db_path, inter_pass):
        issue_ocsp_cert(
            ca_cert_path=str(full_pki / "certs" / "intermediate.cert.pem"),
            ca_key_path=str(full_pki / "private" / "intermediate.key.pem"),
            ca_passphrase=inter_pass,
            subject="/CN=OCSP KU Check/O=TestOrg",
            out_dir=str(full_pki),
            db_path=db_path,
        )
        cert = x509.load_pem_x509_certificate(
            (full_pki / "certs" / "ocsp.cert.pem").read_bytes()
        )
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku.value.digital_signature is True
        assert ku.value.key_encipherment is False
        assert ku.value.key_cert_sign is False

    def test_ключ_незашифрован(self, full_pki, db_path, inter_pass):
        _, key_path = issue_ocsp_cert(
            ca_cert_path=str(full_pki / "certs" / "intermediate.cert.pem"),
            ca_key_path=str(full_pki / "private" / "intermediate.key.pem"),
            ca_passphrase=inter_pass,
            subject="/CN=OCSP Key Check/O=TestOrg",
            out_dir=str(full_pki),
            db_path=db_path,
        )
        # Должен загружаться без пароля
        key = serialization.load_pem_private_key(
            open(key_path, "rb").read(), password=None
        )
        assert key is not None

    def test_сертификат_в_базе(self, full_pki, db_path, inter_pass):
        issue_ocsp_cert(
            ca_cert_path=str(full_pki / "certs" / "intermediate.cert.pem"),
            ca_key_path=str(full_pki / "private" / "intermediate.key.pem"),
            ca_passphrase=inter_pass,
            subject="/CN=OCSP DB Check/O=TestOrg",
            out_dir=str(full_pki),
            db_path=db_path,
        )
        cert = x509.load_pem_x509_certificate(
            (full_pki / "certs" / "ocsp.cert.pem").read_bytes()
        )
        serial_hex = format(cert.serial_number, "X")
        record = get_by_serial(db_path, serial_hex)
        assert record is not None
        assert record["status"] == "valid"


# ─────────────────────────────────────────────
#  Тесты статусов OCSP-ответов
# ─────────────────────────────────────────────

class TestOCSPStatus:

    def test_good_статус(self, ocsp_setup, inter_pass):
        record, leaf_cert = _issue_leaf(
            ocsp_setup["full_pki"], ocsp_setup["db_path"], inter_pass, "ocsp-good.local"
        )
        req_der = _build_ocsp_req(leaf_cert, ocsp_setup["issuer_cert"])
        resp_der = process_ocsp_request(
            request_der=req_der,
            issuer_cert=ocsp_setup["issuer_cert"],
            responder_cert=ocsp_setup["responder_cert"],
            responder_key=ocsp_setup["responder_key"],
            db_path=ocsp_setup["db_path"],
        )
        resp = ocsp.load_der_ocsp_response(resp_der)
        assert resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
        assert resp.certificate_status == ocsp.OCSPCertStatus.GOOD

    def test_revoked_статус(self, ocsp_setup, inter_pass):
        record, leaf_cert = _issue_leaf(
            ocsp_setup["full_pki"], ocsp_setup["db_path"], inter_pass, "ocsp-revoked.local"
        )
        revoke_certificate(
            ocsp_setup["db_path"], record["serial_hex"], reason="keyCompromise"
        )
        req_der = _build_ocsp_req(leaf_cert, ocsp_setup["issuer_cert"])
        resp_der = process_ocsp_request(
            request_der=req_der,
            issuer_cert=ocsp_setup["issuer_cert"],
            responder_cert=ocsp_setup["responder_cert"],
            responder_key=ocsp_setup["responder_key"],
            db_path=ocsp_setup["db_path"],
        )
        resp = ocsp.load_der_ocsp_response(resp_der)
        assert resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
        assert resp.certificate_status == ocsp.OCSPCertStatus.REVOKED

    def test_revoked_время_отзыва_присутствует(self, ocsp_setup, inter_pass):
        record, leaf_cert = _issue_leaf(
            ocsp_setup["full_pki"], ocsp_setup["db_path"], inter_pass, "ocsp-rev-time.local"
        )
        revoke_certificate(ocsp_setup["db_path"], record["serial_hex"])
        req_der = _build_ocsp_req(leaf_cert, ocsp_setup["issuer_cert"])
        resp_der = process_ocsp_request(
            request_der=req_der,
            issuer_cert=ocsp_setup["issuer_cert"],
            responder_cert=ocsp_setup["responder_cert"],
            responder_key=ocsp_setup["responder_key"],
            db_path=ocsp_setup["db_path"],
        )
        resp = ocsp.load_der_ocsp_response(resp_der)
        assert resp.revocation_time_utc is not None

    def test_unknown_статус(self, ocsp_setup):
        """Серийный номер не в базе → unknown."""
        # Используем подлинный CA-сертификат как cert объект для построения запроса.
        # Создаём запрос от имени "фиктивного" сертификата с произвольным серийным.
        fake_serial = 0xDEADBEEFCAFE0001

        # Чтобы построить OCSP-запрос, нужен x509.Certificate с нужным серийником.
        # Используем issuer_cert как заготовку и строим запрос вручную через OCSPRequestBuilder.
        # Для этого создадим временный cert с нужным серийником.
        stub_key = ec.generate_private_key(ec.SECP256R1())
        from datetime import datetime, timedelta, timezone
        now = datetime.now(tz=timezone.utc)
        stub_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "unknown")]))
            .issuer_name(ocsp_setup["issuer_cert"].subject)
            .public_key(stub_key.public_key())
            .serial_number(fake_serial)
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(stub_key, hashes.SHA256())
        )
        req_der = _build_ocsp_req(stub_cert, ocsp_setup["issuer_cert"])
        resp_der = process_ocsp_request(
            request_der=req_der,
            issuer_cert=ocsp_setup["issuer_cert"],
            responder_cert=ocsp_setup["responder_cert"],
            responder_key=ocsp_setup["responder_key"],
            db_path=ocsp_setup["db_path"],
        )
        resp = ocsp.load_der_ocsp_response(resp_der)
        assert resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
        assert resp.certificate_status == ocsp.OCSPCertStatus.UNKNOWN

    def test_serial_number_в_ответе_совпадает_с_запросом(self, ocsp_setup, inter_pass):
        record, leaf_cert = _issue_leaf(
            ocsp_setup["full_pki"], ocsp_setup["db_path"], inter_pass, "ocsp-serial.local"
        )
        req_der = _build_ocsp_req(leaf_cert, ocsp_setup["issuer_cert"])
        resp_der = process_ocsp_request(
            request_der=req_der,
            issuer_cert=ocsp_setup["issuer_cert"],
            responder_cert=ocsp_setup["responder_cert"],
            responder_key=ocsp_setup["responder_key"],
            db_path=ocsp_setup["db_path"],
        )
        resp = ocsp.load_der_ocsp_response(resp_der)
        assert resp.serial_number == leaf_cert.serial_number


# ─────────────────────────────────────────────
#  Тесты nonce
# ─────────────────────────────────────────────

class TestOCSPNonce:

    def test_nonce_отражается_в_ответе(self, ocsp_setup, inter_pass):
        record, leaf_cert = _issue_leaf(
            ocsp_setup["full_pki"], ocsp_setup["db_path"], inter_pass, "ocsp-nonce.local"
        )
        nonce = os.urandom(16)
        req_der = _build_ocsp_req(leaf_cert, ocsp_setup["issuer_cert"], nonce=nonce)
        resp_der = process_ocsp_request(
            request_der=req_der,
            issuer_cert=ocsp_setup["issuer_cert"],
            responder_cert=ocsp_setup["responder_cert"],
            responder_key=ocsp_setup["responder_key"],
            db_path=ocsp_setup["db_path"],
        )
        resp = ocsp.load_der_ocsp_response(resp_der)
        nonce_ext = resp.extensions.get_extension_for_class(x509.OCSPNonce)
        assert nonce_ext.value.nonce == nonce

    def test_без_nonce_в_запросе_нет_nonce_в_ответе(self, ocsp_setup, inter_pass):
        record, leaf_cert = _issue_leaf(
            ocsp_setup["full_pki"], ocsp_setup["db_path"], inter_pass, "ocsp-no-nonce.local"
        )
        req_der = _build_ocsp_req(leaf_cert, ocsp_setup["issuer_cert"])
        resp_der = process_ocsp_request(
            request_der=req_der,
            issuer_cert=ocsp_setup["issuer_cert"],
            responder_cert=ocsp_setup["responder_cert"],
            responder_key=ocsp_setup["responder_key"],
            db_path=ocsp_setup["db_path"],
        )
        resp = ocsp.load_der_ocsp_response(resp_der)
        with pytest.raises(x509.ExtensionNotFound):
            resp.extensions.get_extension_for_class(x509.OCSPNonce)

    def test_разные_nonce_дают_разные_ответы(self, ocsp_setup, inter_pass):
        record, leaf_cert = _issue_leaf(
            ocsp_setup["full_pki"], ocsp_setup["db_path"], inter_pass, "ocsp-nonce2.local"
        )
        nonce1 = os.urandom(16)
        nonce2 = os.urandom(16)
        resp1_der = process_ocsp_request(
            request_der=_build_ocsp_req(leaf_cert, ocsp_setup["issuer_cert"], nonce=nonce1),
            **{k: ocsp_setup[k] for k in ("issuer_cert", "responder_cert", "responder_key", "db_path")},
        )
        resp2_der = process_ocsp_request(
            request_der=_build_ocsp_req(leaf_cert, ocsp_setup["issuer_cert"], nonce=nonce2),
            **{k: ocsp_setup[k] for k in ("issuer_cert", "responder_cert", "responder_key", "db_path")},
        )
        r1 = ocsp.load_der_ocsp_response(resp1_der)
        r2 = ocsp.load_der_ocsp_response(resp2_der)
        n1 = r1.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce
        n2 = r2.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce
        assert n1 == nonce1
        assert n2 == nonce2
        assert n1 != n2


# ─────────────────────────────────────────────
#  Тест верификации подписи
# ─────────────────────────────────────────────

class TestOCSPSignature:

    def test_подпись_ответа_верифицируется_ключом_ocsp(self, ocsp_setup, inter_pass):
        record, leaf_cert = _issue_leaf(
            ocsp_setup["full_pki"], ocsp_setup["db_path"], inter_pass, "ocsp-sig.local"
        )
        req_der = _build_ocsp_req(leaf_cert, ocsp_setup["issuer_cert"])
        resp_der = process_ocsp_request(
            request_der=req_der,
            issuer_cert=ocsp_setup["issuer_cert"],
            responder_cert=ocsp_setup["responder_cert"],
            responder_key=ocsp_setup["responder_key"],
            db_path=ocsp_setup["db_path"],
        )
        resp = ocsp.load_der_ocsp_response(resp_der)
        assert resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL

        pub = ocsp_setup["responder_cert"].public_key()
        # Верификация без исключения означает корректную подпись
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(
                resp.signature,
                resp.tbs_response_bytes,
                padding.PKCS1v15(),
                resp.signature_hash_algorithm,
            )
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(
                resp.signature,
                resp.tbs_response_bytes,
                ec.ECDSA(resp.signature_hash_algorithm),
            )

    def test_ответ_подписан_не_чужим_ключом(self, ocsp_setup, inter_pass):
        """Проверяем, что верификация чужим ключом падает."""
        record, leaf_cert = _issue_leaf(
            ocsp_setup["full_pki"], ocsp_setup["db_path"], inter_pass, "ocsp-wrong-sig.local"
        )
        req_der = _build_ocsp_req(leaf_cert, ocsp_setup["issuer_cert"])
        resp_der = process_ocsp_request(
            request_der=req_der,
            issuer_cert=ocsp_setup["issuer_cert"],
            responder_cert=ocsp_setup["responder_cert"],
            responder_key=ocsp_setup["responder_key"],
            db_path=ocsp_setup["db_path"],
        )
        resp = ocsp.load_der_ocsp_response(resp_der)
        wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with pytest.raises(Exception):
            wrong_key.public_key().verify(
                resp.signature,
                resp.tbs_response_bytes,
                padding.PKCS1v15(),
                resp.signature_hash_algorithm,
            )


# ─────────────────────────────────────────────
#  Тест отказа на кривой запрос
# ─────────────────────────────────────────────

class TestOCSPBadRequest:

    def test_мусор_возвращает_malformed_request(self, ocsp_setup):
        resp_der = process_ocsp_request(
            request_der=b"this is definitely not a valid DER OCSP request",
            issuer_cert=ocsp_setup["issuer_cert"],
            responder_cert=ocsp_setup["responder_cert"],
            responder_key=ocsp_setup["responder_key"],
            db_path=ocsp_setup["db_path"],
        )
        resp = ocsp.load_der_ocsp_response(resp_der)
        assert resp.response_status == ocsp.OCSPResponseStatus.MALFORMED_REQUEST

    def test_пустые_байты_возвращают_malformed_request(self, ocsp_setup):
        resp_der = process_ocsp_request(
            request_der=b"",
            issuer_cert=ocsp_setup["issuer_cert"],
            responder_cert=ocsp_setup["responder_cert"],
            responder_key=ocsp_setup["responder_key"],
            db_path=ocsp_setup["db_path"],
        )
        resp = ocsp.load_der_ocsp_response(resp_der)
        assert resp.response_status == ocsp.OCSPResponseStatus.MALFORMED_REQUEST

    def test_der_crl_не_является_ocsp_запросом(self, ocsp_setup):
        """Передаём DER, который не является OCSPRequest (например, сертификат)."""
        cert_pem = (ocsp_setup["full_pki"] / "certs" / "intermediate.cert.pem").read_bytes()
        cert_der = x509.load_pem_x509_certificate(cert_pem).public_bytes(
            serialization.Encoding.DER
        )
        resp_der = process_ocsp_request(
            request_der=cert_der,
            issuer_cert=ocsp_setup["issuer_cert"],
            responder_cert=ocsp_setup["responder_cert"],
            responder_key=ocsp_setup["responder_key"],
            db_path=ocsp_setup["db_path"],
        )
        resp = ocsp.load_der_ocsp_response(resp_der)
        assert resp.response_status == ocsp.OCSPResponseStatus.MALFORMED_REQUEST


# ─────────────────────────────────────────────
#  Тесты HTTP-транспорта
# ─────────────────────────────────────────────

class TestOCSPHTTP:

    @pytest.fixture
    def ocsp_server(self, ocsp_setup, inter_pass):
        """Запускает HTTP OCSP-сервер на случайном порту."""
        from cryptography.hazmat.primitives.asymmetric import ec as _ec
        stub_key = _ec.generate_private_key(_ec.SECP256R1())

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]

        handler = partial(
            OCSPHandler,
            ocsp_setup["issuer_cert"],
            ocsp_setup["responder_cert"],
            ocsp_setup["responder_key"],
            ocsp_setup["db_path"],
            stub_key,
        )
        server = HTTPServer(("127.0.0.1", port), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        time.sleep(0.1)
        yield port, ocsp_setup
        server.shutdown()

    def test_post_valid_request_возвращает_200(self, ocsp_server, inter_pass):
        port, setup = ocsp_server
        record, leaf_cert = _issue_leaf(
            setup["full_pki"], setup["db_path"], inter_pass, "http-good.local"
        )
        req_der = _build_ocsp_req(leaf_cert, setup["issuer_cert"])

        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/",
            data=req_der,
            headers={"Content-Type": "application/ocsp-request"},
            method="POST",
        )
        resp = urllib.request.urlopen(req)
        assert resp.status == 200
        assert resp.headers["Content-Type"] == "application/ocsp-response"

    def test_http_ответ_парсируется_как_ocsp(self, ocsp_server, inter_pass):
        port, setup = ocsp_server
        record, leaf_cert = _issue_leaf(
            setup["full_pki"], setup["db_path"], inter_pass, "http-parse.local"
        )
        req_der = _build_ocsp_req(leaf_cert, setup["issuer_cert"])

        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/",
            data=req_der,
            headers={"Content-Type": "application/ocsp-request"},
            method="POST",
        )
        resp = urllib.request.urlopen(req)
        resp_body = resp.read()
        parsed = ocsp.load_der_ocsp_response(resp_body)
        assert parsed.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
        assert parsed.certificate_status == ocsp.OCSPCertStatus.GOOD

    def test_неверный_content_type_возвращает_400(self, ocsp_server):
        port, _ = ocsp_server
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/",
            data=b"garbage",
            headers={"Content-Type": "text/plain"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req)
        assert exc_info.value.code == 400

    def test_пустое_тело_возвращает_400(self, ocsp_server):
        port, _ = ocsp_server
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/",
            data=b"",
            headers={"Content-Type": "application/ocsp-request", "Content-Length": "0"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req)
        assert exc_info.value.code == 400

    def test_мусорный_der_возвращает_200_с_malformed(self, ocsp_server):
        """Мусор с правильным Content-Type → HTTP 200, тело — OCSP malformedRequest."""
        port, _ = ocsp_server
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/",
            data=b"this is not DER",
            headers={"Content-Type": "application/ocsp-request"},
            method="POST",
        )
        resp = urllib.request.urlopen(req)
        assert resp.status == 200
        body = resp.read()
        parsed = ocsp.load_der_ocsp_response(body)
        assert parsed.response_status == ocsp.OCSPResponseStatus.MALFORMED_REQUEST
