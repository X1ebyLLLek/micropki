"""
HTTP-сервер репозитория сертификатов для MicroPKI.

Отдает сертификаты через REST-подобные эндпоинты, используя встроенный http.server.
Не требует внешних зависимостей.

Эндпоинты:
  GET  /certificate/<serial>   — получить PEM сертификата из БД
  GET  /ca/root                — Корневой сертификат (Root CA)
  GET  /ca/intermediate        — Промежуточный сертификат (Intermediate CA)
  GET  /crl                    — CRL (PEM) для root или intermediate
  POST /request-cert           — Выпустить сертификат из CSR (требует X-API-Key)

ВНИМАНИЕ: эндпоинт /request-cert не использует TLS и передаёт CSR открытым текстом.
Для производственного использования необходим HTTPS-прокси (nginx, caddy и т.д.).
"""


from __future__ import annotations

import logging
import re
from functools import partial
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .database import get_by_serial

logger = logging.getLogger("micropki")

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


class RepositoryHandler(BaseHTTPRequestHandler):
    """Обработчик HTTP-запросов репозитория сертификатов."""

    def __init__(
        self,
        db_path: str,
        cert_dir: str,
        *args,
        ca_cert=None,
        ca_key=None,
        api_key: str | None = None,
        **kwargs,
    ):
        self.db_path = db_path
        self.cert_dir = Path(cert_dir)
        self.ca_cert = ca_cert
        self.ca_key = ca_key
        self.api_key = api_key
        super().__init__(*args, **kwargs)

    def log_message(self, format: str, *args) -> None:
        client_ip = self.client_address[0]
        logger.info("[HTTP] %s %s - %s", client_ip, self.requestline, args[0] if args else "")

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path.startswith("/certificate/"):
            self._handle_certificate(path[len("/certificate/"):])
        elif path.startswith("/ca/"):
            self._handle_ca(path[len("/ca/"):])
        elif path == "/crl":
            self._handle_crl(parsed.query)
        else:
            self._send_error(HTTPStatus.NOT_FOUND, "Not Found")

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/request-cert":
            self._handle_request_cert(parsed.query)
        else:
            self._send_error(HTTPStatus.NOT_FOUND, "Not Found")

    def _handle_certificate(self, serial: str) -> None:
        serial = serial.strip()
        if not serial or not _HEX_RE.match(serial):
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                f"Неверный формат серийного номера: '{serial}'.",
            )
            return

        record = get_by_serial(self.db_path, serial)
        if record is None:
            self._send_error(HTTPStatus.NOT_FOUND, f"Сертификат '{serial}' не найден.")
            return

        self._send_pem(record["cert_pem"])

    def _handle_ca(self, level: str) -> None:
        level = level.strip().lower()
        file_map = {"root": "ca.cert.pem", "intermediate": "intermediate.cert.pem"}
        filename = file_map.get(level)
        if filename is None:
            self._send_error(HTTPStatus.NOT_FOUND, f"Неизвестный уровень CA: '{level}'.")
            return

        cert_path = self.cert_dir / filename
        if not cert_path.exists():
            self._send_error(HTTPStatus.NOT_FOUND, f"Файл сертификата CA не найден: {filename}")
            return

        self._send_pem(cert_path.read_text(encoding="utf-8"))

    def _handle_crl(self, query_string: str = "") -> None:
        params = parse_qs(query_string)
        ca_level = params.get("ca", ["intermediate"])[0].lower()

        if ca_level not in ("root", "intermediate"):
            self._send_error(HTTPStatus.BAD_REQUEST, f"Неверный параметр ca='{ca_level}'.")
            return

        crl_file = self.cert_dir.parent / "crl" / f"{ca_level}.crl.pem"
        if not crl_file.exists():
            self._send_error(
                HTTPStatus.NOT_FOUND,
                f"CRL для '{ca_level}' не сгенерирован.",
            )
            return

        crl_data = crl_file.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/pkix-crl")
        self.send_header("Content-Length", str(len(crl_data)))
        self.send_header("Cache-Control", "max-age=3600")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(crl_data)

    def _handle_request_cert(self, query_string: str = "") -> None:
        """POST /request-cert?template=<name> — выпуск сертификата из CSR."""
        client_ip = self.client_address[0]

        if self.ca_cert is None or self.ca_key is None:
            logger.warning("[HTTP] /request-cert: CA не настроен для подписи CSR")
            self._send_error(HTTPStatus.NOT_IMPLEMENTED, "CA не настроен для подписи CSR")
            return

        # Проверка API-ключа
        if self.api_key:
            req_key = self.headers.get("X-API-Key", "")
            if req_key != self.api_key:
                logger.warning("[HTTP] /request-cert: неверный API-ключ от %s", client_ip)
                self._send_error(HTTPStatus.UNAUTHORIZED, "Неверный или отсутствующий X-API-Key")
                return

        # Шаблон из query string
        params = parse_qs(query_string)
        template_name = params.get("template", ["server"])[0]

        # Читаем тело запроса (CSR PEM)
        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            self._send_error(HTTPStatus.BAD_REQUEST, "Неверный Content-Length")
            return

        if content_length <= 0:
            self._send_error(HTTPStatus.BAD_REQUEST, "Тело запроса не может быть пустым")
            return

        csr_pem = self.rfile.read(content_length)

        # Подписываем CSR
        try:
            from .ca import sign_csr_request
            cert_pem = sign_csr_request(
                csr_pem=csr_pem,
                template_name=template_name,
                ca_cert=self.ca_cert,
                ca_key=self.ca_key,
                db_path=self.db_path,
            )
            logger.info(
                "[HTTP] /request-cert: сертификат выпущен (template=%s, ip=%s)",
                template_name, client_ip,
            )
        except ValueError as exc:
            logger.warning("[HTTP] /request-cert: ошибка CSR от %s: %s", client_ip, exc)
            self._send_error(HTTPStatus.BAD_REQUEST, str(exc))
            return
        except Exception as exc:
            logger.error("[HTTP] /request-cert: внутренняя ошибка: %s", exc)
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Внутренняя ошибка сервера")
            return

        body = cert_pem if isinstance(cert_pem, bytes) else cert_pem.encode()
        self.send_response(HTTPStatus.CREATED)
        self.send_header("Content-Type", "application/x-pem-file")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_pem(self, pem_text: str) -> None:
        body = pem_text.encode("utf-8") if isinstance(pem_text, str) else pem_text
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/x-pem-file")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, status: HTTPStatus, message: str) -> None:
        body = message.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)


def run_server(
    host: str = "127.0.0.1",
    port: int = 8080,
    db_path: str = "./pki/micropki.db",
    cert_dir: str = "./pki/certs",
    ca_cert=None,
    ca_key=None,
    api_key: str | None = None,
) -> None:
    """
    Запуск HTTP-сервера репозитория сертификатов.

    ca_cert / ca_key — предзагруженные объекты x509.Certificate и PrivateKey.
    Если переданы, активируется эндпоинт POST /request-cert.
    api_key — опциональный предварительно согласованный ключ для /request-cert.
    """
    handler = partial(RepositoryHandler, db_path, cert_dir, ca_cert=ca_cert, ca_key=ca_key, api_key=api_key)
    server = HTTPServer((host, port), handler)

    logger.info("Сервер репозитория запущен на http://%s:%d", host, port)
    logger.info("База данных: %s, Директория сертификатов: %s", db_path, cert_dir)
    if ca_cert is not None:
        logger.info("Эндпоинт POST /request-cert активирован (API-ключ: %s)", "задан" if api_key else "не задан")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Сервер репозитория останавливается.")
    finally:
        server.server_close()
