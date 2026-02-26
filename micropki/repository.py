"""
HTTP-сервер репозитория сертификатов для MicroPKI.

Отдает сертификаты через REST-подобные эндпоинты, используя встроенный http.server.
Не требует внешних зависимостей.

Эндпоинты:
  GET /certificate/<serial>   — получить PEM сертификата из БД
  GET /ca/root                — Корневой сертификат (Root CA)
  GET /ca/intermediate        — Промежуточный сертификат (Intermediate CA)
  GET /crl                    — Заглушка (501)
"""


from __future__ import annotations

import json
import logging
import re
from functools import partial
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from .database import get_by_serial

logger = logging.getLogger("micropki")

# Регулярное выражение для валидного hex серийного номера
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


class RepositoryHandler(BaseHTTPRequestHandler):
    """Класс-обработчик HTTP запросов для репозитория сертификатов."""

    def __init__(self, db_path: str, cert_dir: str, *args, **kwargs):
        self.db_path = db_path
        self.cert_dir = Path(cert_dir)
        super().__init__(*args, **kwargs)

    def log_message(self, format: str, *args) -> None:
        """Переопределение стандартного логирования для использования нашего логгера с префиксом [HTTP]."""
        client_ip = self.client_address[0]
        logger.info(
            "[HTTP] %s %s - %s",
            client_ip,
            self.requestline,
            args[0] if args else "",
        )

    def do_GET(self) -> None:
        """Маршрутизация GET-запросов к соответствующим обработчикам."""
        path = self.path.rstrip("/")

        if path.startswith("/certificate/"):
            self._handle_certificate(path[len("/certificate/"):])
        elif path.startswith("/ca/"):
            self._handle_ca(path[len("/ca/"):])
        elif path == "/crl":
            self._handle_crl()
        else:
            self._send_error(HTTPStatus.NOT_FOUND, "Not Found")

    def do_HEAD(self) -> None:
        """Обработка HEAD-запросов (та же маршрутизация, но без тела ответа)."""
        self.do_GET()

    def _handle_certificate(self, serial: str) -> None:
        """GET /certificate/<serial> — получение сертификата из БД."""
        serial = serial.strip()

        if not serial or not _HEX_RE.match(serial):
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                f"Неверный формат серийного номера: '{serial}'. Ожидается шестнадцатеричное значение.",
            )
            return

        record = get_by_serial(self.db_path, serial)
        if record is None:
            self._send_error(
                HTTPStatus.NOT_FOUND,
                f"Сертификат с серийным номером '{serial}' не найден.",
            )
            return

        self._send_pem(record["cert_pem"])

    def _handle_ca(self, level: str) -> None:
        """GET /ca/<level> — отдача файла сертификата УЦ с диска."""
        level = level.strip().lower()

        file_map = {
            "root": "ca.cert.pem",
            "intermediate": "intermediate.cert.pem",
        }

        filename = file_map.get(level)
        if filename is None:
            self._send_error(
                HTTPStatus.NOT_FOUND,
                f"Неизвестный уровень CA: '{level}'. Используйте 'root' или 'intermediate'.",
            )
            return

        cert_path = self.cert_dir / filename
        if not cert_path.exists():
            self._send_error(
                HTTPStatus.NOT_FOUND,
                f"Файл сертификата CA не найден: {filename}",
            )
            return

        pem_data = cert_path.read_text(encoding="utf-8")
        self._send_pem(pem_data)

    def _handle_crl(self) -> None:
        """GET /crl — заглушка для Спринта 4."""
        self._send_error(
            HTTPStatus.NOT_IMPLEMENTED,
            "Генерация CRL пока не реализована.",
        )

    def _send_pem(self, pem_text: str) -> None:
        """Отправка ответа в формате PEM с правильными заголовками."""
        body = pem_text.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/x-pem-file")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, status: HTTPStatus, message: str) -> None:
        """Отправка ответа об ошибке в виде обычного текста."""
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
) -> None:
    """
    Запуск HTTP-сервера репозитория сертификатов.

    Работает до прерывания комбинацией Ctrl+C.

    Аргументы:
        host: IP-адрес для привязки сервера.
        port: TCP порт.
        db_path: Путь к базе данных SQLite.
        cert_dir: Директория, содержащая PEM-файлы сертификатов УЦ.
    """
    handler = partial(RepositoryHandler, db_path, cert_dir)
    server = HTTPServer((host, port), handler)

    logger.info("Сервер репозитория запущен на http://%s:%d", host, port)
    logger.info("База данных: %s, Директория сертификатов: %s", db_path, cert_dir)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Сервер репозитория останавливается.")
    finally:
        server.server_close()
