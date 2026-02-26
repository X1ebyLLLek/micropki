"""
HTTP certificate repository server for MicroPKI.

Serves certificates via REST-like endpoints using the built-in http.server.
No external dependencies required.

Endpoints:
  GET /certificate/<serial>   — fetch cert PEM from DB
  GET /ca/root                — Root CA certificate
  GET /ca/intermediate        — Intermediate CA certificate
  GET /crl                    — 501 placeholder
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
    """HTTP request handler for the certificate repository."""

    def __init__(self, db_path: str, cert_dir: str, *args, **kwargs):
        self.db_path = db_path
        self.cert_dir = Path(cert_dir)
        super().__init__(*args, **kwargs)

    def log_message(self, format: str, *args) -> None:
        """Override default logging to use our logger with [HTTP] prefix."""
        client_ip = self.client_address[0]
        logger.info(
            "[HTTP] %s %s - %s",
            client_ip,
            self.requestline,
            args[0] if args else "",
        )

    def do_GET(self) -> None:
        """Route GET requests to appropriate handlers."""
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
        """Handle HEAD requests (same routing, no body)."""
        self.do_GET()

    def _handle_certificate(self, serial: str) -> None:
        """GET /certificate/<serial> — fetch cert from DB."""
        serial = serial.strip()

        if not serial or not _HEX_RE.match(serial):
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                f"Invalid serial number format: '{serial}'. Must be hexadecimal.",
            )
            return

        record = get_by_serial(self.db_path, serial)
        if record is None:
            self._send_error(
                HTTPStatus.NOT_FOUND,
                f"Certificate with serial '{serial}' not found.",
            )
            return

        self._send_pem(record["cert_pem"])

    def _handle_ca(self, level: str) -> None:
        """GET /ca/<level> — serve CA certificate from disk."""
        level = level.strip().lower()

        file_map = {
            "root": "ca.cert.pem",
            "intermediate": "intermediate.cert.pem",
        }

        filename = file_map.get(level)
        if filename is None:
            self._send_error(
                HTTPStatus.NOT_FOUND,
                f"Unknown CA level: '{level}'. Use 'root' or 'intermediate'.",
            )
            return

        cert_path = self.cert_dir / filename
        if not cert_path.exists():
            self._send_error(
                HTTPStatus.NOT_FOUND,
                f"CA certificate file not found: {filename}",
            )
            return

        pem_data = cert_path.read_text(encoding="utf-8")
        self._send_pem(pem_data)

    def _handle_crl(self) -> None:
        """GET /crl — placeholder for Sprint 4."""
        self._send_error(
            HTTPStatus.NOT_IMPLEMENTED,
            "CRL generation not yet implemented.",
        )

    def _send_pem(self, pem_text: str) -> None:
        """Send a PEM response with correct headers."""
        body = pem_text.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/x-pem-file")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, status: HTTPStatus, message: str) -> None:
        """Send an error response in plain text."""
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
    Start the HTTP certificate repository server.

    Runs until interrupted with Ctrl+C.

    Args:
        host: Bind address.
        port: TCP port.
        db_path: Path to the SQLite database.
        cert_dir: Directory containing CA certificate PEM files.
    """
    handler = partial(RepositoryHandler, db_path, cert_dir)
    server = HTTPServer((host, port), handler)

    logger.info("Repository server starting on http://%s:%d", host, port)
    logger.info("Database: %s, Cert dir: %s", db_path, cert_dir)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Repository server shutting down.")
    finally:
        server.server_close()
