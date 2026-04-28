"""
Парсер аргументов командной строки для MicroPKI.

Предоставляет команду `micropki` с подкомандами:
  - ca init                 (Спринт 1)
  - ca issue-intermediate   (Спринт 2)
  - ca issue-cert           (Спринты 2, 6: добавлен --csr)
  - ca list-certs           (Спринт 3)
  - ca show-cert            (Спринт 3)
  - db init                 (Спринт 3)
  - repo serve              (Спринты 3, 6: добавлены --ca-cert/--ca-key/--api-key)
  - ca revoke               (Спринт 4)
  - ca gen-crl              (Спринт 4)
  - ca issue-ocsp-cert      (Спринт 5)
  - ocsp serve              (Спринт 5)
  - client gen-csr          (Спринт 6)
  - client request-cert     (Спринт 6)
  - client validate         (Спринт 6)
  - client check-status     (Спринт 6)
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import sys
from pathlib import Path

from .ca import init_ca, issue_cert, issue_intermediate, issue_ocsp_cert
from .database import get_by_serial, init_db, list_certificates
from .logger import setup_logger
from .repository import run_server

DEFAULT_DB_PATH = "./pki/micropki.db"


def main(argv: list[str] | None = None) -> int:
    """Главная точка входа для CLI MicroPKI."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not hasattr(args, "func"):
        parser.print_help(sys.stderr)
        return 1

    return args.func(args)


def _build_parser() -> argparse.ArgumentParser:
    """Создает главный парсер аргументов с подкомандами."""
    parser = argparse.ArgumentParser(
        prog="micropki",
        description="MicroPKI — минималистичный инструмент инфраструктуры открытых ключей.",
    )

    subparsers = parser.add_subparsers(
        title="команды", dest="command", help="Доступные команды",
    )

    # ---- ca ----
    ca_parser = subparsers.add_parser("ca", help="Операции Центра Сертификации (CA)")
    ca_subparsers = ca_parser.add_subparsers(
        title="подкоманды ca", dest="ca_command", help="Операции CA",
    )
    _add_ca_init_parser(ca_subparsers)
    _add_ca_issue_intermediate_parser(ca_subparsers)
    _add_ca_issue_cert_parser(ca_subparsers)
    _add_ca_list_certs_parser(ca_subparsers)
    _add_ca_show_cert_parser(ca_subparsers)
    _add_ca_revoke_parser(ca_subparsers)
    _add_ca_gen_crl_parser(ca_subparsers)
    _add_ca_issue_ocsp_cert_parser(ca_subparsers)
    ca_parser.set_defaults(func=lambda args: (ca_parser.print_help(sys.stderr) or 1))

    # ---- db ----
    db_parser = subparsers.add_parser("db", help="Операции с базой данных")
    db_subparsers = db_parser.add_subparsers(
        title="подкоманды db", dest="db_command", help="Операции БД",
    )
    _add_db_init_parser(db_subparsers)
    db_parser.set_defaults(func=lambda args: (db_parser.print_help(sys.stderr) or 1))

    # ---- repo ----
    repo_parser = subparsers.add_parser("repo", help="Операции репозитория")
    repo_subparsers = repo_parser.add_subparsers(
        title="подкоманды repo", dest="repo_command", help="Операции репозитория",
    )
    _add_repo_serve_parser(repo_subparsers)
    repo_parser.set_defaults(func=lambda args: (repo_parser.print_help(sys.stderr) or 1))

    # ---- ocsp ----
    ocsp_parser = subparsers.add_parser("ocsp", help="Операции OCSP-респондера")
    ocsp_subparsers = ocsp_parser.add_subparsers(
        title="подкоманды ocsp", dest="ocsp_command", help="Операции OCSP",
    )
    _add_ocsp_serve_parser(ocsp_subparsers)
    ocsp_parser.set_defaults(func=lambda args: (ocsp_parser.print_help(sys.stderr) or 1))

    # ---- client ----
    client_parser = subparsers.add_parser("client", help="Клиентские операции PKI (Спринт 6)")
    client_subparsers = client_parser.add_subparsers(
        title="подкоманды client", dest="client_command", help="Клиентские операции",
    )
    _add_client_gen_csr_parser(client_subparsers)
    _add_client_request_cert_parser(client_subparsers)
    _add_client_validate_parser(client_subparsers)
    _add_client_check_status_parser(client_subparsers)
    client_parser.set_defaults(func=lambda args: (client_parser.print_help(sys.stderr) or 1))

    return parser


# ════════════════════════════════════════
#  Парсеры подкоманд
# ════════════════════════════════════════

def _add_ca_init_parser(sub) -> None:
    p = sub.add_parser("init", help="Инициализировать самоподписанный Корневой CA")
    p.add_argument("--subject", required=True)
    p.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    p.add_argument("--key-size", type=int)
    p.add_argument("--passphrase-file", required=True)
    p.add_argument("--out-dir", default="./pki")
    p.add_argument("--validity-days", type=int, default=3650)
    p.add_argument("--log-file", default=None)
    p.add_argument("--force", action="store_true", default=False)
    p.add_argument("--db-path", default=DEFAULT_DB_PATH)
    p.set_defaults(func=_handle_ca_init)


def _add_ca_issue_intermediate_parser(sub) -> None:
    p = sub.add_parser("issue-intermediate", help="Выпустить сертификат Промежуточного CA")
    p.add_argument("--root-cert", required=True)
    p.add_argument("--root-key", required=True)
    p.add_argument("--root-pass-file", required=True)
    p.add_argument("--subject", required=True)
    p.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    p.add_argument("--key-size", type=int)
    p.add_argument("--passphrase-file", required=True)
    p.add_argument("--out-dir", default="./pki")
    p.add_argument("--validity-days", type=int, default=1825)
    p.add_argument("--pathlen", type=int, default=0)
    p.add_argument("--log-file", default=None)
    p.add_argument("--db-path", default=DEFAULT_DB_PATH)
    p.set_defaults(func=_handle_ca_issue_intermediate)


def _add_ca_issue_cert_parser(sub) -> None:
    p = sub.add_parser("issue-cert", help="Выпустить конечный сертификат")
    p.add_argument("--ca-cert", required=True)
    p.add_argument("--ca-key", required=True)
    p.add_argument("--ca-pass-file", required=True)
    p.add_argument("--template", required=True, choices=["server", "client", "code_signing"])
    # --subject необязателен при --csr (субъект берётся из CSR)
    p.add_argument("--subject", default=None)
    p.add_argument("--san", action="append", dest="sans")
    p.add_argument("--csr", default=None, help="Путь к файлу CSR (PEM). При указании --subject игнорируется.")
    p.add_argument("--out-dir", default="./pki/certs")
    p.add_argument("--validity-days", type=int, default=365)
    p.add_argument("--log-file", default=None)
    p.add_argument("--db-path", default=DEFAULT_DB_PATH)
    p.set_defaults(func=_handle_ca_issue_cert)


def _add_ca_list_certs_parser(sub) -> None:
    p = sub.add_parser("list-certs", help="Вывести список сертификатов в базе")
    p.add_argument("--status", choices=["valid", "revoked", "expired"], default=None)
    p.add_argument("--format", dest="output_format", choices=["table", "json", "csv"], default="table")
    p.add_argument("--db-path", default=DEFAULT_DB_PATH)
    p.add_argument("--log-file", default=None)
    p.set_defaults(func=_handle_ca_list_certs)


def _add_ca_show_cert_parser(sub) -> None:
    p = sub.add_parser("show-cert", help="Показать сертификат по серийному номеру")
    p.add_argument("serial")
    p.add_argument("--db-path", default=DEFAULT_DB_PATH)
    p.add_argument("--log-file", default=None)
    p.set_defaults(func=_handle_ca_show_cert)


def _add_db_init_parser(sub) -> None:
    p = sub.add_parser("init", help="Инициализировать базу сертификатов")
    p.add_argument("--db-path", default=DEFAULT_DB_PATH)
    p.add_argument("--log-file", default=None)
    p.set_defaults(func=_handle_db_init)


def _add_repo_serve_parser(sub) -> None:
    p = sub.add_parser("serve", help="Запустить HTTP сервер репозитория сертификатов")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--db-path", default=DEFAULT_DB_PATH)
    p.add_argument("--cert-dir", default="./pki/certs")
    # Параметры для /request-cert (необязательные)
    p.add_argument("--ca-cert", default=None, help="Сертификат CA для подписи CSR (включает /request-cert)")
    p.add_argument("--ca-key", default=None, help="Зашифрованный ключ CA")
    p.add_argument("--ca-pass-file", default=None, help="Файл с парольной фразой CA")
    p.add_argument("--api-key", default=None, help="Предварительно согласованный API-ключ для /request-cert")
    p.add_argument("--log-file", default=None)
    p.set_defaults(func=_handle_repo_serve)


def _add_ca_revoke_parser(sub) -> None:
    p = sub.add_parser("revoke", help="Отозвать сертификат по серийному номеру")
    p.add_argument("serial")
    p.add_argument(
        "--reason", default="unspecified",
        choices=[
            "unspecified", "keyCompromise", "cACompromise",
            "affiliationChanged", "superseded", "cessationOfOperation",
            "certificateHold", "removeFromCRL", "privilegeWithdrawn", "aACompromise",
        ],
    )
    p.add_argument("--db-path", default=DEFAULT_DB_PATH)
    p.add_argument("--yes", action="store_true", default=False)
    p.add_argument("--log-file", default=None)
    p.set_defaults(func=_handle_ca_revoke)


def _add_ca_gen_crl_parser(sub) -> None:
    p = sub.add_parser("gen-crl", help="Сгенерировать список отозванных сертификатов (CRL)")
    p.add_argument("--ca", dest="ca_level", choices=["root", "intermediate"], required=True)
    p.add_argument("--ca-cert", required=True)
    p.add_argument("--ca-key", required=True)
    p.add_argument("--ca-pass-file", required=True)
    p.add_argument("--out-dir", default="./pki")
    p.add_argument("--validity-days", type=int, default=7)
    p.add_argument("--db-path", default=DEFAULT_DB_PATH)
    p.add_argument("--log-file", default=None)
    p.set_defaults(func=_handle_ca_gen_crl)


def _add_ca_issue_ocsp_cert_parser(sub) -> None:
    p = sub.add_parser("issue-ocsp-cert", help="Выпустить OCSP-сертификат подписи")
    p.add_argument("--ca-cert", required=True)
    p.add_argument("--ca-key", required=True)
    p.add_argument("--ca-pass-file", required=True)
    p.add_argument("--subject", required=True)
    p.add_argument("--out-dir", default="./pki")
    p.add_argument("--validity-days", type=int, default=365)
    p.add_argument("--db-path", default=DEFAULT_DB_PATH)
    p.add_argument("--log-file", default=None)
    p.set_defaults(func=_handle_ca_issue_ocsp_cert)


def _add_ocsp_serve_parser(sub) -> None:
    p = sub.add_parser("serve", help="Запустить HTTP OCSP-респондер")
    p.add_argument("--issuer-cert", required=True)
    p.add_argument("--ocsp-cert", required=True)
    p.add_argument("--ocsp-key", required=True)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8081)
    p.add_argument("--db-path", default=DEFAULT_DB_PATH)
    p.add_argument("--log-file", default=None)
    p.set_defaults(func=_handle_ocsp_serve)


# ---- Клиентские команды (Спринт 6) ----

def _add_client_gen_csr_parser(sub) -> None:
    p = sub.add_parser("gen-csr", help="Сгенерировать приватный ключ и CSR (PKCS#10)")
    p.add_argument("--subject", required=True, help="Distinguished Name (например, CN=app.local,O=Test)")
    p.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    p.add_argument("--key-size", type=int, default=None,
                   help="RSA: 2048 или 4096 (по умолчанию 2048); ECC: 256 или 384 (по умолчанию 256)")
    p.add_argument("--san", action="append", dest="sans", help="SAN в формате type:value (можно повторять)")
    p.add_argument("--out-key", default="./key.pem", help="Файл для приватного ключа (незашифрованный PEM)")
    p.add_argument("--out-csr", default="./request.csr.pem", help="Файл для CSR (PEM)")
    p.add_argument("--log-file", default=None)
    p.set_defaults(func=_handle_client_gen_csr)


def _add_client_request_cert_parser(sub) -> None:
    p = sub.add_parser("request-cert", help="Отправить CSR в CA и получить сертификат")
    p.add_argument("--csr", required=True, help="Путь к файлу CSR (PEM)")
    p.add_argument("--template", required=True, choices=["server", "client", "code_signing"])
    p.add_argument("--ca-url", required=True, help="Базовый URL репозитория (например, http://localhost:8080)")
    p.add_argument("--out-cert", default="./cert.pem", help="Файл для сохранения сертификата")
    p.add_argument("--api-key", default=None, help="API-ключ (X-API-Key заголовок)")
    p.add_argument("--log-file", default=None)
    p.set_defaults(func=_handle_client_request_cert)


def _add_client_validate_parser(sub) -> None:
    p = sub.add_parser("validate", help="Проверить цепочку сертификатов")
    p.add_argument("--cert", required=True, help="Путь к конечному сертификату (PEM)")
    p.add_argument("--untrusted", action="append", dest="untrusted", default=[],
                   help="Промежуточный сертификат (PEM, можно повторять)")
    p.add_argument("--trusted", default="./pki/certs/ca.cert.pem",
                   help="Доверенный корневой сертификат (PEM bundle)")
    p.add_argument("--crl", default=None, help="CRL для проверки отзыва (файл или URL)")
    p.add_argument("--ocsp", action="store_true", default=False,
                   help="Выполнить проверку через OCSP (URL из AIA)")
    p.add_argument("--mode", choices=["chain", "full"], default="full",
                   help="chain — только цепочка; full — включая проверку отзыва")
    p.add_argument("--validation-time", default=None,
                   help="Время проверки ISO 8601 (по умолчанию — текущее время)")
    p.add_argument("--format", dest="output_format", choices=["text", "json"], default="text")
    p.add_argument("--log-file", default=None)
    p.set_defaults(func=_handle_client_validate)


def _add_client_check_status_parser(sub) -> None:
    p = sub.add_parser("check-status", help="Проверить статус отзыва сертификата")
    p.add_argument("--cert", required=True, help="Путь к проверяемому сертификату (PEM)")
    p.add_argument("--ca-cert", required=True, help="Сертификат CA-издателя (PEM)")
    p.add_argument("--crl", default=None, help="CRL (файл или URL) для резервной проверки")
    p.add_argument("--ocsp-url", default=None, help="Переопределить URL OCSP-респондера")
    p.add_argument("--log-file", default=None)
    p.set_defaults(func=_handle_client_check_status)


# ════════════════════════════════════════
#  Обработчики
# ════════════════════════════════════════

def _handle_ca_init(args: argparse.Namespace) -> int:
    _ensure_log_dir(args)
    log = setup_logger(args.log_file)
    try:
        key_size = _validate_key_params(args.key_type, args.key_size)
        _validate_subject(args.subject, log)
        passphrase = _read_passphrase(args.passphrase_file, log)
        _validate_validity_days(args.validity_days, log)
        _validate_out_dir(args.out_dir)

        init_ca(
            subject=args.subject, key_type=args.key_type, key_size=key_size,
            passphrase=passphrase, out_dir=args.out_dir,
            validity_days=args.validity_days, force=args.force,
            db_path=args.db_path,
        )
        return 0
    except (FileExistsError, ValueError) as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        log.error("%s", e)
        return 1
    except Exception as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        log.error("Непредвиденная ошибка: %s", e)
        return 1


def _handle_ca_issue_intermediate(args: argparse.Namespace) -> int:
    _ensure_log_dir(args)
    log = setup_logger(args.log_file)
    try:
        key_size = _validate_key_params(args.key_type, args.key_size)
        _validate_subject(args.subject, log)
        root_passphrase = _read_passphrase(args.root_pass_file, log)
        intermediate_passphrase = _read_passphrase(args.passphrase_file, log)
        _validate_validity_days(args.validity_days, log)
        _validate_file_exists(args.root_cert, "Корневой сертификат")
        _validate_file_exists(args.root_key, "Приватный ключ корневого CA")
        if args.pathlen < 0:
            raise ValueError("--pathlen должен быть не отрицательным.")

        issue_intermediate(
            root_cert_path=args.root_cert, root_key_path=args.root_key,
            root_passphrase=root_passphrase, subject=args.subject,
            key_type=args.key_type, key_size=key_size,
            passphrase=intermediate_passphrase, out_dir=args.out_dir,
            validity_days=args.validity_days, path_length=args.pathlen,
            db_path=args.db_path,
        )
        return 0
    except (FileExistsError, ValueError, FileNotFoundError) as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        log.error("%s", e)
        return 1
    except Exception as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        log.error("Непредвиденная ошибка: %s", e)
        return 1


def _handle_ca_issue_cert(args: argparse.Namespace) -> int:
    _ensure_log_dir(args)
    log = setup_logger(args.log_file)
    try:
        csr_pem: bytes | None = None
        if args.csr:
            _validate_file_exists(args.csr, "Файл CSR")
            csr_pem = Path(args.csr).read_bytes()
        elif args.subject is None:
            raise ValueError("Необходимо указать --subject или --csr.")
        else:
            _validate_subject(args.subject, log)

        ca_passphrase = _read_passphrase(args.ca_pass_file, log)
        _validate_validity_days(args.validity_days, log)
        _validate_file_exists(args.ca_cert, "Сертификат CA")
        _validate_file_exists(args.ca_key, "Приватный ключ CA")

        issue_cert(
            ca_cert_path=args.ca_cert, ca_key_path=args.ca_key,
            ca_passphrase=ca_passphrase, template_name=args.template,
            subject=args.subject, san_strings=args.sans,
            out_dir=args.out_dir, validity_days=args.validity_days,
            db_path=args.db_path, csr_pem=csr_pem,
        )
        return 0
    except (ValueError, FileNotFoundError) as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        log.error("%s", e)
        return 1
    except Exception as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        log.error("Непредвиденная ошибка: %s", e)
        return 1


def _handle_db_init(args: argparse.Namespace) -> int:
    _ensure_log_dir(args)
    log = setup_logger(args.log_file)
    try:
        init_db(args.db_path)
        print(f"База данных инициализирована: {args.db_path}")
        return 0
    except Exception as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        log.error("Ошибка инициализации БД: %s", e)
        return 1


def _handle_ca_list_certs(args: argparse.Namespace) -> int:
    _ensure_log_dir(args)
    log = setup_logger(args.log_file)
    try:
        _validate_file_exists(args.db_path, "Файл базы данных")
        certs = list_certificates(args.db_path, status=args.status)
        log.info("Извлечено %d сертификатов.", len(certs))

        if args.output_format == "json":
            print(json.dumps(certs, indent=2))
        elif args.output_format == "csv":
            _print_csv(certs)
        else:
            _print_table(certs)
        return 0
    except Exception as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        log.error("Ошибка в list-certs: %s", e)
        return 1


def _handle_ca_show_cert(args: argparse.Namespace) -> int:
    _ensure_log_dir(args)
    log = setup_logger(args.log_file)
    try:
        _validate_file_exists(args.db_path, "Файл базы данных")
        record = get_by_serial(args.db_path, args.serial)
        if record is None:
            print(f"Сертификат '{args.serial}' не найден.", file=sys.stderr)
            return 1
        print(record["cert_pem"])
        return 0
    except Exception as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        log.error("Ошибка в show-cert: %s", e)
        return 1


def _handle_repo_serve(args: argparse.Namespace) -> int:
    _ensure_log_dir(args)
    log = setup_logger(args.log_file)
    try:
        ca_cert_obj = None
        ca_key_obj = None

        if args.ca_cert and args.ca_key and args.ca_pass_file:
            from cryptography import x509 as _x509
            from .crypto_utils import load_encrypted_key
            _validate_file_exists(args.ca_cert, "Сертификат CA")
            _validate_file_exists(args.ca_key, "Ключ CA")
            ca_passphrase = _read_passphrase(args.ca_pass_file, log)
            ca_cert_obj = _x509.load_pem_x509_certificate(Path(args.ca_cert).read_bytes())
            ca_key_obj = load_encrypted_key(Path(args.ca_key).read_bytes(), ca_passphrase)
            log.info("CA загружен для /request-cert: %s", args.ca_cert)

        print(f"Запуск сервера репозитория на http://{args.host}:{args.port}")
        print("Нажмите Ctrl+C для остановки.")
        run_server(
            host=args.host, port=args.port,
            db_path=args.db_path, cert_dir=args.cert_dir,
            ca_cert=ca_cert_obj, ca_key=ca_key_obj,
            api_key=args.api_key,
        )
        return 0
    except Exception as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        log.error("Ошибка сервера: %s", e)
        return 1


def _handle_ca_revoke(args: argparse.Namespace) -> int:
    _ensure_log_dir(args)
    log = setup_logger(args.log_file)
    try:
        from .revocation import revoke_certificate

        if not args.yes:
            confirm = input(f"Отозвать сертификат {args.serial} (причина: {args.reason})? [y/N] ")
            if confirm.strip().lower() not in ("y", "yes", "д", "да"):
                print("Отмена.")
                return 0

        revoke_certificate(args.db_path, args.serial, reason=args.reason)
        print(f"Сертификат {args.serial} успешно отозван (причина: {args.reason}).")
        return 0
    except ValueError as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        log.error("%s", e)
        return 1
    except Exception as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        log.error("Непредвиденная ошибка: %s", e)
        return 1


def _handle_ca_gen_crl(args: argparse.Namespace) -> int:
    _ensure_log_dir(args)
    log = setup_logger(args.log_file)
    try:
        from .crl import generate_crl
        _validate_file_exists(args.ca_cert, "Сертификат CA")
        _validate_file_exists(args.ca_key, "Приватный ключ CA")
        ca_passphrase = _read_passphrase(args.ca_pass_file, log)

        crl_path = generate_crl(
            ca_cert_path=args.ca_cert, ca_key_path=args.ca_key,
            ca_passphrase=ca_passphrase, db_path=args.db_path,
            out_dir=args.out_dir, ca_level=args.ca_level,
            validity_days=args.validity_days,
        )
        print(f"CRL сгенерирован: {crl_path}")
        return 0
    except (ValueError, FileNotFoundError) as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        log.error("%s", e)
        return 1
    except Exception as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        log.error("Непредвиденная ошибка: %s", e)
        return 1


def _handle_ca_issue_ocsp_cert(args: argparse.Namespace) -> int:
    _ensure_log_dir(args)
    log = setup_logger(args.log_file)
    try:
        _validate_subject(args.subject, log)
        _validate_file_exists(args.ca_cert, "Сертификат CA")
        _validate_file_exists(args.ca_key, "Приватный ключ CA")
        ca_passphrase = _read_passphrase(args.ca_pass_file, log)
        _validate_validity_days(args.validity_days, log)

        cert_path, key_path = issue_ocsp_cert(
            ca_cert_path=args.ca_cert, ca_key_path=args.ca_key,
            ca_passphrase=ca_passphrase, subject=args.subject,
            out_dir=args.out_dir, validity_days=args.validity_days,
            db_path=args.db_path,
        )
        print(f"OCSP-сертификат: {cert_path}")
        print(f"OCSP-ключ:       {key_path}")
        return 0
    except (ValueError, FileNotFoundError) as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        log.error("%s", e)
        return 1
    except Exception as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        log.error("Непредвиденная ошибка: %s", e)
        return 1


def _handle_ocsp_serve(args: argparse.Namespace) -> int:
    _ensure_log_dir(args)
    log = setup_logger(args.log_file)
    try:
        from .ocsp_responder import run_ocsp_server
        _validate_file_exists(args.issuer_cert, "Сертификат CA-издателя")
        _validate_file_exists(args.ocsp_cert, "OCSP-сертификат")
        _validate_file_exists(args.ocsp_key, "OCSP-ключ")

        print(f"Запуск OCSP-респондера на http://{args.host}:{args.port}")
        print("Нажмите Ctrl+C для остановки.")
        run_ocsp_server(
            host=args.host, port=args.port,
            issuer_cert_path=args.issuer_cert,
            responder_cert_path=args.ocsp_cert,
            responder_key_path=args.ocsp_key,
            db_path=args.db_path,
        )
        return 0
    except (ValueError, FileNotFoundError) as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        log.error("%s", e)
        return 1
    except Exception as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        log.error("Ошибка OCSP-сервера: %s", e)
        return 1


# ---- Обработчики клиентских команд ----

def _handle_client_gen_csr(args: argparse.Namespace) -> int:
    _ensure_log_dir(args)
    log = setup_logger(args.log_file)
    try:
        from .client import gen_csr
        key_size = _client_key_size(args.key_type, args.key_size)
        key_path, csr_path = gen_csr(
            subject=args.subject,
            key_type=args.key_type,
            key_size=key_size,
            san_strings=args.sans,
            out_key=args.out_key,
            out_csr=args.out_csr,
        )
        print(f"Приватный ключ: {key_path}  (ВНИМАНИЕ: незашифрован)")
        print(f"CSR:            {csr_path}")
        return 0
    except (ValueError, OSError) as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        log.error("%s", e)
        return 1
    except Exception as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        log.error("Непредвиденная ошибка: %s", e)
        return 1


def _handle_client_request_cert(args: argparse.Namespace) -> int:
    _ensure_log_dir(args)
    log = setup_logger(args.log_file)
    try:
        from .client import request_cert
        _validate_file_exists(args.csr, "Файл CSR")
        cert_path = request_cert(
            csr_path=args.csr,
            template=args.template,
            ca_url=args.ca_url,
            out_cert=args.out_cert,
            api_key=args.api_key,
        )
        print(f"Сертификат сохранён: {cert_path}")
        return 0
    except RuntimeError as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        log.error("%s", e)
        return 1
    except Exception as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        log.error("Непредвиденная ошибка: %s", e)
        return 1


def _handle_client_validate(args: argparse.Namespace) -> int:
    _ensure_log_dir(args)
    log = setup_logger(args.log_file)
    try:
        from .client import validate_cert
        _validate_file_exists(args.cert, "Сертификат")
        _validate_file_exists(args.trusted, "Доверенный сертификат")

        validation_time = None
        if args.validation_time:
            from datetime import datetime, timezone
            validation_time = datetime.fromisoformat(args.validation_time)
            if validation_time.tzinfo is None:
                validation_time = validation_time.replace(tzinfo=timezone.utc)

        result = validate_cert(
            cert_path=args.cert,
            untrusted_paths=args.untrusted,
            trusted_path=args.trusted,
            crl_source=args.crl,
            check_ocsp_flag=args.ocsp,
            mode=args.mode,
            validation_time=validation_time,
        )

        if args.output_format == "json":
            import dataclasses
            print(json.dumps({
                "valid": result.valid,
                "error": result.error,
                "steps": [dataclasses.asdict(s) for s in result.steps],
            }, indent=2, ensure_ascii=False))
        else:
            status = "УСПЕШНО" if result.valid else "ОШИБКА"
            print(f"Результат проверки: {status}")
            for step in result.steps:
                mark = "✓" if step.passed else "✗"
                print(f"  {mark} {step.name}: {step.detail}")
            if not result.valid:
                print(f"\nПричина: {result.error}")

        return 0 if result.valid else 1
    except (ValueError, FileNotFoundError) as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        log.error("%s", e)
        return 1
    except Exception as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        log.error("Непредвиденная ошибка: %s", e)
        return 1


def _handle_client_check_status(args: argparse.Namespace) -> int:
    _ensure_log_dir(args)
    log = setup_logger(args.log_file)
    try:
        from .client import check_cert_status
        _validate_file_exists(args.cert, "Сертификат")
        _validate_file_exists(args.ca_cert, "Сертификат CA")

        rev = check_cert_status(
            cert_path=args.cert,
            ca_cert_path=args.ca_cert,
            crl_source=args.crl,
            ocsp_url=args.ocsp_url,
        )
        print(f"Статус:  {rev.status}")
        print(f"Метод:   {rev.method}")
        if rev.revocation_time:
            print(f"Отозван: {rev.revocation_time.isoformat()}")
        if rev.reason:
            print(f"Причина: {rev.reason}")
        print(f"Детали:  {rev.detail}")
        return 0 if rev.status != "revoked" else 1
    except (ValueError, FileNotFoundError) as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        log.error("%s", e)
        return 1
    except Exception as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        log.error("Непредвиденная ошибка: %s", e)
        return 1


# ════════════════════════════════════════
#  Форматировщики вывода
# ════════════════════════════════════════

def _print_table(certs: list[dict]) -> None:
    if not certs:
        print("Сертификаты не найдены.")
        return
    header = f"{'Serial':<20} {'Subject':<40} {'Status':<10} {'Expires':<22}"
    print(header)
    print("-" * len(header))
    for c in certs:
        print(
            f"{c['serial_hex'][:18]:<20} {c['subject'][:38]:<40} "
            f"{c['status']:<10} {c['not_after']:<22}"
        )
    print(f"\nВсего: {len(certs)} сертификат(ов)")


def _print_csv(certs: list[dict]) -> None:
    if not certs:
        print("Сертификаты не найдены.")
        return
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=["serial_hex", "subject", "issuer", "status", "not_before", "not_after"],
    )
    writer.writeheader()
    for c in certs:
        writer.writerow({k: c[k] for k in writer.fieldnames})
    print(buf.getvalue(), end="")


# ════════════════════════════════════════
#  Валидаторы
# ════════════════════════════════════════

def _ensure_log_dir(args) -> None:
    if hasattr(args, "log_file") and args.log_file:
        Path(args.log_file).parent.mkdir(parents=True, exist_ok=True)


def _validate_key_params(key_type: str, key_size: int | None) -> int:
    """Валидация параметров CA-ключа: RSA только 4096, ECC только 384."""
    if key_type == "rsa":
        size = key_size if key_size is not None else 4096
        if size != 4096:
            raise ValueError(f"Для CA RSA-ключ должен быть 4096 бит, получено {size}")
        return size
    size = key_size if key_size is not None else 384
    if size != 384:
        raise ValueError(f"Для CA ECC-ключ должен быть 384 бит, получено {size}")
    return size


def _client_key_size(key_type: str, key_size: int | None) -> int:
    """Значения по умолчанию для клиентских ключей (RSA-2048, ECC-256)."""
    if key_type == "rsa":
        return key_size if key_size is not None else 2048
    return key_size if key_size is not None else 256


def _validate_subject(subject: str, log) -> None:
    if not subject or not subject.strip():
        log.error("--subject пустой.")
        raise ValueError("--subject не может быть пустым.")


def _validate_validity_days(days: int, log) -> None:
    if days <= 0:
        log.error("--validity-days=%d не положительное.", days)
        raise ValueError("--validity-days должно быть положительным числом.")


def _validate_file_exists(path: str, description: str) -> None:
    p = Path(path)
    if not p.exists():
        raise ValueError(f"{description} не существует: '{path}'")
    if not p.is_file():
        raise ValueError(f"{description} не является файлом: '{path}'")


def _read_passphrase(passphrase_file: str, log) -> bytes:
    path = Path(passphrase_file)
    if not path.exists():
        raise ValueError(f"Файл с парольной фразой не существует: '{passphrase_file}'")
    if not path.is_file():
        raise ValueError(f"Путь к парольной фразе не является файлом: '{passphrase_file}'")
    if not os.access(str(path), os.R_OK):
        raise ValueError(f"Файл с парольной фразой недоступен для чтения: '{passphrase_file}'")
    passphrase = path.read_bytes().rstrip(b"\n").rstrip(b"\r\n")
    if not passphrase:
        raise ValueError("Файл с парольной фразой пуст.")
    log.info("Парольная фраза прочитана (содержимое скрыто).")
    return passphrase


def _validate_out_dir(out_dir: str) -> None:
    path = Path(out_dir)
    if path.exists():
        if not path.is_dir():
            raise ValueError(f"Выходной путь не является папкой: '{out_dir}'")
        if not os.access(str(path), os.W_OK):
            raise ValueError(f"Выходная папка недоступна для записи: '{out_dir}'")
