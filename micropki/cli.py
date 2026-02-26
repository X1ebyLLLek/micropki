"""
Парсер аргументов командной строки для MicroPKI.

Предоставляет команду `micropki` с подкомандами:
  - ca init                 (Спринт 1)
  - ca issue-intermediate   (Спринт 2)
  - ca issue-cert           (Спринт 2)
  - ca list-certs           (Спринт 3)
  - ca show-cert            (Спринт 3)
  - db init                 (Спринт 3)
  - repo serve              (Спринт 3)
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import sys
from pathlib import Path

from .ca import init_ca, issue_cert, issue_intermediate
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

    # ---- Группа команд ca ----
    ca_parser = subparsers.add_parser("ca", help="Операции Центра Сертификации (CA)")
    ca_subparsers = ca_parser.add_subparsers(
        title="подкоманды ca", dest="ca_command", help="Операции CA",
    )

    _add_ca_init_parser(ca_subparsers)
    _add_ca_issue_intermediate_parser(ca_subparsers)
    _add_ca_issue_cert_parser(ca_subparsers)
    _add_ca_list_certs_parser(ca_subparsers)
    _add_ca_show_cert_parser(ca_subparsers)

    ca_parser.set_defaults(func=lambda args: (ca_parser.print_help(sys.stderr) or 1))

    # ---- Группа команд db ----
    db_parser = subparsers.add_parser("db", help="Операции с базой данных")
    db_subparsers = db_parser.add_subparsers(
        title="подкоманды db", dest="db_command", help="Операции БД",
    )
    _add_db_init_parser(db_subparsers)
    db_parser.set_defaults(func=lambda args: (db_parser.print_help(sys.stderr) or 1))

    # ---- Группа команд repo ----
    repo_parser = subparsers.add_parser("repo", help="Операции репозитория")
    repo_subparsers = repo_parser.add_subparsers(
        title="подкоманды repo", dest="repo_command", help="Операции репозитория",
    )
    _add_repo_serve_parser(repo_subparsers)
    repo_parser.set_defaults(func=lambda args: (repo_parser.print_help(sys.stderr) or 1))

    return parser


# ---- Парсеры подкоманд ----

def _add_ca_init_parser(sub) -> None:
    p = sub.add_parser("init", help="Инициализировать самоподписанный Корневой CA")
    p.add_argument("--subject", required=True, help="Отличительное Имя (Distinguished Name)")
    p.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    p.add_argument("--key-size", type=int, help="RSA: 4096, ECC: 384")
    p.add_argument("--passphrase-file", required=True, help="Файл с парольной фразой")
    p.add_argument("--out-dir", default="./pki", help="Папка для вывода")
    p.add_argument("--validity-days", type=int, default=3650)
    p.add_argument("--log-file", default=None)
    p.add_argument("--force", action="store_true", default=False)
    p.add_argument("--db-path", default=DEFAULT_DB_PATH, help="Путь к базе данных")
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
    p.add_argument("--subject", required=True)
    p.add_argument("--san", action="append", dest="sans")
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
    p.add_argument("serial", help="Серийный номер сертификата (hex)")
    p.add_argument("--db-path", default=DEFAULT_DB_PATH)
    p.add_argument("--log-file", default=None)
    p.set_defaults(func=_handle_ca_show_cert)


def _add_db_init_parser(sub) -> None:
    p = sub.add_parser("init", help="Инициализировать базу сертификатов")
    p.add_argument("--db-path", default=DEFAULT_DB_PATH, help="Путь к файлу базы данных")
    p.add_argument("--log-file", default=None)
    p.set_defaults(func=_handle_db_init)


def _add_repo_serve_parser(sub) -> None:
    p = sub.add_parser("serve", help="Запустить HTTP сервер репозитория сертификатов")
    p.add_argument("--host", default="127.0.0.1", help="Адрес (host)")
    p.add_argument("--port", type=int, default=8080, help="TCP порт")
    p.add_argument("--db-path", default=DEFAULT_DB_PATH)
    p.add_argument("--cert-dir", default="./pki/certs", help="Папка с сертификатами CA")
    p.add_argument("--log-file", default=None)
    p.set_defaults(func=_handle_repo_serve)


# ---- Обработчики ----

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
        _validate_file_exists(args.root_cert, "Корневой сертификат (Root CA)")
        _validate_file_exists(args.root_key, "Приватный ключ корневого сертификата")
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
            db_path=args.db_path,
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
        print(f"База данных инициализирована по пути: {args.db_path}")
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
        log.info("Извлечено %d сертификатов из БД.", len(certs))

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
            print(f"Сертификат с серийным номером '{args.serial}' не найден.", file=sys.stderr)
            log.info("show-cert: серийный номер %s не найден.", args.serial)
            return 1
        log.info("show-cert: извлечен серийный номер %s.", args.serial)
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
        print(f"Запуск сервера репозитория на http://{args.host}:{args.port}")
        print(f"База данных: {args.db_path}, Папка сертификатов: {args.cert_dir}")
        print("Нажмите Ctrl+C для остановки.")
        run_server(
            host=args.host, port=args.port,
            db_path=args.db_path, cert_dir=args.cert_dir,
        )
        return 0
    except Exception as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        log.error("Ошибка сервера: %s", e)
        return 1


# ---- Форматировщики вывода ----

def _print_table(certs: list[dict]) -> None:
    """Вывод сертификатов в виде таблицы."""
    if not certs:
        print("Сертификаты не найдены.")
        return

    header = f"{'Serial':<20} {'Subject':<40} {'Status':<10} {'Expires':<22}"
    print(header)
    print("-" * len(header))
    for c in certs:
        serial = c["serial_hex"][:18]
        subject = c["subject"][:38]
        print(f"{serial:<20} {subject:<40} {c['status']:<10} {c['not_after']:<22}")
    print(f"\nВсего: {len(certs)} сертификат(ов)")


def _print_csv(certs: list[dict]) -> None:
    """Вывод сертификатов в формате CSV."""
    if not certs:
        print("Сертификаты не найдены.")
        return

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=["serial_hex", "subject", "issuer", "status", "not_before", "not_after"])
    writer.writeheader()
    for c in certs:
        writer.writerow({k: c[k] for k in writer.fieldnames})
    print(buf.getvalue(), end="")


# ---- Валидаторы ----

def _ensure_log_dir(args) -> None:
    if hasattr(args, "log_file") and args.log_file:
        Path(args.log_file).parent.mkdir(parents=True, exist_ok=True)


def _validate_key_params(key_type: str, key_size: int | None) -> int:
    if key_type == "rsa":
        if key_size is None:
            return 4096
        if key_size != 4096:
            raise ValueError(f"Размер ключа RSA должен быть 4096, получено {key_size}.")
        return key_size
    else:
        if key_size is None:
            return 384
        if key_size != 384:
            raise ValueError(f"Размер ключа ECC должен быть 384 (NIST P-384), получено {key_size}.")
        return key_size


def _validate_subject(subject: str, log) -> None:
    if not subject or not subject.strip():
        log.error("Validation failed: --subject is empty.")
        raise ValueError("--subject не может быть пустым.")


def _validate_validity_days(days: int, log) -> None:
    if days <= 0:
        log.error("Validation failed: --validity-days=%d is not positive.", days)
        raise ValueError("--validity-days должно быть положительным числом.")


def _validate_file_exists(path: str, description: str) -> None:
    p = Path(path)
    if not p.exists():
        raise ValueError(f"{description} не существует: '{path}'")
    if not p.is_file():
        raise ValueError(f"{description} не является файлом: '{path}'")


def _read_passphrase(passphrase_file: str, log) -> bytes:
    """Безопасное чтение парольной фразы из файла. Не записывается в лог."""
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

    log.info("Файл с парольной фразой успешно прочитан (содержимое скрыто).")
    return passphrase


def _validate_out_dir(out_dir: str) -> None:
    path = Path(out_dir)
    if path.exists():
        if not path.is_dir():
            raise ValueError(f"Выходной путь существует, но не является папкой: '{out_dir}'")
        if not os.access(str(path), os.W_OK):
            raise ValueError(f"Выходная папка недоступна для записи: '{out_dir}'")
