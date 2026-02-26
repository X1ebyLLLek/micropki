"""
Шаблоны сертификатов для MicroPKI.

Определяет шаблоны server, client и code_signing с соответствующими
расширениями X.509v3 (Key Usage, Extended Key Usage, Basic Constraints).
Также обрабатывает парсинг и валидацию SAN в зависимости от типа шаблона.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import List

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID


@dataclass
class CertificateTemplate:
    """Определение шаблона сертификата с политиками расширений."""

    name: str
    # Флаги Key Usage
    digital_signature: bool = False
    key_encipherment: bool = False
    key_agreement: bool = False
    key_cert_sign: bool = False
    crl_sign: bool = False
    # OID для Extended Key Usage
    extended_key_usages: list = field(default_factory=list)
    # Политика SAN
    allowed_san_types: list = field(default_factory=list)
    require_san: bool = False


# ---- Определения шаблонов ----

SERVER_TEMPLATE = CertificateTemplate(
    name="server",
    digital_signature=True,
    key_encipherment=True,  # Для обмена ключами RSA; ECC переопределит
    extended_key_usages=[ExtendedKeyUsageOID.SERVER_AUTH],
    allowed_san_types=["dns", "ip"],
    require_san=True,
)

CLIENT_TEMPLATE = CertificateTemplate(
    name="client",
    digital_signature=True,
    key_agreement=False,
    extended_key_usages=[ExtendedKeyUsageOID.CLIENT_AUTH],
    allowed_san_types=["dns", "email", "uri"],
    require_san=False,
)

CODE_SIGNING_TEMPLATE = CertificateTemplate(
    name="code_signing",
    digital_signature=True,
    extended_key_usages=[ExtendedKeyUsageOID.CODE_SIGNING],
    allowed_san_types=["dns", "uri"],
    require_san=False,
)

TEMPLATES = {
    "server": SERVER_TEMPLATE,
    "client": CLIENT_TEMPLATE,
    "code_signing": CODE_SIGNING_TEMPLATE,
}


def get_template(name: str) -> CertificateTemplate:
    """
    Получить шаблон сертификата по имени.

    Аргументы:
        name: Имя шаблона ('server', 'client', 'code_signing').

    Возвращает:
        Соответствующий CertificateTemplate.

    Вызывает исключения:
        ValueError: Если имя шаблона неизвестно.
    """
    template = TEMPLATES.get(name)
    if template is None:
        raise ValueError(
            f"Неизвестный шаблон сертификата '{name}'. "
            f"Доступные: {', '.join(TEMPLATES.keys())}"
        )
    return template


def parse_san_entries(san_strings: list[str]) -> list[x509.GeneralName]:
    """
    Распарсить строки SAN в формате 'type:value' в объекты GeneralName.

    Поддерживаемые типы: dns, ip, email, uri.

    Аргументы:
        san_strings: Список строк SAN (например, ['dns:example.com', 'ip:1.2.3.4']).

    Возвращает:
        Список объектов x509.GeneralName.

    Вызывает исключения:
        ValueError: Если строка SAN имеет неверный формат или неподдерживаемый тип.
    """
    names = []
    for san in san_strings:
        if ":" not in san:
            raise ValueError(
                f"Неверный формат SAN: '{san}'. Ожидается 'type:value' "
                f"(например 'dns:example.com')."
            )

        san_type, _, san_value = san.partition(":")
        san_type = san_type.strip().lower()
        san_value = san_value.strip()

        if not san_value:
            raise ValueError(f"Пустое значение SAN для типа '{san_type}'.")

        if san_type == "dns":
            names.append(x509.DNSName(san_value))
        elif san_type == "ip":
            try:
                addr = ipaddress.ip_address(san_value)
            except ValueError:
                raise ValueError(f"Неверный IP-адрес в SAN: '{san_value}'.")
            names.append(x509.IPAddress(addr))
        elif san_type == "email":
            names.append(x509.RFC822Name(san_value))
        elif san_type == "uri":
            names.append(x509.UniformResourceIdentifier(san_value))
        else:
            raise ValueError(
                f"Неподдерживаемый тип SAN: '{san_type}'. "
                f"Поддерживаются: dns, ip, email, uri."
            )

    return names


def validate_sans_for_template(
    template: CertificateTemplate,
    san_entries: list[x509.GeneralName],
) -> None:
    """
    Проверить, совместимы ли предоставленные SAN с шаблоном.

    Аргументы:
        template: Шаблон сертификата.
        san_entries: Распарсенные объекты SAN GeneralName.

    Вызывает исключения:
        ValueError: Если требуемые SAN отсутствуют или содержат
                    неподдерживаемые типы для данного шаблона.
    """
    if template.require_san and not san_entries:
        raise ValueError(
            f"Шаблон '{template.name}' требует как минимум одну запись SAN."
        )

    # Сопоставление классов GeneralName с именами типов
    type_map = {
        x509.DNSName: "dns",
        x509.IPAddress: "ip",
        x509.RFC822Name: "email",
        x509.UniformResourceIdentifier: "uri",
    }

    for entry in san_entries:
        entry_type = type_map.get(type(entry))
        if entry_type and entry_type not in template.allowed_san_types:
            raise ValueError(
                f"Тип SAN '{entry_type}' не разрешен для шаблона "
                f"'{template.name}'. Разрешены: {', '.join(template.allowed_san_types)}"
            )
