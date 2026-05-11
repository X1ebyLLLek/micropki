"""
Проверка политик безопасности PKI (Sprint 7).

Реализует обязательные ограничения:
  POL-3: минимальные размеры ключей (RSA / ECC)
  POL-4: максимальные сроки действия сертификатов
  POL-5: ограничения SAN (wildcards, типы по шаблону)
  POL-6: алгоритмы подписи (SHA-1 запрещён)
  POL-7: pathLen для промежуточных CA
"""

from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

# ------------------------------------------------------------------ #
#  Минимальные размеры ключей                                          #
# ------------------------------------------------------------------ #

# RSA: минимальный размер ключа (бит) по роли
_RSA_MIN_BITS: dict[str, int] = {
    "root":         4096,
    "intermediate": 2048,  # рекомендуется 3072, минимум 2048
    "end_entity":   2048,
}

# ECC: список допустимых кривых по роли (в порядке строгости)
_ECC_FORBIDDEN_FOR_CA = {ec.SECP256R1}  # P-256 запрещён для root/intermediate


# ------------------------------------------------------------------ #
#  Максимальные сроки действия                                         #
# ------------------------------------------------------------------ #

MAX_VALIDITY_DAYS: dict[str, int] = {
    "root":         3650,  # 10 лет
    "intermediate": 1825,  # 5 лет
    "end_entity":   365,   # 1 год
}

# ------------------------------------------------------------------ #
#  Публичные функции проверки                                          #
# ------------------------------------------------------------------ #


def check_key_size(public_key: object, role: str) -> None:
    """
    Проверяет, что размер/кривая ключа соответствует политике для данной роли.

    Аргументы:
        public_key: Объект открытого ключа (RSA или ECC).
        role:       "root", "intermediate" или "end_entity".

    Вызывает исключения:
        ValueError: Если ключ не соответствует политике.
    """
    if isinstance(public_key, rsa.RSAPublicKey):
        min_bits = _RSA_MIN_BITS.get(role, 2048)
        actual = public_key.key_size
        if actual < min_bits:
            raise ValueError(
                f"Размер RSA-ключа {actual} бит недостаточен для роли '{role}'. "
                f"Минимум: {min_bits} бит."
            )

    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        curve = type(public_key.curve)
        if role in ("root", "intermediate") and curve in _ECC_FORBIDDEN_FOR_CA:
            raise ValueError(
                f"Кривая P-256 запрещена для роли '{role}'. "
                f"Используйте P-384 (secp384r1) или сильнее."
            )
        # P-256 и P-384 допустимы для конечных субъектов
    else:
        raise ValueError(
            f"Неподдерживаемый тип ключа: {type(public_key).__name__}. "
            "Поддерживаются RSA и ECC."
        )


def check_validity_days(validity_days: int, role: str) -> None:
    """
    Проверяет, что срок действия не превышает максимально допустимый для роли.

    Аргументы:
        validity_days: Запрошенный срок в днях.
        role:          "root", "intermediate" или "end_entity".

    Вызывает исключения:
        ValueError: Если срок превышает лимит.
    """
    max_days = MAX_VALIDITY_DAYS.get(role)
    if max_days is None:
        raise ValueError(f"Неизвестная роль: '{role}'.")

    if validity_days > max_days:
        raise ValueError(
            f"Срок действия {validity_days} дней превышает максимум "
            f"для роли '{role}' ({max_days} дней)."
        )


def check_san_policy(
    san_entries: list[x509.GeneralName],
    template_name: str,
    allow_wildcards: bool = False,
) -> None:
    """
    Проверяет SAN-записи согласно политике шаблона.

    Правила:
      - server:       только dns и ip; wildcards по умолчанию запрещены.
      - client:       разрешены email и dns; ip и uri допустимы.
      - code_signing: разрешены dns и uri; ip и email запрещены.

    Аргументы:
        san_entries:     Список объектов GeneralName.
        template_name:   Имя шаблона.
        allow_wildcards: Если True — wildcard DNS разрешены.

    Вызывает исключения:
        ValueError: При нарушении политики.
    """
    forbidden_by_template: dict[str, set[type]] = {
        "server":       {x509.RFC822Name, x509.UniformResourceIdentifier},
        "client":       set(),  # всё разрешено (email предпочтителен, но ip/uri не запрещены)
        "code_signing": {x509.IPAddress, x509.RFC822Name},
    }

    forbidden_types = forbidden_by_template.get(template_name, set())

    for entry in san_entries:
        entry_cls = type(entry)
        if entry_cls in forbidden_types:
            _type_name = _san_type_name(entry)
            raise ValueError(
                f"Тип SAN '{_type_name}' не разрешен для шаблона '{template_name}'."
            )

        # Проверка wildcard-DNS
        if isinstance(entry, x509.DNSName) and entry.value.startswith("*."):
            if not allow_wildcards:
                raise ValueError(
                    f"Wildcard SAN '{entry.value}' запрещён политикой. "
                    "Используйте --allow-wildcards для явного разрешения."
                )


def check_signature_algorithm(cert_or_csr: object) -> None:
    """
    Проверяет, что алгоритм подписи соответствует политике (SHA-1 запрещён).

    Аргументы:
        cert_or_csr: Объект x509.Certificate или x509.CertificateSigningRequest.

    Вызывает исключения:
        ValueError: Если используется SHA-1.
    """
    from cryptography.hazmat.primitives import hashes as _h

    hash_alg = None
    sig_alg = getattr(cert_or_csr, "signature_hash_algorithm", None)
    if sig_alg is not None:
        hash_alg = type(sig_alg)

    if hash_alg is _h.SHA1:
        raise ValueError(
            "SHA-1 запрещён политикой безопасности. "
            "Используйте SHA-256, SHA-384 или SHA-512."
        )


def check_path_length(path_length: int | None, role: str) -> None:
    """
    Проверяет ограничение pathLen для сертификата CA.

    По умолчанию промежуточный CA должен иметь pathLen=0.

    Аргументы:
        path_length: Значение pathLen из BasicConstraints (None или int).
        role:        "root" или "intermediate".

    Вызывает исключения:
        ValueError: Если pathLen нарушает политику.
    """
    if role == "intermediate":
        if path_length is not None and path_length > 0:
            raise ValueError(
                f"Промежуточный CA должен иметь pathLen=0 (получено {path_length}). "
                "Используйте --allow-subordinate для явного разрешения (не реализовано)."
            )


# ------------------------------------------------------------------ #
#  Утилиты                                                             #
# ------------------------------------------------------------------ #

def _san_type_name(entry: x509.GeneralName) -> str:
    """Возвращает строковое имя типа SAN для сообщений об ошибках."""
    mapping = {
        x509.DNSName:                    "dns",
        x509.IPAddress:                  "ip",
        x509.RFC822Name:                 "email",
        x509.UniformResourceIdentifier: "uri",
    }
    return mapping.get(type(entry), type(entry).__name__)
