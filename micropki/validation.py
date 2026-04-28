"""
Движок проверки пути сертификации (RFC 5280, упрощённая реализация) для MicroPKI.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

logger = logging.getLogger("micropki")


@dataclass
class StepResult:
    name: str
    passed: bool
    detail: str = ""


@dataclass
class ValidationResult:
    valid: bool
    chain: list = field(default_factory=list)
    steps: list = field(default_factory=list)
    error: str = ""

    def add_step(self, name: str, passed: bool, detail: str = "") -> None:
        self.steps.append(StepResult(name, passed, detail))
        if not passed and not self.error:
            self.error = detail or name


def build_chain(
    leaf: x509.Certificate,
    untrusted: list[x509.Certificate],
    trusted: list[x509.Certificate],
) -> list[x509.Certificate] | None:
    """
    Строит цепочку от leaf до trusted root.
    Возвращает [leaf, ..., root] или None, если цепочка не построена.
    Выбирает кратчайший валидный путь.
    """
    # Индексируем по строке subject (rfc4514) для поиска издателей
    candidates: dict[str, list[x509.Certificate]] = {}
    for c in untrusted + trusted:
        key = c.subject.rfc4514_string()
        candidates.setdefault(key, []).append(c)

    trusted_subjects = {c.subject.rfc4514_string() for c in trusted}

    def _build(cert: x509.Certificate, depth: int, visited: frozenset) -> list[x509.Certificate] | None:
        if depth > 20:
            return None

        subj = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()

        # Самоподписанный — якорь доверия
        if issuer == subj:
            if subj in trusted_subjects:
                return [cert]
            return None

        best: list[x509.Certificate] | None = None
        for candidate in candidates.get(issuer, []):
            cand_subj = candidate.subject.rfc4514_string()
            if cand_subj in visited:
                continue
            rest = _build(candidate, depth + 1, visited | {cand_subj})
            if rest is not None:
                chain = [cert] + rest
                if best is None or len(chain) < len(best):
                    best = chain
        return best

    leaf_subj = leaf.subject.rfc4514_string()
    return _build(leaf, 0, frozenset({leaf_subj}))


def _verify_signature(cert: x509.Certificate, issuer_cert: x509.Certificate) -> bool:
    """Верифицирует подпись сертификата открытым ключом издателя."""
    pub = issuer_cert.public_key()
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm),
            )
        else:
            return False
        return True
    except (InvalidSignature, Exception):
        return False


def validate_chain(
    chain: list[x509.Certificate],
    validation_time: datetime | None = None,
) -> ValidationResult:
    """
    Проверяет цепочку сертификатов.
    chain[0] — leaf, chain[-1] — доверенный root (не проверяется).
    """
    result = ValidationResult(valid=True, chain=chain)
    now = validation_time or datetime.now(tz=timezone.utc)

    if len(chain) < 2:
        result.valid = False
        result.add_step(
            "минимальная длина цепочки", False,
            "Цепочка должна содержать минимум 2 сертификата (leaf + root)",
        )
        return result

    for i, cert in enumerate(chain[:-1]):
        issuer_cert = chain[i + 1]

        # Проверка подписи
        sig_ok = _verify_signature(cert, issuer_cert)
        result.add_step(
            f"[{i}] подпись",
            sig_ok,
            f"Подпись действительна: {cert.subject.rfc4514_string()}" if sig_ok
            else f"Недействительная подпись: {cert.subject.rfc4514_string()}",
        )
        if not sig_ok:
            result.valid = False

        # Проверка срока действия
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        time_ok = not_before <= now <= not_after
        result.add_step(
            f"[{i}] срок действия",
            time_ok,
            f"notBefore={not_before.isoformat()}, notAfter={not_after.isoformat()}" if time_ok
            else (
                f"Сертификат ещё не действителен: notBefore={not_before.isoformat()}"
                if now < not_before
                else f"Сертификат истёк: notAfter={not_after.isoformat()}"
            ),
        )
        if not time_ok:
            result.valid = False

        # BasicConstraints
        try:
            bc_ext = cert.extensions.get_extension_for_class(x509.BasicConstraints)
            is_ca_cert = bc_ext.value.ca
        except x509.ExtensionNotFound:
            is_ca_cert = False

        if i == 0:
            # Первый сертификат может быть конечным субъектом (CA=False)
            # или CA-сертификатом (CA=True) — оба варианта допустимы
            result.add_step(
                f"[{i}] basicConstraints",
                True,
                "CA=True (промежуточный CA)" if is_ca_cert else "CA=False (конечный субъект)",
            )
        else:
            # Промежуточные позиции обязаны иметь CA=True
            bc_ok = is_ca_cert
            result.add_step(
                f"[{i}] basicConstraints (промежуточный CA)",
                bc_ok,
                "CA=True ✓" if bc_ok else "Промежуточный CA должен иметь CA=True",
            )
            if not bc_ok:
                result.valid = False

        # pathLenConstraint и KeyUsage — только для CA-сертификатов
        if is_ca_cert:
            try:
                bc_ext2 = cert.extensions.get_extension_for_class(x509.BasicConstraints)
                path_len = bc_ext2.value.path_length
                if path_len is not None:
                    # Количество подчинённых CA-сертификатов ниже данного
                    remaining = len(chain) - 2 - i
                    pl_ok = remaining <= path_len
                    result.add_step(
                        f"[{i}] pathLenConstraint",
                        pl_ok,
                        f"pathLen={path_len}, требуется {remaining}" if pl_ok
                        else f"Нарушение pathLenConstraint: limit={path_len}, required={remaining}",
                    )
                    if not pl_ok:
                        result.valid = False
            except x509.ExtensionNotFound:
                pass

            try:
                ku_ext = cert.extensions.get_extension_for_class(x509.KeyUsage)
                if ku_ext.critical:
                    ku_ok = ku_ext.value.key_cert_sign
                    result.add_step(
                        f"[{i}] keyUsage keyCertSign",
                        ku_ok,
                        "keyCertSign=True" if ku_ok
                        else "CA должен иметь keyCertSign=True",
                    )
                    if not ku_ok:
                        result.valid = False
            except x509.ExtensionNotFound:
                pass

    return result
