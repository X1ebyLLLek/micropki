"""Тесты для модуля templates: парсинг SAN, валидация, определения шаблонов."""

import pytest

from cryptography import x509

from micropki.templates import (
    get_template,
    parse_san_entries,
    validate_sans_for_template,
)


class TestTemplates:
    """Тесты определений шаблонов сертификатов."""

    def test_get_server_template(self):
        t = get_template("server")
        assert t.name == "server"
        assert t.digital_signature is True
        assert t.key_encipherment is True
        assert t.require_san is True

    def test_get_client_template(self):
        t = get_template("client")
        assert t.name == "client"
        assert t.require_san is False

    def test_get_code_signing_template(self):
        t = get_template("code_signing")
        assert t.name == "code_signing"
        assert t.require_san is False

    def test_unknown_template_raises(self):
        with pytest.raises(ValueError, match="Неизвестный шаблон сертификата"):
            get_template("nonexistent_template")


class TestSANParsing:
    """Тесты парсинга строк SAN."""

    def test_parse_dns(self):
        result = parse_san_entries(["dns:example.com"])
        assert len(result) == 1
        assert isinstance(result[0], x509.DNSName)
        assert result[0].value == "example.com"

    def test_parse_ip(self):
        result = parse_san_entries(["ip:192.168.1.1"])
        assert len(result) == 1
        assert isinstance(result[0], x509.IPAddress)

    def test_parse_email(self):
        result = parse_san_entries(["email:alice@example.com"])
        assert len(result) == 1
        assert isinstance(result[0], x509.RFC822Name)

    def test_parse_uri(self):
        result = parse_san_entries(["uri:https://example.com"])
        assert len(result) == 1
        assert isinstance(result[0], x509.UniformResourceIdentifier)

    def test_parse_multiple(self):
        result = parse_san_entries([
            "dns:example.com",
            "dns:www.example.com",
            "ip:10.0.0.1",
        ])
        assert len(result) == 3

    def test_invalid_format_raises(self):
        with pytest.raises(ValueError, match="Неверный формат SAN"):
            parse_san_entries(["invalidformat"])

    def test_unsupported_type_raises(self):
        with pytest.raises(ValueError, match="Неподдерживаемый тип SAN"):
            parse_san_entries(["UNKNOWN:value"])

    def test_invalid_ip_raises(self):
        with pytest.raises(ValueError, match="Неверный IP-адрес"):
            parse_san_entries(["IP:invalid-ip"])

    def test_empty_value_raises(self):
        with pytest.raises(ValueError, match="Пустое значение SAN"):
            parse_san_entries(["DNS:"])


class TestSANValidation:
    """Тесты валидации совместимости SAN и шаблонов."""

    def test_server_requires_san(self):
        t = get_template("server")
        with pytest.raises(ValueError, match="Шаблон .+ требует как минимум одну запись SAN"):
            validate_sans_for_template(t, [])

    def test_server_accepts_dns(self):
        t = get_template("server")
        sans = parse_san_entries(["dns:example.com"])
        validate_sans_for_template(t, sans)  # Не должно вызывать исключений

    def test_server_rejects_email(self):
        t = get_template("server")
        sans = parse_san_entries(["email:a@b.com"])
        with pytest.raises(ValueError, match="не разрешен"):
            validate_sans_for_template(t, sans)

    def test_code_signing_rejects_ip(self):
        t = get_template("code_signing")
        sans = parse_san_entries(["ip:1.2.3.4"])
        with pytest.raises(ValueError, match="не разрешен"):
            validate_sans_for_template(t, sans)

    def test_client_accepts_email(self):
        t = get_template("client")
        sans = parse_san_entries(["email:alice@test.com"])
        validate_sans_for_template(t, sans)  # Не должно вызывать исключений

    def test_client_no_san_ok(self):
        t = get_template("client")
        validate_sans_for_template(t, [])  # Не должно вызывать исключений
