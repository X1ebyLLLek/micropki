"""Интеграционные тесты CLI - негативные / пограничные случаи."""

import pytest

from micropki.cli import main


class TestCLIValidation:
    """Тесты валидации аргументов CLI и обработки ошибок."""

    def test_missing_subject(self, tmp_path):
        """Отсутствие параметра --subject должно вызывать ошибку."""
        passfile = tmp_path / "pass.txt"
        passfile.write_text("testpass")

        # argparse должен завершиться с ошибкой из-за отсутствия обязательного аргумента
        with pytest.raises(SystemExit) as exc_info:
            main([
                "ca", "init",
                "--passphrase-file", str(passfile),
                "--out-dir", str(tmp_path / "pki"),
            ])
        assert exc_info.value.code != 0

    def test_invalid_key_size_ecc_256(self, tmp_path):
        """--key-type ecc с размером ключа 256 должно завершаться ошибкой."""
        passfile = tmp_path / "pass.txt"
        passfile.write_bytes(b"testpass")

        result = main([
            "ca", "init",
            "--subject", "/CN=Test",
            "--key-type", "ecc",
            "--key-size", "256",
            "--passphrase-file", str(passfile),
            "--out-dir", str(tmp_path / "pki"),
        ])
        assert result != 0

    def test_invalid_key_size_rsa_2048(self, tmp_path):
        """--key-type rsa с размером ключа 2048 должно завершаться ошибкой."""
        passfile = tmp_path / "pass.txt"
        passfile.write_bytes(b"testpass")

        result = main([
            "ca", "init",
            "--subject", "/CN=Test",
            "--key-type", "rsa",
            "--key-size", "2048",
            "--passphrase-file", str(passfile),
            "--out-dir", str(tmp_path / "pki"),
        ])
        assert result != 0

    def test_nonexistent_passphrase_file(self, tmp_path):
        """Несуществующий файл с парольной фразой должен вызывать ошибку."""
        result = main([
            "ca", "init",
            "--subject", "/CN=Test",
            "--passphrase-file", str(tmp_path / "does-not-exist.txt"),
            "--out-dir", str(tmp_path / "pki"),
        ])
        assert result != 0

    def test_invalid_key_type(self, tmp_path):
        """Неверное значение --key-type должно вызывать ошибку."""
        passfile = tmp_path / "pass.txt"
        passfile.write_bytes(b"testpass")

        with pytest.raises(SystemExit) as exc_info:
            main([
                "ca", "init",
                "--subject", "/CN=Test",
                "--key-type", "dsa",
                "--passphrase-file", str(passfile),
                "--out-dir", str(tmp_path / "pki"),
            ])
        assert exc_info.value.code != 0

    def test_no_subcommand_shows_help(self):
        """Запуск без аргументов должен выводить справку и возвращать 1."""
        result = main([])
        assert result == 1

    def test_successful_ca_init_returns_zero(self, tmp_path):
        """Успешная инициализация CA должна возвращать код 0."""
        passfile = tmp_path / "pass.txt"
        passfile.write_bytes(b"mypassphrase")

        result = main([
            "ca", "init",
            "--subject", "/CN=CLI Test CA",
            "--key-type", "rsa",
            "--key-size", "4096",
            "--passphrase-file", str(passfile),
            "--out-dir", str(tmp_path / "pki"),
            "--validity-days", "365",
            "--db-path", str(tmp_path / "pki" / "test.db"),
        ])
        assert result == 0

        # Проверить, что файлы были созданы
        assert (tmp_path / "pki" / "private" / "ca.key.pem").exists()
        assert (tmp_path / "pki" / "certs" / "ca.cert.pem").exists()
        assert (tmp_path / "pki" / "policy.txt").exists()

    def test_empty_passphrase_file(self, tmp_path):
        """Пустой файл парольной фразы должен вызывать ошибку."""
        passfile = tmp_path / "pass.txt"
        passfile.write_bytes(b"")

        result = main([
            "ca", "init",
            "--subject", "/CN=Test",
            "--passphrase-file", str(passfile),
            "--out-dir", str(tmp_path / "pki"),
        ])
        assert result != 0

    def test_log_file_creation(self, tmp_path):
        """Должен создаваться файл журнала, если указан --log-file."""
        passfile = tmp_path / "pass.txt"
        passfile.write_bytes(b"testpass")
        log_file = tmp_path / "logs" / "test.log"

        result = main([
            "ca", "init",
            "--subject", "/CN=Log Test",
            "--passphrase-file", str(passfile),
            "--out-dir", str(tmp_path / "pki"),
            "--log-file", str(log_file),
            "--db-path", str(tmp_path / "pki" / "test.db"),
        ])
        assert result == 0
        assert log_file.exists()

        log_content = log_file.read_text(encoding="utf-8")
        assert "INFO" in log_content
        assert "passphrase" not in log_content.lower() or "redacted" in log_content.lower()
