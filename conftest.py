"""
Конфигурация pytest для MicroPKI.

Регистрирует кастомные маркеры и настраивает пропуск тестов производительности.
"""

import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--run-perf",
        action="store_true",
        default=False,
        help="Запустить тесты производительности (помечены @pytest.mark.perf)",
    )


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "perf: тест производительности (пропускается по умолчанию, используйте --run-perf для запуска)",
    )


def pytest_collection_modifyitems(config, items):
    # Пропускаем @perf тесты если не передан --run-perf
    if config.getoption("--run-perf"):
        return
    skip_perf = pytest.mark.skip(reason="Тест производительности — передайте --run-perf для запуска")
    for item in items:
        if "perf" in item.keywords:
            item.add_marker(skip_perf)
