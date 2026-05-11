"""
Ограничитель скорости запросов (Rate Limiter) для MicroPKI (Sprint 7).

Реализует алгоритм «token bucket» (CTL-1):
  - Для каждого IP-адреса ведётся отдельный bucket.
  - Параметры: rate (запросов/сек) и burst (максимальный запас токенов).
  - Потокобезопасен: используется threading.Lock.
  - При превышении лимита возвращает (False, retry_after_sec).
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class _Bucket:
    """Состояние token bucket для одного клиента."""
    tokens: float
    last_refill: float = field(default_factory=time.monotonic)


class RateLimiter:
    """
    Потокобезопасный ограничитель скорости на основе token bucket.

    Аргументы:
        rate:  Количество токенов, добавляемых в секунду.
        burst: Максимальный запас токенов (размер bucket).

    Использование:
        limiter = RateLimiter(rate=5, burst=10)
        allowed, retry_after = limiter.consume("192.168.1.1")
        if not allowed:
            # Ответить HTTP 429 с заголовком Retry-After: retry_after
    """

    def __init__(self, rate: float, burst: int) -> None:
        if rate <= 0:
            raise ValueError("rate должен быть > 0.")
        if burst <= 0:
            raise ValueError("burst должен быть > 0.")

        self._rate = rate
        self._burst = float(burst)
        self._buckets: dict[str, _Bucket] = defaultdict(
            lambda: _Bucket(tokens=self._burst)
        )
        self._lock = threading.Lock()

    def consume(self, client_id: str) -> tuple[bool, float]:
        """
        Пытается потребить один токен для клиента.

        Аргументы:
            client_id: Идентификатор клиента (обычно IP-адрес).

        Возвращает:
            (True, 0.0)     — запрос разрешён.
            (False, N)      — запрос отклонён; N — секунд до следующего токена.
        """
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets[client_id]

            # Пополнение токенов пропорционально прошедшему времени
            elapsed = now - bucket.last_refill
            bucket.tokens = min(
                self._burst,
                bucket.tokens + elapsed * self._rate,
            )
            bucket.last_refill = now

            if bucket.tokens >= 1.0:
                bucket.tokens -= 1.0
                return True, 0.0
            else:
                # Время до появления следующего токена
                retry_after = (1.0 - bucket.tokens) / self._rate
                return False, round(retry_after, 2)

    def reset(self, client_id: str) -> None:
        """Сбрасывает bucket для клиента (для тестов)."""
        with self._lock:
            self._buckets.pop(client_id, None)

    @property
    def rate(self) -> float:
        return self._rate

    @property
    def burst(self) -> int:
        return int(self._burst)


def make_rate_limit_middleware(limiter: RateLimiter):
    """
    Создаёт WSGI-совместимый middleware для Flask/встроенного HTTP-сервера.

    Аргументы:
        limiter: Экземпляр RateLimiter.

    Возвращает:
        Функцию-декоратор для Flask-обработчиков.
    """
    def decorator(handler):
        def wrapper(environ, start_response):
            client_ip = (
                environ.get("HTTP_X_FORWARDED_FOR", "").split(",")[0].strip()
                or environ.get("REMOTE_ADDR", "unknown")
            )
            allowed, retry_after = limiter.consume(client_ip)
            if not allowed:
                body = b"429 Too Many Requests\n"
                start_response(
                    "429 Too Many Requests",
                    [
                        ("Content-Type", "text/plain"),
                        ("Content-Length", str(len(body))),
                        ("Retry-After", str(int(retry_after) + 1)),
                    ],
                )
                return [body]
            return handler(environ, start_response)
        return wrapper
    return decorator
