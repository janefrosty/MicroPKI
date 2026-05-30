import time
from collections import defaultdict
from threading import Lock

class RateLimit:
    """Реализация алгоритма Token Bucket для ограничения запросов."""
    def __init__(self, rate: int, burst: int):
        self.rate = rate
        self.burst = burst
        self.buckets = defaultdict(lambda: (burst, time.time()))
        self.lock = Lock()

    def check(self, client_ip: str) -> bool:
        """Проверяет, может ли клиент выполнить запрос. Возвращает True, если разрешено."""
        if self.rate == 0:
            return True
        
        with self.lock:
            tokens, last = self.buckets[client_ip]
            now = time.time()
            elapsed = now - last
            # Добавляем новые токены в корзину, но не больше burst
            tokens = min(self.burst, tokens + elapsed * self.rate)
            
            if tokens >= 1:
                self.buckets[client_ip] = (tokens - 1, now)
                return True
            else:
                return False