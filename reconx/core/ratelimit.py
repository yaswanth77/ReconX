"""
Token-bucket rate limiter.

Applied globally across all HTTP-touching stages to stay
within target's tolerance and avoid bans.
"""

import time
import threading


class RateLimiter:
    """
    Thread-safe token-bucket rate limiter.

    Usage:
        limiter = RateLimiter(rate=10)  # 10 requests/sec
        limiter.acquire()  # blocks until a token is available
    """

    def __init__(self, rate: float = 10.0):
        """
        Args:
            rate: Maximum requests per second.
        """
        self.rate = rate
        self.tokens = rate
        self.max_tokens = rate
        self.last_refill = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self):
        """Block until a token is available."""
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self.last_refill
                self.tokens = min(
                    self.max_tokens,
                    self.tokens + elapsed * self.rate,
                )
                self.last_refill = now

                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return

            # Wait a short interval before trying again
            time.sleep(1.0 / self.rate)

    def set_rate(self, rate: float):
        """Update the rate limit dynamically."""
        with self._lock:
            self.rate = rate
            self.max_tokens = rate
