import time


class FakeEmailSender:
    def __init__(self):
        self.sent = []

    def ensure_ready(self):
        return None

    def send_text(self, email: str, subject: str, text: str):
        self.sent.append(
            {
                "email": email,
                "subject": subject,
                "text": text,
            }
        )


class FakeRedis:
    def __init__(self):
        self._values = {}
        self._expires_at = {}

    def _purge_if_expired(self, key):
        expires_at = self._expires_at.get(key)
        if expires_at is not None and expires_at <= time.monotonic():
            self._values.pop(key, None)
            self._expires_at.pop(key, None)

    def set(self, key, value, ex=None):
        self._values[key] = value
        if ex is None:
            self._expires_at.pop(key, None)
        else:
            self._expires_at[key] = time.monotonic() + ex
        return True

    def get(self, key):
        self._purge_if_expired(key)
        return self._values.get(key)

    def delete(self, *keys):
        deleted = 0
        for key in keys:
            self._purge_if_expired(key)
            if key in self._values:
                deleted += 1
            self._values.pop(key, None)
            self._expires_at.pop(key, None)
        return deleted

    def incr(self, key):
        self._purge_if_expired(key)
        current = int(self._values.get(key, 0)) + 1
        self._values[key] = current
        return current

    def expire(self, key, seconds):
        self._purge_if_expired(key)
        if key not in self._values:
            return False
        self._expires_at[key] = time.monotonic() + seconds
        return True

    def ttl(self, key):
        self._purge_if_expired(key)
        if key not in self._values:
            return -2
        expires_at = self._expires_at.get(key)
        if expires_at is None:
            return -1
        return max(0, int(expires_at - time.monotonic()))

    def clear(self):
        self._values.clear()
        self._expires_at.clear()
