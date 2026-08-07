from typing import Any


class MemoryCache:
    def __init__(self):
        self._cache: dict[str, Any] = {}

    def get(self, key: str):
        return self._cache.get(key)

    def set(self, key: str, value: Any):
        self._cache[key] = value

    def exists(self, key: str) -> bool:
        return key in self._cache

    def delete(self, key: str):
        self._cache.pop(key, None)

    def clear(self):
        self._cache.clear()