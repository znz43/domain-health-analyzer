import json
from datetime import datetime, timedelta
from pathlib import Path


class FileCache:

    def __init__(self, cache_dir="cache_data"):
        self.base = Path(cache_dir)
        self.base.mkdir(parents=True, exist_ok=True)

    def _path(self, namespace: str, key: str):

        folder = self.base / namespace
        folder.mkdir(parents=True, exist_ok=True)

        safe = key.replace("/", "_")

        return folder / f"{safe}.json"

    def get(self, namespace, key):

        path = self._path(namespace, key)

        if not path.exists():
            return None

        with open(path, "r", encoding="utf8") as f:
            obj = json.load(f)

        expires = datetime.fromisoformat(obj["expires"])

        if datetime.utcnow() > expires:
            path.unlink(missing_ok=True)
            return None

        return obj["data"]

    def set(self, namespace, key, value, ttl_hours=24):

        path = self._path(namespace, key)

        expires = datetime.utcnow() + timedelta(hours=ttl_hours)

        with open(path, "w", encoding="utf8") as f:

            json.dump(
                {
                    "expires": expires.isoformat(),
                    "data": value
                },
                f,
                indent=2
            )

    def delete(self, namespace, key):

        self._path(namespace, key).unlink(missing_ok=True)