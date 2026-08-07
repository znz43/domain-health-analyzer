from .memory_cache import MemoryCache
from .file_cache import FileCache


class CacheManager:

    def __init__(self):
        self.memory = MemoryCache()
        self.file = FileCache()

    def _memory_key(self, namespace, key):
        return f"{namespace}:{key}"

    def get(self, namespace, key):

        mem_key = self._memory_key(namespace, key)

        value = self.memory.get(mem_key)

        if value is not None:
            return value

        value = self.file.get(
            namespace,
            key
        )

        if value is not None:
            self.memory.set(
                mem_key,
                value
            )

        return value


    def set(
        self,
        namespace,
        key,
        value,
        ttl_hours=24
    ):

        mem_key = self._memory_key(
            namespace,
            key
        )

        self.memory.set(
            mem_key,
            value
        )

        self.file.set(
            namespace,
            key,
            value,
            ttl_hours
        )


    def delete(
        self,
        namespace,
        key
    ):

        mem_key = self._memory_key(
            namespace,
            key
        )

        self.memory.delete(mem_key)

        self.file.delete(
            namespace,
            key
        )


    def remember(
        self,
        namespace,
        key,
        ttl_hours,
        loader
    ):

        value = self.get(
            namespace,
            key
        )

        if value is not None:
            print(
                f"CACHE HIT: {namespace}/{key}"
            )
            return value


        print(
            f"CACHE MISS: {namespace}/{key}"
        )

        value = loader()


        self.set(
            namespace,
            key,
            value,
            ttl_hours
        )

        return value