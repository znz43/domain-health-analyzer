from .memory_cache import MemoryCache
from .file_cache import FileCache


class CacheManager:

    def __init__(self):

        self.memory = MemoryCache()
        self.file = FileCache()

    # ==========================================================
    # INTERNAL
    # ==========================================================

    def _memory_key(
        self,
        namespace,
        key
    ):

        return f"{namespace}:{key}"

    # ==========================================================
    # GET
    # ==========================================================

    def get(
        self,
        namespace,
        key
    ):

        mem_key = self._memory_key(
            namespace,
            key
        )

        value = self.memory.get(
            mem_key
        )

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

        return None

    # ==========================================================
    # SET
    # ==========================================================

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

    # ==========================================================
    # DELETE
    # ==========================================================

    def delete(
        self,
        namespace,
        key
    ):

        mem_key = self._memory_key(
            namespace,
            key
        )

        self.memory.delete(
            mem_key
        )

        self.file.delete(
            namespace,
            key
        )

    # ==========================================================
    # REMEMBER
    # ==========================================================

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
            return value

        value = loader()

        if value is not None:

            self.set(
                namespace,
                key,
                value,
                ttl_hours
            )

        return value

    # ==========================================================
    # CLEAR NAMESPACE
    # ==========================================================

    def clear_namespace(
        self,
        namespace
    ):

        if hasattr(
            self.file,
            "clear_namespace"
        ):

            self.file.clear_namespace(
                namespace
            )

        if hasattr(
            self.memory,
            "clear_namespace"
        ):

            self.memory.clear_namespace(
                namespace
            )