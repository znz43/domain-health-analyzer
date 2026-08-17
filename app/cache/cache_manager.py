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

        # ------------------------------------------------------
        # MEMORY CACHE
        # ------------------------------------------------------

        value = self.memory.get(
            mem_key
        )

        if value is not None:
            return value

        # ------------------------------------------------------
        # FILE CACHE
        # ------------------------------------------------------

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

        # ------------------------------------------------------
        # MEMORY CACHE
        # ------------------------------------------------------

        self.memory.set(
            mem_key,
            value
        )

        # ------------------------------------------------------
        # FILE CACHE
        # ------------------------------------------------------

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

        print(
            f"CACHE DELETE: {namespace}/{key}"
        )

        # ------------------------------------------------------
        # MEMORY CACHE
        # ------------------------------------------------------

        self.memory.delete(
            mem_key
        )

        # ------------------------------------------------------
        # FILE CACHE
        # ------------------------------------------------------

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

    # ==========================================================
    # CLEAR NAMESPACE
    # ==========================================================

    def clear_namespace(
        self,
        namespace
    ):

        """
        Clear all cached values from a namespace.

        This method is intentionally optional and does not
        affect existing cache behaviour.
        """

        print(
            f"CACHE CLEAR NAMESPACE: {namespace}"
        )

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