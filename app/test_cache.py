from cache.cache_manager import CacheManager


cache = CacheManager()


def load_data():

    print("CALLING API")

    return {
        "test": True
    }


result1 = cache.remember(
    "test",
    "example",
    24,
    load_data
)


result2 = cache.remember(
    "test",
    "example",
    24,
    load_data
)


print(result1)
print(result2)