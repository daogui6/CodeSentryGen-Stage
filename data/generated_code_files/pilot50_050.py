from collections.abc import Callable
from functools import wraps
from typing import Any


class MemoizingCollection:
    def __init__(self) -> None:
        self._cache: dict[tuple[Any, ...], Any] = {}

    def get(self, key: tuple[Any, ...]) -> Any | None:
        return self._cache.get(key)

    def set(self, key: tuple[Any, ...], value: Any) -> None:
        self._cache[key] = value

    def invalidate(self, key: tuple[Any, ...] | None = None) -> None:
        if key is None:
            self._cache.clear()
        else:
            self._cache.pop(key, None)

    def contains(self, key: tuple[Any, ...]) -> bool:
        return key in self._cache


def make_cache_key(args: tuple[Any, ...], kwargs: dict[str, Any]) -> tuple[Any, ...]:
    return args + tuple(sorted(kwargs.items()))


def memoize(collection: MemoizingCollection | None = None):
    cache = collection or MemoizingCollection()

    def decorator(function: Callable):
        @wraps(function)
        def wrapper(*args, **kwargs):
            key = make_cache_key(args, kwargs)

            if cache.contains(key):
                return cache.get(key)

            result = function(*args, **kwargs)
            cache.set(key, result)
            return result

        wrapper.invalidate_cache = cache.invalidate
        return wrapper

    return decorator


@memoize()
def fibonacci(number: int) -> int:
    if number < 2:
        return number
    return fibonacci(number - 1) + fibonacci(number - 2)


if __name__ == "__main__":
    print(fibonacci(10))
    fibonacci.invalidate_cache()
    print(fibonacci(8))
