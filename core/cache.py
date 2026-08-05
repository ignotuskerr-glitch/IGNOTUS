import threading
from typing import Dict, Any, Callable

class ThreadSafeCache:
    def __init__(self):
        self._lock = threading.Lock()
        self._cache: Dict[str, Any] = {}

    def get(self, key: str) -> Any:
        with self._lock:
            return self._cache.get(key)

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self._cache[key] = value

    def get_or_set(self, key: str, resolver_fn: Callable[[], Any]) -> Any:
        with self._lock:
            if key in self._cache:
                return self._cache[key]
        
        # Call the resolver outside the lock if possible, or inside if it's safe and fast.
        # Inside the lock guarantees single execution for the key.
        with self._lock:
            if key in self._cache:
                return self._cache[key]
            value = resolver_fn()
            self._cache[key] = value
            return value

# Global cache instances
dns_cache = ThreadSafeCache()
asn_cache = ThreadSafeCache()
reverse_cache = ThreadSafeCache()
http_cache = ThreadSafeCache()
