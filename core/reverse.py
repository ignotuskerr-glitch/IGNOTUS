import socket
from typing import Optional
from core.cache import reverse_cache

def reverse_dns(ip: str) -> Optional[str]:
    """
    Performs reverse DNS lookup (PTR record) for a given IP.
    Uses reverse_cache to avoid redundant networking.
    """
    if not ip:
        return None

    cached = reverse_cache.get(ip)
    if cached is not None:
        return cached

    try:
        # socket.gethostbyaddr returns a tuple: (hostname, aliaslist, ipaddrlist)
        hostname, _, _ = socket.gethostbyaddr(ip)
        reverse_cache.set(ip, hostname)
        return hostname
    except Exception:
        reverse_cache.set(ip, "")
        return None
