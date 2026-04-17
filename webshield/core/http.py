"""
Shared HTTP session with sensible defaults.
All modules import get_client() — never create raw httpx.Client() in modules.
"""

from __future__ import annotations
import httpx
from typing import Optional, Dict
import threading

# Global auth state (set once by CLI --auth-cookie / --auth-header)
_auth_cookies: Dict[str, str] = {}
_auth_headers: Dict[str, str] = {}
_lock = threading.Lock()


def set_auth_cookies(cookies: Dict[str, str]) -> None:
    """Set session-level auth cookies for all subsequent requests."""
    with _lock:
        _auth_cookies.update(cookies)


def set_auth_headers(headers: Dict[str, str]) -> None:
    """Set session-level auth headers (e.g. Authorization: Bearer <token>)."""
    with _lock:
        _auth_headers.update(headers)


def clear_auth() -> None:
    """Clear all auth state."""
    with _lock:
        _auth_cookies.clear()
        _auth_headers.clear()


DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.5",
}


def get_client(timeout: float = 10.0, verify_ssl: bool = False) -> httpx.Client:
    """Return a configured httpx Client for synchronous use.

    Automatically includes auth cookies/headers if set via set_auth_cookies()
    or set_auth_headers().
    """
    merged_headers = {**DEFAULT_HEADERS}
    with _lock:
        merged_headers.update(_auth_headers)
        cookies = dict(_auth_cookies)

    return httpx.Client(
        headers=merged_headers,
        cookies=cookies if cookies else None,
        timeout=timeout,
        verify=verify_ssl,
        follow_redirects=True,
        http2=True,
    )


def get_async_client(timeout: float = 10.0, verify_ssl: bool = False) -> httpx.AsyncClient:
    """Return a configured httpx AsyncClient for async use."""
    merged_headers = {**DEFAULT_HEADERS}
    with _lock:
        merged_headers.update(_auth_headers)
        cookies = dict(_auth_cookies)

    return httpx.AsyncClient(
        headers=merged_headers,
        cookies=cookies if cookies else None,
        timeout=timeout,
        verify=verify_ssl,
        follow_redirects=True,
        http2=True,
    )


def normalize_url(url: str) -> str:
    """Ensure URL has a scheme."""
    url = url.strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url
