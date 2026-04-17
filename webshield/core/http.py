"""
Shared HTTP session with sensible defaults.
All modules import get_client() — never create raw httpx.Client() in modules.

Termux / ARM / restricted environments:
- HTTP/2 is optional — falls back to HTTP/1.1 if h2 not installed
- SSL verification is off by default for wider compatibility
- Timeouts are conservative to work on mobile data connections
"""

from __future__ import annotations
import httpx
from typing import Optional, Dict
import threading
import sys

# Global auth state (set once by CLI --auth-cookie / --auth-header)
_auth_cookies: Dict[str, str] = {}
_auth_headers: Dict[str, str] = {}
_lock = threading.Lock()

# Detect HTTP/2 support (optional h2 package)
try:
    import h2  # noqa: F401
    _HTTP2_AVAILABLE = True
except ImportError:
    _HTTP2_AVAILABLE = False

# Detect if running on a resource-constrained environment (Termux / Android)
import os as _os
_IS_ANDROID = (
    "ANDROID_ROOT" in _os.environ or
    "TERMUX_VERSION" in _os.environ or
    _os.path.exists("/data/data/com.termux")
)

# Conservative timeout for mobile / slow connections
DEFAULT_TIMEOUT = 8.0 if _IS_ANDROID else 10.0


def set_auth_cookies(cookies: Dict[str, str]) -> None:
    with _lock:
        _auth_cookies.update(cookies)


def set_auth_headers(headers: Dict[str, str]) -> None:
    with _lock:
        _auth_headers.update(headers)


def clear_auth() -> None:
    with _lock:
        _auth_cookies.clear()
        _auth_headers.clear()


def is_android() -> bool:
    """Returns True when running inside Termux / Android."""
    return _IS_ANDROID


DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Linux; Android 13; Pixel 7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Mobile Safari/537.36"
        if _IS_ANDROID else
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


def get_client(
    timeout: float = DEFAULT_TIMEOUT,
    verify_ssl: bool = False,
    follow_redirects: bool = True,
) -> httpx.Client:
    """Return a configured httpx Client for synchronous use.

    - HTTP/2 used only when h2 package is available
    - Falls back gracefully on Termux / ARM
    - Auth cookies/headers injected automatically if set
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
        follow_redirects=follow_redirects,
        http2=_HTTP2_AVAILABLE,
    )


def get_async_client(
    timeout: float = DEFAULT_TIMEOUT,
    verify_ssl: bool = False,
    follow_redirects: bool = True,
) -> httpx.AsyncClient:
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
        follow_redirects=follow_redirects,
        http2=_HTTP2_AVAILABLE,
    )


def normalize_url(url: str) -> str:
    """Ensure URL has a scheme."""
    url = url.strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url
