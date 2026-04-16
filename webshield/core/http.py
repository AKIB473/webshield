"""
Shared HTTP session with sensible defaults.
All modules import get_session() — never create raw requests.Session() in modules.
"""

from __future__ import annotations
import httpx
from typing import Optional


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
    """Return a configured httpx Client for synchronous use."""
    return httpx.Client(
        headers=DEFAULT_HEADERS,
        timeout=timeout,
        verify=verify_ssl,
        follow_redirects=True,
        http2=True,
    )


def get_async_client(timeout: float = 10.0, verify_ssl: bool = False) -> httpx.AsyncClient:
    """Return a configured httpx AsyncClient for async use."""
    return httpx.AsyncClient(
        headers=DEFAULT_HEADERS,
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
