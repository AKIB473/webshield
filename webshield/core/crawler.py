"""
Lightweight URL Crawler for WebShield
Discovers URLs with query parameters to feed injection modules.
Also returns interesting paths found in HTML (forms, links).
"""

from __future__ import annotations
import re
from typing import List, Set, Tuple
from urllib.parse import urlparse, urljoin, parse_qs, urlunparse, urlencode
from webshield.core.http import get_client

# Params that are high-value for injection testing
HIGH_VALUE_PARAMS = {
    # SQL injection targets
    "id", "user_id", "product_id", "order_id", "cat", "category",
    "page", "item", "pid", "cid", "nid", "tid",
    # File inclusion
    "file", "path", "include", "template", "view", "lang", "page",
    "document", "load", "read", "dir",
    # SSRF
    "url", "uri", "fetch", "src", "source", "dest", "redirect",
    "callback", "proxy", "image", "feed", "endpoint",
    # XSS / injection
    "q", "query", "search", "name", "msg", "message", "title",
    "text", "content", "keyword", "term",
    # Command injection
    "host", "ip", "cmd", "command", "exec",
    # SSTI
    "template", "tpl", "format", "theme",
    # Open redirect
    "next", "return", "redirect", "goto", "ref",
}


def crawl(base_url: str, timeout: float = 8.0, max_pages: int = 15) -> Tuple[List[str], List[str]]:
    """
    Crawl the target and return:
      (urls_with_params, interesting_paths)
    Only follows links on the same domain.
    """
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    visited: Set[str] = set()
    urls_with_params: List[str] = []
    interesting_paths: Set[str] = set()

    # Seed with the base URL
    queue = [base_url]
    # Also probe known high-value paths
    probe_paths = [
        "/?id=1", "/?q=test", "/?search=test", "/?page=1",
        "/?name=test", "/?url=test", "/?file=test",
        "/products?id=1", "/search?q=test", "/items?id=1",
        "/item?id=1", "/article?id=1", "/news?id=1",
        "/greet?name=test", "/template?msg=test", "/ping?host=test",
        "/file?path=test", "/fetch?url=test",
        "/redirect?next=/", "/host-reflect",
        # SSTI / template injection targets
        "/render?template=test", "/page?view=test", "/content?tpl=test",
        # Command injection
        "/cmd?host=test", "/exec?cmd=test", "/run?command=test",
        "/dns?host=test", "/nslookup?q=test",
        # SSRF
        "/proxy?url=test", "/image?src=test", "/api/fetch?url=test",
        # LFI
        "/include?page=test", "/load?file=test", "/view?path=test",
        # Open redirect
        "/login?next=/", "/auth?redirect=/", "/sso?return=/",
    ]
    for path in probe_paths:
        queue.append(origin + path)

    with get_client(timeout=timeout) as client:
        while queue and len(visited) < max_pages:
            url = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)

            try:
                resp = client.get(url)
                if resp.status_code != 200:
                    continue
                ct = resp.headers.get("content-type", "")
                if "html" not in ct and "json" not in ct:
                    continue
            except Exception:
                continue

            # Collect this URL if it has params
            if "?" in url:
                params = parse_qs(urlparse(url).query)
                if params:
                    urls_with_params.append(url)

            # Parse HTML for more links
            if "html" in ct:
                body = resp.text

                # Find all href/action/src with same-origin links
                for match in re.finditer(
                    r'(?:href|action|src)\s*=\s*["\']([^"\'#]+)["\']',
                    body, re.I
                ):
                    href = match.group(1).strip()
                    if not href or href.startswith(("javascript:", "mailto:", "tel:", "#")):
                        continue

                    full_url = urljoin(origin, href)
                    if not full_url.startswith(origin):
                        continue  # external link

                    # Track interesting paths
                    path = urlparse(full_url).path
                    if path and path != "/":
                        interesting_paths.add(path)

                    # Queue if not visited
                    if full_url not in visited and len(queue) < 50:
                        queue.append(full_url)

                # Find forms and extract action + input names
                for form in re.finditer(r'<form[^>]*>(.*?)</form>', body, re.I | re.S):
                    form_html = form.group(0)
                    action_m = re.search(r'action=["\']([^"\']+)["\']', form_html, re.I)
                    action = action_m.group(1) if action_m else url

                    # Find input names
                    param_names = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', form_html, re.I)
                    if param_names:
                        # Build a test URL with dummy values
                        qs = urlencode({p: "test123" for p in param_names[:5]})
                        form_url = urljoin(origin, action) + "?" + qs
                        if form_url not in visited:
                            urls_with_params.append(form_url)

    # Deduplicate
    seen = set()
    unique_urls = []
    for u in urls_with_params:
        key = urlparse(u).path + "?" + "&".join(
            sorted(parse_qs(urlparse(u).query).keys())
        )
        if key not in seen:
            seen.add(key)
            unique_urls.append(u)

    return unique_urls, sorted(interesting_paths)
