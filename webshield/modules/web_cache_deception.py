"""
Web Cache Deception & Cache Poisoning Module (v1.5.0)

Two distinct but related attacks:

── WEB CACHE DECEPTION (stealing private data from cache) ──────────────────────
  Discovered by Omer Gil (2017), still widely exploited in bug bounties 2024-2025.

  How it works:
  1. Target has a page like /account/profile that returns private data
  2. Attacker crafts URL: /account/profile/nonexistent.css
  3. Cache server caches it (thinks it's a static asset by extension)
  4. Attacker visits same URL → gets victim's cached private data

  Why it works:
  - CDN/cache keyed on URL path (includes extension)
  - App ignores the suffix (returns /account/profile content for unknown routes)
  - Different cache rules: cache everything with .css/.js/.jpg extension
  - Result: victim's private data cached publicly

── WEB CACHE POISONING (injecting malicious content into cache) ──────────────
  James Kettle research (PortSwigger, 2018-2025)

  How it works:
  1. Find an unkeyed header that changes the response
  2. Cache stores the poisoned response
  3. All users receive the attacker-controlled response

  Common unkeyed headers:
  - X-Forwarded-Host → changes URLs in page (open redirect, XSS)
  - X-Forwarded-Scheme → protocol
  - X-Original-URL → routing
  - Vary header manipulation

References:
  - https://portswigger.net/research/web-cache-deception
  - https://portswigger.net/research/practical-web-cache-poisoning
  - CVE-2024-55591 (Fortinet), multiple CDN cache bugs 2025
"""

from __future__ import annotations
import re
import time
from typing import List
from urllib.parse import urlparse, urljoin
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client

# ─── Cache Deception Test Suffixes ────────────────────────────────────────────
# These extensions trick caches into caching the response as a static asset
CACHE_BUSTER_SUFFIXES = [
    "/webshield-test.css",
    "/webshield-test.js",
    "/webshield-test.png",
    "/.webshield-test.js",
    ";webshield-test.css",
    "%0Awebshield-test.css",
]

# Private/authenticated paths to test cache deception on
PRIVATE_PATHS = [
    "/account", "/profile", "/dashboard", "/settings",
    "/api/me", "/api/user", "/api/v1/me", "/api/v1/user",
    "/my-account", "/user/profile", "/admin",
]

# Headers that indicate caching
CACHE_HEADERS = ["x-cache", "cf-cache-status", "age", "x-cache-hits",
                 "x-served-by", "x-varnish", "fastly-debug-digest"]

# ─── Cache Poisoning Test Headers ─────────────────────────────────────────────
POISON_HEADERS = [
    {"X-Forwarded-Host": "evil-webshield-poison.example.com"},
    {"X-Forwarded-Scheme": "nothttps"},
    {"X-Forwarded-Port": "1337"},
    {"X-Host": "evil-webshield-poison.example.com"},
    {"X-Rewrite-URL": "/poison-path-webshield"},
    {"X-Original-URL": "/poison-path-webshield"},
    {"Forwarded": "host=evil-webshield-poison.example.com"},
]

EVIL_HOST_CACHE = "evil-webshield-poison.example.com"


def _is_cached(resp) -> bool:
    """Returns True if response appears to be from cache."""
    headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
    if headers.get("x-cache") in ("hit", "hit, hit"):
        return True
    if headers.get("cf-cache-status") in ("hit", "revalidated"):
        return True
    if headers.get("age", "0") not in ("0", ""):
        try:
            return int(headers["age"]) > 0
        except Exception:
            pass
    if headers.get("x-cache-hits", "0") not in ("0", ""):
        return True
    return False


def _check_cache_headers_present(client, url: str, findings: List[Finding]) -> None:
    """Detect if caching is active at all — precondition for both attacks."""
    try:
        resp = client.get(url)
        has_cache = any(
            h.lower() in {k.lower() for k in resp.headers.keys()}
            for h in CACHE_HEADERS
        )
        if has_cache:
            cache_info = {h: resp.headers.get(h, resp.headers.get(h.lower(), ""))
                          for h in CACHE_HEADERS if h in resp.headers or
                          h.lower() in {k.lower() for k in resp.headers.keys()}}
            findings.append(Finding(
                title="Caching Layer Detected (Cache Poisoning/Deception Risk)",
                severity=Severity.INFO,
                description=(
                    "A CDN or caching layer is active. This is not a vulnerability by itself, "
                    "but enables cache poisoning and cache deception attacks if other conditions "
                    "are met. Testing for web cache poisoning and deception vulnerabilities."
                ),
                evidence=f"Cache headers present: {cache_info}",
                remediation="Ensure cache keys include all security-relevant headers. Audit cache rules.",
                reference="https://portswigger.net/research/web-cache-deception",
                cvss=0.0,
            ))
    except Exception:
        pass


def _check_cache_deception(client, base: str, findings: List[Finding]) -> None:
    """
    Test web cache deception: append static-looking suffix to private paths.
    If the server returns the same private content for /profile/x.css as /profile,
    and the response gets cached, private data is exposed.
    """
    for path in PRIVATE_PATHS:
        target = base + path
        try:
            # Get baseline response for private path
            base_resp = client.get(target)
            if base_resp.status_code not in (200, 302):
                continue

            base_body = base_resp.text
            if len(base_body) < 100:
                continue

            # Test cache deception suffixes
            for suffix in CACHE_BUSTER_SUFFIXES[:3]:
                deception_url = target + suffix
                try:
                    # First request (may populate cache)
                    r1 = client.get(deception_url)
                    if r1.status_code != 200:
                        continue

                    # Check if content matches private path (deception confirmed)
                    similarity = 0
                    if len(base_body) > 50 and len(r1.text) > 50:
                        # Rough similarity: check if significant portions match
                        overlap = sum(1 for a, b in zip(base_body, r1.text) if a == b)
                        similarity = overlap / max(len(base_body), len(r1.text))

                    if similarity > 0.7:
                        # Second request to check if cached
                        time.sleep(0.3)
                        r2 = client.get(deception_url)
                        is_cached = _is_cached(r2)

                        severity = Severity.HIGH if is_cached else Severity.MEDIUM
                        findings.append(Finding(
                            title=f"Web Cache Deception — Private Content Cacheable: {path}",
                            severity=severity,
                            description=(
                                f"The path '{path}' returns the same content when appended with "
                                f"'{suffix}'. This enables Web Cache Deception:\n"
                                "1. Attacker sends victim: " + base + path + suffix + "\n"
                                "2. Victim visits it (authenticated) → response cached by CDN\n"
                                "3. Attacker visits same URL → gets victim's private data\n\n"
                                "Impact: account takeover, PII theft, session token exposure."
                                + (" Response appears to be cached!" if is_cached else "")
                            ),
                            evidence=(
                                f"Private path: {target}\n"
                                f"Deception URL: {deception_url}\n"
                                f"Content similarity: {similarity:.0%}\n"
                                f"Response cached: {is_cached}\n"
                                f"Cache headers: { {h: r2.headers.get(h, '') for h in CACHE_HEADERS if h in r2.headers} }"
                            ),
                            remediation=(
                                "1. Configure cache to NOT cache authenticated responses\n"
                                "2. Add 'Cache-Control: no-store, private' to all authenticated pages\n"
                                "3. Configure CDN to respect Cache-Control headers\n"
                                "4. Use cache key normalization to ignore path extensions"
                            ),
                            code_fix=(
                                "# Add to ALL authenticated responses:\n"
                                "response.headers['Cache-Control'] = 'no-store, private, no-cache'\n"
                                "response.headers['Pragma'] = 'no-cache'\n\n"
                                "# Nginx — don't cache authenticated paths:\n"
                                "location /account {\n"
                                "    proxy_no_cache 1;\n"
                                "    proxy_cache_bypass 1;\n"
                                "    add_header Cache-Control 'no-store, private';\n"
                                "}\n\n"
                                "# Cloudflare Page Rule:\n"
                                "# URL: example.com/account/*\n"
                                "# Setting: Cache Level = Bypass"
                            ),
                            reference="https://portswigger.net/research/web-cache-deception",
                            cvss=8.1 if is_cached else 6.5,
                        ))
                        return  # one finding is enough

                except Exception:
                    continue
        except Exception:
            continue


def _check_cache_poisoning(client, url: str, findings: List[Finding]) -> None:
    """
    Test web cache poisoning via unkeyed headers.
    Inject a crafted header and check if it's reflected in the response
    in a way that would affect cached responses served to other users.
    """
    try:
        baseline_resp = client.get(url)
        baseline = baseline_resp.text
    except Exception:
        return

    for headers in POISON_HEADERS:
        header_name = list(headers.keys())[0]
        header_value = list(headers.values())[0]
        try:
            resp = client.get(url, headers=headers)
            body = resp.text

            # Check if the injected value appears in the response
            # AND differs from baseline (not just naturally present)
            if EVIL_HOST_CACHE in body and EVIL_HOST_CACHE not in baseline:
                # Check context — is it in a link/script/meta that could execute?
                in_link = bool(re.search(
                    r'(?:href|src|action|location)[^>]*' + re.escape(EVIL_HOST_CACHE),
                    body, re.I
                ))
                is_cached = _is_cached(resp)
                severity = Severity.CRITICAL if (in_link and is_cached) else \
                           Severity.HIGH if in_link else Severity.MEDIUM

                findings.append(Finding(
                    title=f"Web Cache Poisoning via '{header_name}' Header",
                    severity=severity,
                    description=(
                        f"The '{header_name}' header value is reflected in the response "
                        f"{'in a link/script src (directly exploitable!)' if in_link else 'in the response body'}. "
                        f"{'Response appears cached.' if is_cached else ''}\n\n"
                        "Attack chain:\n"
                        f"1. Attacker sends request with {header_name}: attacker.com\n"
                        "2. Response is cached with attacker-controlled URL\n"
                        "3. All users receive the poisoned cached response\n"
                        "4. Impact: XSS, redirect to phishing, malicious JS injection"
                    ),
                    evidence=(
                        f"Header injected: {header_name}: {header_value}\n"
                        f"Reflected in response: yes\n"
                        f"In executable context (link/src): {in_link}\n"
                        f"Response cached: {is_cached}"
                    ),
                    remediation=(
                        "1. Include all security-relevant headers in cache key\n"
                        "2. Never reflect unvalidated request headers in responses\n"
                        "3. Set Vary header to include all headers that affect the response\n"
                        "4. Use CDN cache key normalization"
                    ),
                    code_fix=(
                        "# Include X-Forwarded-Host in Vary header:\n"
                        "Vary: X-Forwarded-Host, X-Forwarded-Scheme\n\n"
                        "# Or better: normalize at edge and don't pass through:\n"
                        "# Nginx — strip potentially dangerous forwarded headers:\n"
                        "proxy_set_header X-Forwarded-Host '';\n"
                        "proxy_set_header X-Original-URL '';\n\n"
                        "# Validate Host against allowlist instead of trusting X-Forwarded-Host:\n"
                        "SITE_URL = 'https://example.com'  # hardcoded, not from headers"
                    ),
                    reference="https://portswigger.net/research/practical-web-cache-poisoning",
                    cvss=9.0 if severity == Severity.CRITICAL else 7.5,
                ))
                return  # one finding per scan

            # Even if EVIL_HOST not reflected, check for /poison-path being routed
            if "poison-path-webshield" in body and "poison-path-webshield" not in baseline:
                findings.append(Finding(
                    title=f"URL Rewriting via '{header_name}' Header (Routing Bypass)",
                    severity=Severity.HIGH,
                    description=(
                        f"The '{header_name}: /poison-path-webshield' header caused the server "
                        "to route to a different path. This can be chained with cache poisoning "
                        "to serve malicious responses to legitimate users."
                    ),
                    evidence=(
                        f"Header: {header_name}: /poison-path-webshield\n"
                        "Response reflects injected path"
                    ),
                    remediation="Strip or validate routing headers at the reverse proxy layer.",
                    reference="https://portswigger.net/research/practical-web-cache-poisoning",
                    cvss=7.5,
                ))
                return

        except Exception:
            continue


def scan(url: str, timeout: float = 12.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    with get_client(timeout=min(timeout, 10.0)) as client:
        # 1. Detect caching layer
        _check_cache_headers_present(client, url, findings)

        # 2. Web cache deception
        _check_cache_deception(client, base, findings)

        # 3. Web cache poisoning
        _check_cache_poisoning(client, url, findings)

    return findings
