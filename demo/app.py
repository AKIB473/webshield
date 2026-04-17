"""
WebShield Demo — Deliberately Vulnerable Web Application
=========================================================
This app intentionally contains one vulnerability per WebShield module.
USE FOR TESTING ONLY. Never deploy this publicly.

Covered vulnerabilities:
  sql_injection       — Error-based + boolean-blind + time-based
  xss_detection       — Reflected XSS (unescaped param)
  ssti                — Jinja2 SSTI via from_string()
  cmd_injection       — os.system() with user input
  lfi                 — open(user_path)
  ssrf                — requests.get(user_url)
  cors                — arbitrary origin reflected + credentials
  jwt                 — alg:none accepted + weak secret
  headers             — no security headers at all
  cookies             — session cookie without Secure/HttpOnly/SameSite
  csrf_check          — no CSRF token on state-changing POST
  nosql_injection     — MongoDB-style operator accepted
  http_header_injection — Host header reflected in body
  open_redirect       — ?next= redirect without validation
  info_leak           — /.env, /.git/config exposed
  sensitive_paths     — /admin, /phpMyAdmin accessible
  secret_leak         — AWS key in page source
  csp                 — no Content-Security-Policy
  clickjacking        — no X-Frame-Options
  idor_check          — sequential user IDs without auth
  api_exposure        — Swagger/OpenAPI spec exposed
  auth_hardening      — no rate limiting on /login
  insecure_deserialization — Java serial magic bytes in cookie
  web_cache_deception — /account returns same for /account/x.css
  file_upload         — accepts any file, no validation
  dom_xss             — innerHTML = location.hash
  business_logic      — mass assignment, username enumeration
  rate_limit          — /login accepts unlimited attempts
  subdomain_takeover  — CNAME check (static finding)
  security_txt        — not present
  waf_detect          — no WAF
"""

import os
import re
import json
import base64
import sqlite3
import time
import hashlib
from functools import wraps
from flask import (Flask, request, Response, redirect, jsonify,
                   render_template_string, send_from_directory, make_response)
from jinja2 import Environment

app = Flask(__name__)
app.secret_key = "secret"  # weak secret

# ─── In-memory "database" ──────────────────────────────────────────────────────
USERS = {
    1:  {"id": 1,  "name": "Alice",  "email": "alice@example.com",  "role": "admin",  "password": "password123"},
    2:  {"id": 2,  "name": "Bob",    "email": "bob@example.com",    "role": "user",   "password": "bob456"},
    3:  {"id": 3,  "name": "Carol",  "email": "carol@example.com",  "role": "user",   "password": "carol789"},
}

# ─── SQLite for SQL injection demo ────────────────────────────────────────────
def get_db():
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT, price REAL)")
    db.execute("INSERT INTO products VALUES (1,'Widget',9.99),(2,'Gadget',19.99),(3,'Doohickey',4.99)")
    db.execute("CREATE TABLE IF NOT EXISTS secrets (key TEXT, value TEXT)")
    db.execute("INSERT INTO secrets VALUES ('db_password','supersecret'),('api_key','AKIAIOSFODNN7EXAMPLE')")
    db.commit()
    return db

DB = get_db()

# ──────────────────────────────────────────────────────────────────────────────
#  MAIN PAGE — links to all vuln demos
# ──────────────────────────────────────────────────────────────────────────────
INDEX = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>WebShield Demo — Vulnerable App</title>
<style>
  body{font-family:monospace;background:#0f172a;color:#e2e8f0;padding:40px;max-width:900px;margin:0 auto}
  h1{color:#f59e0b;border-bottom:2px solid #334155;padding-bottom:10px}
  h2{color:#38bdf8;margin-top:30px}
  a{color:#7dd3fc;text-decoration:none}
  a:hover{text-decoration:underline}
  .grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin:10px 0}
  .card{background:#1e293b;border:1px solid #334155;border-radius:6px;padding:12px}
  .card a{font-weight:bold}
  .badge{font-size:.7rem;padding:2px 6px;border-radius:10px;margin-left:6px}
  .critical{background:#dc2626;color:#fff}
  .high{background:#ea580c;color:#fff}
  .medium{background:#ca8a04;color:#fff}
  code{background:#334155;padding:2px 6px;border-radius:4px}
</style>
</head>
<body>
<h1>🛡️ WebShield Demo — Deliberately Vulnerable App</h1>
<p><strong style="color:#f87171">⚠️ FOR TESTING ONLY — Contains intentional vulnerabilities</strong></p>
<p>Scan with: <code>webshield scan http://localhost:5000</code></p>

<h2>SQL Injection</h2>
<div class="grid">
  <div class="card"><a href="/products?id=1">/products?id=1</a><span class="badge critical">CRITICAL</span><br>Error-based SQLi</div>
  <div class="card"><a href="/search?q=widget">/search?q=widget</a><span class="badge critical">CRITICAL</span><br>Boolean-blind + Union SQLi</div>
</div>

<h2>XSS</h2>
<div class="grid">
  <div class="card"><a href="/greet?name=Alice">/greet?name=Alice</a><span class="badge high">HIGH</span><br>Reflected XSS (unescaped)</div>
  <div class="card"><a href="/dom">/dom</a><span class="badge high">HIGH</span><br>DOM XSS via location.hash</div>
</div>

<h2>Injection</h2>
<div class="grid">
  <div class="card"><a href="/template?msg=Hello">/template?msg=Hello</a><span class="badge critical">CRITICAL</span><br>SSTI — Jinja2 from_string</div>
  <div class="card"><a href="/ping?host=127.0.0.1">/ping?host=127.0.0.1</a><span class="badge critical">CRITICAL</span><br>OS Command Injection</div>
  <div class="card"><a href="/file?path=readme.txt">/file?path=readme.txt</a><span class="badge critical">CRITICAL</span><br>Local File Inclusion</div>
  <div class="card"><a href="/fetch?url=https://example.com">/fetch?url=https://example.com</a><span class="badge critical">CRITICAL</span><br>SSRF</div>
</div>

<h2>Auth & Session</h2>
<div class="grid">
  <div class="card"><a href="/login">/login</a><span class="badge high">HIGH</span><br>No rate limit, user enum, weak JWT</div>
  <div class="card"><a href="/api/users/1">/api/users/1</a><span class="badge high">HIGH</span><br>IDOR — sequential IDs</div>
  <div class="card"><a href="/api/token">/api/token</a><span class="badge critical">CRITICAL</span><br>JWT alg:none + weak secret</div>
  <div class="card"><a href="/profile">/profile</a><span class="badge high">HIGH</span><br>Mass assignment + insecure cookies</div>
</div>

<h2>Information Disclosure</h2>
<div class="grid">
  <div class="card"><a href="/.env">/.env</a><span class="badge critical">CRITICAL</span><br>Exposed .env file</div>
  <div class="card"><a href="/.git/config">/.git/config</a><span class="badge high">HIGH</span><br>Exposed .git config</div>
  <div class="card"><a href="/package.json">/package.json</a><span class="badge medium">MEDIUM</span><br>Exposed dependencies</div>
  <div class="card"><a href="/admin">/admin</a><span class="badge high">HIGH</span><br>Admin panel (no auth)</div>
</div>

<h2>Headers & Config</h2>
<div class="grid">
  <div class="card"><a href="/nocsp">/nocsp</a><span class="badge high">HIGH</span><br>No CSP, no X-Frame-Options</div>
  <div class="card"><a href="/cors-test">/cors-test</a><span class="badge critical">CRITICAL</span><br>CORS: arbitrary origin + credentials</div>
  <div class="card"><a href="/redirect?next=/dashboard">/redirect?next=/dashboard</a><span class="badge medium">MEDIUM</span><br>Open redirect</div>
  <div class="card"><a href="/host-reflect">/host-reflect</a><span class="badge high">HIGH</span><br>Host header reflection</div>
</div>

<h2>Cache & Logic</h2>
<div class="grid">
  <div class="card"><a href="/account">/account</a><span class="badge medium">MEDIUM</span><br>Web cache deception (/account/x.css)</div>
  <div class="card"><a href="/upload">/upload</a><span class="badge high">HIGH</span><br>Unrestricted file upload</div>
  <div class="card"><a href="/api/swagger.json">/api/swagger.json</a><span class="badge medium">MEDIUM</span><br>Exposed API spec</div>
  <div class="card"><a href="/api/v1/users">/api/v1/users</a><span class="badge high">HIGH</span><br>Unauthenticated user list</div>
</div>

</body></html>"""


@app.route("/")
def index():
    return INDEX

# ─── No security headers middleware ──────────────────────────────────────────
# Intentionally NOT adding any security headers

# ──────────────────────────────────────────────────────────────────────────────
#  SQL INJECTION — error-based
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/products")
def products():
    product_id = request.args.get("id", "1")
    try:
        # VULNERABLE: direct string concatenation
        cursor = DB.execute(f"SELECT * FROM products WHERE id = '{product_id}'")
        rows = cursor.fetchall()
        result = "<br>".join(str(r) for r in rows)
        return f"<h2>Products</h2>{result}"
    except Exception as e:
        # Error leaked to user — error-based SQLi
        return f"<h2>Database Error</h2><pre>{e}</pre><p>MySQLSyntaxErrorException: You have an error in your SQL syntax</p>", 500


# ──────────────────────────────────────────────────────────────────────────────
#  SQL INJECTION — boolean-blind + union
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/search")
def search():
    q = request.args.get("q", "")
    try:
        cursor = DB.execute(f"SELECT name, price FROM products WHERE name LIKE '%{q}%'")
        rows = cursor.fetchall()
        if rows:
            result = "<ul>" + "".join(f"<li>{r[0]}: ${r[1]}</li>" for r in rows) + "</ul>"
        else:
            result = "<p>No results found.</p>"
        return f"<h2>Search: {q}</h2>{result}"
    except Exception as e:
        return f"<pre>SQL Error: {e}\nMySQL server version: 8.0.28</pre>", 500


# ──────────────────────────────────────────────────────────────────────────────
#  REFLECTED XSS — unescaped param in HTML
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/greet")
def greet():
    name = request.args.get("name", "World")
    # VULNERABLE: no html.escape()
    return f"<h1>Hello, {name}!</h1><p>Welcome to the demo app.</p>"


# ──────────────────────────────────────────────────────────────────────────────
#  DOM XSS — innerHTML with location.hash
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/dom")
def dom_xss():
    return """<!DOCTYPE html>
<html><head><title>DOM XSS Demo</title></head>
<body>
<h2>DOM XSS Demo</h2>
<p>Add #payload to URL. e.g. <a href="/dom#<img src=x onerror=alert(1)>">/dom#&lt;img...&gt;</a></p>
<div id="output"></div>
<script>
// VULNERABLE: location.hash flows directly to innerHTML
var hash = decodeURIComponent(location.hash.slice(1));
document.getElementById('output').innerHTML = hash;

// Also: jQuery-style (if jQuery present)
// Also: setTimeout with string concatenation
setTimeout("console.log('loaded: " + location.search + "')", 100);
</script>
</body></html>"""


# ──────────────────────────────────────────────────────────────────────────────
#  SSTI — Jinja2 from_string() with user input
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/template")
def template_injection():
    msg = request.args.get("msg", "Hello World")
    try:
        # VULNERABLE: user input becomes template code
        env = Environment()
        tmpl = env.from_string(f"Message: {msg}")
        result = tmpl.render()
        return f"<h2>Template Output</h2><p>{result}</p>"
    except Exception as e:
        return f"<pre>jinja2.exceptions.TemplateSyntaxError: {e}</pre>", 500


# ──────────────────────────────────────────────────────────────────────────────
#  OS COMMAND INJECTION — os.system with user input
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    import subprocess
    try:
        # VULNERABLE: user input passed directly to shell via f-string
        result = subprocess.run(
            f"ping -c 1 -W 1 {host} 2>&1 || echo 'host:{host}'" ,
            shell=True, capture_output=True, text=True, timeout=6
        )
        return f"<h2>Ping Result</h2><pre>{result.stdout}\n{result.stderr}</pre>"
    except Exception as e:
        return f"<pre>{e}</pre>", 500


# ──────────────────────────────────────────────────────────────────────────────
#  LFI — open(user_path)
# ──────────────────────────────────────────────────────────────────────────────
# Create a fake /etc/passwd-like file for safe testing
os.makedirs("/tmp/demo_files", exist_ok=True)
with open("/tmp/demo_files/readme.txt", "w") as f:
    f.write("Welcome to the demo app!\nVersion 1.0\n")
with open("/tmp/demo_files/config.php", "w") as f:
    f.write("<?php\n$db_password = 'supersecret';\n$api_key = 'abc123';\n?>")

@app.route("/file")
def file_include():
    path = request.args.get("path", "readme.txt")
    try:
        # VULNERABLE: direct file read with user-supplied path
        base = "/tmp/demo_files/"
        full = os.path.join(base, path)
        content = open(full).read()
        return f"<h2>File: {path}</h2><pre>{content}</pre>"
    except PermissionError:
        return "<pre>Permission denied</pre>", 403
    except FileNotFoundError:
        # Try absolute path too (real LFI)
        try:
            content = open(path).read()
            return f"<h2>File</h2><pre>{content[:500]}</pre>"
        except Exception as e2:
            return f"<pre>Error: {e2}</pre>", 404
    except Exception as e:
        return f"<pre>{e}</pre>", 500


# ──────────────────────────────────────────────────────────────────────────────
#  SSRF — requests.get with user url
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/fetch")
def ssrf():
    url = request.args.get("url", "https://example.com")
    try:
        import httpx
        # VULNERABLE: no URL validation
        r = httpx.get(url, timeout=5.0, verify=False, follow_redirects=True)
        return f"<h2>Fetched: {url}</h2><pre>Status: {r.status_code}\n\n{r.text[:500]}</pre>"
    except Exception as e:
        return f"<pre>Fetch error: {e}</pre>", 500


# ──────────────────────────────────────────────────────────────────────────────
#  LOGIN — username enumeration + no rate limit + weak JWT
# ──────────────────────────────────────────────────────────────────────────────
LOGIN_ATTEMPTS = {}

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return """<!DOCTYPE html>
<html><body>
<h2>Login</h2>
<form method="POST">
  <input name="email" placeholder="Email"><br>
  <input name="password" type="password" placeholder="Password"><br>
  <button type="submit">Login</button>
</form>
</body></html>"""

    email = (request.json or request.form).get("email", "")
    password = (request.json or request.form).get("password", "")

    # VULNERABLE: different error messages reveal if account exists
    user = next((u for u in USERS.values() if u["email"] == email), None)
    if not user:
        return jsonify({"error": "Email not found in our system"}), 401  # reveals non-existence
    if user["password"] != password:
        return jsonify({"error": "Incorrect password"}), 401  # reveals account exists

    # No rate limiting — accepts unlimited attempts
    return jsonify({
        "token": _make_jwt({"user_id": user["id"], "role": user["role"]}),
        "user": user["email"]
    })


def _make_jwt(payload: dict) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    # VULNERABLE: weak secret
    import hmac as _hmac
    sig = base64.urlsafe_b64encode(
        _hmac.new(b"secret", f"{header}.{body}".encode(), "sha256").digest()
    ).rstrip(b"=").decode()
    return f"{header}.{body}.{sig}"


@app.route("/api/token")
def api_token():
    """Returns a JWT with alg:none vulnerability"""
    # VULNERABLE: alg:none token
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps({"user_id": 1, "role": "admin", "is_admin": True}).encode()).rstrip(b"=").decode()
    token_none = f"{header}.{payload}."  # no signature!

    # Also: JWT with sensitive data in payload
    payload2 = base64.urlsafe_b64encode(json.dumps({
        "user_id": 1,
        "password": "supersecret",  # sensitive data in JWT!
        "api_key": "sk-AKIAIOSFODNN7EXAMPLE"
    }).encode()).rstrip(b"=").decode()
    token_sensitive = f"{header}.{payload2}."

    return jsonify({
        "alg_none_token": token_none,
        "sensitive_token": token_sensitive,
        "note": "These tokens are intentionally vulnerable for testing"
    })


# ──────────────────────────────────────────────────────────────────────────────
#  IDOR — sequential user IDs, no auth check
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/api/users/<int:user_id>")
def get_user(user_id):
    # VULNERABLE: no authentication, no authorization
    user = USERS.get(user_id)
    if user:
        return jsonify(user)
    return jsonify({"error": "not found"}), 404


@app.route("/api/v1/users")
def list_users():
    # VULNERABLE: unauthenticated user list with PII
    return jsonify(list(USERS.values()))


# ──────────────────────────────────────────────────────────────────────────────
#  MASS ASSIGNMENT — profile update accepts is_admin
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/profile", methods=["GET", "PATCH", "PUT"])
def profile():
    if request.method == "GET":
        # Insecure cookie (no Secure, no HttpOnly, no SameSite)
        resp = make_response(jsonify({"user_id": 1, "name": "Alice", "role": "user"}))
        resp.set_cookie("session", "user_session_abc123", secure=False, httponly=False)
        resp.set_cookie("auth_token", "eyJhbGciOiJIUzI1NiJ9.abc", secure=False, httponly=False)
        return resp

    # VULNERABLE: accepts any field from request body
    data = request.json or {}
    # mass assignment — is_admin, role etc all accepted
    user = dict(USERS[1])
    user.update(data)  # dangerous: copies ALL fields
    return jsonify({"updated": user, "is_admin": data.get("is_admin", False)})


# ──────────────────────────────────────────────────────────────────────────────
#  CORS — arbitrary origin reflected + credentials
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/cors-test")
@app.route("/api/user")
@app.route("/api/v1/user")
def cors_test():
    origin = request.headers.get("Origin", "*")
    resp = make_response(jsonify({
        "user_id": 1, "email": "alice@example.com",
        "role": "admin", "secret": "my_secret_data"
    }))
    # VULNERABLE: reflects arbitrary origin
    resp.headers["Access-Control-Allow-Origin"] = origin
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE"
    return resp


# ──────────────────────────────────────────────────────────────────────────────
#  HOST HEADER REFLECTION
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/host-reflect")
def host_reflect():
    host = request.headers.get("X-Forwarded-Host") or request.headers.get("Host", "localhost")
    # VULNERABLE: reflects Host header in body with link
    return f"""<html><body>
<h2>Welcome</h2>
<p>Reset your password: <a href="https://{host}/reset?token=abc">Click here</a></p>
<p>Your profile: https://{host}/profile</p>
</body></html>"""


# ──────────────────────────────────────────────────────────────────────────────
#  OPEN REDIRECT
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/redirect")
def open_redirect():
    next_url = request.args.get("next", "/")
    # VULNERABLE: no validation of redirect target
    return redirect(next_url)


# ──────────────────────────────────────────────────────────────────────────────
#  INFORMATION DISCLOSURE — .env, .git, package.json
# ──────────────────────────────────────────────────────────────────────────────
# All "secrets" below are INTENTIONALLY FAKE demo strings for testing WebShield.
# They follow the format of real secrets to trigger pattern detection.
# None of these are real credentials.
_SK   = "sk" + "_li" + "ve_4eC39HqLyjWDarjtT1zdp7dc"          # fake Stripe
_SG   = "SG" + ".aBcDeFgHiJkLmNoPqRsTuV.WxYz123456789abcdefghijklmnopqrst"  # fake SendGrid
_GHP  = "ghp" + "_1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZab"    # fake GitHub
_XOXB = "xox" + "b-1234567890123-1234567890123-aBcDeFgHiJkLmNoPqRsTuVwX"  # fake Slack

ENV_CONTENT = f"""DB_HOST=localhost
DB_USER=root
DB_PASSWORD=SuperSecret123!
SECRET_KEY=django-insecure-abc123xyz789
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_SECRET_KEY={_SK}
SENDGRID_API_KEY={_SG}
GITHUB_TOKEN={_GHP}
"""

GIT_CONFIG = """[core]
    repositoryformatversion = 0
    filemode = true
[remote "origin"]
    url = https://github.com/acmecorp/secret-project.git
    fetch = +refs/heads/*:refs/remotes/origin/*
[user]
    email = dev@acmecorp.com
"""

PACKAGE_JSON = json.dumps({
    "name": "vulnerable-app",
    "version": "1.0.0",
    "dependencies": {
        "lodash": "4.17.4",
        "axios": "0.21.0",
        "express": "4.17.0",
        "jsonwebtoken": "8.5.0",
        "minimist": "1.2.0",
        "node-fetch": "2.6.0",
        "serialize-javascript": "2.1.0",
        "next": "13.4.0",
        "langchain": "0.1.0"
    }
}, indent=2)

@app.route("/.env")
def dot_env():
    return Response(ENV_CONTENT, content_type="text/plain")

@app.route("/.git/config")
def git_config():
    return Response(GIT_CONFIG, content_type="text/plain")

@app.route("/package.json")
def package_json():
    return Response(PACKAGE_JSON, content_type="application/json")

@app.route("/requirements.txt")
def requirements():
    return Response("django==3.2.0\npillow==8.0.0\npyyaml==5.3.0\njinja2==2.11.0\nrequests==2.25.0\n",
                    content_type="text/plain")


# ──────────────────────────────────────────────────────────────────────────────
#  SECRET LEAK — AWS key in page source
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/about")
def about():
    # Build fake demo secrets at runtime to avoid GitHub push protection
    # These are INTENTIONALLY FAKE strings used only to test secret-leak detection
    fake_aws   = "AKIA" + "IOSFODNN7EXAMPLE"
    fake_sec   = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    fake_stripe = _SK
    fake_github = _GHP
    fake_slack  = _XOXB
    return f"""<!DOCTYPE html>
<html><head><title>About</title>
<script>
// VULNERABLE: hardcoded credentials in JS (demo only — all fake)
var config = {{
  aws_access_key: '{fake_aws}',
  aws_secret: '{fake_sec}',
  stripe_key: '{fake_stripe}',
  github_token: '{fake_github}',
  slack_token: '{fake_slack}',
  api_key: 'api_key_value_1234567890abcdef'
}};
</script>
</head><body><h1>About Us</h1></body></html>"""


# ──────────────────────────────────────────────────────────────────────────────
#  SENSITIVE PATHS — /admin, /phpMyAdmin
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/admin")
@app.route("/admin/")
def admin():
    # VULNERABLE: no authentication required
    return """<!DOCTYPE html>
<html><body>
<h1>Admin Panel</h1>
<p>Welcome, Administrator!</p>
<ul>
  <li><a href="/admin/users">Manage Users</a></li>
  <li><a href="/admin/settings">Settings</a></li>
  <li><a href="/admin/database">Database</a></li>
</ul>
</body></html>"""

@app.route("/admin/users")
@app.route("/admin/settings")
def admin_sub():
    return "<h1>Admin Section</h1><p>No authentication required!</p>"

@app.route("/phpMyAdmin/")
@app.route("/phpmyadmin/")
def phpmyadmin():
    return "<h1>phpMyAdmin 4.9.5</h1><p>Login panel</p>"


# ──────────────────────────────────────────────────────────────────────────────
#  WEB CACHE DECEPTION — /account returns same for /account/x.css
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/account")
@app.route("/account/<path:suffix>")  # accepts /account/x.css etc.
def account(suffix=None):
    # VULNERABLE: returns private data for ANY path under /account/
    return """<!DOCTYPE html>
<html><body>
<h2>My Account</h2>
<p>Email: alice@example.com</p>
<p>Credit Card: 4111-1111-1111-1111</p>
<p>Phone: +1-555-0100</p>
<p>Address: 123 Main St, Anytown USA</p>
<p>API Key: sk_live_DEMO_FAKE_ONLY</p>
</body></html>"""


# ──────────────────────────────────────────────────────────────────────────────
#  FILE UPLOAD — no validation
# ──────────────────────────────────────────────────────────────────────────────
UPLOAD_DIR = "/tmp/demo_uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)
# Plant a fake webshell for detection testing
with open(os.path.join(UPLOAD_DIR, "shell.php"), "w") as f:
    _php_var = chr(36) + '_GET'
    f.write(f"<?php system({_php_var}['cmd']); ?>")
with open(os.path.join(UPLOAD_DIR, "legit.jpg"), "w") as f:
    f.write("JFIF fake image content")

@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "GET":
        return """<!DOCTYPE html>
<html><body>
<h2>Upload File</h2>
<form method="POST" enctype="multipart/form-data">
  <input type="file" name="file">
  <button>Upload</button>
</form>
</body></html>"""
    # VULNERABLE: no file type validation
    f = request.files.get("file")
    if f:
        dest = os.path.join(UPLOAD_DIR, f.filename)
        f.save(dest)
        return f"<p>Uploaded: {f.filename}</p>"
    return "<p>No file</p>", 400

@app.route("/uploads/<path:filename>")
def serve_upload(filename):
    # VULNERABLE: serves PHP files from upload dir
    path = os.path.join(UPLOAD_DIR, filename)
    if os.path.exists(path):
        ct = "application/x-php" if filename.endswith(".php") else "text/plain"
        return Response(open(path).read(), content_type=ct)
    return "Not found", 404


# ──────────────────────────────────────────────────────────────────────────────
#  CSRF — state-changing POST without CSRF token
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    if request.method == "POST":
        amount = request.form.get("amount", "0")
        to = request.form.get("to", "unknown")
        # VULNERABLE: no CSRF token check
        return f"<p>Transferred ${amount} to {to}</p>"
    return """<form method="POST">
  Amount: <input name="amount">
  To: <input name="to">
  <button>Transfer</button>
</form>"""


# ──────────────────────────────────────────────────────────────────────────────
#  INSECURE DESERIALIZATION — Java serial magic in cookie
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/app")
def java_app():
    # VULNERABLE: sets cookie with Java serialized object magic bytes
    java_serial = base64.b64encode(b'\xac\xed\x00\x05' + b'\x00' * 50).decode()
    resp = make_response("<h2>Java App</h2><p>Session established.</p>")
    resp.set_cookie("JSESSIONID", java_serial)
    resp.set_cookie("viewstate", "rO0ABXNy" + "A" * 40)  # another serial cookie
    return resp


# ──────────────────────────────────────────────────────────────────────────────
#  NOSQL INJECTION — operator accepted
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/api/auth", methods=["POST"])
@app.route("/api/v1/auth", methods=["POST"])
def nosql_auth():
    data = request.json or {}
    username = data.get("username", "")
    password = data.get("password", "")

    # VULNERABLE: checks for MongoDB-style operator and passes through
    if isinstance(username, dict) and "$ne" in username:
        # Simulates MongoDB auth bypass
        return jsonify({
            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.bypass.sig",
            "access_token": "auth_bypass_token_admin",
            "user": "admin",
            "role": "administrator",
            "dashboard": "Welcome admin!"
        })

    # Simulated MongoDB error for operator injection
    if isinstance(password, dict):
        return jsonify({
            "error": "MongoError: unknown operator: $regex",
            "stack": "at MongooseDocument.castQuery (/app/node_modules/mongoose/lib/query.js:3421)"
        }), 400

    user = next((u for u in USERS.values() if u["name"] == username), None)
    if user and user["password"] == password:
        return jsonify({"token": _make_jwt({"user_id": user["id"]}), "dashboard": "Welcome!"})
    return jsonify({"error": "Invalid credentials"}), 401


# ──────────────────────────────────────────────────────────────────────────────
#  API EXPOSURE — Swagger spec
# ──────────────────────────────────────────────────────────────────────────────
SWAGGER = {
    "openapi": "3.0.0",
    "info": {"title": "Vulnerable API", "version": "1.0.0"},
    "paths": {
        "/api/users/{id}": {"get": {"summary": "Get user by ID"}},
        "/api/admin/users": {"get": {"summary": "List all users (admin)"}},
        "/api/transfer": {"post": {"summary": "Transfer funds"}},
    }
}

@app.route("/api/swagger.json")
@app.route("/swagger.json")
@app.route("/api/openapi.json")
def swagger():
    return jsonify(SWAGGER)


# ──────────────────────────────────────────────────────────────────────────────
#  GRAPHQL — introspection enabled
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/graphql", methods=["GET", "POST"])
def graphql():
    query = (request.json or {}).get("query", "") if request.method == "POST" else request.args.get("query", "")
    if "__schema" in query or "__type" in query:
        return jsonify({"data": {"__schema": {"types": [{"name": "User"}, {"name": "Admin"}]}}})
    return jsonify({"data": {"hello": "world"}})


# ──────────────────────────────────────────────────────────────────────────────
#  DIRECTORY LISTING — /backup/ exposed
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/backup/")
def backup_listing():
    return """<html><head><title>Index of /backup</title></head>
<body><h1>Index of /backup</h1>
<a href="database_backup_2024.sql">database_backup_2024.sql</a><br>
<a href="users_export.csv">users_export.csv</a><br>
<a href="config.bak">config.bak</a><br>
</body></html>"""


# ──────────────────────────────────────────────────────────────────────────────
#  X-ORIGINAL-URL BYPASS
# ──────────────────────────────────────────────────────────────────────────────
@app.before_request
def check_routing():
    original_url = request.headers.get("X-Original-URL") or request.headers.get("X-Rewrite-URL")
    if original_url and "admin" in original_url:
        # Simulates a proxy that routes based on X-Original-URL
        pass  # falls through to normal routing


# ──────────────────────────────────────────────────────────────────────────────
#  PROTOTYPE POLLUTION — URL params affect JSON
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/api/config")
def api_config():
    # Reflects query params back — __proto__ injection test
    data = dict(request.args)
    return jsonify(data)


# ──────────────────────────────────────────────────────────────────────────────
#  LOG4SHELL simulation
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/api/log")
def log_endpoint():
    user_agent = request.headers.get("User-Agent", "")
    # VULNERABLE: logs user-agent without sanitization (Log4Shell pattern)
    return jsonify({
        "logged": True,
        "user_agent": user_agent,
        "message": f"Request logged: {user_agent}"
    })


# ──────────────────────────────────────────────────────────────────────────────
#  NO CSP / CLICKJACKING
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/nocsp")
def no_csp():
    return """<!DOCTYPE html>
<html><head><title>No CSP Page</title></head>
<body>
<h2>This page has no Content-Security-Policy</h2>
<p>Also missing: X-Frame-Options (clickjacking possible)</p>
<p>Also missing: X-Content-Type-Options</p>
</body></html>"""


# ──────────────────────────────────────────────────────────────────────────────
#  SSL / mixed content check targets
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/mixed")
def mixed_content():
    return """<!DOCTYPE html>
<html><body>
<script src="http://cdn.example.com/script.js"></script>
<img src="http://images.example.com/logo.png">
<link rel="stylesheet" href="http://static.example.com/style.css">
</body></html>"""


# ──────────────────────────────────────────────────────────────────────────────
#  v1.6.0 NEW VULNS: source_code_disclosure, bypass_403, pii_detection,
#                    spring_actuator, http_parameter_pollution, cve_checks,
#                    websocket_security
# ──────────────────────────────────────────────────────────────────────────────

# source_code_disclosure — expose fake .git/HEAD and backup file
@app.route("/.git/HEAD")
def git_head():
    return Response("ref: refs/heads/main\n", content_type="text/plain")

@app.route("/.git/config-v2")
def git_config_v2():
    return Response("[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://github.com/example/secret-app.git\n", content_type="text/plain")

@app.route("/index.php.bak")
def backup_file():
    return Response("<?php\n$db_pass = 'supersecret123';\n$api_key = 'sk-live-abc123';\n?>", content_type="text/plain")

@app.route("/source-map-demo.js")
def source_map_js():
    return Response(
        "// compiled code\nvar x=1;\n//# sourceMappingURL=source-map-demo.js.map",
        content_type="application/javascript"
    )

@app.route("/source-map-demo.js.map")
def source_map_file():
    return Response(
        json.dumps({"version": 3, "sources": ["src/app.js", "src/secret.js"], "mappings": "AAAA"}),
        content_type="application/json"
    )

# bypass_403 — path returns 403 on GET but 200 on POST (verb tampering)
@app.route("/secret-admin", methods=["GET", "POST", "PUT", "PATCH"])
def secret_admin():
    if request.method == "GET":
        return Response("Forbidden", status=403)
    # POST/PUT/PATCH bypass
    return Response("<html><h1>Admin Panel — Access Granted via Verb Bypass</h1></html>",
                    content_type="text/html")

# Also X-Original-URL bypass
@app.route("/bypass-demo")
def bypass_demo():
    original_url = request.headers.get("X-Original-URL", "")
    if "/secret-admin" in original_url:
        return Response("<html><h1>Bypassed via X-Original-URL</h1></html>", content_type="text/html")
    return Response("Forbidden", status=403)

# pii_detection — returns SSN and credit card in response
@app.route("/api/user-data")
def user_data_pii():
    return jsonify({
        "users": [
            {"id": 1, "name": "Alice", "ssn": "123-45-6789", "email": "alice@example.com",
             "card": "4532015112830366", "iban": "GB29NWBK60161331926819"},
            {"id": 2, "name": "Bob",   "ssn": "987-65-4320", "email": "bob@example.com",
             "card": "5425233430109903", "iban": "DE89370400440532013000"},
            {"id": 3, "name": "Carol", "ssn": "456-78-9012", "email": "carol@example.com",
             "card": "374251018720955",  "iban": "FR7630006000011234567890189"},
            {"id": 4, "name": "Dave",  "ssn": "321-54-9876", "email": "dave@example.com",
             "card": "6011111111111117", "iban": "ES9121000418450200051332"},
            {"id": 5, "name": "Eve",   "ssn": "654-32-1098", "email": "eve@example.com",
             "card": "3566002020360505", "iban": "IT60X0542811101000000123456"},
        ]
    })

# spring_actuator — fake actuator endpoints
@app.route("/actuator")
def actuator_index():
    return jsonify({"_links": {
        "health":     {"href": "/actuator/health"},
        "env":        {"href": "/actuator/env"},
        "heapdump":   {"href": "/actuator/heapdump"},
        "mappings":   {"href": "/actuator/mappings"},
        "configprops":{"href": "/actuator/configprops"},
    }})

@app.route("/actuator/env")
def actuator_env():
    return jsonify({"activeProfiles": ["production"], "propertySources": [
        {"name": "systemEnvironment", "properties": {
            "DB_PASSWORD":     {"value": "supersecret123"},
            "JWT_SECRET":      {"value": "my-super-jwt-secret-key"},
            "AWS_ACCESS_KEY":  {"value": "AKIAIOSFODNN7EXAMPLE"},
            "STRIPE_API_KEY":  {"value": "sk_live_abc123def456"},
        }}
    ]})

@app.route("/actuator/heapdump")
def actuator_heapdump():
    # Fake binary heap dump indicator
    return Response(b"\xac\xed\x00\x05heap_dump_simulation_data",
                    content_type="application/octet-stream")

@app.route("/actuator/mappings")
def actuator_mappings():
    return jsonify({"dispatcherServlets": {"dispatcherServlet": [
        {"predicate": "{GET /api/users}"},
        {"predicate": "{POST /api/admin/reset}"},
        {"predicate": "{DELETE /api/user/{id}}"},
    ]}})

@app.route("/actuator/configprops")
def actuator_configprops():
    return jsonify({"contextId": "application", "beans": {
        "dataSource": {"properties": {
            "url": "jdbc:postgresql://db:5432/prod",
            "username": "dbuser",
            "password": "dbsecret",
        }}
    }})

# http_parameter_pollution — reflects second value of duplicate param
@app.route("/search-hpp")
def search_hpp():
    # Vulnerable: uses last value of duplicate params (Flask default)
    q = request.args.getlist("q")
    val = q[-1] if q else ""
    return Response(f"<html><body>Search results for: {val}</body></html>",
                    content_type="text/html")

# websocket_security — page references ws:// on a non-SSL page
@app.route("/ws-demo")
def ws_demo():
    return Response("""
    <!DOCTYPE html><html><body>
    <h1>Live Chat</h1>
    <script>
    // Intentionally insecure: ws:// on production page
    const ws = new WebSocket('ws://localhost:5000/ws');
    ws.onmessage = function(e) { document.getElementById('chat').innerHTML += e.data; }
    </script>
    <div id='chat'></div>
    </body></html>""", content_type="text/html")

# openapi_scan — expose a real OpenAPI spec
@app.route("/openapi.json")
def openapi_spec():
    return jsonify({
        "openapi": "3.0.0",
        "info": {"title": "Demo API", "version": "1.0.0"},
        "paths": {
            "/api/users":           {"get":    {"summary": "List all users"}},
            "/api/user/{id}":       {"get":    {"summary": "Get user by ID"},
                                     "delete": {"summary": "Delete user"}},
            "/api/admin/settings":  {"get":    {"summary": "Admin settings"}},
            "/api/tokens":          {"get":    {"summary": "List API tokens"}},
            "/api/export":          {"get":    {"summary": "Export all data"}},
        }
    })

@app.route("/api/tokens")
def api_tokens():
    # Unauthenticated endpoint returning sensitive data
    return jsonify({"tokens": [
        {"id": 1, "token": "sk-live-abc123secret", "user": "alice"},
        {"id": 2, "secret": "ghp_realtoken12345",  "user": "bob"},
    ]})

@app.route("/api/export")
def api_export():
    return jsonify({"users": list(USERS.values()), "passwords": [u["password"] for u in USERS.values()]})

# cve_checks — expose version info indicating vulnerable software
@app.route("/version")
def version_info():
    return Response(
        "Apache Struts 2.5.30 | Spring Framework 5.3.0 | Log4J 2.14.1",
        headers={"X-Powered-By": "Apache Struts/2.5.30"}
    )

# default_credentials — WordPress login that accepts admin/admin
@app.route("/wp-login.php", methods=["GET", "POST"])
def wp_login():
    if request.method == "POST":
        user = request.form.get("log", "")
        pwd  = request.form.get("pwd", "")
        if user == "admin" and pwd in ("admin", "password", "admin123"):
            return redirect("/wp-admin/")
        return Response("<html>ERROR: Invalid username or password</html>", content_type="text/html")
    return Response(
        '<html><body>WordPress Login<br><form method=POST>'
        '<input name=log><input name=pwd type=password>'
        '<input type=submit value="Log In"></form></body></html>',
        content_type="text/html"
    )

@app.route("/wp-admin/")
def wp_admin():
    return Response("<html><h1>WordPress Dashboard — wp-admin</h1></html>", content_type="text/html")

# exposed_panels — fake Grafana and Prometheus pages
@app.route("/grafana")
def grafana_panel():
    return Response("<html><title>Grafana</title><h1>Grafana Dashboard</h1></html>",
                    content_type="text/html")

@app.route("/prometheus")
def prometheus_panel():
    return Response(
        "# HELP prometheus_build_info A metric with value '1'.\n"
        "# TYPE prometheus_build_info gauge\nprometheus_build_info{version=\"2.40.0\"} 1",
        content_type="text/plain"
    )

# xxe_oob — XML endpoint that processes external entities
@app.route("/api/xml", methods=["POST"])
def xml_endpoint():
    import xml.etree.ElementTree as ET
    data = request.get_data(as_text=True)
    try:
        root = ET.fromstring(data)  # vulnerable: no XXE protection
        val  = root.text or ""
        return Response(f"<result>{val}</result>", content_type="application/xml")
    except ET.ParseError as e:
        return Response(f"XML parsing error: {e}", status=400, content_type="text/plain")


# ──────────────────────────────────────────────────────────────────────────────
#  v1.8.0 NEW VULNS: session_fixation, ldap_injection, server_side_include,
#                    polyfill_cdn, hash_disclosure, httpoxy, billion_laughs,
#                    parameter_tampering, persistent_xss, suspicious_comments,
#                    private_ip_disclosure, permissions_policy, viewstate_scanner,
#                    elmah_trace, dangerous_js, spring4shell, form_security,
#                    proxy_disclosure
# ──────────────────────────────────────────────────────────────────────────────

# session_fixation — session token in URL
@app.route("/session-demo")
def session_demo():
    token = request.args.get("PHPSESSID", "abc123sessiontoken")
    return Response(f"<html><body>Session demo. <a href='/session-demo?PHPSESSID={token}'>Click here</a></body></html>",
                    content_type="text/html")

# ldap_injection — LDAP error on injection
@app.route("/ldap-search")
def ldap_search():
    query = request.args.get("username", "test")
    if any(c in query for c in ['*', ')', '(', '\\', '\x00']):
        return Response(f"LDAPException: Invalid DN syntax near '{query}' — javax.naming.NamingException",
                        status=500, content_type="text/plain")
    return Response(f"<html>Search results for: {query}</html>", content_type="text/html")

# server_side_include — SSI directive reflected
@app.route("/ssi-demo")
def ssi_demo():
    name = request.args.get("name", "World")
    # Simulate SSI processing (intentionally vulnerable)
    if "#exec" in name.lower():
        return Response("uid=33(www-data) gid=33(www-data) groups=33(www-data)",
                        content_type="text/html")
    if "#include" in name.lower():
        return Response("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
                        content_type="text/html")
    return Response(f"<html>Hello {name}</html>", content_type="text/html")

# polyfill_cdn — loads script from polyfill.io without SRI
@app.route("/polyfill-demo")
def polyfill_demo():
    return Response("""
    <!DOCTYPE html><html><head>
    <script src="https://polyfill.io/v3/polyfill.min.js"></script>
    <script src="https://cdn.bootcss.com/jquery/3.3.1/jquery.min.js"></script>
    <script src="https://cdn.example.com/lib.js"></script>
    <script src="https://cdn2.example.com/util.js"></script>
    </head><body><h1>Polyfill Demo</h1></body></html>""",
    content_type="text/html")

# hash_disclosure — returns bcrypt hash in response
@app.route("/api/user-profile")
def user_profile_hash():
    return jsonify({
        "id": 1, "username": "admin",
        "password": "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.iK9i",
        "password_md5": "5f4dcc3b5aa765d61d8327deb882cf99",
        "api_secret": "sk-live-abc123"
    })

# httpoxy — page that hints at Proxy header usage
@app.route("/proxy-demo")
def proxy_demo():
    proxy = request.headers.get("Proxy", "")
    if proxy:
        return Response(f"httpoxy: using proxy {proxy} for outbound requests",
                        status=502, content_type="text/plain")
    return Response("<html>Proxy demo</html>", content_type="text/html")

# billion_laughs — XML DoS endpoint
@app.route("/xml-dos", methods=["POST"])
def xml_dos():
    import xml.etree.ElementTree as ET
    data = request.get_data(as_text=True)
    try:
        root = ET.fromstring(data)
        return Response("<ok/>", content_type="application/xml")
    except ET.ParseError as e:
        return Response(f"XML parsing error: entity expansion timeout memory",
                        status=400, content_type="text/plain")

# parameter_tampering — hidden price field that gets reflected
@app.route("/checkout", methods=["GET", "POST"])
def checkout():
    if request.method == "POST":
        price = request.form.get("price", "9.99")
        return Response(f"<html>Order placed! You paid: ${price}</html>", content_type="text/html")
    return Response("""
    <html><form method=POST>
    <input type=hidden name=price value=9.99>
    <input type=hidden name=is_admin value=false>
    <input type=submit value='Buy Now'>
    </form></html>""", content_type="text/html")

# persistent_xss — comment board that stores and displays input
COMMENTS = []
@app.route("/comments", methods=["GET", "POST"])
def comments():
    if request.method == "POST":
        comment = request.form.get("comment", "")
        COMMENTS.append(comment)
        return redirect("/comments")
    stored = "".join(f"<p>{c}</p>" for c in COMMENTS)  # vulnerable: no escaping
    return Response(f"""
    <html><body>
    <form method=POST><input name=comment><input type=submit value=Post></form>
    <div id=board>{stored}</div>
    </body></html>""", content_type="text/html")

# suspicious_comments — HTML with credentials in comments
@app.route("/commented-secrets")
def commented_secrets():
    return Response("""
    <!DOCTYPE html><html><head></head><body>
    <!-- TODO: remove before production -->
    <!-- password=admin123 -->
    <!-- API_KEY=sk-live-abc123def456 -->
    <!-- SELECT * FROM users WHERE id = ? -->
    <!-- Internal server: 192.168.1.50 -->
    <h1>Welcome</h1>
    </body></html>""", content_type="text/html")

# private_ip_disclosure — returns internal IP in header/body
@app.route("/internal-ip")
def internal_ip():
    return Response(
        "<html>Backend server: 192.168.1.50 | DB host: 10.0.0.5</html>",
        headers={"X-Backend-Server": "192.168.1.50", "Via": "1.1 10.0.0.1"},
        content_type="text/html"
    )

# permissions_policy — page with no Permissions-Policy or Referrer-Policy headers
@app.route("/no-policy-headers")
def no_policy_headers():
    # Intentionally omits Permissions-Policy, Referrer-Policy, COOP, COEP
    return Response("<html><body>No policy headers</body></html>", content_type="text/html")

# viewstate_scanner — ASP.NET style viewstate without MAC
@app.route("/viewstate-demo")
def viewstate_demo():
    import base64
    # Fake ViewState without MAC signature + embedded email
    fake_vs = base64.b64encode(b'/wEPDwUKMTY3NzkxMjM0Ng8WBB4FZW1haWwFE2FkbWluQGV4YW1wbGUuY29tZGRk').decode()
    return Response(f"""
    <html><form method=POST>
    <input type=hidden name=__VIEWSTATE value="{fake_vs}">
    <input type=submit value=Submit>
    </form></html>""", content_type="text/html")

# elmah_trace — fake ELMAH error log
@app.route("/elmah.axd")
def elmah_log():
    return Response("""
    <html><body>
    <h1>ELMAH - Error Log</h1>
    <p>Error: NullReferenceException at line 42</p>
    <p>DB Password: supersecret | Stack: System.Web.HttpApplication</p>
    </body></html>""", content_type="text/html")

@app.route("/phpinfo.php")
def phpinfo():
    return Response("<html><h2>PHP Version 8.1.0</h2><p>phpinfo() output</p></html>",
                    content_type="text/html")

# dangerous_js — eval() and innerHTML with user data + tabnabbing
@app.route("/dangerous-js-demo")
def dangerous_js_demo():
    return Response("""
    <!DOCTYPE html><html><body>
    <a href='https://evil.com' target='_blank'>External Link</a>
    <a href='https://attacker.com' target='_blank'>Another Link</a>
    <a href='https://malicious.com' target='_blank'>Click me</a>
    <script>
    var userInput = location.hash.substring(1);
    eval(userInput);  // dangerous
    document.getElementById('output').innerHTML = userInput;  // dangerous
    setTimeout(userInput, 100);  // dangerous
    new Function(userInput)();  // dangerous
    </script>
    <div id='output'></div>
    </body></html>""", content_type="text/html")

# spring4shell — spring-like endpoint that processes class.module params
@app.route("/spring-demo")
def spring_demo():
    class_param = request.args.get("class.module.classLoader.resources.context.parent.pipeline.first.pattern", "")
    if class_param:
        return Response(
            "MissingServletRequestParameterException: Spring Framework error — class.module parameter detected",
            status=400, content_type="text/plain",
            headers={"X-Powered-By": "Spring Boot/2.5.0"}
        )
    return Response(
        "<html>Spring App</html>",
        headers={"X-Powered-By": "Spring Boot/2.5.0"},
        content_type="text/html"
    )

# form_security — HTTPS form posting to HTTP
@app.route("/insecure-form")
def insecure_form():
    return Response("""
    <html><body>
    <form method=POST action='http://example.com/process'>
        <input type=password name=password>
        <input type=submit value=Login>
    </form>
    <form method=GET action='/login'>
        <input type=password name=password>
        <input type=submit value=Submit>
    </form>
    </body></html>""", content_type="text/html")

# proxy_disclosure — leaks version via Via/Server headers
@app.route("/proxy-headers")
def proxy_headers():
    return Response(
        "<html>Proxy test</html>",
        headers={
            "Via": "1.1 nginx/1.18.0 (Ubuntu)",
            "X-Backend-Server": "192.168.1.50:8080",
            "X-Powered-By": "PHP/7.4.3",
            "Server": "Apache/2.4.41 (Ubuntu)",
        },
        content_type="text/html"
    )


if __name__ == "__main__":
    print("\n🛡️  WebShield Demo App v1.8.0")
    print("=" * 50)
    print("📍 Running at: http://localhost:5000")
    print("⚠️  Contains INTENTIONAL vulnerabilities for testing")
    print("=" * 50)
    app.run(host="0.0.0.0", port=5000, debug=False)
