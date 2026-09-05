"""
api_security.py - API Security Testing (OWASP API Top 10)

Tools for testing REST APIs for common API-specific flaws that generic web
scanners miss:
- API endpoint discovery via OpenAPI/Swagger specs
- Excessive Data Exposure (API3) — sensitive fields leaked in responses
- Broken Object Level Authorization / BOLA (API1) — cross-user object access
- JWT weakness analysis (alg=none, weak HS256 secret)

All requests use httpx (no shell). URLs are validated. These tools are for
authorized testing of APIs you own or are permitted to assess.
"""

import json
import re

import httpx

_URL_RE = re.compile(r"^https?://[^\s;|&`$><]+$")

# Field names that should never appear in an API response body.
_SENSITIVE_FIELDS = [
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "private_key", "ssn", "credit_card", "card_number", "cvv", "auth_token",
    "session", "hash",
]


def _validate_url(url: str) -> str:
    url = url.strip()
    if not _URL_RE.match(url):
        raise ValueError(f"Invalid URL: {url}")
    return url.rstrip("/")


def _get(url: str, headers: dict | None = None, timeout: float = 15.0) -> httpx.Response | None:
    try:
        from quarr.core.target_throttle import get_throttle
        get_throttle().wait(url)  # honor per-target rate limit (scope compliance)
    except Exception:
        pass
    try:
        return httpx.get(url, headers=headers or {}, timeout=timeout, follow_redirects=True)
    except httpx.HTTPError:
        return None


def api_endpoint_discovery(target: str) -> str:
    """
    Discover API endpoints by locating and parsing an OpenAPI/Swagger spec.
    Tries common spec locations and lists every path + method.
    """
    base = _validate_url(target)
    candidates = [
        "/openapi.json", "/swagger.json", "/api-docs", "/v2/api-docs",
        "/v3/api-docs", "/swagger/v1/swagger.json", "/openapi.yaml",
    ]
    for path in candidates:
        resp = _get(base + path)
        if resp is None or resp.status_code != 200:
            continue
        try:
            spec = resp.json()
        except (json.JSONDecodeError, ValueError):
            continue
        paths = spec.get("paths", {})
        if not paths:
            continue
        lines = [f"=== API SPEC FOUND: {path} ==="]
        title = spec.get("info", {}).get("title", "?")
        lines.append(f"Title: {title}")
        lines.append(f"Endpoints ({len(paths)}):")
        for p, methods in sorted(paths.items()):
            for m in methods:
                if m.lower() in ("get", "post", "put", "delete", "patch"):
                    lines.append(f"  {m.upper():6s} {p}")
        return "\n".join(lines)
    return "[INFO] No OpenAPI/Swagger spec found at common locations."


def api_data_exposure_check(target: str, headers: str = "") -> str:
    """
    Fetch a JSON endpoint and flag Excessive Data Exposure (OWASP API3):
    sensitive field names (password, token, ssn, ...) present in the response.
    headers: optional 'Key: Value' lines (e.g. an Authorization header),
    separated by ';;'.
    """
    url = _validate_url(target)
    hdrs = {}
    for pair in filter(None, (h.strip() for h in headers.split(";;"))):
        if ":" in pair:
            k, v = pair.split(":", 1)
            hdrs[k.strip()] = v.strip()

    resp = _get(url, headers=hdrs)
    if resp is None:
        return f"[ERROR] Could not reach {url}"
    try:
        data = resp.json()
    except (json.JSONDecodeError, ValueError):
        return f"[INFO] Response is not JSON (HTTP {resp.status_code}); no API3 check performed."

    blob = json.dumps(data).lower()
    found = sorted({f for f in _SENSITIVE_FIELDS if f'"{f}"' in blob})
    lines = [f"=== EXCESSIVE DATA EXPOSURE CHECK: {url} ===", f"HTTP {resp.status_code}"]
    if found:
        lines.append(f"🚨 API3 — Sensitive field(s) exposed in response: {', '.join(found)}")
        lines.append("Impact: the API returns fields that should be filtered server-side.")
    else:
        lines.append("✅ No obviously-sensitive field names in the response body.")
    return "\n".join(lines)


def api_bola_check(
    target: str,
    object_path: str,
    id_a: str,
    id_b: str,
    token_a: str = "",
) -> str:
    """
    Test Broken Object Level Authorization / BOLA (OWASP API1).

    Using user A's token, request A's own object (id_a) then user B's object
    (id_b) at object_path (use '{id}' as the placeholder). If B's object is
    returned with A's token, BOLA is present.

    Example: object_path='/users/v1/{id}', id_a='alice', id_b='admin'.
    """
    base = _validate_url(target)
    if "{id}" not in object_path:
        return "[ERROR] object_path must contain the '{id}' placeholder."
    hdrs = {"Authorization": f"Bearer {token_a}"} if token_a else {}

    own = _get(base + object_path.replace("{id}", id_a), headers=hdrs)
    other = _get(base + object_path.replace("{id}", id_b), headers=hdrs)
    if own is None or other is None:
        return f"[ERROR] Could not reach {base}"

    lines = [f"=== BOLA CHECK (API1): {object_path} ==="]
    lines.append(f"Own object  ({id_a}): HTTP {own.status_code}")
    lines.append(f"Other object({id_b}): HTTP {other.status_code}")

    # If accessing another user's object with A's token returns 2xx (and content
    # differs from an error), that's a BOLA finding.
    if other.status_code < 300 and other.text and other.text != own.text:
        lines.append(
            f"🚨 BOLA CONFIRMED — user A's token accessed user B's object "
            f"({id_b}) and received HTTP {other.status_code}."
        )
        lines.append("Impact: horizontal privilege escalation / cross-tenant data access.")
    elif other.status_code in (401, 403):
        lines.append("✅ Access to another user's object was correctly denied.")
    else:
        lines.append(f"[INFO] Inconclusive — review manually (HTTP {other.status_code}).")
    return "\n".join(lines)


def http_request(
    method: str,
    url: str,
    headers: str = "",
    body: str = "",
    cookie: str = "",
    follow_redirects: bool = False,
) -> str:
    """Send a single arbitrary HTTP request and return a summary of the response.

    The core primitive for MANUAL verification and business-logic testing
    (bug bounty): reproduce a request, tamper a parameter, replay with another
    user's token, test IDOR/BOLA/access-control, etc.

    method: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS.
    headers: optional 'Name: value' lines separated by ';;'
             (e.g. 'Authorization: Bearer X;;X-Api: 9').
    body: optional request body (JSON or form string).
    cookie: optional Cookie header value (e.g. 'session=abc').
    Returns status, response headers, and a truncated body — never raises.
    """
    method = (method or "GET").strip().upper()
    if method not in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
        return f"[ERROR] Unsupported method: {method}"
    try:
        url = _validate_url(url)
    except ValueError as e:
        return f"[ERROR] {e}"

    hdrs = {}
    for pair in filter(None, (h.strip() for h in headers.split(";;"))):
        if ":" in pair:
            k, v = pair.split(":", 1)
            hdrs[k.strip()] = v.strip()
    if cookie:
        hdrs["Cookie"] = cookie.strip()

    content = body.encode() if body else None
    try:
        from quarr.core.target_throttle import get_throttle
        get_throttle().wait(url)  # per-target rate limit (scope compliance)
    except Exception:
        pass
    try:
        resp = httpx.request(
            method, url, headers=hdrs, content=content,
            timeout=20.0, follow_redirects=follow_redirects,
        )
    except httpx.HTTPError as e:
        return f"[ERROR] Request failed: {e}"

    lines = [
        f"=== HTTP {method} {url} ===",
        f"Status: {resp.status_code} {resp.reason_phrase}",
        f"Length: {len(resp.content)} bytes",
    ]
    # Security-relevant response headers.
    interesting = [
        "content-type", "set-cookie", "location", "www-authenticate",
        "access-control-allow-origin", "x-frame-options",
        "content-security-policy", "strict-transport-security",
    ]
    hdr_lines = [f"  {k}: {v}" for k, v in resp.headers.items() if k.lower() in interesting]
    if hdr_lines:
        lines.append("Response headers:")
        lines.extend(hdr_lines)
    # Redact secrets in the returned body before showing it.
    from quarr.core.secrets import redact
    body_text = redact(resp.text[:1500])
    lines.append("Body (first 1500 chars, secrets redacted):")
    lines.append(body_text)
    return "\n".join(lines)


def web_login(
    url: str,
    username: str,
    password: str,
    mode: str = "json",
    user_field: str = "username",
    pass_field: str = "password",
    token_field: str = "",
) -> str:
    """Authenticate to a web/API login endpoint and extract the session token/cookie.

    The output (Authorization header and/or Cookie) can be fed to authenticated
    scans (sqli_scan/vulnerability_scan/web_vuln_scan) and http_request — the
    key enabler for testing authenticated attack surface (BOLA/IDOR/etc.).

    mode: 'json' (POST JSON body) or 'form' (POST form-encoded).
    user_field/pass_field: credential field names in the request body.
    token_field: JSON key holding the token (auto-detected if empty, trying
                 common names: token, auth_token, access_token, jwt, id_token).
    """
    try:
        url = _validate_url(url)
    except ValueError as e:
        return f"[ERROR] {e}"
    if mode not in ("json", "form"):
        return "[ERROR] mode must be 'json' or 'form'."

    payload = {user_field: username, pass_field: password}
    try:
        if mode == "json":
            resp = httpx.post(url, json=payload, timeout=20.0, follow_redirects=False)
        else:
            resp = httpx.post(url, data=payload, timeout=20.0, follow_redirects=False)
    except httpx.HTTPError as e:
        return f"[ERROR] Login request failed: {e}"

    lines = [f"=== WEB LOGIN: {url} ===", f"Status: {resp.status_code}"]
    got_something = False

    # 1. Token from JSON body.
    token = None
    try:
        data = resp.json()
        if isinstance(data, dict):
            candidates = ([token_field] if token_field else
                          ["token", "auth_token", "access_token", "jwt",
                           "id_token", "accessToken", "authToken"])
            for key in candidates:
                if key and key in data and isinstance(data[key], str) and data[key]:
                    token = data[key]
                    break
            # Nested (e.g. {"data": {"token": ...}}).
            if token is None and isinstance(data.get("data"), dict):
                for key in candidates:
                    if key and isinstance(data["data"].get(key), str):
                        token = data["data"][key]
                        break
    except (json.JSONDecodeError, ValueError):
        pass

    if token:
        got_something = True
        lines.append(f"Token found: {token[:24]}...")
        lines.append(f"  → use as header: Authorization: Bearer {token}")

    # 2. Session cookie from Set-Cookie.
    set_cookie = resp.headers.get("set-cookie")
    if set_cookie:
        # Reduce to name=value pairs (drop attributes like Path/HttpOnly).
        jar = "; ".join(
            part.split(";", 1)[0].strip()
            for part in set_cookie.split(", ")
            if "=" in part.split(";", 1)[0]
        )
        if jar:
            got_something = True
            lines.append(f"Session cookie: {jar[:60]}")
            lines.append(f"  → use as cookie: {jar}")

    if resp.status_code >= 400:
        lines.append("⚠️ Login likely failed (HTTP >= 400). Check credentials/fields.")
    elif not got_something:
        lines.append("⚠️ Authenticated but no token/cookie detected — inspect the "
                     "response manually or set token_field.")
    return "\n".join(lines)


def jwt_analyze(token: str) -> str:
    """
    Analyze a JWT for common weaknesses: alg=none, weak/guessable HS256 secret,
    and decode the claims. Does not require network access.
    """
    import base64
    import hashlib
    import hmac

    token = token.strip()
    parts = token.split(".")
    if len(parts) != 3:
        return "[ERROR] Not a well-formed JWT (expected header.payload.signature)."

    def _b64d(seg: str) -> bytes:
        seg += "=" * (-len(seg) % 4)
        return base64.urlsafe_b64decode(seg)

    try:
        header = json.loads(_b64d(parts[0]))
        payload = json.loads(_b64d(parts[1]))
    except Exception:
        return "[ERROR] Could not decode JWT header/payload."

    lines = ["=== JWT ANALYSIS ==="]
    alg = header.get("alg", "?")
    lines.append(f"Algorithm: {alg}")
    lines.append(f"Claims: {json.dumps(payload)}")

    if str(alg).lower() == "none":
        lines.append("🚨 CRITICAL — alg=none: signature not verified, tokens can be forged.")

    if str(alg).upper() == "HS256":
        # Try a small list of common/weak secrets.
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        sig = _b64d(parts[2])
        weak = ["secret", "password", "123456", "changeme", "jwt_secret",
                "key", "admin", "qwerty", "test", "vampi", "your-256-bit-secret"]
        cracked = None
        for cand in weak:
            calc = hmac.new(cand.encode(), signing_input, hashlib.sha256).digest()
            if hmac.compare_digest(calc, sig):
                cracked = cand
                break
        if cracked:
            lines.append(f"🚨 HIGH — HS256 secret is weak/guessable: '{cracked}'. Tokens can be forged.")
        else:
            lines.append("✅ HS256 secret not in the common-weak-secret list.")
    return "\n".join(lines)
