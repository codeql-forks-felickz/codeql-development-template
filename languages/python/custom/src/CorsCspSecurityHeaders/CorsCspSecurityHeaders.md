# Permissive CORS or weak Content-Security-Policy configuration

## Overview

Browsers enforce the same-origin policy and, when configured, a Content-Security-Policy (CSP). Both can be weakened by response headers or middleware configuration:

- `Access-Control-Allow-Origin: *` (or `null`) lets scripts on any website read the response. This exposes data from unauthenticated endpoints, and from deployments that are only reachable from a victim's browser or an internal network (CWE-942).
- A CORS middleware such as Starlette/FastAPI `CORSMiddleware` with `allow_credentials=True` and an origin pattern that is too broad lets attacker-controlled origins send credentialed cross-origin requests and read the responses. Examples are `allow_origins=["*"]`, `allow_origin_regex=".*"`, a regex with unescaped dots (`restaurant.com` also matches `restaurantXcom`), an unbounded wildcard directly before the domain (`.*example\.com` also matches `evilexample.com`), or an unbounded wildcard after the domain (`example\.com.*` also matches `example.com.evil.com`) (CWE-942).
- A CSP whose `script-src` (or `default-src` when no `script-src` is present) contains `'unsafe-inline'` without a nonce or hash allows injected inline scripts to run, which negates the CSP's protection against cross-site scripting (CWE-693).

This query reports:

- response header writes modeled by CodeQL (Flask, Werkzeug, Django, and others, plus the response passed to Flask `after_request` / `after_app_request` hooks) that set `Access-Control-Allow-Origin` to `*` or `null`, or set `Content-Security-Policy` to a value that allows inline scripts, and
- Starlette/FastAPI `CORSMiddleware` configurations with `allow_credentials=True` and a permissive `allow_origin_regex` or a wildcard in `allow_origins`.

## Recommendation

- Only allow explicitly trusted origins. Avoid `*`, and never combine permissive origins with credentials.
- For `allow_origin_regex`, escape literal dots and use an explicit sub-domain boundary, for example `https://([a-z0-9-]+\.)?example\.com`.
- Remove `'unsafe-inline'` from `script-src`. Use nonce- or hash-based sources instead.

## Example

The following Flask hook allows any origin to read responses and allows inline scripts:

```python
@app.after_request
def add_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'  # BAD
    response.headers['Content-Security-Policy'] = "script-src 'self' 'unsafe-inline'"  # BAD
    return response
```

Restrict the origin and use a nonce instead:

```python
@app.after_request
def add_headers(response):
    response.headers['Access-Control-Allow-Origin'] = 'https://trusted.example.com'  # GOOD
    response.headers['Content-Security-Policy'] = f"script-src 'self' 'nonce-{g.csp_nonce}'"  # GOOD
    return response
```

The following FastAPI middleware accepts origins such as `https://evilrestaurant.com` with credentials:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=".*.(restaurant.com|deliveryservice.com)",  # BAD
    allow_credentials=True,
)
```

Escape the dots and anchor the sub-domain boundary:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https://([a-z0-9-]+\.)?(restaurant\.com|deliveryservice\.com)",  # GOOD
    allow_credentials=True,
)
```

## References

- MDN: [Access-Control-Allow-Origin](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin)
- MDN: [Content-Security-Policy: script-src](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src)
- Starlette: [CORSMiddleware](https://www.starlette.io/middleware/#corsmiddleware)
- OWASP: [CORS origin header scrutiny](https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny)
- Common Weakness Enumeration: [CWE-693](https://cwe.mitre.org/data/definitions/693.html)
- Common Weakness Enumeration: [CWE-942](https://cwe.mitre.org/data/definitions/942.html)
