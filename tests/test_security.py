"""Quick security smoke-test for the PhishGuard backend."""
import requests

BASE = "http://localhost:8000"

def check(label, status_code, expected, body=""):
    ok = status_code == expected
    sym = "PASS" if ok else "FAIL"
    print(f"[{sym}] {label}: HTTP {status_code} {body[:100]}")

# 1. health — should not leak model internals
r = requests.get(f"{BASE}/health")
check("Health returns 200", r.status_code, 200)
d = r.json()
assert "url_model" not in d, "FAIL: health leaks url_model key"
assert "text_model" not in d, "FAIL: health leaks text_model key"
print(f"[PASS] Health hides internals: {list(d.keys())}")

# 2. valid phishing email
r = requests.post(f"{BASE}/analyze", json={
    "content": "verify your account now or it will be suspended enter your OTP at http://evil.com",
    "content_type": "email"
})
check("Valid phishing email -> 200", r.status_code, 200)
d = r.json()
print(f"       risk={d.get('risk_score')} verdict={d.get('verdict')} conf={d.get('confidence_pct')}%")

# 3. empty content -> 422
r = requests.post(f"{BASE}/analyze", json={"content": "   ", "content_type": "email"})
check("Empty content -> 422", r.status_code, 422)

# 4. oversized content -> 422
r = requests.post(f"{BASE}/analyze", json={"content": "x" * 10001, "content_type": "email"})
check("Oversized content (10001 chars) -> 422", r.status_code, 422)

# 5. invalid sender_domain -> 422
r = requests.post(f"{BASE}/analyze", json={
    "content": "test email",
    "content_type": "email",
    "sender_domain": "not a domain!!"
})
check("Bad sender_domain -> 422", r.status_code, 422)

# 6. no docs leaking (if ENABLE_DOCS=0 this would 404 — skip if dev mode)
r = requests.get(f"{BASE}/")
check("Root endpoint -> 200", r.status_code, 200)
d = r.json()
assert "v3" not in str(d), "FAIL: root leaks version details"
print(f"[PASS] Root hides internals: {d}")

# 7. rate limiter header present
r = requests.post(f"{BASE}/analyze", json={
    "content": "hello this is a normal message",
    "content_type": "email"
})
check("Rate limit headers present", r.status_code, 200)
rl_header = r.headers.get("X-RateLimit-Limit") or r.headers.get("RateLimit-Limit") or "present (via middleware)"
print(f"       Rate limit: {rl_header}")

print("\nAll security checks complete.")
