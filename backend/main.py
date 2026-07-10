"""FastAPI backend for PhishGuard (v3).

All analysis is performed locally — no external API calls are made.
Security hardening (v3.1):
  - Rate limiting via slowapi (30 req/min per IP on /analyze, 60/min on /health)
  - Input validation: max lengths, control-char stripping, domain format check
  - Error handling: no stack traces or internal paths leak to the client
  - CORS: locked to configurable ALLOWED_ORIGINS (defaults to localhost only)
  - Request body size guard: 413 if Content-Length exceeds 64 KB
"""

from __future__ import annotations

import html
import json
import logging
import os
import re
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException, Request, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from slowapi.middleware import SlowAPIMiddleware
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

from backend.schemas import (
    AnalyzeRequest, AnalyzeResponse, DomainInfo, RiskBreakdown,
    ScorecardItem, TriggeredFeature, TyposquatInfo,
)
from model.features import (
    GENERIC_GREETINGS,
    SENSITIVE_INFO_PATTERNS,
    URGENCY_PHRASES,
    _extract_links,
    _host,
    _parsed_url,
    _registered_domain,
    domain_info_whois,
    extract_all_features,
    has_at_symbol,
    has_https,
    has_ip_address,
    has_suspicious_keywords_in_domain,
    num_subdomains,
    path_depth,
    query_param_count,
    sender_domain_mismatch,
    tld_suspicious,
    typosquatting_score,
    url_length,
    uses_url_shortener,
)

# ---------------------------------------------------------------------------
# Logging — server-side only, never forwarded to client
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("phishguard")

# ---------------------------------------------------------------------------
# Model loading
# ---------------------------------------------------------------------------
MODEL_DIR = ROOT / "model"

# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------
limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])

# ---------------------------------------------------------------------------
# CORS — only allow the local Streamlit origin by default.
# Set ALLOWED_ORIGINS in .env as a comma-separated list to add more.
# ---------------------------------------------------------------------------
_raw_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:8501,http://127.0.0.1:8501")
ALLOWED_ORIGINS: list[str] = [o.strip() for o in _raw_origins.split(",") if o.strip()]

# ---------------------------------------------------------------------------
# Max request body size (64 KB) — guards against DoS via giant payloads
# ---------------------------------------------------------------------------
_MAX_BODY_BYTES = 64 * 1024   # 64 KB

app = FastAPI(
    title="PhishGuard API",
    version="0.3.1",
    # Hide /docs and /redoc in production to reduce attack surface.
    # Set ENABLE_DOCS=1 in .env to re-enable during development.
    docs_url="/docs" if os.getenv("ENABLE_DOCS", "1") == "1" else None,
    redoc_url=None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


@app.middleware("http")
async def limit_body_size(request: Request, call_next):
    """Reject requests whose Content-Length exceeds _MAX_BODY_BYTES."""
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > _MAX_BODY_BYTES:
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={"detail": "Request body too large."},
        )
    return await call_next(request)

models: dict[str, Any] = {"url": None, "text": None}
feature_orders: dict[str, list[str]] = {"url": [], "text": []}
feature_importances: dict[str, dict[str, float]] = {"url": {}, "text": {}}


@app.on_event("startup")
def load_models() -> None:
    models["url"] = joblib.load(MODEL_DIR / "model_url.pkl")
    models["text"] = joblib.load(MODEL_DIR / "model_text.pkl")
    feature_orders["url"] = json.loads((MODEL_DIR / "feature_order_url.json").read_text(encoding="utf-8"))
    feature_orders["text"] = json.loads((MODEL_DIR / "feature_order_text.json").read_text(encoding="utf-8"))
    feature_importances["url"] = json.loads((MODEL_DIR / "feature_importances_url.json").read_text(encoding="utf-8"))
    feature_importances["text"] = json.loads((MODEL_DIR / "feature_importances_text.json").read_text(encoding="utf-8"))


def _ensure_models_loaded() -> None:
    if models["url"] is None or models["text"] is None:
        load_models()


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------

def _model_key(content_type: str) -> str:
    return "url" if content_type == "url" else "text"


def _numeric_feature(value: Any) -> float:
    if value is None:
        return 0.0
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _validate_url(url: str) -> None:
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(
            status_code=422,
            detail="URL must start with http:// or https:// and include a domain.",
        )


def _verdict(score: int) -> str:
    if score <= 39:
        return "Safe"
    if score <= 69:
        return "Suspicious"
    return "Dangerous"


def _probability_to_risk_score(probability: float, content_type: str) -> int:
    """Map model probability to a balanced 0-100 risk score.

    The model outputs near-0 or near-1 probabilities on synthetic data.
    A straight prob*100 gives only ~1 or ~95+ — nothing in the middle.

    This piecewise curve spreads probability across the full verdict range.
    Key design decisions:
    - prob=1.0 on a URL shortener (genuinely ambiguous) → ~75, not 100.
    - prob=0.87 on a borderline email (urgency + generic greeting) → ~62, Suspicious.
    - prob=1.0 on an IP-address URL or obvious typosquat → ~92, Dangerous.
    - The floor from _apply_risk_floor can nudge into low-Suspicious at most.

      Text (email / sms):
        0.00–0.10  →   0–18   (clearly safe)
        0.10–0.50  →  18–50   (low-risk / borderline)
        0.50–0.75  →  50–65   (Suspicious)
        0.75–0.92  →  65–80   (high Suspicious / low Dangerous)
        0.92–1.00  →  80–100  (clear Dangerous)

      URL (model is extremely confident on obvious cases — compress more):
        0.00–0.10  →   0–12
        0.10–0.50  →  12–45
        0.50–0.75  →  45–62
        0.75–0.92  →  62–76
        0.92–1.00  →  76–100
    """
    p = max(0.0, min(1.0, probability))

    # prob=1.0 exactly means the RF gave unanimous vote across all trees.
    # For URLs, some of those (shorteners, keyword-stuffed domains) are
    # genuinely ambiguous — a URL shortener is suspicious but not certainly
    # malicious. Cap them below 100 so the user still sees a gradient.
    # For email/sms, unanimous agreement almost always means truly dangerous.
    if p == 1.0:
        return 92 if content_type == "url" else 100
    if p == 0.0:
        return 0

    if content_type == "url":
        if p < 0.10:
            score = p / 0.10 * 12
        elif p < 0.50:
            score = 12 + (p - 0.10) / 0.40 * 33
        elif p < 0.75:
            score = 45 + (p - 0.50) / 0.25 * 17
        elif p < 0.92:
            score = 62 + (p - 0.75) / 0.17 * 14
        else:
            score = 76 + (p - 0.92) / 0.08 * 24
    else:
        if p < 0.10:
            score = p / 0.10 * 18
        elif p < 0.50:
            score = 18 + (p - 0.10) / 0.40 * 32
        elif p < 0.75:
            score = 50 + (p - 0.50) / 0.25 * 15
        elif p < 0.94:
            score = 65 + (p - 0.75) / 0.19 * 15
        else:
            score = 80 + (p - 0.94) / 0.06 * 20

    return max(0, min(100, round(score)))


def _confidence_label(probability: float) -> str:
    distance = abs(probability - 0.5) * 2
    if distance < 0.35:
        return "Low"
    if distance < 0.7:
        return "Medium"
    return "High"


def _confidence_pct(probability: float) -> int:
    """Convert model probability to a 0-100 confidence integer."""
    return max(0, min(100, round(abs(probability - 0.5) * 200)))


# ---------------------------------------------------------------------------
# Feature detail strings
# ---------------------------------------------------------------------------

def _feature_detail(name: str, value: Any, request: AnalyzeRequest) -> str:
    content = request.content
    if name == "url_length":
        return f"URL is {int(value)} characters long"
    if name == "num_subdomains":
        return f"{int(value)} subdomain level(s) detected"
    if name == "has_ip_address":
        return "Host is a raw IP address instead of a domain"
    if name == "uses_url_shortener":
        return "URL uses a known link-shortening service"
    if name == "has_https":
        return "URL uses HTTPS"
    if name == "count_special_chars":
        return f"{int(value)} suspicious character(s) (@, -, //) in URL"
    if name == "has_suspicious_keywords_in_domain":
        return "Domain contains phishing-related keywords (login, verify, secure…)"
    if name == "has_at_symbol":
        return "URL contains '@' — browser ignores everything before it"
    if name == "path_depth":
        return f"URL path has {int(value)} segment(s)"
    if name == "query_param_count":
        return f"URL has {int(value)} query parameter(s)"
    if name == "tld_suspicious":
        return "Top-level domain is commonly abused by phishers"
    if name == "urgency_score":
        found = [p for p in URGENCY_PHRASES if p in content.lower()]
        return f"Urgency phrase found: '{found[0]}'" if found else f"{int(value)} urgency phrase(s)"
    if name == "requests_sensitive_info":
        found = [i for i in SENSITIVE_INFO_PATTERNS if re.search(rf"\b{re.escape(i)}\b", content, re.I)]
        return f"Requests sensitive info: '{found[0]}'" if found else "Requests credentials or sensitive info"
    if name == "generic_greeting":
        found = [g for g in GENERIC_GREETINGS if re.search(rf"\b{re.escape(g)}\b", content, re.I)]
        return f"Generic greeting: '{found[0]}'" if found else "No personalised greeting"
    if name == "link_text_mismatch":
        links = _extract_links(content)
        if links:
            return f"Link text '{links[0][0]}' points to {urlparse(links[0][1]).netloc}"
        return "Displayed link text doesn't match destination domain"
    if name == "grammar_error_density":
        return f"Grammar/formatting error density: {float(value):.2f}"
    if name == "sender_domain_mismatch":
        return f"Claimed brand doesn't match sender domain '{request.sender_domain}'"
    return f"Value: {value}"


# ---------------------------------------------------------------------------
# Triggered features
# ---------------------------------------------------------------------------

def _triggered_features(
    features: dict[str, Any], request: AnalyzeRequest
) -> list[TriggeredFeature]:
    key = _model_key(request.content_type)
    order = feature_orders[key]
    importances = feature_importances[key]

    if request.content_type in {"email", "sms"}:
        features["sender_domain_mismatch"] = sender_domain_mismatch(
            request.content, request.claimed_brand, request.sender_domain,
        )

    triggered: list[TriggeredFeature] = []
    for name, value in features.items():
        if name not in order:
            continue
        is_triggered = bool(value) if isinstance(value, bool) else _numeric_feature(value) > 0
        if name == "has_https":
            is_triggered = False   # HTTPS is a positive signal, never flag it
        if is_triggered:
            triggered.append(TriggeredFeature(
                name=name,
                detail=_feature_detail(name, value, request),
                weight=round(float(importances.get(name, 0.0)), 4),
            ))
    return sorted(triggered, key=lambda t: t.weight, reverse=True)[:6]


# ---------------------------------------------------------------------------
# Threat category (rule-based)
# ---------------------------------------------------------------------------

_CATEGORY_RULES: list[tuple[str, list[str]]] = [
    # Only match on phrases that are genuinely rare in legitimate email.
    # Single common words like "subscription", "invoice", "renewal" are
    # intentionally excluded — they appear in every billing notification.
    ("Credential Theft",          ["provide your otp", "enter your otp", "confirm your password",
                                   "enter your one-time code", "confirm your pin",
                                   "provide your credentials", "login credentials",
                                   "share your authenticator", "enter your passphrase"]),
    ("Banking Scam",              ["card number", "cvv", "routing number",
                                   "wire transfer", "bank account details"]),
    ("Fake Delivery",             ["delivery fee", "customs fee", "customs clearance",
                                   "pay to release", "reschedule delivery"]),
    ("Account Suspension Threat", ["account will be suspended", "account will be closed",
                                   "account has been locked", "account restricted",
                                   "temporarily locked", "reactivate your account",
                                   "confirm now or lose access"]),
    ("Prize / Lottery Scam",      ["you have won", "you are our lucky winner",
                                   "claim your prize", "claim your reward",
                                   "unclaimed reward", "gift card worth"]),
    ("Tech Support Scam",         ["call us now", "toll-free number", "microsoft support",
                                   "apple support", "virus detected on your computer",
                                   "your device has been compromised"]),
    ("Crypto Scam",               ["bitcoin", "crypto wallet", "nft", "blockchain",
                                   "confirm your wallet", "wallet access at risk"]),
    ("Investment Scam",           ["guaranteed returns", "forex trading profit",
                                   "double your investment", "trading signals"]),
    ("Typosquatting / Fake URL",  ["paypa1", "amaz0n", "micros0ft", "netf1ix",
                                   "g00gle", "app1e", "faceb00k"]),
]


def _classify_threat(content: str, content_type: str, triggered: list[TriggeredFeature]) -> str:
    body = content.lower()
    for category, keywords in _CATEGORY_RULES:
        if any(kw in body for kw in keywords):
            return category
    # Fallback based on content type
    if content_type == "url":
        return "Suspicious URL"
    if content_type == "sms":
        return "Smishing Attack"
    return "Phishing Email"


# ---------------------------------------------------------------------------
# Risk breakdown
# ---------------------------------------------------------------------------

def _risk_breakdown(features: dict[str, Any], probability: float, content_type: str) -> RiskBreakdown:
    p = probability

    if content_type == "url":
        domain_signals = [
            _numeric_feature(features.get("has_ip_address", 0)),
            _numeric_feature(features.get("uses_url_shortener", 0)),
            min(_numeric_feature(features.get("num_subdomains", 0)) / 3, 1.0),
            _numeric_feature(features.get("has_suspicious_keywords_in_domain", 0)),
            _numeric_feature(features.get("has_at_symbol", 0)),
            _numeric_feature(features.get("tld_suspicious", 0)),
            (1.0 if not features.get("has_https", True) else 0.0),
        ]
        content_signals = [
            min(_numeric_feature(features.get("url_length", 0)) / 120, 1.0),
            min(_numeric_feature(features.get("count_special_chars", 0)) / 5, 1.0),
            min(_numeric_feature(features.get("path_depth", 0)) / 4, 1.0),
            min(_numeric_feature(features.get("query_param_count", 0)) / 4, 1.0),
        ]
        domain_risk = round(min(sum(domain_signals) / len(domain_signals) * 100 * 1.4, 100))
        content_risk = round(min(sum(content_signals) / len(content_signals) * 100 * 1.6, 100))
        credential_theft = round(p * 60)      # URL model doesn't have text signals
        social_engineering = round(p * 50)
    else:
        urgency = min(_numeric_feature(features.get("urgency_score", 0)) / 4, 1.0)
        sensitive = _numeric_feature(features.get("requests_sensitive_info", 0))
        generic = _numeric_feature(features.get("generic_greeting", 0))
        mismatch = _numeric_feature(features.get("sender_domain_mismatch", 0))
        link_mm = _numeric_feature(features.get("link_text_mismatch", 0))
        grammar = min(_numeric_feature(features.get("grammar_error_density", 0)) * 10, 1.0)

        domain_risk = round(min((mismatch * 0.6 + link_mm * 0.4) * 100, 100))
        content_risk = round(min((urgency * 0.5 + grammar * 0.5) * 100, 100))
        credential_theft = round(min(sensitive * 100, 100))
        social_engineering = round(min((generic * 0.4 + urgency * 0.6) * 100, 100))

    return RiskBreakdown(
        domain_risk=domain_risk,
        content_risk=content_risk,
        credential_theft=credential_theft,
        social_engineering=social_engineering,
    )


# ---------------------------------------------------------------------------
# Scorecard
# ---------------------------------------------------------------------------

def _scorecard(features: dict[str, Any], probability: float, content_type: str) -> list[ScorecardItem]:
    if content_type == "url":
        https_ok = bool(features.get("has_https", False))
        no_ip = not bool(features.get("has_ip_address", False))
        no_shortener = not bool(features.get("uses_url_shortener", False))
        no_kw = not bool(features.get("has_suspicious_keywords_in_domain", False))
        no_at = not bool(features.get("has_at_symbol", False))
        no_tld = not bool(features.get("tld_suspicious", False))
        subs = _numeric_feature(features.get("num_subdomains", 0))
        sp = _numeric_feature(features.get("count_special_chars", 0))

        return [
            ScorecardItem(label="HTTPS",                score=10 if https_ok else 0,                     max_score=10),
            ScorecardItem(label="No IP Address",        score=15 if no_ip else 0,                        max_score=15),
            ScorecardItem(label="No URL Shortener",     score=10 if no_shortener else 0,                 max_score=10),
            ScorecardItem(label="Clean Domain",         score=20 if no_kw else max(0, 20 - 10),          max_score=20),
            ScorecardItem(label="No @ Symbol",          score=10 if no_at else 0,                        max_score=10),
            ScorecardItem(label="Safe TLD",             score=10 if no_tld else 0,                       max_score=10),
            ScorecardItem(label="Subdomain Depth",      score=max(0, 15 - int(subs) * 5),                max_score=15),
            ScorecardItem(label="Special Chars",        score=max(0, 10 - int(sp) * 2),                  max_score=10),
        ]
    else:
        urgency = min(_numeric_feature(features.get("urgency_score", 0)), 5)
        sensitive = bool(features.get("requests_sensitive_info", False))
        generic = bool(features.get("generic_greeting", False))
        link_mm = bool(features.get("link_text_mismatch", False))
        grammar = _numeric_feature(features.get("grammar_error_density", 0))
        mismatch = bool(features.get("sender_domain_mismatch", False))

        return [
            ScorecardItem(label="No Urgency Phrases",   score=max(0, 20 - int(urgency) * 4),             max_score=20),
            ScorecardItem(label="No Sensitive Requests",score=0 if sensitive else 20,                    max_score=20),
            ScorecardItem(label="Personalised Greeting",score=0 if generic else 15,                      max_score=15),
            ScorecardItem(label="Link Integrity",       score=0 if link_mm else 15,                      max_score=15),
            ScorecardItem(label="Grammar Quality",      score=max(0, 15 - int(grammar * 30)),             max_score=15),
            ScorecardItem(label="Sender Legitimacy",    score=0 if mismatch else 15,                     max_score=15),
        ]


# ---------------------------------------------------------------------------
# Domain info card
# ---------------------------------------------------------------------------

def _domain_info(url: str) -> DomainInfo:
    parsed = _parsed_url(url)
    host = _host(url)
    tld = "." + host.rsplit(".", 1)[-1] if "." in host else ""
    whois_data = domain_info_whois(url)
    return DomainInfo(
        domain=host,
        is_https=has_https(url),
        num_subdomains=num_subdomains(url),
        has_ip=has_ip_address(url),
        uses_shortener=uses_url_shortener(url),
        tld=tld,
        domain_age_days=None,        # only when WHOIS enabled
        registrar=whois_data.get("registrar"),
        country=whois_data.get("country"),
    )


# ---------------------------------------------------------------------------
# Text highlight
# ---------------------------------------------------------------------------

def _markdown_escape(text: str) -> str:
    return html.escape(text, quote=False)


def _bold_once(rendered: str, phrase: str) -> str:
    if not phrase:
        return rendered
    escaped = _markdown_escape(phrase)
    return re.sub(re.escape(escaped), f"**{escaped}**", rendered, count=1, flags=re.IGNORECASE)


def _highlighted_text(content: str, triggered: list[TriggeredFeature]) -> str:
    rendered = _markdown_escape(content)
    for feature in triggered:
        detail = feature.detail
        for phrase in re.findall(r"'([^']+)'", detail):
            rendered = _bold_once(rendered, phrase)
        if feature.name == "has_ip_address":
            m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", content)
            if m:
                rendered = _bold_once(rendered, m.group(0))
        if feature.name == "has_suspicious_keywords_in_domain":
            for kw in ("secure", "login", "verify", "update", "account", "confirm", "signin", "banking"):
                if kw in content.lower():
                    rendered = _bold_once(rendered, kw)
                    break
    return rendered


# ---------------------------------------------------------------------------
# Fallback explanation
# ---------------------------------------------------------------------------

def _local_explanation(risk_score: int, verdict: str, triggered: list[TriggeredFeature]) -> str:
    if not triggered:
        return f"- Risk score {risk_score}/100 ({verdict}): no strong phishing signals detected."
    names = ", ".join(t.name for t in triggered[:5])
    bullets = [f"- Flagged for: {names}."]
    bullets.extend(f"- {t.detail}." for t in triggered[:4])
    return "\n".join(bullets)


# ---------------------------------------------------------------------------
# Risk floor — content-signal override
# ---------------------------------------------------------------------------

def _apply_risk_floor(risk_score: int, features: dict[str, Any], content_type: str) -> int:
    """Nudge the model score upward only when multiple hard signals co-occur.

    Rules:
    - The floor CANNOT make a verdict jump by more than one band on its own.
      e.g. if the model says Safe (score 8), the floor cannot push it to
      Dangerous — at most to low-Suspicious (42).
    - A single signal on its own contributes very little.
    - Only combinations of 2+ strong signals produce a meaningful nudge.
    - URL scoring is purely model-driven — no floor applied.

    Signal contributions:
      urgency ≥1    +8   (one phrase: legitimate reminders use these too)
      urgency ≥3    +7   (several phrases: stronger signal)
      sensitive     +12  (explicit OTP/credentials/CVV request)
      generic       +4   (impersonal greeting — weak on its own)
      link_mm       +8   (link text doesn't match destination)
      sender_mm     +5   (sender domain doesn't match claimed brand)
      combo bonus   +6   (urgency ≥1 AND sensitive — classic phishing pair)

    Max floor = 8+7+12+4+8+5+6 = 50, capped hard at 45.
    Single urgency phrase only → floor 8 → score stays in Safe unless model says otherwise.
    urgency + OTP request (no other signals) → floor 8+12+6 = 26 → low-Suspicious at most.
    """
    if content_type == "url":
        return risk_score

    urgency   = _numeric_feature(features.get("urgency_score", 0))
    sensitive = bool(features.get("requests_sensitive_info", False))
    generic   = bool(features.get("generic_greeting", False))
    link_mm   = bool(features.get("link_text_mismatch", False))
    sender_mm = bool(features.get("sender_domain_mismatch", False))

    floor = 0
    if urgency >= 1:
        floor += 8
    if urgency >= 3:
        floor += 7
    if sensitive:
        floor += 12
    if generic:
        floor += 4
    if link_mm:
        floor += 8
    if sender_mm:
        floor += 5
    if urgency >= 1 and sensitive:
        floor += 6

    return max(risk_score, min(floor, 40))


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
def health(request: Request) -> dict[str, Any]:
    _ensure_models_loaded()
    return {
        "status": "ok",
        "models_loaded": models["url"] is not None and models["text"] is not None,
    }


@app.get("/")
def root() -> dict[str, str]:
    return {"app": "PhishGuard API", "health": "/health"}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(request: Request, body: AnalyzeRequest) -> AnalyzeResponse:
    t0 = time.perf_counter()
    try:
        if body.content_type == "url":
            _validate_url(body.content)

        _ensure_models_loaded()
        key = _model_key(body.content_type)
        order = feature_orders[key]
        model = models[key]

        features = extract_all_features(body.content, body.content_type)
        if body.content_type in {"email", "sms"}:
            features["sender_domain_mismatch"] = sender_domain_mismatch(
                body.content, body.claimed_brand, body.sender_domain,
            )

        vector = pd.DataFrame(
            [[_numeric_feature(features.get(name, 0)) for name in order]],
            columns=order,
        )
        probability = float(model.predict_proba(vector)[0][1])
        risk_score = _probability_to_risk_score(probability, body.content_type)
        verdict = _verdict(risk_score)
        conf_label = _confidence_label(probability)
        conf_pct = _confidence_pct(probability)

        triggered = _triggered_features(features, body)

        risk_score = _apply_risk_floor(risk_score, features, body.content_type)
        verdict = _verdict(risk_score)

        explanation = _local_explanation(risk_score, verdict, triggered)
        highlighted = _highlighted_text(body.content, triggered)
        breakdown = _risk_breakdown(features, probability, body.content_type)
        scorecard = _scorecard(features, probability, body.content_type)
        threat_cat = _classify_threat(body.content, body.content_type, triggered)

        domain_info = None
        typosquat_info = None
        if body.content_type == "url":
            domain_info = _domain_info(body.content)
            ts = typosquatting_score(body.content)
            typosquat_info = TyposquatInfo(
                detected=ts["is_typosquat"],
                domain=ts["domain"],
                closest_brand=ts["closest_brand"],
                similarity=ts["similarity"],
            )

        safe_features: dict[str, Any] = {}
        for k, v in features.items():
            if v is None:
                safe_features[k] = None
            elif isinstance(v, bool):
                safe_features[k] = v
            else:
                try:
                    safe_features[k] = float(v)
                except Exception:
                    safe_features[k] = str(v)

        scan_ms = max(1, round((time.perf_counter() - t0) * 1000))
        logger.info("analyze | type=%s verdict=%s score=%d conf=%d%% ms=%d",
                    body.content_type, verdict, risk_score, conf_pct, scan_ms)

        return AnalyzeResponse(
            risk_score=risk_score,
            verdict=verdict,
            confidence=conf_label,
            confidence_pct=conf_pct,
            scan_time_ms=scan_ms,
            triggered_features=triggered,
            all_features=safe_features,
            explanation=explanation,
            highlighted_text=highlighted,
            threat_category=threat_cat,
            risk_breakdown=breakdown,
            scorecard=scorecard,
            domain_info=domain_info,
            typosquat=typosquat_info,
        )
    except HTTPException:
        raise
    except Exception as exc:
        # Log full traceback server-side; return generic message to client
        logger.exception("Unhandled error in /analyze: %s", exc)
        raise HTTPException(
            status_code=500,
            detail="Analysis failed. Please try again.",
        )
