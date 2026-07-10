"""Defensive feature extraction for PhishGuard.

Each public feature function is intentionally small and pure from the caller's
point of view: malformed input should return a safe default, not raise. The
optional WHOIS lookup is best-effort and excluded from training when unavailable.

v4 additions:
  URL: domain_entropy, digit_ratio_in_domain, hyphen_count_in_domain
  Text: uppercase_ratio, exclamation_count, url_count_in_text,
        keyword_density, suspicious_tld_in_body
  typosquatting_score remains runtime-only (not in training matrix).
"""

from __future__ import annotations

import math
import re
import signal
import os
from collections import Counter
from contextlib import contextmanager
from typing import Any, Optional
from urllib.parse import urlparse, parse_qs


# ---------------------------------------------------------------------------
# Constant pools (shared with backend for detail generation)
# ---------------------------------------------------------------------------

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "short.io",
    "bl.ink", "tiny.cc", "rb.gy", "shorturl.at",
}

SUSPICIOUS_DOMAIN_KEYWORDS = {
    "secure", "login", "verify", "update", "account", "confirm",
    "signin", "banking", "support", "billing", "alert", "service",
    "portal", "help", "ref", "validate", "recover", "unlock",
    "access", "credential", "auth", "identity", "limited",
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".info", ".tk", ".ml", ".ga",
    ".cf", ".gq", ".pw", ".work", ".online", ".site", ".space",
    ".buzz", ".click", ".link", ".live", ".win", ".download",
    ".icu", ".vip", ".loan", ".review", ".date", ".faith",
}

URGENCY_PHRASES = [
    "act now", "verify immediately", "account will be suspended",
    "urgent action required", "limited time", "click immediately",
    "your account has been locked", "final notice", "action required",
    "unusual activity", "unauthorized attempt", "security alert",
    "account restricted", "temporarily locked", "billing update",
    "payment declined", "action needed", "click here",
    "immediate attention", "suspension warning", "update details",
    "verify your identity", "delivery fee", "package pending",
    "confirm now", "respond immediately", "expires today",
    "last chance", "your account will be closed", "reactivate now",
    "we detected", "suspicious login", "access blocked",
]

SENSITIVE_INFO_PATTERNS = [
    "password", "OTP", "one-time code", "card number", "CVV", "SSN",
    "PIN", "social security", "credentials", "credit card",
    "billing address", "bank details", "verification link",
    "security code", "social security number", "login credentials",
    "account number", "routing number", "date of birth", "mother's maiden",
    "secret answer", "passphrase", "two-factor", "authenticator code",
]

GENERIC_GREETINGS = [
    "Dear Customer", "Dear User", "Dear Valued Member",
    "Dear Account Holder", "Hello User", "Valued Customer",
    "Dear Sir", "Dear Madam", "Dear Sir/Madam", "Dear member",
    "Dear Account Owner", "Attention",
]

BRAND_DOMAINS = {
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "your bank": "bank",
    "netflix": "netflix.com",
    "google": "google.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "coinbase": "coinbase.com",
    "binance": "binance.com",
    "chase": "chase.com",
    "wells fargo": "wellsfargo.com",
    "linkedin": "linkedin.com",
    "dropbox": "dropbox.com",
    "spotify": "spotify.com",
    "uber": "uber.com",
    "airbnb": "airbnb.com",
    "twitter": "twitter.com",
    "whatsapp": "whatsapp.com",
}

# Phishing keyword set used for keyword_density feature.
#
# IMPORTANT: only include words that are genuinely rare in legitimate
# transactional email. Common business words like "account", "payment",
# "billing", "security", "link", "login", "update", "notice" appear
# constantly in safe emails (receipts, statements, password-change
# confirmations) and must NOT be here — their presence in safe training
# data would cause the model to fire on every normal email.
#
# Good candidates: words that essentially never appear in a real company
# email unless it is a scam.
PHISHING_KEYWORDS = {
    # Explicit credential demands
    "otp", "credentials", "passphrase", "authenticator",
    # Extreme threat / punishment language
    "suspended", "permanently", "terminated", "reactivate",
    "unauthorized", "compromised", "fraudulent",
    # Implausible reward language
    "congratulations", "winner", "lucky", "unclaimed",
    # Deceptive action words rarely used by real companies
    "validate", "unlock", "unblock",
}

# Known brands for typosquatting comparison (runtime only)
KNOWN_BRANDS_FOR_TYPOSQUAT = {
    "paypal.com", "amazon.com", "microsoft.com", "apple.com",
    "netflix.com", "google.com", "facebook.com", "instagram.com",
    "coinbase.com", "binance.com", "chase.com", "wellsfargo.com",
    "linkedin.com", "twitter.com", "yahoo.com", "ebay.com",
    "dropbox.com", "github.com", "spotify.com", "uber.com",
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _to_text(value: Any) -> str:
    try:
        return "" if value is None else str(value)
    except Exception:
        return ""


def _parsed_url(url: Any):
    try:
        text = _to_text(url).strip()
        if not text:
            return urlparse("")
        if "://" not in text:
            text = f"http://{text}"
        return urlparse(text)
    except Exception:
        return urlparse("")


def _host(url: Any) -> str:
    try:
        return (_parsed_url(url).hostname or "").lower().strip(".")
    except Exception:
        return ""


def _domain_without_common_prefix(url: Any) -> str:
    host = _host(url)
    return host[4:] if host.startswith("www.") else host


def _registered_domain(host: str) -> str:
    parts = [p for p in host.lower().strip(".").split(".") if p]
    if len(parts) < 2:
        return host.lower()
    return ".".join(parts[-2:])


# ---------------------------------------------------------------------------
# URL features — original set
# ---------------------------------------------------------------------------

def url_length(url: str) -> int:
    """Raw character length of the URL string."""
    try:
        return len(_to_text(url))
    except Exception:
        return 0


def num_subdomains(url: str) -> int:
    """Number of subdomain levels (dot count in host minus one)."""
    try:
        host = _host(url)
        if not host or has_ip_address(host):
            return 0
        return max(host.count(".") - 1, 0)
    except Exception:
        return 0


def has_ip_address(url: str) -> bool:
    """True when the host is an IPv4 address."""
    try:
        host = _host(url) or _to_text(url)
        return bool(re.search(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
            host,
        ))
    except Exception:
        return False


def uses_url_shortener(url: str) -> bool:
    """True when the host is a known URL-shortening service."""
    try:
        host = _domain_without_common_prefix(url)
        return host in SHORTENER_DOMAINS
    except Exception:
        return False


def has_https(url: str) -> bool:
    """True when the URL scheme is HTTPS."""
    try:
        return _parsed_url(url).scheme.lower() == "https"
    except Exception:
        return False


def count_special_chars(url: str) -> int:
    """Count @, - and // occurrences in the URL after the scheme."""
    try:
        text = _to_text(url)
        remainder = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", text, count=1)
        return remainder.count("@") + remainder.count("-") + remainder.count("//")
    except Exception:
        return 0


def has_suspicious_keywords_in_domain(url: str) -> bool:
    """True when the domain/subdomain contains phishing-oriented keywords."""
    try:
        domain = _domain_without_common_prefix(url)
        return any(keyword in domain for keyword in SUSPICIOUS_DOMAIN_KEYWORDS)
    except Exception:
        return False


def has_at_symbol(url: str) -> bool:
    """True when '@' appears in the URL (browser ignores everything before it)."""
    try:
        return "@" in _to_text(url)
    except Exception:
        return False


def path_depth(url: str) -> int:
    """Number of non-empty path segments (e.g. /login/verify/confirm → 3)."""
    try:
        path = _parsed_url(url).path or ""
        return len([s for s in path.split("/") if s])
    except Exception:
        return 0


def query_param_count(url: str) -> int:
    """Number of query parameters in the URL."""
    try:
        qs = _parsed_url(url).query or ""
        if not qs:
            return 0
        return len(parse_qs(qs, keep_blank_values=True))
    except Exception:
        return 0


def tld_suspicious(url: str) -> bool:
    """True when the TLD is commonly associated with free/abuse-prone registrars."""
    try:
        host = _host(url)
        if not host:
            return False
        for tld in SUSPICIOUS_TLDS:
            if host.endswith(tld):
                return True
        return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# URL features — v4 additions
# ---------------------------------------------------------------------------

def domain_entropy(url: str) -> float:
    """Shannon entropy of the registered domain name (excluding TLD).

    Legitimate domains tend to use pronounceable, low-entropy strings.
    Randomly generated phishing domains (e.g. 'x7k2p9mq.com') have high entropy.
    Returns a float in [0, log2(26)] ≈ [0, 4.7].
    """
    try:
        host = _host(url)
        reg = _registered_domain(host)
        # Strip the TLD portion — keep only the SLD label
        label = reg.rsplit(".", 1)[0] if "." in reg else reg
        label = re.sub(r"[^a-z0-9]", "", label.lower())
        if not label:
            return 0.0
        freq = Counter(label)
        length = len(label)
        return -sum((c / length) * math.log2(c / length) for c in freq.values())
    except Exception:
        return 0.0


def digit_ratio_in_domain(url: str) -> float:
    """Fraction of digits in the registered domain label (SLD, not TLD).

    Legitimate domains rarely have many digits. A high ratio (>0.3) is suspicious.
    Returns a float in [0.0, 1.0].
    """
    try:
        host = _host(url)
        reg = _registered_domain(host)
        label = reg.rsplit(".", 1)[0] if "." in reg else reg
        label = re.sub(r"[^a-z0-9]", "", label.lower())
        if not label:
            return 0.0
        return sum(1 for c in label if c.isdigit()) / len(label)
    except Exception:
        return 0.0


def hyphen_count_in_domain(url: str) -> int:
    """Number of hyphens in the full hostname.

    Phishing domains often chain words with hyphens: secure-login-verify.com.
    Legitimate domains rarely exceed one hyphen.
    """
    try:
        host = _host(url)
        return host.count("-")
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# Typosquatting score (inference-only — not in training matrix)
# ---------------------------------------------------------------------------

def _levenshtein(a: str, b: str) -> int:
    """Standard Levenshtein distance, O(n*m)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = curr
    return prev[-1]


def typosquatting_score(url: str) -> dict:
    """Return the closest known brand domain and a similarity % (0–100).

    Returns {"domain": str, "closest_brand": str, "similarity": int, "is_typosquat": bool}.
    is_typosquat is True when similarity >= 75% but the domain is NOT the brand itself.
    """
    try:
        host = _host(url)
        reg = _registered_domain(host)
        if not reg:
            return {"domain": host, "closest_brand": "", "similarity": 0, "is_typosquat": False}

        best_brand = ""
        best_sim = 0
        for brand in KNOWN_BRANDS_FOR_TYPOSQUAT:
            max_len = max(len(reg), len(brand))
            if max_len == 0:
                continue
            dist = _levenshtein(reg, brand)
            sim = round((1 - dist / max_len) * 100)
            if sim > best_sim:
                best_sim = sim
                best_brand = brand

        is_typosquat = best_sim >= 75 and reg != best_brand
        return {
            "domain": reg,
            "closest_brand": best_brand,
            "similarity": best_sim,
            "is_typosquat": is_typosquat,
        }
    except Exception:
        return {"domain": "", "closest_brand": "", "similarity": 0, "is_typosquat": False}


# ---------------------------------------------------------------------------
# WHOIS (optional, disabled during training)
# ---------------------------------------------------------------------------

@contextmanager
def _timeout(seconds: int):
    if not hasattr(signal, "SIGALRM"):
        yield
        return

    def _handler(signum, frame):
        raise TimeoutError("WHOIS lookup timed out")

    old_handler = signal.signal(signal.SIGALRM, _handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)


def domain_age_days(url: str) -> Optional[int]:
    """Return domain age in days via WHOIS, or None when unavailable."""
    try:
        if os.getenv("PHISHGUARD_ENABLE_WHOIS") != "1":
            return None
        host = _host(url)
        if not host or has_ip_address(host):
            return None
        import datetime as _dt
        import whois  # type: ignore

        with _timeout(2):
            record = whois.whois(host)
        created = getattr(record, "creation_date", None) or record.get("creation_date")
        if isinstance(created, list):
            created = next((item for item in created if item), None)
        if not created:
            return None
        if isinstance(created, str):
            created = _dt.datetime.fromisoformat(created.replace("Z", "+00:00"))
        import datetime as _dt2
        if isinstance(created, _dt2.date) and not isinstance(created, _dt2.datetime):
            created = _dt2.datetime.combine(created, _dt2.time.min)
        now = _dt2.datetime.now(created.tzinfo) if getattr(created, "tzinfo", None) else _dt2.datetime.now()
        return max((now - created).days, 0)
    except Exception:
        return None


def domain_info_whois(url: str) -> dict:
    """Return dict with registrar, country, creation_date strings (best-effort)."""
    result = {"registrar": None, "country": None, "creation_date": None}
    try:
        if os.getenv("PHISHGUARD_ENABLE_WHOIS") != "1":
            return result
        host = _host(url)
        if not host or has_ip_address(host):
            return result
        import whois  # type: ignore

        with _timeout(3):
            record = whois.whois(host)
        result["registrar"] = getattr(record, "registrar", None) or record.get("registrar")
        result["country"] = getattr(record, "country", None) or record.get("country")
        created = getattr(record, "creation_date", None) or record.get("creation_date")
        if isinstance(created, list):
            created = created[0]
        if created:
            result["creation_date"] = str(created)[:10]
    except Exception:
        pass
    return result


# ---------------------------------------------------------------------------
# Text features — original set
# ---------------------------------------------------------------------------

def urgency_score(text: str) -> int:
    """Count urgency phrases found in the text."""
    try:
        body = _to_text(text).lower()
        return sum(len(re.findall(re.escape(p), body, flags=re.IGNORECASE)) for p in URGENCY_PHRASES)
    except Exception:
        return 0


def requests_sensitive_info(text: str) -> bool:
    """True when the text requests credentials or sensitive identifiers."""
    try:
        body = _to_text(text)
        pattern = r"\b(" + "|".join(re.escape(i) for i in SENSITIVE_INFO_PATTERNS) + r")\b"
        return bool(re.search(pattern, body, flags=re.IGNORECASE))
    except Exception:
        return False


def generic_greeting(text: str) -> bool:
    """True for generic greetings (no personal name)."""
    try:
        if text is None:
            return False
        body = _to_text(text).strip()
        first_line = body.splitlines()[0] if body else ""
        if any(re.search(rf"\b{re.escape(g)}\b", first_line, re.IGNORECASE) for g in GENERIC_GREETINGS):
            return True
        return not bool(re.search(r"\b(?:Hi|Hello|Dear)\s+[A-Z][a-z]{1,30}\b", first_line))
    except Exception:
        return False


def _extract_links(text: str) -> list[tuple[str, str]]:
    links: list[tuple[str, str]] = []
    try:
        links.extend(re.findall(r"\[([^\]]+)\]\((https?://[^)\s]+)\)", text, flags=re.IGNORECASE))
        links.extend(re.findall(r"<a\s+[^>]*href=[\"'](https?://[^\"']+)[\"'][^>]*>(.*?)</a>", text, flags=re.IGNORECASE))
        links.extend((d, u) for d, u in re.findall(r"([A-Za-z][A-Za-z0-9 .-]{1,40})\s+\((https?://[^)\s]+)\)", text))
    except Exception:
        return links
    normalized = []
    for first, second in links:
        if first.lower().startswith("http"):
            normalized.append((second, first))
        else:
            normalized.append((first, second))
    return normalized


def link_text_mismatch(text: str) -> bool:
    """True when displayed link text claims a brand different from URL domain."""
    try:
        body = _to_text(text)
        for display, url in _extract_links(body):
            display_lower = display.lower()
            actual_domain = _registered_domain(_host(url))
            for brand, official_domain in BRAND_DOMAINS.items():
                if brand in display_lower and official_domain not in actual_domain:
                    return True
        return False
    except Exception:
        return False


def grammar_error_density(text: str) -> float:
    """Lightweight grammar-error ratio based on spacing and punctuation."""
    try:
        body = _to_text(text)
        words = re.findall(r"\b\w+\b", body)
        if not words:
            return 0.0
        double_spaces = len(re.findall(r" {2,}", body))
        repeated_punct = len(re.findall(r"!!!+|\.\.+|\?\?\?+", body))
        sentence_starts = re.findall(r"(?:^|[.!?]\s+)([a-z])", body)
        errors = double_spaces + repeated_punct + len(sentence_starts)
        return errors / len(words)
    except Exception:
        return 0.0


def sender_domain_mismatch(text: str, claimed_brand: str, sender_domain: str) -> bool:
    """True when a claimed brand name appears but sender domain is not official."""
    try:
        body = _to_text(text).lower()
        sender = _to_text(sender_domain).lower().strip("@ ")
        if not sender:
            return False
        brand_candidates = []
        explicit_brand = _to_text(claimed_brand).lower().strip()
        if explicit_brand:
            brand_candidates.append(explicit_brand)
        brand_candidates.extend(b for b in BRAND_DOMAINS if b in body)
        for brand in brand_candidates:
            official = BRAND_DOMAINS.get(brand)
            if official and official not in sender:
                return True
        return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Text features — v4 additions
# ---------------------------------------------------------------------------

def uppercase_ratio(text: str) -> float:
    """Fraction of alphabetic characters that are uppercase.

    Phishing messages often SHOUT to create urgency (e.g. 'ALERT', 'VERIFY NOW').
    Legitimate messages rarely exceed ~15% uppercase ratio.
    Returns a float in [0.0, 1.0].
    """
    try:
        body = _to_text(text)
        alpha = [c for c in body if c.isalpha()]
        if not alpha:
            return 0.0
        return sum(1 for c in alpha if c.isupper()) / len(alpha)
    except Exception:
        return 0.0


def exclamation_count(text: str) -> int:
    """Number of exclamation marks in the text.

    Phishing messages routinely pile on exclamation marks for urgency.
    Legitimate messages seldom use more than one or two.
    """
    try:
        return _to_text(text).count("!")
    except Exception:
        return 0


def url_count_in_text(text: str) -> int:
    """Number of distinct URLs (http/https) embedded in the text.

    Most legitimate single-purpose messages contain zero or one link.
    Multiple links — especially to different domains — raise suspicion.
    """
    try:
        body = _to_text(text)
        return len(re.findall(r"https?://[^\s\)\"'>]+", body, flags=re.IGNORECASE))
    except Exception:
        return 0


def keyword_density(text: str) -> float:
    """Fraction of words that are known phishing keywords.

    Counts how many words in the message are in PHISHING_KEYWORDS.
    Safe messages naturally have low density; phishing messages are packed with
    action-oriented, fear-inducing vocabulary.
    Returns a float in [0.0, 1.0].
    """
    try:
        body = _to_text(text).lower()
        words = re.findall(r"\b[a-z]{2,}\b", body)
        if not words:
            return 0.0
        hits = sum(1 for w in words if w in PHISHING_KEYWORDS)
        return hits / len(words)
    except Exception:
        return 0.0


def suspicious_tld_in_body(text: str) -> bool:
    """True when the message body contains a URL whose TLD is in SUSPICIOUS_TLDS.

    This catches SMS/email messages that embed suspicious-TLD links directly
    in the text — a very common smishing pattern.
    """
    try:
        body = _to_text(text)
        urls_found = re.findall(r"https?://[^\s\)\"'>]+", body, flags=re.IGNORECASE)
        for u in urls_found:
            if tld_suspicious(u):
                return True
        # Also check bare domains (without scheme) that end with a suspicious TLD
        bare = re.findall(r"\b[\w.-]+\.(?:xyz|top|club|tk|ml|ga|cf|gq|pw|work|online|site|space|buzz|click|link|live|win|icu|vip|loan|review|date|faith)\b", body, re.IGNORECASE)
        return len(bare) > 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def extract_all_features(content: str, content_type: str) -> dict:
    """Return feature dict for the given content_type ('url', 'email', 'sms')."""
    try:
        ct = _to_text(content_type).lower()
        if ct == "url":
            return {
                # Original features
                "url_length":                       url_length(content),
                "num_subdomains":                   num_subdomains(content),
                "has_ip_address":                   has_ip_address(content),
                "uses_url_shortener":               uses_url_shortener(content),
                "has_https":                        has_https(content),
                "count_special_chars":              count_special_chars(content),
                "has_suspicious_keywords_in_domain": has_suspicious_keywords_in_domain(content),
                "has_at_symbol":                    has_at_symbol(content),
                "path_depth":                       path_depth(content),
                "query_param_count":                query_param_count(content),
                "tld_suspicious":                   tld_suspicious(content),
                # v4 additions
                "domain_entropy":                   domain_entropy(content),
                "digit_ratio_in_domain":            digit_ratio_in_domain(content),
                "hyphen_count_in_domain":           hyphen_count_in_domain(content),
                # WHOIS (runtime only, excluded from training vector)
                "domain_age_days":                  domain_age_days(content),
            }
        if ct in {"email", "sms"}:
            return {
                # Original features
                "urgency_score":            urgency_score(content),
                "requests_sensitive_info":  requests_sensitive_info(content),
                "generic_greeting":         generic_greeting(content),
                "link_text_mismatch":       link_text_mismatch(content),
                "grammar_error_density":    grammar_error_density(content),
                "sender_domain_mismatch":   sender_domain_mismatch(content, None, None),
                # v4 additions
                "uppercase_ratio":          uppercase_ratio(content),
                "exclamation_count":        exclamation_count(content),
                "url_count_in_text":        url_count_in_text(content),
                "keyword_density":          keyword_density(content),
                "suspicious_tld_in_body":   suspicious_tld_in_body(content),
            }
        return {}
    except Exception:
        return {}
