"""Pydantic schemas for the PhishGuard analysis API (v3)."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_MAX_CONTENT_LEN   = 10_000   # chars — blocks giant pastes / DoS attempts
_MAX_BRAND_LEN     = 100      # claimed brand name
_MAX_DOMAIN_LEN    = 253      # RFC 1035 max domain length
_SAFE_TEXT_RE      = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")  # strip control chars


def _strip_controls(value: str) -> str:
    """Remove ASCII control characters (keeps \\t \\n \\r)."""
    return _SAFE_TEXT_RE.sub("", value)


# ---------------------------------------------------------------------------
# Request
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=_MAX_CONTENT_LEN)
    content_type: Literal["email", "sms", "url"]
    claimed_brand: Optional[str] = Field(None, max_length=_MAX_BRAND_LEN)
    sender_domain: Optional[str] = Field(None, max_length=_MAX_DOMAIN_LEN)

    @field_validator("content")
    @classmethod
    def validate_content(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Content must not be blank.")
        return _strip_controls(v)

    @field_validator("claimed_brand")
    @classmethod
    def validate_brand(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.strip()
        return _strip_controls(v) if v else None

    @field_validator("sender_domain")
    @classmethod
    def validate_sender_domain(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.strip().lower()
        if not v:
            return None
        # Must look like a domain: letters, digits, hyphens, dots — no spaces
        if not re.match(r"^[a-z0-9]([a-z0-9\-\.]{0,251}[a-z0-9])?$", v):
            raise ValueError("sender_domain must be a valid domain name.")
        return v


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class TriggeredFeature(BaseModel):
    name: str
    detail: str
    weight: float


class RiskBreakdown(BaseModel):
    domain_risk: int        # 0-100
    content_risk: int       # 0-100
    credential_theft: int   # 0-100
    social_engineering: int # 0-100


class DomainInfo(BaseModel):
    domain: str
    is_https: bool
    num_subdomains: int
    has_ip: bool
    uses_shortener: bool
    tld: str
    domain_age_days: Optional[int] = None
    registrar: Optional[str] = None
    country: Optional[str] = None


class TyposquatInfo(BaseModel):
    detected: bool
    domain: str
    closest_brand: str
    similarity: int   # 0-100


class ScorecardItem(BaseModel):
    label: str
    score: int
    max_score: int


class AnalyzeResponse(BaseModel):
    # Core
    risk_score: int
    verdict: Literal["Safe", "Suspicious", "Dangerous"]
    confidence: Literal["Low", "Medium", "High"]
    confidence_pct: int   # 0-100 numeric confidence
    scan_time_ms: int

    # Features / explanation
    triggered_features: List[TriggeredFeature]
    all_features: Dict[str, Any]
    explanation: str
    highlighted_text: str

    # Extra panels
    threat_category: str
    risk_breakdown: RiskBreakdown
    scorecard: List[ScorecardItem]

    # URL-specific (None for email/sms)
    domain_info: Optional[DomainInfo] = None
    typosquat: Optional[TyposquatInfo] = None
