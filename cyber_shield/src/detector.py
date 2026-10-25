"""
detector.py
-----------
Core fraud analysis engine for CyberShield.

Uses a weighted rule-based scoring system (no external ML dependency)
to produce a risk score and detailed findings for each email.
"""

from dataclasses import dataclass, field
from .email_parser import ParsedEmail
from .feature_extractor import extract_features


# ── Risk levels ────────────────────────────────────────────────────────────────

class RiskLevel:
    SAFE        = "SAFE"
    LOW         = "LOW RISK"
    MEDIUM      = "MEDIUM RISK"
    HIGH        = "HIGH RISK"
    CRITICAL    = "CRITICAL — LIKELY FRAUD"


@dataclass
class Finding:
    """A single detected indicator."""
    category: str
    description: str
    weight: int       # contribution to score (0-100 scale)
    indicator: str    # short tag shown in the report


@dataclass
class AnalysisResult:
    score: int = 0                         # 0–100
    risk_level: str = RiskLevel.SAFE
    findings: list[Finding] = field(default_factory=list)
    features: dict = field(default_factory=dict)
    summary: str = ""

    @property
    def is_fraud(self) -> bool:
        return self.score >= 45


# ── Scoring rules ──────────────────────────────────────────────────────────────
# Each rule: (feature_key, weight, category, description, indicator_tag)

RULES: list[tuple] = [
    # Sender
    ("sender_is_free_email",        5,  "Sender",       "Sender uses a free/public email provider",                   "FREE_EMAIL"),
    ("sender_domain_mismatch",     20,  "Sender",       "Reply-To domain differs from From domain (spoofing signal)", "DOMAIN_MISMATCH"),
    ("sender_spoofed_display",     20,  "Sender",       "Display name contains a different domain than actual address","SPOOFED_DISPLAY"),
    ("has_reply_to_different",      8,  "Sender",       "Reply-To address is different from sender",                  "REPLY_TO_DIFF"),
    ("missing_message_id",         10,  "Headers",      "Email is missing a Message-ID header",                       "NO_MESSAGE_ID"),

    # Subject
    ("subject_has_urgency",        10,  "Subject",      "Subject line contains urgency-trigger language",             "URGENCY_SUBJECT"),
    ("subject_has_reward",         12,  "Subject",      "Subject line promises prizes or rewards",                    "REWARD_SUBJECT"),
    ("subject_has_threat",         15,  "Subject",      "Subject line contains account-threat language",              "THREAT_SUBJECT"),
    ("subject_all_caps",            5,  "Subject",      "Subject line is written in ALL CAPS",                        "ALL_CAPS"),

    # Body
    ("body_has_urgency",            8,  "Body",         "Body text uses urgency-trigger language",                    "URGENCY_BODY"),
    ("body_has_reward",            10,  "Body",         "Body text promises lottery, prizes, or gifts",               "REWARD_BODY"),
    ("body_has_threat",            12,  "Body",         "Body text contains account-threat or suspension language",   "THREAT_BODY"),
    ("body_has_money",             10,  "Body",         "Body text references large money transfers or payments",      "MONEY_BODY"),
    ("body_has_phishing",          15,  "Body",         "Body text contains phishing call-to-action language",        "PHISHING_BODY"),
    ("body_requests_sensitive",    20,  "Body",         "Email requests passwords, card numbers, or PINs",            "SENSITIVE_REQUEST"),

    # URLs
    ("has_suspicious_tld",         15,  "URLs",         "Contains links with suspicious top-level domains",           "SUSPICIOUS_TLD"),
    ("has_ip_url",                 20,  "URLs",         "Contains links using raw IP addresses",                      "IP_URL"),
    ("has_url_shortener",          10,  "URLs",         "Contains shortened / obfuscated URLs",                       "URL_SHORTENER"),
    ("urls_domain_mismatch",        8,  "URLs",         "URL domains do not match the sender's domain",               "URL_DOMAIN_MISMATCH"),

    # Attachments
    ("has_executable_attachment",  25,  "Attachments",  "Contains an executable file attachment (.exe, .bat, etc.)",  "EXEC_ATTACHMENT"),
    ("has_archive_attachment",     10,  "Attachments",  "Contains an archive file attachment (.zip, .rar, etc.)",     "ARCHIVE_ATTACHMENT"),
]

# Max possible raw score if ALL rules fire
_MAX_RAW = sum(r[1] for r in RULES)


def analyze(parsed: ParsedEmail) -> AnalysisResult:
    """Run full fraud analysis on a ParsedEmail and return an AnalysisResult."""
    features = extract_features(parsed)
    result = AnalysisResult(features=features)

    raw_score = 0
    for feat_key, weight, category, description, indicator in RULES:
        if features.get(feat_key):
            raw_score += weight
            result.findings.append(Finding(
                category=category,
                description=description,
                weight=weight,
                indicator=indicator,
            ))

    # Normalise to 0-100
    result.score = min(100, int((raw_score / _MAX_RAW) * 100))
    result.risk_level = _score_to_risk(result.score)
    result.summary = _build_summary(result)
    return result


# ── helpers ────────────────────────────────────────────────────────────────────

def _score_to_risk(score: int) -> str:
    if score == 0:
        return RiskLevel.SAFE
    elif score < 20:
        return RiskLevel.LOW
    elif score < 45:
        return RiskLevel.MEDIUM
    elif score < 65:
        return RiskLevel.HIGH
    else:
        return RiskLevel.CRITICAL


def _build_summary(result: AnalysisResult) -> str:
    if not result.findings:
        return "No fraud indicators detected. This email appears to be safe."
    cats = list({f.category for f in result.findings})
    top = sorted(result.findings, key=lambda x: x.weight, reverse=True)
    top3 = ", ".join(f.indicator for f in top[:3])
    return (
        f"Detected {len(result.findings)} fraud indicator(s) across: {', '.join(cats)}. "
        f"Top signals: {top3}."
    )
