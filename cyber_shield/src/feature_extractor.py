"""
feature_extractor.py
--------------------
Converts a ParsedEmail into a flat dictionary of numeric / boolean
features used by the fraud detector.
"""

import re
import urllib.parse
from .email_parser import ParsedEmail

# ── Keyword lists ──────────────────────────────────────────────────────────────

URGENCY_WORDS = [
    "urgent", "immediately", "act now", "limited time", "expires",
    "deadline", "asap", "right away", "do not delay", "respond now",
    "time sensitive", "last chance",
]

REWARD_WORDS = [
    "winner", "won", "prize", "lottery", "reward", "claim",
    "free", "gift", "bonus", "congratulations", "selected",
    "exclusive offer", "you have been chosen",
]

THREAT_WORDS = [
    "account suspended", "verify your account", "unauthorized access",
    "suspicious activity", "security alert", "locked", "disabled",
    "confirm your identity", "unusual sign", "immediate action required",
]

MONEY_WORDS = [
    "million", "billion", "dollar", "$", "€", "£", "bitcoin",
    "wire transfer", "bank account", "payment", "funds", "transfer",
    "inheritance", "compensation", "refund",
]

PHISHING_WORDS = [
    "click here", "log in", "sign in", "update your", "verify",
    "confirm", "validate", "reactivate", "unlock", "access restored",
]

SENSITIVE_REQUEST_WORDS = [
    "password", "ssn", "social security", "credit card", "cvv",
    "date of birth", "mother's maiden", "pin", "otp", "passcode",
]

KNOWN_FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "protonmail.com", "mail.com", "yandex.com",
    "icloud.com", "live.com", "msn.com",
}

SUSPICIOUS_TLD = {
    ".xyz", ".top", ".club", ".online", ".site", ".gq",
    ".tk", ".ml", ".cf", ".ga", ".pw", ".work", ".click",
}


def extract_features(parsed: "ParsedEmail") -> dict:
    """Return a feature dict from a ParsedEmail object."""
    body_lower = (parsed.body + " " + parsed.subject).lower()

    features = {
        # --- sender analysis ---
        "sender_is_free_email":    _sender_is_free_email(parsed.sender),
        "sender_domain_mismatch":  _sender_domain_mismatch(parsed.sender, parsed.reply_to),
        "sender_spoofed_display":  _spoofed_display_name(parsed.sender),

        # --- subject analysis ---
        "subject_has_urgency":     _keyword_hit(parsed.subject.lower(), URGENCY_WORDS),
        "subject_has_reward":      _keyword_hit(parsed.subject.lower(), REWARD_WORDS),
        "subject_has_threat":      _keyword_hit(parsed.subject.lower(), THREAT_WORDS),
        "subject_all_caps":        parsed.subject.isupper() and len(parsed.subject) > 4,

        # --- body keyword analysis ---
        "body_has_urgency":        _keyword_hit(body_lower, URGENCY_WORDS),
        "body_has_reward":         _keyword_hit(body_lower, REWARD_WORDS),
        "body_has_threat":         _keyword_hit(body_lower, THREAT_WORDS),
        "body_has_money":          _keyword_hit(body_lower, MONEY_WORDS),
        "body_has_phishing":       _keyword_hit(body_lower, PHISHING_WORDS),
        "body_requests_sensitive": _whole_word_hit(body_lower, SENSITIVE_REQUEST_WORDS),

        # --- URL analysis ---
        "url_count":               len(parsed.urls),
        "has_suspicious_tld":      _urls_have_suspicious_tld(parsed.urls),
        "has_ip_url":              _urls_have_ip(parsed.urls),
        "has_url_shortener":       _urls_have_shortener(parsed.urls),
        "urls_domain_mismatch":    _urls_mismatch_sender(parsed.urls, parsed.sender),

        # --- attachment analysis ---
        "has_executable_attachment": _has_executable_attachment(parsed.attachments),
        "has_archive_attachment":    _has_archive_attachment(parsed.attachments),

        # --- header analysis ---
        "missing_message_id":      "message-id" not in {k.lower() for k in parsed.headers},
        "has_reply_to_different":  bool(parsed.reply_to) and _extract_email_domain(parsed.reply_to) != _extract_email_domain(parsed.sender),
    }
    return features


# ── helper functions ───────────────────────────────────────────────────────────

def _keyword_hit(text: str, keywords: list[str]) -> bool:
    return any(kw in text for kw in keywords)


def _whole_word_hit(text: str, keywords: list[str]) -> bool:
    """Match only whole words to avoid false positives like 'pin' in 'shipping'."""
    for kw in keywords:
        pattern = r"\b" + re.escape(kw) + r"\b"
        if re.search(pattern, text):
            return True
    return False


def _sender_is_free_email(sender: str) -> bool:
    domain = _extract_email_domain(sender)
    return domain in KNOWN_FREE_EMAIL_DOMAINS


def _extract_email_domain(address: str) -> str:
    match = re.search(r"@([\w.\-]+)", address)
    return match.group(1).lower() if match else ""


def _sender_domain_mismatch(sender: str, reply_to: str) -> bool:
    if not reply_to:
        return False
    return _extract_email_domain(sender) != _extract_email_domain(reply_to)


def _spoofed_display_name(sender: str) -> bool:
    """Check if display name contains a different domain than the actual address."""
    match = re.match(r"(.+?)\s*<(.+?)>", sender)
    if not match:
        return False
    display, address = match.group(1), match.group(2)
    domain_in_display = re.search(r"@([\w.\-]+)", display)
    if domain_in_display:
        return domain_in_display.group(1).lower() != _extract_email_domain(address)
    return False


def _urls_have_suspicious_tld(urls: list[str]) -> bool:
    for url in urls:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or ""
        if any(host.endswith(tld) for tld in SUSPICIOUS_TLD):
            return True
    return False


def _urls_have_ip(urls: list[str]) -> bool:
    ip_re = re.compile(r"https?://(\d{1,3}\.){3}\d{1,3}")
    return any(ip_re.match(u) for u in urls)


URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "is.gd", "buff.ly", "short.io", "rb.gy", "cutt.ly",
}

def _urls_have_shortener(urls: list[str]) -> bool:
    for url in urls:
        host = (urllib.parse.urlparse(url).hostname or "").lower()
        if host in URL_SHORTENERS:
            return True
    return False


def _urls_mismatch_sender(urls: list[str], sender: str) -> bool:
    sender_domain = _extract_email_domain(sender)
    if not sender_domain:
        return False
    for url in urls:
        host = (urllib.parse.urlparse(url).hostname or "").lower()
        if host and sender_domain not in host:
            return True
    return False


EXECUTABLE_EXT = {".exe", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".sh", ".jar", ".com"}
ARCHIVE_EXT    = {".zip", ".rar", ".7z", ".tar", ".gz", ".iso"}

def _has_executable_attachment(attachments: list[str]) -> bool:
    return any(
        any(a.lower().endswith(ext) for ext in EXECUTABLE_EXT)
        for a in attachments
    )

def _has_archive_attachment(attachments: list[str]) -> bool:
    return any(
        any(a.lower().endswith(ext) for ext in ARCHIVE_EXT)
        for a in attachments
    )
