"""
email_parser.py
---------------
Parses raw email content (.eml files, plain text, or pasted text)
and extracts structured fields for analysis.
"""

import re
import email
from email import policy
from email.parser import BytesParser, Parser
from typing import Optional


class ParsedEmail:
    """Holds all extracted fields from a raw email."""

    def __init__(self):
        self.sender: str = ""
        self.reply_to: str = ""
        self.subject: str = ""
        self.body: str = ""
        self.html_body: str = ""
        self.urls: list[str] = []
        self.attachments: list[str] = []
        self.headers: dict = {}
        self.raw: str = ""

    def __repr__(self):
        return (
            f"ParsedEmail(sender={self.sender!r}, "
            f"subject={self.subject!r}, urls={len(self.urls)})"
        )


def parse_eml_file(filepath: str) -> ParsedEmail:
    """Parse a .eml file from disk."""
    with open(filepath, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    return _extract_from_message(msg)


def parse_raw_text(raw: str) -> ParsedEmail:
    """Parse a raw email string (headers + body)."""
    msg = Parser(policy=policy.default).parsestr(raw)
    parsed = _extract_from_message(msg)
    parsed.raw = raw
    return parsed


def parse_body_only(body: str) -> ParsedEmail:
    """
    When the user pastes only the email body (no headers),
    wrap it in a minimal envelope and parse.
    """
    parsed = ParsedEmail()
    parsed.body = body
    parsed.raw = body
    parsed.urls = _extract_urls(body)
    return parsed


# ── internals ──────────────────────────────────────────────────────────────────

def _extract_from_message(msg) -> ParsedEmail:
    parsed = ParsedEmail()

    parsed.sender   = str(msg.get("From", ""))
    parsed.reply_to = str(msg.get("Reply-To", ""))
    parsed.subject  = str(msg.get("Subject", ""))

    # Collect all headers as a plain dict
    parsed.headers = {k: str(v) for k, v in msg.items()}

    # Walk MIME parts
    for part in msg.walk():
        ct = part.get_content_type()
        disposition = str(part.get("Content-Disposition", ""))

        if "attachment" in disposition:
            filename = part.get_filename() or "unknown"
            parsed.attachments.append(filename)
        elif ct == "text/plain":
            payload = part.get_payload(decode=True)
            if payload:
                parsed.body += payload.decode(errors="replace")
        elif ct == "text/html":
            payload = part.get_payload(decode=True)
            if payload:
                parsed.html_body += payload.decode(errors="replace")

    # Combine plain + stripped-HTML for URL extraction
    combined = parsed.body + " " + _strip_html(parsed.html_body)
    parsed.urls = _extract_urls(combined)

    return parsed


_URL_RE = re.compile(
    r"https?://[^\s\"'<>\]\)]+",
    re.IGNORECASE,
)

_HTML_TAG_RE = re.compile(r"<[^>]+>")


def _extract_urls(text: str) -> list[str]:
    return list(set(_URL_RE.findall(text)))


def _strip_html(html: str) -> str:
    return _HTML_TAG_RE.sub(" ", html)
