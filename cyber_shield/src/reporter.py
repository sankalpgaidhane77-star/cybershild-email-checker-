"""
reporter.py
-----------
Generates human-readable and JSON reports from an AnalysisResult.
"""

import json
import os
from datetime import datetime
from .detector import AnalysisResult

# ANSI colour codes for terminal output
_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_RED    = "\033[91m"
_YELLOW = "\033[93m"
_GREEN  = "\033[92m"
_CYAN   = "\033[96m"
_WHITE  = "\033[97m"
_DIM    = "\033[2m"

_RISK_COLOURS = {
    "SAFE":                    _GREEN,
    "LOW RISK":                _CYAN,
    "MEDIUM RISK":             _YELLOW,
    "HIGH RISK":               _RED,
    "CRITICAL — LIKELY FRAUD": _RED + _BOLD,
}

_RISK_BARS = {
    "SAFE":                    "█" * 2  + "░" * 18,
    "LOW RISK":                "█" * 5  + "░" * 15,
    "MEDIUM RISK":             "█" * 10 + "░" * 10,
    "HIGH RISK":               "█" * 15 + "░" * 5,
    "CRITICAL — LIKELY FRAUD": "█" * 20,
}


def print_report(result: AnalysisResult, parsed=None) -> None:
    """Pretty-print the analysis result to the terminal."""
    colour = _RISK_COLOURS.get(result.risk_level, _WHITE)
    bar    = _RISK_BARS.get(result.risk_level, "")

    _hr()
    print(f"{_BOLD}{_CYAN}  [CYBERSHIELD]  Email Fraud Analysis Report{_RESET}")
    _hr()
    print(f"  Timestamp  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    if parsed:
        print(f"  From       : {parsed.sender or '(unknown)'}")
        print(f"  Reply-To   : {parsed.reply_to or '(none)'}")
        print(f"  Subject    : {parsed.subject or '(no subject)'}")
        att = ", ".join(parsed.attachments) if parsed.attachments else "none"
        print(f"  Attachments: {att}")
        print(f"  URLs found : {len(parsed.urls)}")

    _hr()
    print(f"  Risk Score : {_BOLD}{colour}{result.score}/100{_RESET}  [{colour}{bar}{_RESET}]")
    print(f"  Risk Level : {colour}{_BOLD}{result.risk_level}{_RESET}")
    _hr()
    print(f"  {_BOLD}Summary:{_RESET} {result.summary}")
    _hr()

    if result.findings:
        print(f"  {_BOLD}Indicators Detected ({len(result.findings)}):{_RESET}")
        print()
        # Group by category
        cats: dict[str, list] = {}
        for f in result.findings:
            cats.setdefault(f.category, []).append(f)

        for cat, findings in cats.items():
            print(f"    {_BOLD}{_YELLOW}[{cat}]{_RESET}")
            for f in findings:
                print(f"      {_RED}[!]{_RESET}  {f.description}")
                print(f"         {_DIM}Tag: {f.indicator}  |  Weight: +{f.weight}{_RESET}")
            print()
    else:
        print(f"  {_GREEN}[OK]  No fraud indicators found.{_RESET}")

    _hr()

    if result.is_fraud:
        print(f"  {_RED}{_BOLD}[WARNING]  RECOMMENDATION: DO NOT interact with this email.{_RESET}")
        print(f"  {_RED}   Do not click links, download attachments, or reply.{_RESET}")
    else:
        print(f"  {_GREEN}[OK]  This email does not appear to be fraudulent.{_RESET}")
        print(f"  {_GREEN}   Always exercise caution with unexpected messages.{_RESET}")
    _hr()
    print()


def save_json_report(result: AnalysisResult, parsed=None, output_dir: str = "reports") -> str:
    """Save a machine-readable JSON report and return the file path."""
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(output_dir, f"report_{ts}.json")

    data = {
        "timestamp": datetime.now().isoformat(),
        "score": result.score,
        "risk_level": result.risk_level,
        "is_fraud": result.is_fraud,
        "summary": result.summary,
        "findings": [
            {
                "category": f.category,
                "description": f.description,
                "indicator": f.indicator,
                "weight": f.weight,
            }
            for f in result.findings
        ],
    }

    if parsed:
        data["email_meta"] = {
            "sender": parsed.sender,
            "reply_to": parsed.reply_to,
            "subject": parsed.subject,
            "url_count": len(parsed.urls),
            "urls": parsed.urls,
            "attachments": parsed.attachments,
        }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    return path


def _hr():
    print(f"  {_DIM}{'-' * 62}{_RESET}")
