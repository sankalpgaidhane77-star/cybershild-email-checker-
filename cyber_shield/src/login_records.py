"""
login_records.py
----------------
Provides 20 pre-built fake login records for CyberShield demonstration.
Also exposes generate_sample_data() to produce a fresh randomised set on demand.

Record schema:
    {
        "time":     str  — "YYYY-MM-DD HH:MM:SS"
        "username": str
        "ip":       str
        "result":   "Success" | "Failed"
    }
"""

import random
from datetime import datetime, timedelta
from typing import Literal

# ---------------------------------------------------------------------------
# Static seed records (always the same – good for docs / screenshots)
# ---------------------------------------------------------------------------

SEED_RECORDS: list[dict] = [
    # --- Normal successful logins from varied IPs ---
    {"time": "2024-06-10 08:02:11", "username": "alice.morgan",   "ip": "192.168.1.12",  "result": "Success"},
    {"time": "2024-06-10 08:15:44", "username": "bob.carter",     "ip": "10.0.0.55",     "result": "Success"},
    {"time": "2024-06-10 08:31:07", "username": "carol.white",    "ip": "172.16.5.23",   "result": "Success"},
    {"time": "2024-06-10 09:04:52", "username": "david.hall",     "ip": "192.168.1.88",  "result": "Success"},
    {"time": "2024-06-10 09:20:33", "username": "emma.brooks",    "ip": "10.0.0.101",    "result": "Success"},

    # --- A few isolated failed logins (wrong password etc.) ---
    {"time": "2024-06-10 09:45:01", "username": "frank.stone",    "ip": "203.0.113.7",   "result": "Failed"},
    {"time": "2024-06-10 10:02:18", "username": "grace.hill",     "ip": "192.168.2.14",  "result": "Failed"},

    # --- Suspicious IP 198.51.100.42 – 7 rapid failed attempts (brute-force) ---
    {"time": "2024-06-10 10:30:00", "username": "admin",          "ip": "198.51.100.42", "result": "Failed"},
    {"time": "2024-06-10 10:30:14", "username": "admin",          "ip": "198.51.100.42", "result": "Failed"},
    {"time": "2024-06-10 10:30:29", "username": "admin",          "ip": "198.51.100.42", "result": "Failed"},
    {"time": "2024-06-10 10:30:47", "username": "root",           "ip": "198.51.100.42", "result": "Failed"},
    {"time": "2024-06-10 10:31:02", "username": "root",           "ip": "198.51.100.42", "result": "Failed"},
    {"time": "2024-06-10 10:31:18", "username": "alice.morgan",   "ip": "198.51.100.42", "result": "Failed"},
    {"time": "2024-06-10 10:31:35", "username": "alice.morgan",   "ip": "198.51.100.42", "result": "Success"},  # finally got in

    # --- Normal activity resumes after the attack ---
    {"time": "2024-06-10 11:05:44", "username": "henry.price",    "ip": "10.0.0.77",     "result": "Success"},
    {"time": "2024-06-10 11:22:09", "username": "iris.james",     "ip": "172.16.5.99",   "result": "Success"},
    {"time": "2024-06-10 11:48:53", "username": "jack.norris",    "ip": "192.168.1.33",  "result": "Failed"},
    {"time": "2024-06-10 12:03:21", "username": "karen.fox",      "ip": "10.0.0.200",    "result": "Success"},
    {"time": "2024-06-10 12:17:44", "username": "leo.grant",      "ip": "192.168.2.61",  "result": "Success"},
    {"time": "2024-06-10 12:45:00", "username": "mia.chen",       "ip": "172.16.5.8",    "result": "Success"},
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_USERNAMES = [
    "alice.morgan", "bob.carter", "carol.white", "david.hall", "emma.brooks",
    "frank.stone", "grace.hill", "henry.price", "iris.james", "jack.norris",
    "karen.fox", "leo.grant", "mia.chen", "admin", "root", "sysop",
]

_NORMAL_IPS = [
    "192.168.1.12", "192.168.1.33", "192.168.1.88", "192.168.2.14", "192.168.2.61",
    "10.0.0.55", "10.0.0.77", "10.0.0.101", "10.0.0.200",
    "172.16.5.8", "172.16.5.23", "172.16.5.99",
]

SUSPICIOUS_IP = "198.51.100.42"


def generate_sample_data(n: int = 20, seed: int | None = None) -> list[dict]:
    """
    Generate *n* randomised login records.

    At least 5 will be failed attempts from SUSPICIOUS_IP
    to demonstrate brute-force detection.
    """
    if seed is not None:
        random.seed(seed)

    base_time = datetime(2024, 6, 10, 8, 0, 0)
    records: list[dict] = []
    delta = 0  # cumulative minutes

    # 1. Insert a brute-force cluster (5–8 records from suspicious IP)
    n_brute = random.randint(5, 8)
    brute_start = random.randint(n // 3, n // 2)  # inject mid-sequence

    for i in range(n):
        delta += random.randint(1, 15)
        ts = base_time + timedelta(minutes=delta)

        if brute_start <= i < brute_start + n_brute:
            ip = SUSPICIOUS_IP
            username = random.choice(["admin", "root", "alice.morgan"])
            # last attempt in cluster succeeds
            result: Literal["Success", "Failed"] = (
                "Success" if i == brute_start + n_brute - 1 else "Failed"
            )
        else:
            ip = random.choice(_NORMAL_IPS)
            username = random.choice(_USERNAMES)
            # ~15 % chance of a normal failed login
            result = "Failed" if random.random() < 0.15 else "Success"

        records.append({
            "time":     ts.strftime("%Y-%m-%d %H:%M:%S"),
            "username": username,
            "ip":       ip,
            "result":   result,
        })

    return records


# ---------------------------------------------------------------------------
# THE SUSPICIOUS-IP RULE
# ---------------------------------------------------------------------------
# Rule (plain English):
#   "If the same IP address appears in 5 or more FAILED login attempts
#    inside the records list, mark that IP as suspicious."
#
# Why 5?
#   One or two failed logins can happen to anyone who mistyped their
#   password.  Five or more failures from the same source strongly
#   suggests an automated tool is trying many passwords — a brute-force
#   attack.  This number is the THRESHOLD and is easy to change.
#
# How it works (step by step):
#   1. Walk through every login record one by one.
#   2. If the result is "Failed", add that record to a list stored
#      under the IP address key.
#   3. After checking all records, look at each IP's failure list.
#   4. If the count of failures for that IP is >= THRESHOLD (5),
#      include it in the result dictionary.
#   5. Return the dictionary so callers can show warnings.
#
# No machine learning.  No external connections.  Just counting + if.
# ---------------------------------------------------------------------------

SUSPICIOUS_THRESHOLD = 5   # <-- change this number to adjust sensitivity


def flag_suspicious(records: list[dict],
                    threshold: int = SUSPICIOUS_THRESHOLD) -> dict[str, list[dict]]:
    """
    Scan *records* and return every IP address that has >= *threshold*
    failed login attempts.

    Returns a dict:  { ip_address: [list of failed records for that IP] }

    Example result:
        {
            "198.51.100.42": [
                {"time": "...", "username": "admin", "ip": "198.51.100.42", "result": "Failed"},
                ... (5 or more entries)
            ]
        }
    """

    # Step 1 — build a dictionary that maps each IP to its failed attempts.
    #          We use a plain dict; no machine learning, just counting.
    fail_counts: dict[str, list[dict]] = {}

    for record in records:
        # Step 2 — only care about records where the login FAILED
        if record["result"] == "Failed":

            ip = record["ip"]   # which IP address caused this failure?

            # Step 3 — if we haven't seen this IP before, create an empty list
            if ip not in fail_counts:
                fail_counts[ip] = []

            # Step 4 — add this failed record to that IP's list
            fail_counts[ip].append(record)

    # Step 5 — now apply the rule:
    #   only keep IPs whose failure count is >= threshold (default: 5)
    suspicious: dict[str, list[dict]] = {}

    for ip, failed_records in fail_counts.items():

        # THE RULE: 5 or more failures from the same IP = suspicious
        if len(failed_records) >= threshold:
            suspicious[ip] = failed_records   # flag it

        # If fewer than threshold, we ignore it — not suspicious enough

    return suspicious


def explain_flag(ip: str, failed_records: list[dict],
                 threshold: int = SUSPICIOUS_THRESHOLD) -> str:
    """
    Return a plain-English warning string explaining WHY an IP was flagged.

    Example output:
        "IP 198.51.100.42 was flagged because it had 6 failed login
         attempts (threshold: 5). Usernames tried: admin, root,
         alice.morgan. Time range: 10:30:00 – 10:31:18.
         This pattern suggests a brute-force attack."
    """
    # Collect the unique usernames that were tried from this IP
    usernames_tried = []
    for rec in failed_records:
        if rec["username"] not in usernames_tried:   # avoid duplicates
            usernames_tried.append(rec["username"])

    # Get the time of the first and last failed attempt
    times       = [rec["time"] for rec in failed_records]
    first_time  = min(times)
    last_time   = max(times)

    # Build a readable explanation — no jargon
    explanation = (
        f"IP {ip} was flagged because it had {len(failed_records)} failed login "
        f"attempts, which meets or exceeds the suspicious threshold of {threshold}. "
        f"Usernames tried: {', '.join(usernames_tried)}. "
        f"Time range: {first_time} to {last_time}. "
        f"This pattern suggests an automated brute-force attack."
    )
    return explanation


# ---------------------------------------------------------------------------
# SECURITY ALERTS — risk-level classification
# ---------------------------------------------------------------------------
# How risk levels are assigned (simple if/elif/else — no machine learning):
#
#   HIGH   — 10 or more failed attempts from the same IP.
#             This volume strongly suggests an automated attack script.
#
#   MEDIUM — 5 to 9 failed attempts from the same IP.
#             Meets the suspicious threshold but could still be a user
#             who genuinely forgot their password repeatedly.
#
#   LOW    — Placeholder for future rules (e.g. new-country login).
#             Not used by the current counting rule.
#
# IMPORTANT DISCLAIMER (shown in the UI):
#   A suspicious login pattern does NOT automatically prove a cyberattack.
#   It is a signal that warrants investigation, not an automatic conclusion.
# ---------------------------------------------------------------------------

HIGH_RISK_THRESHOLD   = 10   # 10+ failures  → HIGH
MEDIUM_RISK_THRESHOLD = 5    # 5–9 failures   → MEDIUM  (same as SUSPICIOUS_THRESHOLD)


def get_alert_details(ip: str, failed_records: list[dict]) -> dict:
    """
    Build a full alert record for one suspicious IP address.

    Returns a dict with:
        ip            — the IP address
        username      — most-targeted username (the one attempted most often)
        all_usernames — list of all unique usernames tried
        fail_count    — total number of failed attempts
        first_seen    — timestamp of the first failed attempt
        last_seen     — timestamp of the last failed attempt
        risk_level    — "HIGH", "MEDIUM", or "LOW"
        risk_color    — CSS hex colour matching the risk level
        reason        — plain-English sentence explaining the flag
        disclaimer    — reminder that this is a signal, not a verdict
    """

    fail_count = len(failed_records)

    # ── Step 1: collect unique usernames, ordered by frequency ──────────────
    username_freq: dict[str, int] = {}
    for rec in failed_records:
        uname = rec["username"]
        if uname not in username_freq:
            username_freq[uname] = 0
        username_freq[uname] += 1

    # Sort usernames so the most-targeted one comes first
    sorted_usernames = sorted(username_freq, key=lambda u: username_freq[u], reverse=True)
    top_username = sorted_usernames[0]   # the username attacked most often

    # ── Step 2: time range ───────────────────────────────────────────────────
    times      = [rec["time"] for rec in failed_records]
    first_seen = min(times)
    last_seen  = max(times)

    # ── Step 3: assign risk level ────────────────────────────────────────────
    # Simple if/elif/else — no machine learning, no scoring formula.
    # Just count how many times this IP failed.
    if fail_count >= HIGH_RISK_THRESHOLD:
        # 10 or more failures = HIGH risk
        risk_level = "HIGH"
        risk_color = "#ef4444"   # red
        risk_bg    = "#450a0a"
        reason = (
            f"This IP made {fail_count} failed login attempts, well above the "
            f"high-risk threshold of {HIGH_RISK_THRESHOLD}. "
            f"This volume is typical of an automated password-guessing script."
        )

    elif fail_count >= MEDIUM_RISK_THRESHOLD:
        # 5–9 failures = MEDIUM risk
        risk_level = "MEDIUM"
        risk_color = "#fb923c"   # orange
        risk_bg    = "#431407"
        reason = (
            f"This IP made {fail_count} failed login attempts, meeting the "
            f"suspicious threshold of {MEDIUM_RISK_THRESHOLD}. "
            f"Could be a forgotten password or an early-stage attack — "
            f"further investigation is recommended."
        )

    else:
        # Fewer than 5 failures — LOW risk (rule should not have flagged this,
        # but we handle it gracefully just in case)
        risk_level = "LOW"
        risk_color = "#facc15"   # yellow
        risk_bg    = "#422006"
        reason = (
            f"This IP made {fail_count} failed login attempt(s). "
            f"Below the main threshold but worth monitoring."
        )

    # ── Step 4: build the disclaimer ─────────────────────────────────────────
    # Always shown alongside the alert so readers don't over-react.
    disclaimer = (
        "Note: A suspicious login pattern does not automatically prove a "
        "cyberattack. It is a signal that warrants human investigation. "
        "The user may have forgotten their password, or a shared IP (such "
        "as a corporate NAT or VPN) may be involved."
    )

    return {
        "ip":            ip,
        "username":      top_username,
        "all_usernames": sorted_usernames,
        "fail_count":    fail_count,
        "first_seen":    first_seen,
        "last_seen":     last_seen,
        "risk_level":    risk_level,
        "risk_color":    risk_color,
        "risk_bg":       risk_bg,
        "reason":        reason,
        "disclaimer":    disclaimer,
    }


def build_alerts(records: list[dict]) -> list[dict]:
    """
    Run flag_suspicious() on *records*, then build a full alert detail dict
    for every flagged IP.  Returns a list of alert dicts, sorted by
    fail_count descending (highest risk first).
    """
    flagged = flag_suspicious(records)   # apply the 5-failure rule

    alerts = []
    for ip, failed_recs in flagged.items():
        alerts.append(get_alert_details(ip, failed_recs))

    # Show the most dangerous IP first
    alerts.sort(key=lambda a: a["fail_count"], reverse=True)
    return alerts
