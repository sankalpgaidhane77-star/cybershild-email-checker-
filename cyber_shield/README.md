# 🛡 CyberShield — Email Fraud Analyzer

CyberShield is a Python command-line tool that analyses emails for fraud, phishing,
and social engineering indicators. It requires **no external ML libraries** — it uses
a transparent, weighted rule-based engine you can read and extend.

---

## Features

| Capability                        | Details                                               |
|-----------------------------------|-------------------------------------------------------|
| **Sender analysis**               | Free-email detection, domain spoofing, display-name tricks |
| **Subject analysis**              | Urgency, reward, threat, and ALL-CAPS triggers        |
| **Body analysis**                 | Phishing CTAs, sensitive data requests, money lures   |
| **URL analysis**                  | Suspicious TLDs, IP-based URLs, URL shorteners        |
| **Attachment analysis**           | Executable and archive file detection                 |
| **Header analysis**               | Missing Message-ID, mismatched Reply-To               |
| **Risk scoring**                  | 0–100 normalised score → SAFE / LOW / MEDIUM / HIGH / CRITICAL |
| **JSON reports**                  | Machine-readable reports saved to `reports/`          |

---

## Project Structure

```
cyber_shield/
├── main.py                   ← Entry point / CLI
├── requirements.txt
├── src/
│   ├── __init__.py
│   ├── email_parser.py       ← Parse .eml files, raw text, or body-only input
│   ├── feature_extractor.py  ← Extract 20+ fraud features from a parsed email
│   ├── detector.py           ← Weighted scoring engine → AnalysisResult
│   └── reporter.py           ← Terminal + JSON report generation
├── data/
│   └── samples/
│       ├── phishing_example.txt   ← Sample fraudulent email
│       └── safe_example.txt       ← Sample safe email
└── reports/                  ← Auto-created JSON reports saved here
```

---

## Installation

```bash
cd cyber_shield
pip install -r requirements.txt   # only colorama (optional, for colour output)
```

> All core functionality uses Python's standard library only.

---

## Usage

### 1. Analyse a `.eml` or `.txt` email file

```bash
# Plain-text file (headers + body)
python main.py --text data/samples/phishing_example.txt

# .eml file
python main.py --file path/to/email.eml

# Save a JSON report
python main.py --text data/samples/phishing_example.txt --save
```

### 2. Interactive mode (paste email content)

```bash
python main.py
```

Paste the full email (or just the body), then type `END` on a new line and press Enter.

---

## Sample Output

```
   ____      _               ____  _     _      _     _
  / ___|   _| |__   ___ _ __/ ___|| |__ (_) ___| | __| |
 ...

  ──────────────────────────────────────────────────────────────
  🛡  CyberShield — Email Fraud Analysis Report
  ──────────────────────────────────────────────────────────────
  Timestamp  : 2024-01-15 14:32:01
  From       : "PayPal Security" <security@paypa1-verify.xyz>
  Subject    : URGENT: Your PayPal Account Has Been Suspended
  ──────────────────────────────────────────────────────────────
  Risk Score : 89/100  [████████████████████]
  Risk Level : CRITICAL — LIKELY FRAUD
  ──────────────────────────────────────────────────────────────
  Summary: Detected 14 fraud indicator(s) across: Sender, Subject, Body, URLs.
           Top signals: SENSITIVE_REQUEST, EXEC_ATTACHMENT, DOMAIN_MISMATCH.
  ──────────────────────────────────────────────────────────────
  Indicators Detected (14):

    [Sender]
      ✖  Reply-To domain differs from From domain (spoofing signal)
         Tag: DOMAIN_MISMATCH  |  Weight: +20
    ...

  ⚠  RECOMMENDATION: DO NOT interact with this email.
     Do not click links, download attachments, or reply.
```

---

## How the Scoring Works

Each rule fires if a feature is detected and adds its **weight** to a raw score.
The raw score is then normalised to **0–100** against the maximum possible score.

| Score Range | Risk Level              |
|-------------|-------------------------|
| 0           | SAFE                    |
| 1–19        | LOW RISK                |
| 20–44       | MEDIUM RISK             |
| 45–64       | HIGH RISK               |
| 65–100      | CRITICAL — LIKELY FRAUD |

---

## Extending CyberShield

- Add new keywords to [`feature_extractor.py`](src/feature_extractor.py) keyword lists.
- Add new rules to the `RULES` list in [`detector.py`](src/detector.py).
- Each rule is a `(feature_key, weight, category, description, indicator_tag)` tuple.

---

## Disclaimer

CyberShield is a heuristic tool for educational and personal use. It does not guarantee
detection of all fraudulent emails and should be used as one layer of a broader
security strategy.
