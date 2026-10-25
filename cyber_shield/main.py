"""
main.py  —  CyberShield Email Fraud Analyzer
============================================
Entry point.  Four modes of operation:

  1.  Analyse a .eml file:
        python main.py --file path/to/email.eml

  2.  Analyse a raw text file (headers + body):
        python main.py --text path/to/email.txt

  3.  Interactive mode (paste email body / raw text at the prompt):
        python main.py

  4.  Login activity monitor (HTML table of login records):
        python main.py --logins
        python main.py --logins --random
        python main.py --logins --seed 42

Optional flags:
  --save      Save a JSON report to the reports/ directory.
  --no-color  Disable ANSI colour output.
"""

import argparse
import sys
import os

# Ensure the package is importable regardless of cwd
sys.path.insert(0, os.path.dirname(__file__))

from src.email_parser   import parse_eml_file, parse_raw_text, parse_body_only
from src.detector       import analyze
from src.reporter       import print_report, save_json_report
from src.login_monitor  import save_and_open as login_save_and_open
from src.login_records  import SEED_RECORDS, generate_sample_data

BANNER = r"""
   ____      _               ____  _     _      _     _
  / ___|   _| |__   ___ _ __/ ___|| |__ (_) ___| | __| |
 | |  | | | | '_ \ / _ \ '__\___ \| '_ \| |/ _ \ |/ _` |
 | |__| |_| | |_) |  __/ |   ___) | | | | |  __/ | (_| |
  \____\__, |_.__/ \___|_|  |____/|_| |_|_|\___|_|\__,_|
        |___/        Email Fraud Analyzer  v1.0
"""


def main():
    parser = argparse.ArgumentParser(
        description="CyberShield — Email Fraud Analyzer"
    )
    parser.add_argument("--file",     metavar="PATH", help="Path to a .eml email file")
    parser.add_argument("--text",     metavar="PATH", help="Path to a plain-text email file")
    parser.add_argument("--save",     action="store_true", help="Save JSON report to reports/")
    parser.add_argument("--no-color", action="store_true", help="Disable colour output")
    # Login monitor flags
    parser.add_argument("--logins",   action="store_true", help="Open the Login Activity Monitor")
    parser.add_argument("--random",   action="store_true", help="Use random data in login monitor")
    parser.add_argument("--seed",     type=int, default=None, help="Random seed for login monitor")
    args = parser.parse_args()

    print(BANNER)

    # ── Mode 4: login activity monitor ────────────────────────────────────────
    if args.logins:
        if args.random or args.seed is not None:
            records = generate_sample_data(n=20, seed=args.seed)
            print(f"  [INFO]  Generated 20 random login records.")
        else:
            records = SEED_RECORDS
            print(f"  [INFO]  Loaded {len(records)} pre-built login records.")

        out_path = os.path.join(os.path.dirname(__file__), "reports", "login_monitor.html")
        login_save_and_open(records, out_path, open_browser=True)
        print(f"  [OK]    Login monitor saved -> {out_path}")
        print(f"  [INFO]  Opening in your browser...")
        return

    parsed = None

    # ── Mode 1: .eml file ──────────────────────────────────────────────────────
    if args.file:
        if not os.path.isfile(args.file):
            _err(f"File not found: {args.file}")
        print(f"  [FILE]  Analysing file: {args.file}\n")
        try:
            parsed = parse_eml_file(args.file)
        except Exception as e:
            _err(f"Failed to parse .eml file: {e}")

    # ── Mode 2: plain-text file ────────────────────────────────────────────────
    elif args.text:
        if not os.path.isfile(args.text):
            _err(f"File not found: {args.text}")
        print(f"  [TEXT]  Analysing text file: {args.text}\n")
        try:
            with open(args.text, "r", encoding="utf-8", errors="replace") as f:
                raw = f.read()
            parsed = parse_raw_text(raw)
        except Exception as e:
            _err(f"Failed to read file: {e}")

    # ── Mode 3: interactive paste ──────────────────────────────────────────────
    else:
        print("  [INPUT]  Interactive mode - paste your email below.")
        print("  [INFO]   Paste the full email (headers + body) or just the body.")
        print("  [INFO]   When done, press Enter then type  END  on a new line and press Enter.\n")
        lines = []
        try:
            while True:
                line = input()
                if line.strip().upper() == "END":
                    break
                lines.append(line)
        except (KeyboardInterrupt, EOFError):
            pass

        raw = "\n".join(lines).strip()
        if not raw:
            _err("No email content provided.")

        # If input looks like it has headers (contains "From:" / "Subject:"), parse as raw
        if any(raw.lower().startswith(h) for h in ("from:", "subject:", "to:", "mime-")):
            parsed = parse_raw_text(raw)
        else:
            parsed = parse_body_only(raw)

    # ── Run analysis ───────────────────────────────────────────────────────────
    result = analyze(parsed)
    print_report(result, parsed)

    if args.save:
        report_path = save_json_report(result, parsed, output_dir="cyber_shield/reports")
        print(f"  [SAVED]  JSON report saved -> {report_path}\n")


def _err(msg: str):
    print(f"\n  [ERROR]: {msg}\n", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
