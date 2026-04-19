#!/usr/bin/env python3
"""
╔══════════════════════════════════════════╗
║        SPAM DETECTOR TOOL v1.0           ║
║        For Kali Linux / Terminal         ║
╚══════════════════════════════════════════╝
"""

import re
import sys
import math
import argparse
from collections import Counter

# ─────────────────────────────────────────────
# ANSI Color Codes (no external dependencies)
# ─────────────────────────────────────────────
RED     = "\033[91m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
MAGENTA = "\033[95m"
WHITE   = "\033[97m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RESET   = "\033[0m"

# ─────────────────────────────────────────────
# SPAM KEYWORD DATABASE
# ─────────────────────────────────────────────
SPAM_KEYWORDS = {
    "financial": {
        "keywords": [
            "free money", "earn money", "make money fast", "guaranteed income",
            "cash prize", "winner", "you won", "claim your prize", "lottery",
            "jackpot", "investment opportunity", "double your money", "risk free",
            "no investment", "earn $", "100% free", "million dollars", "billion",
            "wire transfer", "bank account", "financial freedom", "get rich",
            "unlimited income", "passive income", "work from home", "no experience needed"
        ],
        "weight": 3
    },
    "urgency": {
        "keywords": [
            "act now", "limited time", "expires soon", "urgent", "immediately",
            "don't wait", "last chance", "hurry", "deadline", "respond now",
            "today only", "24 hours", "time sensitive", "act immediately",
            "don't delay", "while supplies last", "final notice", "warning"
        ],
        "weight": 2
    },
    "clickbait": {
        "keywords": [
            "click here", "click below", "click now", "visit our website",
            "follow this link", "open this", "unsubscribe here", "opt out",
            "view online", "confirm your", "verify your account", "update your"
        ],
        "weight": 2
    },
    "medical": {
        "keywords": [
            "lose weight", "weight loss", "diet pill", "miracle cure", "cure all",
            "erectile dysfunction", "viagra", "cialis", "pharmacy", "prescription",
            "no prescription", "doctor approved", "fda approved", "clinically proven",
            "herbal remedy", "100% natural", "detox", "boost metabolism"
        ],
        "weight": 3
    },
    "identity": {
        "keywords": [
            "verify your identity", "confirm your details", "account suspended",
            "your account has been", "security alert", "suspicious activity",
            "unusual login", "unauthorized access", "reset your password",
            "update payment", "billing information", "credit card required",
            "social security", "ssn", "date of birth"
        ],
        "weight": 4
    },
    "offers": {
        "keywords": [
            "congratulations", "selected", "chosen", "exclusive offer",
            "special deal", "discount", "% off", "buy one get one", "bogo",
            "no obligation", "cancel anytime", "satisfaction guaranteed",
            "money back guarantee", "free trial", "free gift", "bonus"
        ],
        "weight": 1
    },
    "adult": {
        "keywords": [
            "xxx", "adult content", "18+", "singles near you", "hot singles",
            "meet singles", "dating site", "hook up", "sexy", "erotic"
        ],
        "weight": 4
    }
}

PHISHING_PATTERNS = [
    r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",   # IP-based URLs
    r"https?://[a-z0-9\-]+\.(tk|ml|ga|cf|gq|xyz|top|click|link|info|biz)/",  # Suspicious TLDs
    r"bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly|is\.gd|buff\.ly",                 # URL shorteners
    r"paypal[^.]*\.(com\.)?[a-z]{2,}",                  # Fake PayPal
    r"apple-[^.]+\.[a-z]+",                              # Fake Apple
    r"amazon[^.]*security[^.]*\.[a-z]+",                 # Fake Amazon
    r"microsoft[^.]*account[^.]*\.[a-z]+",               # Fake Microsoft
]

# ─────────────────────────────────────────────
# ANALYSIS ENGINE
# ─────────────────────────────────────────────

def extract_urls(text):
    pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    return re.findall(pattern, text, re.IGNORECASE)

def analyze_text(text):
    text_lower = text.lower()
    words = re.findall(r'\b\w+\b', text_lower)
    total_words = len(words) if words else 1

    results = {
        "score": 0,
        "max_score": 0,
        "hits": [],
        "categories": {},
        "urls": [],
        "phishing_urls": [],
        "suspicious_patterns": [],
        "text_stats": {}
    }

    # ── Keyword Analysis ──
    for category, data in SPAM_KEYWORDS.items():
        cat_hits = []
        for kw in data["keywords"]:
            if kw.lower() in text_lower:
                cat_hits.append(kw)
        if cat_hits:
            score_add = len(cat_hits) * data["weight"]
            results["categories"][category] = {
                "hits": cat_hits,
                "score": score_add,
                "weight": data["weight"]
            }
            results["score"] += score_add
            results["hits"].extend(cat_hits)

    # ── URL Analysis ──
    urls = extract_urls(text)
    results["urls"] = urls

    for url in urls:
        for pattern in PHISHING_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                results["phishing_urls"].append(url)
                results["score"] += 8
                break

    # ── Text Statistics ──
    uppercase_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)
    exclaim_count   = text.count('!')
    dollar_count    = text.count('$')
    word_freq       = Counter(words)
    repeated_words  = {w: c for w, c in word_freq.items() if c > 3 and len(w) > 3}

    results["text_stats"] = {
        "total_words":     total_words,
        "uppercase_ratio": round(uppercase_ratio * 100, 1),
        "exclamations":    exclaim_count,
        "dollar_signs":    dollar_count,
        "repeated_words":  repeated_words,
        "url_count":       len(urls)
    }

    # ── Heuristic Scoring ──
    if uppercase_ratio > 0.3:
        results["score"] += 5
        results["suspicious_patterns"].append(f"Excessive CAPS ({round(uppercase_ratio*100)}%)")

    if exclaim_count > 3:
        results["score"] += min(exclaim_count, 10)
        results["suspicious_patterns"].append(f"Excessive exclamation marks ({exclaim_count})")

    if dollar_count > 2:
        results["score"] += dollar_count * 2
        results["suspicious_patterns"].append(f"Multiple $ signs ({dollar_count})")

    if repeated_words:
        results["score"] += len(repeated_words) * 2
        results["suspicious_patterns"].append(f"Repeated words: {', '.join(list(repeated_words.keys())[:3])}")

    if len(urls) > 3:
        results["score"] += len(urls) * 3
        results["suspicious_patterns"].append(f"High URL density ({len(urls)} links)")

    # ── Normalize Score (0–100) ──
    raw = results["score"]
    normalized = min(100, int((1 - math.exp(-raw / 25)) * 100))
    results["normalized_score"] = normalized

    return results

def get_verdict(score):
    if score >= 80:
        return ("DEFINITE SPAM", RED, "🔴")
    elif score >= 60:
        return ("LIKELY SPAM", RED, "🟠")
    elif score >= 40:
        return ("SUSPICIOUS", YELLOW, "🟡")
    elif score >= 20:
        return ("POSSIBLY SUSPICIOUS", YELLOW, "🟢")
    else:
        return ("LIKELY CLEAN", GREEN, "✅")

def draw_bar(score, width=40):
    filled = int(score / 100 * width)
    if score >= 70:
        color = RED
    elif score >= 40:
        color = YELLOW
    else:
        color = GREEN
    bar = color + "█" * filled + DIM + "░" * (width - filled) + RESET
    return bar

# ─────────────────────────────────────────────
# DISPLAY
# ─────────────────────────────────────────────

def print_banner():
    print(f"""
{CYAN}{BOLD}╔══════════════════════════════════════════════════╗
║                                                  ║
║    ███████╗██████╗  █████╗ ███╗   ███╗          ║
║    ██╔════╝██╔══██╗██╔══██╗████╗ ████║          ║
║    ███████╗██████╔╝███████║██╔████╔██║          ║
║    ╚════██║██╔═══╝ ██╔══██║██║╚██╔╝██║          ║
║    ███████║██║     ██║  ██║██║ ╚═╝ ██║          ║
║    ╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝     ╚═╝          ║
║         D E T E C T O R   v 1 . 0              ║
║              Kali Linux Edition                 ║
╚══════════════════════════════════════════════════╝{RESET}
""")

def print_report(text, results):
    score = results["normalized_score"]
    verdict, color, icon = get_verdict(score)

    print(f"\n{BOLD}{WHITE}{'─'*52}{RESET}")
    print(f"{BOLD}  ANALYSIS REPORT{RESET}")
    print(f"{BOLD}{WHITE}{'─'*52}{RESET}\n")

    # Score bar
    print(f"  {BOLD}SPAM SCORE:{RESET}  {color}{BOLD}{score}/100{RESET}")
    print(f"  {draw_bar(score)}")
    print(f"\n  {icon}  {color}{BOLD}{verdict}{RESET}\n")

    # Text Stats
    s = results["text_stats"]
    print(f"{BOLD}{CYAN}  TEXT STATISTICS{RESET}")
    print(f"  {'Words:':<22} {s['total_words']}")
    print(f"  {'URLs found:':<22} {s['url_count']}")
    print(f"  {'CAPS ratio:':<22} {s['uppercase_ratio']}%")
    print(f"  {'Exclamation marks:':<22} {s['exclamations']}")
    print(f"  {'Dollar signs:':<22} {s['dollar_signs']}")

    # Suspicious Patterns
    if results["suspicious_patterns"]:
        print(f"\n{BOLD}{YELLOW}  ⚠  SUSPICIOUS PATTERNS{RESET}")
        for p in results["suspicious_patterns"]:
            print(f"     {YELLOW}•{RESET} {p}")

    # Keyword Hits by Category
    if results["categories"]:
        print(f"\n{BOLD}{RED}  🔍 SPAM KEYWORD HITS{RESET}")
        for cat, data in results["categories"].items():
            print(f"\n     {BOLD}{cat.upper()}{RESET}  {DIM}(weight: ×{data['weight']}){RESET}")
            for kw in data["hits"][:5]:
                print(f"       {RED}→{RESET} \"{kw}\"")
            if len(data["hits"]) > 5:
                print(f"       {DIM}... and {len(data['hits'])-5} more{RESET}")

    # URL Analysis
    if results["urls"]:
        print(f"\n{BOLD}{CYAN}  🔗 URLS DETECTED{RESET}")
        for url in results["urls"][:5]:
            flag = f"  {RED}⚠ PHISHING SUSPECT{RESET}" if url in results["phishing_urls"] else ""
            print(f"     {DIM}{url[:60]}{'...' if len(url)>60 else ''}{RESET}{flag}")
        if len(results["urls"]) > 5:
            print(f"     {DIM}... and {len(results['urls'])-5} more URLs{RESET}")

    # Phishing Alert
    if results["phishing_urls"]:
        print(f"\n{RED}{BOLD}  🚨 PHISHING URLS DETECTED!{RESET}")
        for url in results["phishing_urls"]:
            print(f"     {RED}✗{RESET} {url}")

    print(f"\n{BOLD}{WHITE}{'─'*52}{RESET}\n")

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def interactive_mode():
    print_banner()
    print(f"{CYAN}  Enter text to analyze (type END on a new line to finish):{RESET}\n")
    lines = []
    while True:
        try:
            line = input()
            if line.strip().upper() == "END":
                break
            lines.append(line)
        except (EOFError, KeyboardInterrupt):
            break
    text = "\n".join(lines)
    if not text.strip():
        print(f"\n{YELLOW}  No text provided. Exiting.{RESET}\n")
        sys.exit(0)
    results = analyze_text(text)
    print_report(text, results)

def file_mode(filepath):
    print_banner()
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
        print(f"{CYAN}  Analyzing file: {BOLD}{filepath}{RESET}\n")
        results = analyze_text(text)
        print_report(text, results)
    except FileNotFoundError:
        print(f"\n{RED}  ✗ File not found: {filepath}{RESET}\n")
        sys.exit(1)

def quick_mode(text):
    print_banner()
    results = analyze_text(text)
    print_report(text, results)

def batch_mode(filepath):
    print_banner()
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            entries = f.read().split("---")
        print(f"{CYAN}  Batch mode: {len(entries)} entries found in {filepath}{RESET}\n")
        for i, entry in enumerate(entries, 1):
            if entry.strip():
                print(f"{BOLD}{MAGENTA}  ═══ Entry #{i} ══════════════════════════{RESET}")
                results = analyze_text(entry)
                score = results["normalized_score"]
                verdict, color, icon = get_verdict(score)
                print(f"  Score: {color}{score}/100{RESET} — {icon} {color}{verdict}{RESET}")
                print(f"  Keyword hits: {len(results['hits'])} | URLs: {len(results['urls'])}")
    except FileNotFoundError:
        print(f"\n{RED}  ✗ File not found: {filepath}{RESET}\n")
        sys.exit(1)

# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Spam Detector Tool — Kali Linux Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  python3 spam_detector.py                          # interactive mode
  python3 spam_detector.py -f email.txt             # analyze a file
  python3 spam_detector.py -t "Congratulations you won $1000!"
  python3 spam_detector.py -b emails.txt            # batch mode (entries separated by ---)
        """
    )
    parser.add_argument("-f", "--file",  help="Analyze a text file")
    parser.add_argument("-t", "--text",  help="Analyze text directly")
    parser.add_argument("-b", "--batch", help="Batch analyze file (entries split by ---)")

    args = parser.parse_args()

    if args.file:
        file_mode(args.file)
    elif args.text:
        quick_mode(args.text)
    elif args.batch:
        batch_mode(args.batch)
    else:
        interactive_mode()

if __name__ == "__main__":
    main()
