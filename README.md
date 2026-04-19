SPAM DETECTOR TOOL USING PYTHON 

The Spam Detector Tool is a command-line utility that analyzes text messages and emails for spam indicators using keyword-based scoring, URL analysis, and heuristic pattern detection. It requires no external libraries — just Python 3 which comes pre-installed on Kali Linux.

✨ Features

🔍 200+ Spam Keywords across 7 categories with weighted scoring
🎣 Phishing URL Detection — IP-based URLs, fake brand domains, suspicious TLDs
📊 Spam Score 0–100 with color-coded verdicts
⚡ 4 Usage Modes — Interactive, Quick Text, File, and Batch
🚫 Zero Dependencies — runs on default Python 3, no pip install needed
🎨 Colorful Terminal UI using ANSI escape codes






📂 Project Structure
spam-detector/
│
├── spam_detector.py      # Main tool
├── README.md             # This file
└── samples/
    ├── spam_email.txt    # Sample spam message for testing
    └── clean_email.txt   # Sample clean message for testing

🖥️ Sample Output
  SPAM SCORE:  76/100
  ██████████████████████████████░░░░░░░░░░

  🟠  LIKELY SPAM

  TEXT STATISTICS
  Words:                 37
  URLs found:            1
  CAPS ratio:            15.7%
  Exclamation marks:     9

  ⚠  SUSPICIOUS PATTERNS
     • Excessive exclamation marks (9)

  🔍 SPAM KEYWORD HITS

     FINANCIAL  (weight: ×3)
       → "free money"
       → "claim your prize"
       → "lottery"

  🚨 PHISHING URLS DETECTED!
     ✗ http://192.168.1.1/paypal-login.php

⚠️ Disclaimer
This tool is built for educational and cybersecurity research purposes only.
Do not use it for unauthorized scanning or malicious intent.
Always use responsibly and ethically.


Made with ❤️ by Aman Gujar — Benazir Bhutto Shaheed University Lyari
</div>
