SPAM DETECTOR TOOL USING PYTHON 

The Spam Detector Tool is a command-line utility that analyzes text messages and emails for spam indicators using keyword-based scoring, URL analysis, and heuristic pattern detection. It requires no external libraries — just Python 3 which comes pre-installed on Kali Linux.

✨ Features

🔍 200+ Spam Keywords across 7 categories with weighted scoring
🎣 Phishing URL Detection — IP-based URLs, fake brand domains, suspicious TLDs
📊 Spam Score 0–100 with color-coded verdicts
⚡ 4 Usage Modes — Interactive, Quick Text, File, and Batch
🚫 Zero Dependencies — runs on default Python 3, no pip install needed
🎨 Colorful Terminal UI using ANSI escape codes



Detection Layers
LayerWhat It ChecksKeyword Analysis200+ spam phrases across 7 categoriesURL DetectionIP-based URLs, .tk/.xyz TLDs, URL shortenersBrand SpoofingFake PayPal, Apple, Amazon, Microsoft domainsHeuristic RulesCAPS ratio, ! count, $ signs, repeated words
Spam Score Verdicts
ScoreVerdict0 – 19✅ Likely Clean20 – 39🟢 Possibly Suspicious40 – 59🟡 Suspicious60 – 79🟠 Likely Spam80 – 100🔴 Definite Spam

🚀 Installation & Usage
Step 1 — Clone or Download
bashgit clone https://github.com/yourusername/spam-detector.git
cd spam-detector
Step 2 — Make Executable
bashchmod +x spam_detector.py
Step 3 — Run It
▶ Interactive Mode (type your message, end with END)
bashpython3 spam_detector.py
▶ Quick Text Mode
bashpython3 spam_detector.py -t 'Congratulations! You won a free prize click here now!!!'
▶ Analyze a File
bashpython3 spam_detector.py -f email.txt
▶ Batch Mode (multiple messages separated by ---)
bashpython3 spam_detector.py -b emails.txt
▶ Install Globally (use from anywhere)
bashsudo cp spam_detector.py /usr/local/bin/spamcheck
spamcheck -t 'free money win now'

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
