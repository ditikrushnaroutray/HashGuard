# 🛡️ HashGuard Sentinel

[![License](https://img.shields.io/github/license/ditikrushnaroutray/HashGuard?style=for-the-badge&color=4f8cf7)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Manifest V3](https://img.shields.io/badge/Browser_Extension-Manifest_V3-10b981?style=for-the-badge&logo=googlechrome&logoColor=white)](extension/)
[![Privacy](https://img.shields.io/badge/Privacy-Zero--Knowledge-e11d48?style=for-the-badge)](https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange)

**HashGuard Sentinel** is a dual-tier cybersecurity suite featuring a **Manifest V3 Browser Extension** and an **Enterprise Python CLI Tool**. It allows security analysts, system administrators, and privacy-conscious users to evaluate password strength, audit bulk credential datasets, and generate high-entropy alternatives—all without ever exposing plain-text passwords or full hashes to external servers.

---

## 🔒 The Zero-Knowledge Privacy Guarantee

HashGuard Sentinel is engineered under strict **Zero-Knowledge** principles:

- **k-Anonymity Model:** When auditing a password against the Have I Been Pwned (HIBP) database, HashGuard hashes the password locally using **SHA-1** and sends **ONLY the first 5 characters** (`prefix`) to the HIBP API.
- **Local Suffix Matching:** The API responds with a list of leaked hash suffixes sharing that 5-character prefix. Full hash suffix matching is performed 100% locally in your browser or terminal environment.
- **Client-Side Entropy Evaluation:** Strength assessment uses a bundled offline copy of `zxcvbn.js` (browser extension) or the Python `zxcvbn` module (CLI). No metrics or passwords are sent to third-party telemetry services.
- **Zero Disk Persistence:** Plain-text passwords and hashes are purged from memory immediately after evaluation.

```
┌─────────────────┐       SHA-1 Hash       ┌────────────────────────┐
│ Plaintext Input │ ────────────────────>  │  5-Char SHA-1 Prefix   │
└─────────────────┘                        └───────────┬────────────┘
                                                       │  Send Prefix Only
                                                       ▼
┌─────────────────┐      Local Match       ┌────────────────────────┐
│  Breach Result  │ <────────────────────  │ HIBP Range API (200 OK)│
└─────────────────┘  Suffix Comparison     └────────────────────────┘
```

---

## ✨ Features

### 🧩 Browser Extension (Chrome, Brave, Edge)
- **Modern Dark UI:** Flat, high-contrast, professional dark layout.
- **Intelligent Password Mutator ("✨ Suggest Safer Version"):** Transforms weak or breached passwords into 12+ character high-entropy variants that retain ~90% of the original character structure for memorability.
- **Cryptographic Generator:** Built-in 16-character password generator powered by `crypto.getRandomValues` and Fisher-Yates shuffle algorithms.
- **Context Menu Integration:** Right-click selected password fields to inspect credentials via HashGuard with automated single-use memory cleanup.

### 💻 Enterprise Python CLI Tool (`main.py`)
- **Persistent Interactive Session:** Run `python main.py` for a continuous interactive auditing terminal with instant feedback, recommendations, and graceful exit handling.
- **Enterprise Bulk Audit Mode (`--bulk`):** Audit hundreds of credentials at scale from text files with built-in prefix caching and `tqdm` progress tracking.
- **Rate Limit & Retry Protection:** Respects HIBP rate limits (1.5-second inter-request delay on cache miss) and exponential backoff retries (1s, 2s, 4s).
- **Report Export (`--export`):** Save structured audit reports to JSON (`.json`) or CSV (`.csv`) with automatic security warning prompts.

---

## 🚀 Quick Start & Installation

### Option A: Installing the Browser Extension (Chrome / Brave / Edge)

1. Clone or download this repository:
   ```bash
   git clone https://github.com/ditikrushnaroutray/HashGuard.git
   ```
2. Open your browser's Extensions page:
   - **Brave:** `brave://extensions`
   - **Chrome:** `chrome://extensions`
   - **Edge:** `edge://extensions`
3. Enable **Developer mode** in the top right corner.
4. Click **Load unpacked** and select the `/extension` subfolder inside the HashGuard repository.

---

### Option B: Setting Up the Python CLI

1. Ensure Python 3.8+ is installed on your system.
2. Clone the repository and navigate to the project root:
   ```bash
   git clone https://github.com/ditikrushnaroutray/HashGuard.git
   cd HashGuard
   ```
3. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## 💡 Usage Examples

### 1. Interactive CLI Mode
Launch the interactive terminal session:
```bash
python main.py
```
*Type passwords to inspect their breach status and strength. Type `exit` or press `Ctrl+C` to quit.*

### 2. Enterprise Bulk Audit CLI Mode
Audit a text file containing one password per line:
```bash
python main.py --bulk test_passwords.txt
```

### 3. Bulk Audit with JSON/CSV Export
Export detailed audit metrics to structured files:
```bash
# Export to JSON
python main.py --bulk passwords.txt --export audit_report.json

# Export to CSV
python main.py --bulk passwords.txt --export audit_report.csv
```

### 4. Quiet Mode (CI/CD Pipelines)
Suppress stdout progress output and generate summary metrics only:
```bash
python main.py --bulk passwords.txt --export report.json --quiet
```

---

## 📂 Project Structure

```
HashGuard/
├── extension/                   # Manifest V3 Browser Extension
│   ├── manifest.json            # Extension configuration & service worker registration
│   ├── popup.html               # Main extension popup interface
│   ├── popup.css                # Extension dark theme stylesheet
│   ├── popup.js                 # Local hashing, HIBP lookup, zxcvbn integration & mutator
│   ├── background.js            # Service worker & context menu event listener
│   └── libs/
│       └── zxcvbn.js            # Bundled local zero-knowledge entropy library
├── main.py                      # Python CLI (Interactive & Bulk Audit tool)
├── requirements.txt             # CLI Python dependencies
├── test_passwords.txt           # Test sample file for bulk auditing
└── README.md                    # Project documentation
```

---

## 📊 Sample Audit Output (CLI Report Format)

When exporting JSON reports using `--export`, HashGuard outputs structured data:

```json
[
  {
    "password": "password123",
    "breach_count": 2266543,
    "is_breached": true,
    "entropy_score": 2,
    "crack_time": "15 days"
  },
  {
    "password": "P@ssw0rd2026!",
    "breach_count": 0,
    "is_breached": false,
    "entropy_score": 2,
    "crack_time": "14,185,854 years"
  }
]
```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE) - see the LICENSE file for details.

---

## 👤 Author & Maintainer

**Ditikrushna Routray**
- GitHub: [@ditikrushnaroutray](https://github.com/ditikrushnaroutray)
- Repository: [https://github.com/ditikrushnaroutray/HashGuard](https://github.com/ditikrushnaroutray/HashGuard)
