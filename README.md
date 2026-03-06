 # 🛡️ HashGuard Sentinel
![Build Status](https://img.shields.io/badge/Build-Passing-4ade80?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-Verified-blueviolet?style=for-the-badge)
![Stars](https://img.shields.io/github/stars/ditikrushnaroutray/HashGuard?style=for-the-badge&color=38bdf8)
![Forks](https://img.shields.io/github/forks/ditikrushnaroutray/HashGuard?style=for-the-badge&color=7dd3fc)
![License](https://img.shields.io/github/license/ditikrushnaroutray/HashGuard?style=for-the-badge&color=4ade80)

---

## 📖 Project Overview
**HashGuard** is a security intelligence utility developed to bridge the gap between user convenience and robust data protection. This project explores the intersection of **Network Security** and **Data Privacy**.

**HashGuard** is a security intelligence utility developed to bridge the gap between user convenience and robust data protection. This project explores the intersection of **Network Security** and **Data Privacy**.

Unlike standard checkers, HashGuard prioritizes user anonymity by implementing a **local hashing protocol**, ensuring that sensitive plain-text data never leaves the client's environment.

# 🛡️ HashGuard: Password Intelligence & Security Tool

**HashGuard** is a privacy-first cybersecurity utility designed to evaluate password strength using real-world data breach intelligence and entropy-based crack-time estimation.

## 🚀 Features
- **Breach Intelligence:** Uses the **Have I Been Pwned (HIBP) API** with *k-Anonymity* to check if your password has been leaked in known data breaches without ever sending your plain-text password over the internet.
- **Crack-Time Estimation:** Calculates entropy based on character sets (Lowercase, Uppercase, Digits, Symbols) to estimate brute-force resistance.
- **Fortification Engine:** Suggests a high-entropy, secure version of your password using leetspeak substitution and random padding.

## 🛠️ Technical Stack
- **Language:** Python 3.x
- **Libraries:** `requests`, `hashlib`, `re`
- **Security Protocols:** SHA-1 Hashing, k-Anonymity (API interaction)

## 🚧 Project Roadmap (Current Status)
- [x] Core Python Logic (Complete)
- [x] HIBP API Integration (Complete)
- [ ] **Next Phase: Browser Extension (In Development)** 🛠️
  - Translating Python logic to JavaScript.
  - Creating a Chrome/Brave Manifest V3 extension.
  - Building a clean, dark-themed UI for real-time password checking while browsing.

## ⚙️ How to Run (Terminal Version)
1. Clone the repository:
   ```bash
   git clone [https://github.com/ditikrushnaroutray/HashGuard.git](https://github.com/ditikrushnaroutray/HashGuard.git)
