#!/usr/bin/env python3
"""
HashGuard Sentinel - CLI & Bulk Password Audit Tool
Zero-Knowledge Privacy: Only 5-character SHA-1 prefixes are sent to the HIBP API.
All suffix matching and entropy evaluations are performed locally.
"""

import os
import sys
import time
import math
import re
import random
import string
import getpass
import hashlib
import json
import csv
import argparse
import requests

try:
    from zxcvbn import zxcvbn
    HAS_ZXCVBN = True
except ImportError:
    HAS_ZXCVBN = False

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

# Global Prefix Cache to prevent redundant API calls
# Key: 5-character SHA-1 prefix -> Value: dict of {suffix: breach_count}
PREFIX_CACHE = {}

def check_pwned_api_single(password):
    """
    Checks single password against HIBP API using k-Anonymity.
    Returns status string for interactive CLI mode.
    """
    sha1_pw = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_pw[:5], sha1_pw[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {"Add-Padding": "true"}
    try:
        res = requests.get(url, headers=headers, timeout=10)
        if res.status_code != 200:
            return "API Error"
        
        if res.text and res.text.strip():
            hashes = (line.split(':') for line in res.text.splitlines() if ':' in line)
            for h, count in hashes:
                if h.upper() == suffix:
                    return f"VULNERABLE! Found in {int(count):,} leaks."
        return "SECURE: No leaks found."
    except Exception as e:
        return "Connection Error"

def fetch_hibp_prefix_with_retry(prefix, retries=3):
    """
    Fetches suffix map for a 5-character SHA-1 prefix with rate limiting and exponential backoff retry.
    Uses PREFIX_CACHE to optimize repeated prefixes.
    """
    if prefix in PREFIX_CACHE:
        return PREFIX_CACHE[prefix]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {"Add-Padding": "true"}

    for attempt in range(retries):
        try:
            res = requests.get(url, headers=headers, timeout=10)
            if res.status_code == 200:
                suffix_map = {}
                if res.text and res.text.strip():
                    for line in res.text.splitlines():
                        parts = line.strip().split(':')
                        if len(parts) == 2:
                            suffix_map[parts[0].upper()] = int(parts[1])
                PREFIX_CACHE[prefix] = suffix_map
                time.sleep(1.5) # Enforce 1.5s rate limit between fresh API calls
                return suffix_map
            elif res.status_code == 429:
                time.sleep(2 ** (attempt + 1))
            else:
                time.sleep(2 ** attempt)
        except requests.RequestException:
            time.sleep(2 ** attempt)

    return None

def estimate_crack_time_fallback(password):
    """Fallback entropy calculation if zxcvbn is not installed."""
    charset = 0
    if re.search(r'[a-z]', password): charset += 26
    if re.search(r'[A-Z]', password): charset += 26
    if re.search(r'[0-9]', password): charset += 10
    if re.search(r'[^a-zA-Z0-9]', password): charset += 32
    if charset == 0 or len(password) == 0:
        return 0, "Instant"
    
    combinations = charset ** len(password)
    seconds = combinations / 100_000_000_000 # 100 Billion guesses/sec
    
    # Calculate score (0-4)
    if len(password) < 8:
        score = 0
    elif len(password) < 11:
        score = 1
    elif len(password) < 14:
        score = 2
    elif len(password) < 17:
        score = 3
    else:
        score = 4

    if seconds < 1:
        display = "Instant"
    elif seconds < 86400:
        display = "Less than a day"
    elif seconds < 31536000:
        display = f"{int(seconds/86400)} days"
    else:
        display = f"{int(seconds/31536000):,} years"

    return score, display

def evaluate_password_strength(password):
    """Returns (score, crack_time_display) using zxcvbn or fallback."""
    if HAS_ZXCVBN:
        res = zxcvbn(password)
        score = res.get('score', 0)
        crack_time = res.get('crack_times_display', {}).get('offline_slow_hashing_1e4_per_second', 'Instant')
        return score, crack_time
    else:
        return estimate_crack_time_fallback(password)

def recommend_strong_password(old_password):
    """Generates a mutated recommendation for weak passwords."""
    replacements = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7'}
    chars = list(old_password)
    for i, c in enumerate(chars):
        lower = c.lower()
        if lower in replacements:
            if lower == 's' and i == 0:
                continue
            chars[i] = replacements[lower]
    new_pw = "".join(chars)
    if new_pw:
        new_pw = new_pw[0].upper() + new_pw[1:]
    while len(new_pw) < 14:
        new_pw += random.choice(string.ascii_letters + string.digits + "!@#$%^&*")
    return new_pw

def export_results(results, export_path):
    """Exports audit results to JSON or CSV file."""
    print(f"\n⚠️ WARNING: Plain-text passwords are being written to disk ({export_path}). Store this report securely.")
    try:
        if export_path.lower().endswith('.csv'):
            with open(export_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=["password", "breach_count", "is_breached", "entropy_score", "crack_time"])
                writer.writeheader()
                for r in results:
                    writer.writerow({
                        "password": r.get("password", ""),
                        "breach_count": r.get("breach_count", 0),
                        "is_breached": r.get("is_breached", False),
                        "entropy_score": r.get("entropy_score", 0),
                        "crack_time": r.get("crack_time", "")
                    })
        else:
            with open(export_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2)
        print(f"✅ Report successfully saved to: {export_path}")
    except Exception as e:
        print(f"❌ Failed to export report: {e}")

def process_bulk(filepath, export_path=None, quiet=False):
    """
    Executes bulk password auditing from file with rate limiting,
    prefix caching, progress tracking, export, and graceful interrupt.
    """
    if not os.path.exists(filepath):
        print(f"❌ File not found: {filepath}")
        sys.exit(1)

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            raw_lines = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"❌ Error reading file {filepath}: {e}")
        sys.exit(1)

    if not raw_lines:
        print("❌ No passwords found in file.")
        sys.exit(1)

    # Deduplicate passwords while preserving order
    unique_passwords = list(dict.fromkeys(raw_lines))
    total_raw = len(raw_lines)
    total_unique = len(unique_passwords)

    if not quiet:
        print(f"==================================================")
        print(f"🛡️ HASHGUARD SENTINEL - BULK AUDIT MODE")
        print(f"File: {filepath}")
        print(f"Total Lines: {total_raw} | Unique Passwords: {total_unique}")
        print(f"==================================================\n")

    results = []
    start_time = time.time()

    score_labels = {0: "Very Weak", 1: "Weak", 2: "Fair", 3: "Strong", 4: "Excellent"}

    try:
        if HAS_TQDM and not quiet:
            iterator = tqdm(unique_passwords, desc="Auditing Passwords", unit="pw")
        else:
            iterator = unique_passwords

        for idx, password in enumerate(iterator, 1):
            sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix, suffix = sha1[:5], sha1[5:]

            suffix_map = fetch_hibp_prefix_with_retry(prefix)

            if suffix_map is None:
                breach_count = 0
                is_breached = False
                error_msg = "API timeout"
            else:
                breach_count = suffix_map.get(suffix, 0)
                is_breached = breach_count > 0
                error_msg = None

            score, crack_time = evaluate_password_strength(password)

            result_entry = {
                "password": password,
                "breach_count": breach_count,
                "is_breached": is_breached,
                "entropy_score": score,
                "crack_time": crack_time
            }
            if error_msg:
                result_entry["error"] = error_msg

            results.append(result_entry)

            if not quiet and not HAS_TQDM:
                label = score_labels.get(score, "Weak")
                if is_breached:
                    status_str = f"🔴 PWNED ({breach_count:,} breaches)"
                elif error_msg:
                    status_str = f"⚠️ ERROR ({error_msg})"
                else:
                    status_str = f"🟢 SAFE"
                print(f"[{idx}/{total_unique}] {password} → {status_str} | Strength: {label}")

    except KeyboardInterrupt:
        print("\n\n⚠️ Interrupted. Results saved up to this point.")

    elapsed = time.time() - start_time
    breached_count = sum(1 for r in results if r.get('is_breached'))
    breach_pct = (breached_count / len(results) * 100) if results else 0.0
    avg_score = (sum(r.get('entropy_score', 0) for r in results) / len(results)) if results else 0.0

    print("\n==================================================")
    print("📊 BULK AUDIT SUMMARY REPORT")
    print("==================================================")
    print(f"Total Passwords Checked:   {len(results)} / {total_unique} unique ({total_raw} in file)")
    print(f"Breached Passwords:        {breached_count} ({breach_pct:.1f}%)")
    print(f"Safe Passwords:            {len(results) - breached_count}")
    print(f"Average Entropy Score:     {avg_score:.2f} / 4.0")
    print(f"Total Time Elapsed:        {elapsed:.2f} seconds")
    print("==================================================")

    if export_path:
        export_results(results, export_path)

def interactive_mode():
    """Default interactive CLI mode when no arguments are provided."""
    print("--- HASHGUARD TERMINAL ---")
    user_pw = getpass.getpass("Enter a password to test (input hidden): ")

    if not user_pw.strip():
        print("❌ Empty password entered.")
        return

    breach_status = check_pwned_api_single(user_pw.strip())
    score, crack_time = evaluate_password_strength(user_pw.strip())

    print(f"\n[!] Breach Status: {breach_status}")
    print(f"[!] Est. Crack Time: {crack_time}")

    if "VULNERABLE" in breach_status:
        print(f"[!] Recommendation: {recommend_strong_password(user_pw.strip())}")
    else:
        print("[!] Recommendation: No leaks found. Your password is secure!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HashGuard Sentinel - Zero-Knowledge Password Audit Tool")
    parser.add_argument("--bulk", type=str, help="Path to a text file with one password per line.")
    parser.add_argument("--export", type=str, help="Export results to a JSON or CSV file (works with --bulk).")
    parser.add_argument("--quiet", action="store_true", help="Suppress per-password output; only show final summary.")

    args = parser.parse_args()

    if args.bulk:
        process_bulk(args.bulk, export_path=args.export, quiet=args.quiet)
    else:
        interactive_mode()