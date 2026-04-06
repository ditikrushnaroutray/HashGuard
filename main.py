import hashlib
import requests
import math
import re
import random
import string
import getpass

def check_pwned_api(password):
    sha1_pw = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_pw[:5], sha1_pw[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        res = requests.get(url)
        if res.status_code != 200: return "API Error"
        hashes = (line.split(':') for line in res.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return f"VULNERABLE! Found in {count} leaks."
        return "SECURE: No leaks found."
    except:
        return "Connection Error"

def estimate_crack_time(password):
    charset = 0
    if re.search(r'[a-z]', password): charset += 26
    if re.search(r'[A-Z]', password): charset += 26
    if re.search(r'[0-9]', password): charset += 10
    if re.search(r'[^a-zA-Z0-9]', password): charset += 32
    if charset == 0 or len(password) == 0: return "Instant"
    
    combinations = charset ** len(password)
    seconds = combinations / 100_000_000_000 # 100 Billion guesses/sec
    
    if seconds < 1: return "Instant"
    if seconds < 86400: return "Less than a day"
    if seconds < 31536000: return f"{int(seconds/86400)} days"
    return f"{int(seconds/31536000):,} years"

def recommend_strong_password(old_password):
    # Start with their password, swap letters for symbols
    replacements = {'a': '@', 's': '$', 'i': '!', 'o': '0', 'e': '3'}
    new_pw = "".join(replacements.get(c.lower(), c) for c in old_password)
    # Add random characters to ensure it's at least 14 chars long
    while len(new_pw) < 14:
        new_pw += random.choice(string.ascii_letters + string.digits + "!@#$%^&*")
    return new_pw

# --- RUN THE PROGRAM ---
print("--- HASHGUARD TERMINAL ---")

# Use getpass to hide the user's password as they type it
user_pw = getpass.getpass("Enter a password to test (input hidden): ")

# Check the API and save the status
breach_status = check_pwned_api(user_pw)

print(f"\n[!] Breach Status: {breach_status}")
print(f"[!] Est. Crack Time: {estimate_crack_time(user_pw)}")

# Only recommend a strong password if the current one was found in a leak
if "VULNERABLE" in breach_status:
    print(f"[!] Recommendation: {recommend_strong_password(user_pw)}")
else:
    print("[!] Recommendation: No leaks found. Your password is secure!")
    