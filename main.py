import hashlib
import requests
import math
import re

def check_pwned_api(password):
    # Hash the password and get the first 5 chars
    sha1_pw = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_pw[:5], sha1_pw[5:]
    
    # Query HIBP API
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    res = requests.get(url)
    
    if res.status_code != 200:
        return "Error checking breach database."
    
    # Check if suffix is in the results
    hashes = (line.split(':') for line in res.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return f"VULNERABLE! This password appeared in {count} data breaches."
    return "Secure: Not found in known data leaks."

def estimate_crack_time(password):
    # Basic entropy calculation
    charset_size = 0
    if re.search(r'[a-z]', password): charset_size += 26
    if re.search(r'[A-Z]', password): charset_size += 26
    if re.search(r'[0-9]', password): charset_size += 10
    if re.search(r'[^a-zA-Z0-9]', password): charset_size += 32
    
    if charset_size == 0: return "Instant"
    
    combinations = charset_size ** len(password)
    # Assuming a modern 2026 rig doing 100 billion guesses/sec
    seconds = combinations / 100_000_000_000
    
    if seconds < 1: return "Instant"
    if seconds < 3600: return f"{int(seconds/60)} minutes"
    if seconds < 86400: return f"{int(seconds/3600)} hours"
    if seconds < 31536000: return f"{int(seconds/86400)} days"
    return f"{int(seconds/31536000)} years"

# --- Main Execution ---
user_pw = input("Enter password to test: ")
print(f"\n--- Security Report ---")
print(f"Breach Status: {check_pwned_api(user_pw)}")
print(f"Est. Crack Time: {estimate_crack_time(user_pw)}")