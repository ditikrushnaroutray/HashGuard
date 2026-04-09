// 1. Calculate Crack Time (Translated from Python)
function estimateCrackTime(password) {
    let charset = 0;
    if (/[a-z]/.test(password)) charset += 26;
    if (/[A-Z]/.test(password)) charset += 26;
    if (/[0-9]/.test(password)) charset += 10;
    if (/[^a-zA-Z0-9]/.test(password)) charset += 32;
    
    if (charset === 0 || password.length === 0) return "Instant";
    
    const combinations = Math.pow(charset, password.length);
    const seconds = combinations / 100000000000; // 100 Billion guesses/sec
    
    if (seconds < 1) return "Instant";
    if (seconds < 86400) return "Less than a day";
    if (seconds < 31536000) return `${Math.floor(seconds/86400)} days`;
    return `${Math.floor(seconds/31536000).toLocaleString()} years`;
}

// 2. Recommend Password Logic (Translated from Python)
function recommendStrongPassword(oldPassword) {
    const replacements = {'a': '@', 's': '$', 'i': '!', 'o': '0', 'e': '3'};
    let newPw = oldPassword.split('').map(c => replacements[c.toLowerCase()] || c).join('');
    
    const extraChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
    while (newPw.length < 14) {
        newPw += extraChars.charAt(Math.floor(Math.random() * extraChars.length));
    }
    return newPw;
}

// 3. Main Event Listener
document.getElementById('checkBtn').addEventListener('click', async () => {
    const password = document.getElementById('passwordInput').value;
    const resultBox = document.getElementById('resultBox');
    const breachStatus = document.getElementById('breachStatus');
    const crackTime = document.getElementById('crackTime');
    const recommendation = document.getElementById('recommendation');
    
    if (!password) return;
    
    resultBox.style.display = 'block';
    breachStatus.innerHTML = "Checking database...";
    crackTime.innerHTML = "";
    recommendation.innerHTML = "";

    try {
        // SHA-1 Hashing
        const msgBuffer = new TextEncoder().encode(password);
        const hashBuffer = await crypto.subtle.digest('SHA-1', msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
        
        const prefix = hashHex.slice(0, 5);
        const suffix = hashHex.slice(5);

        // Fetch from HIBP API
        const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
        const text = await response.text();
        
        const lines = text.split('\n');
        let foundCount = 0;
        
        for (let line of lines) {
            if (line.startsWith(suffix)) {
                foundCount = line.split(':')[1].trim();
                break;
            }
        }

        // Update UI: Breach Status
        if (foundCount > 0) {
            breachStatus.innerHTML = `Breach Status: <span class="vulnerable">VULNERABLE! Found in ${foundCount} leaks.</span>`;
            // Only recommend if breached
            recommendation.innerHTML = `Recommendation: Try <strong>${recommendStrongPassword(password)}</strong>`;
        } else {
            breachStatus.innerHTML = `Breach Status: <span class="secure">SECURE! No leaks found.</span>`;
            recommendation.innerHTML = `Recommendation: No leaks found. Your password is secure!`;
        }

        // Update UI: Crack Time
        crackTime.innerHTML = `Est. Crack Time: <strong>${estimateCrackTime(password)}</strong>`;

    } catch (error) {
        breachStatus.innerHTML = "Error connecting to API.";
    }
});
