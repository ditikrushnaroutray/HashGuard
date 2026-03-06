document.getElementById('checkBtn').addEventListener('click', async () => {
    const password = document.getElementById('passwordInput').value;
    const resultDiv = document.getElementById('result');
    
    if (!password) return;
    resultDiv.innerHTML = "Checking database...";

    // 1. SHA-1 Hashing (JavaScript Style)
    const msgBuffer = new TextEncoder().encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-1', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    
    const prefix = hashHex.slice(0, 5);
    const suffix = hashHex.slice(5);

    // 2. Fetch from HIBP API (k-Anonymity)
    try {
        const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
        const text = await response.text();
        const found = text.includes(suffix);

        // 3. Simple Strength Recommendation (Logic for demonstration)
        let recommendation = password;
        if (password.length < 12) {
            recommendation = password.replace(/a/g, '@').replace(/s/g, '$') + "!" + Math.floor(Math.random() * 99);
        }

        if (found) {
            resultDiv.innerHTML = `<span class="status-bad">⚠️ BREACHED!</span> This password was found in a leak.<br><br>
                                   <b>Try this instead:</b> <br><code style="color:#4ade80">${recommendation}</code>`;
        } else {
            resultDiv.innerHTML = `<span class="status-good">✅ SECURE!</span> Not found in known leaks.`;
        }
    } catch (error) {
        resultDiv.innerHTML = "Error connecting to API.";
    }
});
