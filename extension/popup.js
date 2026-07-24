/**
 * HashGuard Sentinel - Popup Logic
 * Security-focused browser extension logic featuring:
 * 1. Zero-Knowledge SHA-1 Hashing (Web Crypto API) & k-Anonymity HIBP breach lookup
 * 2. Empty response guard for HIBP range API
 * 3. Loading state / spinner & rate-limiting protection
 * 4. Local zxcvbn entropy evaluation (score, visual progress bar, crack time display)
 * 5. Cryptographically secure 16-character password generator (crypto.getRandomValues)
 * 6. Context menu auto-fill with storage.onChanged listener & immediate cleanup
 */

document.addEventListener('DOMContentLoaded', () => {
  const passwordInput = document.getElementById('passwordInput');
  const togglePassword = document.getElementById('togglePassword');
  const checkBtn = document.getElementById('checkBtn');
  const generateBtn = document.getElementById('generateBtn');

  const resultBox = document.getElementById('resultBox');
  const breachStatus = document.getElementById('breachStatus');
  const strengthContainer = document.getElementById('strengthContainer');
  const strengthLabel = document.getElementById('strengthLabel');
  const meterFill = document.getElementById('meterFill');
  const crackTime = document.getElementById('crackTime');
  const warningBanner = document.getElementById('warningBanner');
  const recommendation = document.getElementById('recommendation');

  // --- 1. EYE TOGGLE (SHOW / HIDE PASSWORD) ---
  togglePassword.addEventListener('click', () => {
    if (passwordInput.type === 'password') {
      passwordInput.type = 'text';
      togglePassword.textContent = '🔒';
    } else {
      passwordInput.type = 'password';
      togglePassword.textContent = '👁️';
    }
  });

  // --- 2. CRYPTOGRAPHICALLY SECURE PASSWORD GENERATOR ---
  function generateSecurePassword(length = 16) {
    const charsetUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const charsetLower = "abcdefghijklmnopqrstuvwxyz";
    const charsetDigits = "0123456789";
    const charsetSymbols = "!@#$%^&*()_+-=[]{}|;:,.<>?";
    const allChars = charsetUpper + charsetLower + charsetDigits + charsetSymbols;

    const getRandomChar = (str) => {
      const array = new Uint32Array(1);
      crypto.getRandomValues(array);
      return str[array[0] % str.length];
    };

    let passwordChars = [
      getRandomChar(charsetUpper),
      getRandomChar(charsetLower),
      getRandomChar(charsetDigits),
      getRandomChar(charsetSymbols)
    ];

    const randomBuffer = new Uint32Array(length - 4);
    crypto.getRandomValues(randomBuffer);
    for (let i = 0; i < randomBuffer.length; i++) {
      passwordChars.push(allChars[randomBuffer[i] % allChars.length]);
    }

    // Cryptographically shuffle array (Fisher-Yates)
    for (let i = passwordChars.length - 1; i > 0; i--) {
      const swapBuf = new Uint32Array(1);
      crypto.getRandomValues(swapBuf);
      const j = swapBuf[0] % (i + 1);
      [passwordChars[i], passwordChars[j]] = [passwordChars[j], passwordChars[i]];
    }

    return passwordChars.join('');
  }

  generateBtn.addEventListener('click', () => {
    const newPassword = generateSecurePassword(16);
    passwordInput.value = newPassword;
    passwordInput.type = 'text';
    togglePassword.textContent = '🔒';
    
    // Automatically perform audit on generated password
    runAudit();
  });

  // --- 3. ZERO-KNOWLEDGE SHA-1 HASHING & HIBP API CHECK ---
  async function computeSHA1Hex(text) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await crypto.subtle.digest('SHA-1', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  }

  async function checkBreachStatus(sha1Prefix, sha1Suffix) {
    const url = `https://api.pwnedpasswords.com/range/${sha1Prefix}`;
    const response = await fetch(url, {
      method: 'GET',
      headers: { 'Add-Padding': 'true' }
    });

    if (!response.ok) {
      throw new Error(`API Error Status: ${response.status}`);
    }

    const responseText = await response.text();

    if (!responseText || !responseText.trim()) {
      return 0; // Return 0 breaches immediately on empty API response
    }

    const lines = responseText.split('\n');

    for (let line of lines) {
      const [suffix, count] = line.trim().split(':');
      if (suffix && suffix.toUpperCase() === sha1Suffix) {
        return parseInt(count, 10);
      }
    }
    return 0;
  }

  // --- 4. ZXCVBN ENTROPY EVALUATION (Option C Color Palette) ---
  const SCORE_MAP = {
    0: { label: "Very Weak 🔴", class: "score-0", color: "#f43f5e" }, // Rose
    1: { label: "Weak 🟠", class: "score-1", color: "#fb923c" },      // Orange
    2: { label: "Fair 🟡", class: "score-2", color: "#fbbf24" },      // Amber
    3: { label: "Strong 🟢", class: "score-3", color: "#34d399" },    // Emerald
    4: { label: "Excellent 🔵", class: "score-4", color: "#2dd4bf" }   // Teal
  };

  function evaluateEntropy(password) {
    if (typeof zxcvbn !== 'function') {
      return { score: 0, crackTime: "Library offline", warning: "", suggestions: [] };
    }
    const evalResult = zxcvbn(password);
    const score = evalResult.score;
    const crackTimeDisplay = evalResult.crack_times_display.offline_slow_hashing_1e4_per_second || "Instant";
    const warning = evalResult.feedback.warning || "";
    const suggestions = evalResult.feedback.suggestions || [];

    return {
      score,
      crackTime: crackTimeDisplay,
      warning,
      suggestions
    };
  }

  // --- 5. MAIN AUDIT EXECUTION ---
  async function runAudit() {
    let password = passwordInput.value;
    password = password.trim();

    if (!password) {
      resultBox.style.display = 'none';
      return;
    }

    // Loading State
    checkBtn.disabled = true;
    checkBtn.textContent = '⏳ Checking...';
    if (strengthContainer) strengthContainer.classList.add('loading-pulse');

    resultBox.style.display = 'block';
    breachStatus.innerHTML = `<strong>Breach Status:</strong> <span style="color: var(--accent-teal);">Checking HIBP database...</span>`;
    strengthLabel.textContent = "Calculating...";
    meterFill.className = "meter-fill";
    meterFill.style.width = "0%";
    crackTime.textContent = "";
    warningBanner.style.display = 'none';
    recommendation.style.display = 'none';

    try {
      // A. Entropy Evaluation
      const entropy = evaluateEntropy(password);
      const scoreInfo = SCORE_MAP[entropy.score] || SCORE_MAP[0];

      strengthLabel.textContent = scoreInfo.label;
      strengthLabel.style.color = scoreInfo.color;
      meterFill.className = `meter-fill ${scoreInfo.class}`;

      crackTime.innerHTML = `<strong>Est. Crack Time:</strong> <span style="color: ${scoreInfo.color}; font-weight: bold;">${entropy.crackTime}</span>`;

      if (entropy.warning || entropy.suggestions.length > 0) {
        let warnText = entropy.warning ? `<strong>⚠️ Warning:</strong> ${entropy.warning}<br>` : '';
        if (entropy.suggestions.length > 0) {
          warnText += `💡 <em>${entropy.suggestions.join(' ')}</em>`;
        }
        warningBanner.innerHTML = warnText;
        warningBanner.style.display = 'block';
      }

      // B. Zero-Knowledge HIBP Breach Check
      const fullHash = await computeSHA1Hex(password);
      const sha1Prefix = fullHash.substring(0, 5);
      const sha1Suffix = fullHash.substring(5);

      const breachCount = await checkBreachStatus(sha1Prefix, sha1Suffix);

      if (breachCount > 0) {
        breachStatus.innerHTML = `<strong>Breach Status:</strong> <span class="vulnerable">🔴 PWNED (${breachCount.toLocaleString()} breaches)</span>`;
        
        const recommendedPw = generateSecurePassword(16);
        recommendation.innerHTML = `<strong>Recommendation:</strong> Switch to a secure alternative: <br><code>${recommendedPw}</code>`;
        recommendation.style.display = 'block';
      } else {
        breachStatus.innerHTML = `<strong>Breach Status:</strong> <span class="secure">🟢 SAFE (No breaches found)</span>`;
      }

    } catch (err) {
      console.error("HIBP Check Error:", err);
      breachStatus.innerHTML = `<strong>Breach Status:</strong> <span style="color: #fbbf24;">⚠️ Network error contacting database.</span>`;
    } finally {
      checkBtn.disabled = false;
      checkBtn.textContent = 'Check Password';
      if (strengthContainer) strengthContainer.classList.remove('loading-pulse');
    }
  }

  checkBtn.addEventListener('click', runAudit);
  passwordInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') runAudit();
  });

  // --- 6. CONTEXT MENU AUTO-FILL ---
  function handleAutoFill(passwordValue) {
    if (passwordValue) {
      passwordInput.value = passwordValue;
      chrome.storage.local.remove(['autoFillPassword']);
      runAudit();
    }
  }

  if (chrome.storage && chrome.storage.local) {
    chrome.storage.local.get(['autoFillPassword'], (result) => {
      handleAutoFill(result.autoFillPassword);
    });

    if (chrome.storage.onChanged) {
      chrome.storage.onChanged.addListener((changes, namespace) => {
        if (namespace === 'local' && changes.autoFillPassword && changes.autoFillPassword.newValue) {
          handleAutoFill(changes.autoFillPassword.newValue);
        }
      });
    }
  }
});
