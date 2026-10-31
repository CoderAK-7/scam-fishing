# PhishGuard AI — Client-Side Email Scam & Phishing Detection Suite

[![Browser Only](https://img.shields.io/badge/Architecture-100%25%20Browser%20Only-emerald.svg)](#)
[![Zero Cloud Transmission](https://img.shields.io/badge/Privacy-Zero%20Data%20Transmission-blue.svg)](#)
[![Mobile & Desktop Responsive](https://img.shields.io/badge/Responsive-Desktop%20%26%20Mobile-purple.svg)](#)
[![Status](https://img.shields.io/badge/Tests-16%20Passed-brightgreen.svg)](#)

> **PhishGuard AI** is a state-of-the-art, 100% client-side cyber defense application designed to detect and dissect email scams, phishing attempts, impersonation attacks, and Business Email Compromise (BEC) directly in your browser.

---

## 🛡️ Core Highlights

- **100% Client-Side Sandbox:** Zero email content or metadata leaves your device. No third-party API or cloud server receives sensitive corporate or personal messages.
- **Desktop & Mobile Responsive:** Tailored layout for large SOC/desktop workstations, tablets, and a native-like mobile view with bottom navigation.
- **Deep Multi-Vector Detection:**
  - **MIME & RFC 5322 Parsing:** Inspects `From`, `Reply-To`, `Return-Path`, `Authentication-Results`, `DKIM-Signature`, and `Received-SPF`.
  - **Brand Impersonation & Sender Spoofing:** Identifies display name mismatches against 50+ enterprise brands (PayPal, Microsoft, Google, Apple, Amazon, Chase, Netflix, DHL, etc.).
  - **Homoglyph & Punycode Deception:** Flags Cyrillic/Greek lookalike substitution (e.g., Cyrillic `а` vs Latin `a` in `раураl.com`) and `xn--` Punycode domains.
  - **Typo-Squatting Engine:** Employs Levenshtein distance to detect deceptive domain variations (e.g., `micros0ft.com`, `paypa1.com`).
  - **Deceptive Link Traps:** Inspects HTML anchors for deceptive mismatches where visible link text states a benign domain (e.g. `https://paypal.com`) while the hidden `href` destination redirects to an attacker-controlled host.
  - **Raw IP & Malicious TLD Profiling:** Flags numerical IP hosts (`http://185.220...`) and high-risk top-level domains (`.xyz`, `.top`, `.click`, `.buzz`, `.work`, `.zip`).
  - **Psychological Pressure & Social Engineering (NLP):** Scores urgency, artificial deadlines ("within 24 hours"), fear of suspension, fake tech support / Geek Squad invoices, BEC wire fraud, and extortion.
  - **Dangerous Attachment Analysis:** Spots high-risk executable payloads, scripts, and double extensions (`.pdf.exe`, `.iso`, `.vbs`, `.docm`).
- **Real-Time Interactive Score Gauge:** Dynamic 0–100 risk scoring with clear categorization:
  - `0 - 20`: Safe / Minimal Risk
  - `21 - 39`: Low Risk / Minor Anomalies
  - `40 - 69`: Suspicious / Elevated Risk
  - `70 - 100`: Critical Phishing Threat
- **Exportable Audit Reports:** Generates structured JSON security reports for SecOps / SOC teams or compliance records.
- **Built-in Sample Corpus:** 6 ready-to-test attack scenarios and clean control samples (PayPal suspension, CEO wire fraud, Geek Squad renewal, DHL malware, M365 expiration, and safe GitHub alerts).

---

## 📂 Project Structure

```text
scam fishing/
├── index.html            # Semantic HTML5 responsive application shell
├── styles.css            # Cyber Defense SOC UI stylesheet (Dark & Light themes)
├── detector.js           # Core client-side detection heuristics & scoring algorithm
├── samples.js            # Realistic test corpus of malicious and safe email samples
├── app.js                # UI controller, file dropzone handler, and report generator
├── test-detector.js      # Automated unit test suite verifying all threat heuristics
├── push-to-github.js     # GitHub sync script utilizing token & REST Git Database API
└── README.md             # Project documentation
```

---

## 🚀 How to Run

### Option 1: Direct Browser Launch (No Installation Required)
Simply open `index.html` in any modern desktop or mobile web browser (Google Chrome, Microsoft Edge, Mozilla Firefox, Apple Safari):
- **Windows:** Double-click `index.html` or run in PowerShell:
  ```powershell
  Start-Process index.html
  ```

### Option 2: Local HTTP Server (Optional)
If you prefer running via a local server:
```powershell
npx serve .
# Or via Python:
python -m http.server 8000
```
Open `http://localhost:8000` in your browser.

---

## 🧪 Running the Automated Verification Tests

PhishGuard includes an automated test runner verifying all heuristics:

```powershell
node test-detector.js
```

Sample output:
```text
--- PHISHGUARD AI DETECTOR TEST SUITE ---
[PASS] PayPal suspension scored as CRITICAL (>= 80)
[PASS] PayPal detected Brand Spoofing flag
[PASS] PayPal detected Link Anchor Mismatch
[PASS] PayPal detected Urgency
[PASS] CEO Wire Fraud scored high (>= 70)
[PASS] CEO Wire Fraud detected Reply-To Mismatch
[PASS] CEO Wire Fraud detected BEC Wire keywords
[PASS] Geek Squad Invoice scored high (>= 60)
[PASS] Geek Squad detected Call-Back Invoice Scam
[PASS] DHL Malware scored high (>= 70)
[PASS] DHL Malware detected Dangerous Attachment (.pdf.exe)
[PASS] DHL Malware detected Raw IP URL
[PASS] M365 Phish scored high (>= 70)
[PASS] M365 Phish detected Typo-squatting or brand impersonation
[PASS] Safe GitHub email scored LOW/SAFE (<= 25)
[PASS] Safe GitHub email verdict is SAFE

Results: 16 / 16 tests passed.
ALL DETECTOR HEURISTICS VALIDATED SUCCESSFULLY!
```

---

## 📱 Mobile Responsiveness

The user interface automatically adapts to handheld devices:
- Flexible single-column stacked layout.
- Sticky top header with zero-cloud security status pill.
- Touch-friendly presets carousel.
- Fixed mobile bottom navigation with quick access to **Input**, **Scan**, and **Results**.
- Horizontal scrollbars for wide data tables (Link Inspector) to prevent viewport distortion.

---

## 🔒 Privacy & Security Architecture

1. **Zero Outbound Network Requests for Analysis:** All regex matching, parsing, Levenshtein distance calculations, and scoring run strictly within browser memory on the client machine.
2. **Safe HTML Sandbox Preview:** Email contents rendered in the "Safe Body Preview" tab are strictly HTML-neutralized to prevent XSS execution, tracking beacons, or unintended redirection.

---

## 📄 License
MIT License. Free for personal, organizational, and educational cybersecurity training.
