/**
 * Test runner to verify PhishGuard detector heuristics against sample corpus
 */

const fs = require('fs');

// Load detector & samples in node environment
const detectorCode = fs.readFileSync('./detector.js', 'utf8');
const samplesCode = fs.readFileSync('./samples.js', 'utf8');

const context = {};
eval(detectorCode);
eval(samplesCode);

const detector = global.PhishGuardDetector;
const samples = global.PhishGuardSamples;

console.log('--- PHISHGUARD AI DETECTOR TEST SUITE ---');

let passed = 0;
let total = 0;

function assert(name, condition, details) {
  total++;
  if (condition) {
    console.log(`[PASS] ${name}`);
    passed++;
  } else {
    console.error(`[FAIL] ${name} - Details: ${details}`);
  }
}

// Test 1: PayPal Phish
const resPaypal = detector.analyze(samples.paypal.raw);
assert('PayPal suspension scored as CRITICAL (>= 80)', resPaypal.score >= 80, `Score: ${resPaypal.score}`);
assert('PayPal detected Brand Spoofing flag', resPaypal.flags.some(f => f.id === 'SPOOF-BRAND-NAME'), 'Missing SPOOF-BRAND-NAME');
assert('PayPal detected Link Anchor Mismatch', resPaypal.flags.some(f => f.id === 'LINK-TEXT-MISMATCH'), 'Missing LINK-TEXT-MISMATCH');
assert('PayPal detected Urgency', resPaypal.flags.some(f => f.id === 'PSYCH-URGENCY'), 'Missing PSYCH-URGENCY');

// Test 2: CEO BEC Wire Fraud
const resCeo = detector.analyze(samples.ceo_bec.raw);
assert('CEO Wire Fraud scored high (>= 70)', resCeo.score >= 70, `Score: ${resCeo.score}`);
assert('CEO Wire Fraud detected Reply-To Mismatch', resCeo.flags.some(f => f.id === 'REPLY-TO-MISMATCH'), 'Missing REPLY-TO-MISMATCH');
assert('CEO Wire Fraud detected BEC Wire keywords', resCeo.flags.some(f => f.id === 'BEC-WIRE-FRAUD'), 'Missing BEC-WIRE-FRAUD');

// Test 3: Geek Squad Fake Invoice
const resGeek = detector.analyze(samples.geeksquad.raw);
assert('Geek Squad Invoice scored high (>= 60)', resGeek.score >= 60, `Score: ${resGeek.score}`);
assert('Geek Squad detected Call-Back Invoice Scam', resGeek.flags.some(f => f.id === 'TECH-SUPPORT-INVOICE-SCAM'), 'Missing TECH-SUPPORT-INVOICE-SCAM');

// Test 4: DHL Shipment with Malware Extension
const resDhl = detector.analyze(samples.dhl_malware.raw);
assert('DHL Malware scored high (>= 70)', resDhl.score >= 70, `Score: ${resDhl.score}`);
assert('DHL Malware detected Dangerous Attachment (.pdf.exe)', resDhl.flags.some(f => f.id === 'DANGEROUS-ATTACHMENT'), 'Missing DANGEROUS-ATTACHMENT');
assert('DHL Malware detected Raw IP URL', resDhl.flags.some(f => f.id === 'RAW-IP-URL'), 'Missing RAW-IP-URL');

// Test 5: M365 Password Expiration
const resM365 = detector.analyze(samples.m365_phish.raw);
assert('M365 Phish scored high (>= 70)', resM365.score >= 70, `Score: ${resM365.score}`);
assert('M365 Phish detected Typo-squatting or brand impersonation', resM365.flags.some(f => f.id === 'TYPOSQUAT-DOMAIN' || f.id === 'SPOOF-BRAND-NAME'), 'Missing brand/typosquat detection');

// Test 6: Safe GitHub Security Alert
const resGithub = detector.analyze(samples.github_safe.raw);
assert('Safe GitHub email scored LOW/SAFE (<= 25)', resGithub.score <= 25, `Score: ${resGithub.score}`);
assert('Safe GitHub email verdict is SAFE', resGithub.verdict === 'SAFE', `Verdict: ${resGithub.verdict}`);

console.log(`\nResults: ${passed} / ${total} tests passed.`);
if (passed === total) {
  console.log('ALL DETECTOR HEURISTICS VALIDATED SUCCESSFULLY!');
} else {
  process.exit(1);
}
