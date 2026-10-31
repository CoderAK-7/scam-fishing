/**
 * PhishGuard AI — Core Email Scam & Phishing Detection Engine
 * 100% Client-Side Pure JavaScript Execution
 */

(function (global) {
  'use strict';

  // High-value brand domains targeted by phishers
  const BRAND_DICTIONARY = [
    { name: 'PayPal', domain: 'paypal.com', aliases: ['paypal', 'paypa1', 'pay-pal'] },
    { name: 'Microsoft', domain: 'microsoft.com', aliases: ['microsoft', 'micros0ft', 'office365', 'outlook', 'live', 'msn', 'm365'] },
    { name: 'Google', domain: 'google.com', aliases: ['google', 'g00gle', 'gmail', 'googlemail'] },
    { name: 'Apple', domain: 'apple.com', aliases: ['apple', 'icloud', 'applestore', 'itunes'] },
    { name: 'Amazon', domain: 'amazon.com', aliases: ['amazon', 'amaz0n', 'primevideo'] },
    { name: 'Netflix', domain: 'netflix.com', aliases: ['netflix', 'netf1ix'] },
    { name: 'Bank of America', domain: 'bankofamerica.com', aliases: ['bankofamerica', 'bofa'] },
    { name: 'Chase Bank', domain: 'chase.com', aliases: ['chase', 'jpmorganchase'] },
    { name: 'Wells Fargo', domain: 'wellsfargo.com', aliases: ['wellsfargo'] },
    { name: 'Citibank', domain: 'citi.com', aliases: ['citi', 'citibank'] },
    { name: 'DHL Express', domain: 'dhl.com', aliases: ['dhl', 'dhlexpress'] },
    { name: 'FedEx', domain: 'fedex.com', aliases: ['fedex'] },
    { name: 'UPS', domain: 'ups.com', aliases: ['ups', 'upsparcel'] },
    { name: 'USPS', domain: 'usps.com', aliases: ['usps', 'uspostal'] },
    { name: 'Geek Squad', domain: 'bestbuy.com', aliases: ['geeksquad', 'bestbuy'] },
    { name: 'Norton Antivirus', domain: 'norton.com', aliases: ['norton', 'nortonlifelock', 'gen'] },
    { name: 'McAfee', domain: 'mcafee.com', aliases: ['mcafee'] },
    { name: 'Internal Revenue Service (IRS)', domain: 'irs.gov', aliases: ['irs', 'internalrevenue'] },
    { name: 'Meta / Facebook', domain: 'meta.com', aliases: ['meta', 'facebook', 'instagram', 'whatsapp'] },
    { name: 'Dropbox', domain: 'dropbox.com', aliases: ['dropbox'] },
    { name: 'DocuSign', domain: 'docusign.com', aliases: ['docusign'] },
    { name: 'Coinbase', domain: 'coinbase.com', aliases: ['coinbase'] },
    { name: 'Binance', domain: 'binance.com', aliases: ['binance'] },
    { name: 'Steam / Valve', domain: 'steampowered.com', aliases: ['steam', 'valvesoftware'] }
  ];

  // Common free webmail providers (fraudsters use these to masquerade as enterprise support)
  const FREE_MAIL_PROVIDERS = [
    'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.uk', 'hotmail.com',
    'outlook.com', 'live.com', 'aol.com', 'mail.ru', 'yandex.ru', 'yandex.com',
    'proton.me', 'protonmail.com', 'zoho.com', 'gmx.com', 'gmx.net', 'inbox.com',
    'tutanota.com', 'tutamail.com', 'fastmail.com'
  ];

  // Suspicious Top Level Domains frequently abused in malicious campaigns
  const SUSPICIOUS_TLDS = new Set([
    'xyz', 'top', 'click', 'buzz', 'club', 'tk', 'ml', 'ga', 'cf', 'gq', 'work',
    'link', 'zip', 'mov', 'rest', 'icu', 'cam', 'sbs', 'quest', 'cfd', 'monster',
    'surf', 'live', 'stream', 'bid', 'racing', 'download', 'win', 'space', 'kim'
  ]);

  // URL Shorteners that conceal destination domains
  const SHORTENERS = new Set([
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
    'cutt.ly', 'rebrand.ly', 'bl.ink', 'shorturl.at', 'rb.gy'
  ]);

  // Cyrillic & Greek homoglyphs commonly substituted for Latin ASCII
  const HOMOGLYPH_MAP = {
    '\u0430': 'a', '\u0435': 'e', '\u043E': 'o', '\u0440': 'p', '\u0441': 'c',
    '\u0443': 'y', '\u0445': 'x', '\u0456': 'i', '\u0458': 'j', '\u0406': 'I',
    '\u0410': 'A', '\u0412': 'B', '\u0415': 'E', '\u041A': 'K', '\u041C': 'M',
    '\u041D': 'H', '\u041E': 'O', '\u0420': 'P', '\u0421': 'C', '\u0422': 'T',
    '\u0425': 'X', '\u03BF': 'o', '\u03BD': 'v', '\u03C1': 'p'
  };

  /**
   * Calculates Levenshtein Distance between two strings.
   */
  function levenshteinDistance(a, b) {
    if (a.length === 0) return b.length;
    if (b.length === 0) return a.length;
    const matrix = [];
    for (let i = 0; i <= b.length; i++) {
      matrix[i] = [i];
    }
    for (let j = 0; j <= a.length; j++) {
      matrix[0][j] = j;
    }
    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        if (b.charAt(i - 1) === a.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1, // substitution
            matrix[i][j - 1] + 1,     // insertion
            matrix[i - 1][j] + 1      // deletion
          );
        }
      }
    }
    return matrix[b.length][a.length];
  }

  /**
   * RFC 822 / 5322 MIME & Header Parser
   */
  function parseEmail(rawContent) {
    const raw = String(rawContent || '').trim();
    if (!raw) {
      return { headers: {}, body: '', isRawEmail: false };
    }

    // Look for double newline separating header block and body
    const splitIndex = raw.search(/\r?\n\r?\n/);
    let headerBlock = '';
    let bodyBlock = '';

    // Check if the input looks like raw RFC headers (starts with From:, Received:, Subject:, etc.)
    const startsWithHeader = /^(From|Received|Return-Path|Subject|Date|To|Message-ID|MIME-Version):/i.test(raw);

    if (splitIndex !== -1 && startsWithHeader) {
      headerBlock = raw.slice(0, splitIndex);
      bodyBlock = raw.slice(splitIndex).trim();
    } else if (startsWithHeader && !raw.includes('\n\n')) {
      headerBlock = raw;
      bodyBlock = '';
    } else {
      // Treat the entire input as email body
      bodyBlock = raw;
    }

    const headers = {};
    if (headerBlock) {
      // Unfold multi-line headers (RFC 5322 folding)
      const unfolded = headerBlock.replace(/\r?\n[ \t]+/g, ' ');
      const lines = unfolded.split(/\r?\n/);

      for (const line of lines) {
        const colonPos = line.indexOf(':');
        if (colonPos > 0) {
          const key = line.slice(0, colonPos).trim();
          const value = line.slice(colonPos + 1).trim();
          const lowerKey = key.toLowerCase();
          headers[lowerKey] = value;
          // preserve capitalized display
          if (!headers['_display']) headers['_display'] = {};
          headers['_display'][key] = value;
        }
      }
    }

    return {
      headers,
      body: bodyBlock,
      isRawEmail: startsWithHeader && Object.keys(headers).length > 0
    };
  }

  /**
   * Extracts display name and clean email address from string:
   * e.g. "PayPal Support" <support@fake-paypa1.com>
   */
  function extractAddressInfo(addrStr) {
    if (!addrStr) return { name: '', email: '', domain: '' };
    const str = addrStr.trim();
    const match = str.match(/^(?:["']?([^"<>]*)["']?\s*)?<?([a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}))>?$/);
    if (match) {
      const name = (match[1] || '').trim();
      const email = match[2].toLowerCase().trim();
      const domain = match[3].toLowerCase().trim();
      return { name, email, domain };
    }
    // Fallback: look for any email
    const emailMatch = str.match(/([a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}))/);
    if (emailMatch) {
      const email = emailMatch[1].toLowerCase().trim();
      const domain = emailMatch[2].toLowerCase().trim();
      const name = str.replace(emailMatch[0], '').replace(/[<>"']/g, '').trim();
      return { name, email, domain };
    }
    return { name: str, email: '', domain: '' };
  }

  /**
   * Extracts domain from URL string
   */
  function extractDomainFromUrl(urlStr) {
    try {
      let normalized = urlStr.trim();
      if (!/^https?:\/\//i.test(normalized)) {
        normalized = 'http://' + normalized;
      }
      const parsed = new URL(normalized);
      return parsed.hostname.toLowerCase();
    } catch (e) {
      return '';
    }
  }

  /**
   * Checks string for homoglyphs or Punycode
   */
  function detectHomoglyphs(str) {
    const findings = [];
    if (!str) return findings;

    if (str.toLowerCase().includes('xn--')) {
      findings.push({
        type: 'punycode',
        description: 'Internationalized Punycode domain detected (commonly used to hide lookalike characters).'
      });
    }

    let detectedChars = [];
    for (let i = 0; i < str.length; i++) {
      const char = str[i];
      if (HOMOGLYPH_MAP[char]) {
        detectedChars.push(`'${char}' (mimics '${HOMOGLYPH_MAP[char]}')`);
      }
    }

    if (detectedChars.length > 0) {
      findings.push({
        type: 'homoglyph',
        description: `Cyrillic/Greek homoglyph character spoofing found: ${detectedChars.join(', ')}`
      });
    }

    return findings;
  }

  /**
   * Extracts all hyperlinks from text and HTML
   */
  function extractLinks(content) {
    const links = [];
    const seen = new Set();

    // 1. HTML <a> tag regex
    const htmlAnchorRegex = /<a\s+(?:[^>]*?\s+)?href=["']([^"']+)["'][^>]*>(.*?)<\/a>/gi;
    let match;

    while ((match = htmlAnchorRegex.exec(content)) !== null) {
      const href = match[1].trim();
      const anchorText = match[2].replace(/<[^>]+>/g, '').trim();
      const key = `${href}|${anchorText}`;
      if (!seen.has(key)) {
        seen.add(key);
        links.push({
          source: 'html',
          href,
          text: anchorText || href,
          domain: extractDomainFromUrl(href)
        });
      }
    }

    // 2. Plain text URLs
    const urlRegex = /(https?:\/\/[^\s<>"'{}|\\^`]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\/[^\s<>"'{}|\\^`]*)/gi;
    while ((match = urlRegex.exec(content)) !== null) {
      let url = match[1].replace(/[.,;:!?)]+$/, ''); // clean trailing punctuation
      if (!url.startsWith('http')) {
        url = 'https://' + url;
      }
      const key = `${url}|${url}`;
      if (!seen.has(key)) {
        seen.add(key);
        links.push({
          source: 'plaintext',
          href: url,
          text: url,
          domain: extractDomainFromUrl(url)
        });
      }
    }

    return links;
  }

  /**
   * Main PhishGuard Detection Algorithm
   */
  function analyze(input, options = {}) {
    const parsed = parseEmail(input);
    const headers = parsed.headers;
    const body = parsed.body || input;

    const flags = [];
    let senderVectorScore = 0;
    let linksVectorScore = 0;
    let urgencyVectorScore = 0;
    let credsVectorScore = 0;

    // Header extraction
    const fromRaw = options.from || headers['from'] || '';
    const replyToRaw = options.replyTo || headers['reply-to'] || '';
    const returnPathRaw = headers['return-path'] || '';
    const subject = options.subject || headers['subject'] || '';
    const authResults = options.auth || headers['authentication-results'] || headers['received-spf'] || '';

    const fromInfo = extractAddressInfo(fromRaw);
    const replyToInfo = extractAddressInfo(replyToRaw);
    const returnPathInfo = extractAddressInfo(returnPathRaw);

    // -------------------------------------------------------------------------
    // 1. SENDER & DOMAIN ANALYSIS
    // -------------------------------------------------------------------------
    if (fromInfo.name || fromInfo.email) {
      // Check Brand Impersonation in Display Name vs Actual Domain
      for (const brand of BRAND_DICTIONARY) {
        const brandRegex = new RegExp(`\\b${brand.name.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&')}\\b`, 'i');
        const aliasRegex = new RegExp(brand.aliases.join('|'), 'i');

        const nameMentionsBrand = brandRegex.test(fromInfo.name) || aliasRegex.test(fromInfo.name);
        const domainIsBrand = fromInfo.domain.endsWith(brand.domain);

        if (nameMentionsBrand && !domainIsBrand && fromInfo.domain) {
          senderVectorScore += 35;
          flags.push({
            id: 'SPOOF-BRAND-NAME',
            severity: 'high',
            category: 'sender',
            title: `Severe Sender Spoofing: Impersonating ${brand.name}`,
            description: `The display name claims to be from "${fromInfo.name}" (${brand.name}), but the sender domain is actually "${fromInfo.domain}" instead of official "${brand.domain}".`,
            snippet: `From: "${fromInfo.name}" <${fromInfo.email}>`
          });
        }
      }

      // Check Free Webmail used as Corporate Support
      if (fromInfo.domain && FREE_MAIL_PROVIDERS.includes(fromInfo.domain)) {
        const hasSupportTitle = /(support|security|billing|verification|service|official|admin|executive|helpdesk|payroll)/i.test(fromInfo.name);
        if (hasSupportTitle) {
          senderVectorScore += 30;
          flags.push({
            id: 'FREE-WEBMAIL-IMPERSONATION',
            severity: 'high',
            category: 'sender',
            title: 'Free Webmail Account Posing as Corporate Support',
            description: `The sender uses an official-sounding name ("${fromInfo.name}") but sends from a free public webmail service (@${fromInfo.domain}). Legitimate enterprises do not send official security notices from free accounts.`,
            snippet: `From: ${fromInfo.name} <${fromInfo.email}>`
          });
        }
      }

      // Check Homoglyphs / Punycode in Sender Domain
      if (fromInfo.domain) {
        const homoglyphs = detectHomoglyphs(fromInfo.domain);
        if (homoglyphs.length > 0) {
          senderVectorScore += 35;
          homoglyphs.forEach(h => {
            flags.push({
              id: 'HOMOGLYPH-SENDER-DOMAIN',
              severity: 'high',
              category: 'sender',
              title: 'Homoglyph / Lookalike Character Attack Detected',
              description: `Sender domain "${fromInfo.domain}" contains unicode deceptive characters: ${h.description}`,
              snippet: fromInfo.domain
            });
          });
        }

        // Typo-Squatting / Levenshtein Distance Check against top brands
        for (const brand of BRAND_DICTIONARY) {
          const brandStem = brand.domain.split('.')[0];
          const senderStem = fromInfo.domain.split('.')[0];

          if (senderStem !== brandStem && senderStem.length >= 4) {
            const dist = levenshteinDistance(senderStem, brandStem);
            if (dist === 1 || (dist === 2 && senderStem.length > 6)) {
              senderVectorScore += 30;
              flags.push({
                id: 'TYPOSQUAT-DOMAIN',
                severity: 'high',
                category: 'sender',
                title: `Typo-Squatted Lookalike Domain (${brand.name})`,
                description: `Domain "${fromInfo.domain}" is only ${dist} character away from legitimate brand "${brand.domain}". Fraudsters intentionally register typos to trick users.`,
                snippet: fromInfo.domain
              });
            }
          }
        }
      }

      // Check Reply-To Mismatch
      if (replyToInfo.email && fromInfo.email && replyToInfo.domain !== fromInfo.domain) {
        senderVectorScore += 25;
        flags.push({
          id: 'REPLY-TO-MISMATCH',
          severity: 'high',
          category: 'sender',
          title: 'Reply-To Routing Discrepancy',
          description: `Replies will be secretly routed to "${replyToInfo.email}" (@${replyToInfo.domain}) instead of the sender address "${fromInfo.email}". This is classic BEC (Business Email Compromise) behavior.`,
          snippet: `From: ${fromInfo.email} -> Reply-To: ${replyToInfo.email}`
        });
      }

      // Check Return-Path Mismatch
      if (returnPathInfo.domain && fromInfo.domain && returnPathInfo.domain !== fromInfo.domain) {
        senderVectorScore += 10;
        flags.push({
          id: 'RETURN-PATH-MISMATCH',
          severity: 'medium',
          category: 'sender',
          title: 'Return-Path Envelope Mismatch',
          description: `Envelope Return-Path (@${returnPathInfo.domain}) does not match sender domain (@${fromInfo.domain}).`,
          snippet: `Return-Path: <${returnPathInfo.email}>`
        });
      }
    }

    // Check Authentication Headers (SPF/DKIM/DMARC)
    if (authResults) {
      if (/spf=(fail|softfail)/i.test(authResults)) {
        senderVectorScore += 20;
        flags.push({
          id: 'AUTH-SPF-FAIL',
          severity: 'high',
          category: 'headers',
          title: 'SPF Authentication Failed',
          description: 'The sending server is not authorized by the domain owner to send mail on their behalf.',
          snippet: authResults.match(/spf=[a-zA-Z]+/i)?.[0] || 'spf=fail'
        });
      }
      if (/dkim=(fail|neutral|permerror)/i.test(authResults)) {
        senderVectorScore += 20;
        flags.push({
          id: 'AUTH-DKIM-FAIL',
          severity: 'high',
          category: 'headers',
          title: 'DKIM Cryptographic Signature Invalid',
          description: 'The email signature failed verification; the email body or headers may have been forged or tampered with in transit.',
          snippet: authResults.match(/dkim=[a-zA-Z]+/i)?.[0] || 'dkim=fail'
        });
      }
      if (/dmarc=fail/i.test(authResults)) {
        senderVectorScore += 25;
        flags.push({
          id: 'AUTH-DMARC-FAIL',
          severity: 'high',
          category: 'headers',
          title: 'DMARC Policy Violation',
          description: 'The sender failed both SPF and DKIM alignment according to the sending domain DMARC policy.',
          snippet: 'dmarc=fail'
        });
      }
    }

    // -------------------------------------------------------------------------
    // 2. HYPERLINK & REDIRECTION INSPECTOR
    // -------------------------------------------------------------------------
    const extractedLinks = extractLinks(body);
    const linkFindings = [];

    for (const link of extractedLinks) {
      const href = link.href;
      const text = link.text;
      const domain = link.domain;
      let linkRisk = 'safe';
      const reasons = [];

      // A. Text vs Destination Mismatch
      const textDomainMatch = text.match(/https?:\/\/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i) || text.match(/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i);
      if (textDomainMatch) {
        const visibleDomain = textDomainMatch[1].toLowerCase().replace(/^www\./, '');
        const actualDomain = domain.replace(/^www\./, '');
        if (visibleDomain && actualDomain && visibleDomain !== actualDomain) {
          linksVectorScore += 35;
          linkRisk = 'danger';
          reasons.push(`DECEPTIVE TARGET: Text shows '${visibleDomain}' but goes to '${actualDomain}'`);
          flags.push({
            id: 'LINK-TEXT-MISMATCH',
            severity: 'high',
            category: 'links',
            title: 'Deceptive Hyperlink Anchor Mismatch',
            description: `The visible link text pretends to be "${text}" (${visibleDomain}), but the actual destination silently redirects to "${href}" (${actualDomain}). This is a definitive sign of phishing.`,
            snippet: `Visible: "${text}" -> Actual: "${href}"`
          });
        }
      }

      // B. Raw IP Address in URL
      if (/^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i.test(href)) {
        linksVectorScore += 30;
        linkRisk = 'danger';
        reasons.push('Raw numerical IP address instead of domain');
        flags.push({
          id: 'RAW-IP-URL',
          severity: 'high',
          category: 'links',
          title: 'Direct IP Address Hyperlink',
          description: `The link points to a raw numerical IP address (${domain}). Legitimate organizations use registered brand domains.`,
          snippet: href
        });
      }

      // C. Suspicious TLD
      const tld = domain.split('.').pop();
      if (SUSPICIOUS_TLDS.has(tld)) {
        linksVectorScore += 18;
        if (linkRisk !== 'danger') linkRisk = 'warning';
        reasons.push(`Suspicious high-risk TLD (.${tld})`);
        flags.push({
          id: 'SUSPICIOUS-TLD',
          severity: 'medium',
          category: 'links',
          title: `Suspicious Top-Level Domain (.${tld})`,
          description: `Destination domain uses the .${tld} TLD, which has a very high correlation with automated phishing and malware spam.`,
          snippet: href
        });
      }

      // D. URL Shortener Masking Destination
      if (SHORTENERS.has(domain)) {
        linksVectorScore += 12;
        if (linkRisk !== 'danger') linkRisk = 'warning';
        reasons.push(`URL shortener (${domain})`);
        flags.push({
          id: 'URL-SHORTENER',
          severity: 'medium',
          category: 'links',
          title: 'Obfuscated Destination via URL Shortener',
          description: `The link uses "${domain}" to obscure the final landing page. Attackers use this to evade automated scanners.`,
          snippet: href
        });
      }

      // E. Homoglyph in link destination
      const linkHomoglyphs = detectHomoglyphs(domain);
      if (linkHomoglyphs.length > 0) {
        linksVectorScore += 35;
        linkRisk = 'danger';
        reasons.push('Homoglyph lookalike characters in link domain');
      }

      // F. Insecure HTTP link with login or verify keywords
      if (href.startsWith('http://') && /(login|signin|verify|secure|account|update)/i.test(href)) {
        linksVectorScore += 20;
        linkRisk = 'danger';
        reasons.push('Insecure unencrypted HTTP protocol for sensitive action');
      }

      linkFindings.push({
        href,
        text,
        domain,
        risk: linkRisk,
        reasons: reasons.length > 0 ? reasons.join('; ') : 'No obvious abnormalities'
      });
    }

    // -------------------------------------------------------------------------
    // 3. PSYCHOLOGICAL & CONTENT THREAT VECTORS (NLP & PATTERNS)
    // -------------------------------------------------------------------------
    const fullText = `${subject} \n ${body}`;

    // A. Extreme Urgency & Artificial Time Pressure
    const urgencyPatterns = [
      /\b(within|in)\s*(24|48|12|2|1)\s*(hours|hrs|days)\b/i,
      /\b(immediate|immediately|urgent|urgently|promptly|without delay)\b/i,
      /\b(account\s+(will be|has been)\s+(suspended|terminated|disabled|restricted|locked|frozen))\b/i,
      /\b(action\s+required|failure\s+to\s+(respond|verify|comply))\b/i,
      /\b(final\s+notice|last\s+chance|last\s+warning)\b/i,
      /\b(unauthorized\s+(access|sign-in|login|activity|transaction))\b/i
    ];

    let urgencyMatches = [];
    urgencyPatterns.forEach(pattern => {
      const m = fullText.match(pattern);
      if (m) urgencyMatches.push(m[0]);
    });

    if (urgencyMatches.length > 0) {
      const severity = urgencyMatches.length >= 2 ? 'high' : 'medium';
      urgencyVectorScore += Math.min(30, urgencyMatches.length * 15);
      flags.push({
        id: 'PSYCH-URGENCY',
        severity,
        category: 'psychology',
        title: 'Artificial Panic & Threat of Account Suspension',
        description: 'Scammers create synthetic deadlines (e.g. "within 24 hours", "account locked") to rush victims into acting before checking the validity.',
        snippet: urgencyMatches.slice(0, 3).join(', ')
      });
    }

    // B. Credential Harvesting & Sensitive Information Solicitations
    const credPatterns = [
      /\b(verify|confirm|validate|update)\s+your\s+(password|passcode|credentials|pin|identity|ssn|social security)\b/i,
      /\b(click\s+(here|below)\s+to\s+(log\s*in|sign\s*in|verify|unlock|activate))\b/i,
      /\b(confirm\s+billing\s+details|update\s+payment\s+method|credit\s+card\s+number)\b/i,
      /\b(mailbox\s+(full|quota\s+exceeded|storage\s+limit))\b/i
    ];

    let credMatches = [];
    credPatterns.forEach(pattern => {
      const m = fullText.match(pattern);
      if (m) credMatches.push(m[0]);
    });

    if (credMatches.length > 0) {
      credsVectorScore += Math.min(35, credMatches.length * 18);
      flags.push({
        id: 'CREDENTIAL-HARVESTING',
        severity: 'high',
        category: 'credentials',
        title: 'Credential / Password Harvesting Lure',
        description: 'Direct requests prompting you to click a link to input passwords, account credentials, or credit card information.',
        snippet: credMatches.slice(0, 3).join(', ')
      });
    }

    // C. BEC / Executive Impersonation & Wire Fraud
    const becPatterns = [
      /\b(are\s+you\s+(at\s+your\s+desk|available|in\s+the\s+office))\b/i,
      /\b(wire\s+transfer|ach\s+transfer|send\s+payment|urgent\s+wire|vendor\s+payment)\b/i,
      /\b(gift\s+cards?|apple\s+gift|google\s+play\s+card|steam\s+card|itunes\s+card)\b/i,
      /\b(strictly\s+confidential|keep\s+this\s+private|do\s+not\s+call\s+me)\b/i
    ];

    let becMatches = [];
    becPatterns.forEach(pattern => {
      const m = fullText.match(pattern);
      if (m) becMatches.push(m[0]);
    });

    if (becMatches.length > 0) {
      credsVectorScore += 30;
      flags.push({
        id: 'BEC-WIRE-FRAUD',
        severity: 'high',
        category: 'bec',
        title: 'Business Email Compromise (BEC) / Gift Card Lure',
        description: 'Pattern matching CEO/Executive impersonation soliciting secret wire transfers, gift cards, or confidential requests.',
        snippet: becMatches.join('; ')
      });
    }

    // D. Fake Invoices / Renewal Scams (Geek Squad, Norton, McAfee, BestBuy)
    const invoicePatterns = [
      /\b(auto[- ]?renew(al|ed)?|\$?\d{2,4}(?:\.\d{2})?\s*(has been charged|deducted|debited|billed|charged to your account))\b/i,
      /\b(toll[- ]free|help\s*desk|billing\s+technician|call\s+(us|our|toll[- ]free|support)|phone\s+support)\b/i,
      /\b(\+?1[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b/,
      /\b(refund|cancel\s+subscription|claim\s+a?\s*refund|cancellation)\b/i
    ];

    let invoiceMatches = [];
    invoicePatterns.forEach(pattern => {
      const m = fullText.match(pattern);
      if (m) invoiceMatches.push(m[0]);
    });

    if (invoiceMatches.length >= 2) {
      credsVectorScore += 28;
      flags.push({
        id: 'TECH-SUPPORT-INVOICE-SCAM',
        severity: 'high',
        category: 'invoice',
        title: 'Fake Invoicing / Refund Call-Back Scam',
        description: 'Attackers pretend you were billed hundreds of dollars for antivirus/tech services and urge you to call a fraudulent phone number to "cancel".',
        snippet: invoiceMatches.join('; ')
      });
    }

    // E. Extortion & Blackmail (Sextortion / Bitcoin)
    const extortionPatterns = [
      /\b(recorded\s+you|webcam|dirty\s+secrets|compromised\s+your\s+device|pegasus\s+spyware)\b/i,
      /\b(bitcoin\s+(address|wallet)|btc|send\s*\$?\d{3,4}\s*(in\s+bitcoin|btc))\b/i
    ];
    let extortionMatches = [];
    extortionPatterns.forEach(p => {
      const m = fullText.match(p);
      if (m) extortionMatches.push(m[0]);
    });

    if (extortionMatches.length > 0) {
      credsVectorScore += 35;
      flags.push({
        id: 'EXTORTION-BLACKMAIL',
        severity: 'high',
        category: 'extortion',
        title: 'Extortion / Blackmail Threat Vector',
        description: 'The email attempts psychological extortion claiming possession of webcam footage or sensitive data and demands cryptocurrency.',
        snippet: extortionMatches.join('; ')
      });
    }

    // F. Impersonal / Generic Salutation
    const genericSalutation = /^(dear\s+(customer|user|valued\s+member|account\s+holder|client|sir\/madam)|undisclosed-recipients)/im.test(body);
    if (genericSalutation) {
      urgencyVectorScore += 8;
      flags.push({
        id: 'GENERIC-SALUTATION',
        severity: 'low',
        category: 'content',
        title: 'Impersonal Generic Greeting',
        description: 'Legitimate institutions you do business with address you by your actual first or last name, not "Dear Customer" or "Dear User".',
        snippet: body.slice(0, 100).match(/dear\s+[a-z\s/]+/i)?.[0] || 'Dear Customer'
      });
    }

    // G. Dangerous Attachment References
    const dangerousAttachments = /\b[\w-]+\.(exe|scr|vbs|hta|iso|img|bat|cmd|ps1|docm|xlsm|zip\.exe|pdf\.exe)\b/i;
    const attachMatch = fullText.match(dangerousAttachments);
    if (attachMatch) {
      credsVectorScore += 35;
      flags.push({
        id: 'DANGEROUS-ATTACHMENT',
        severity: 'high',
        category: 'attachment',
        title: 'High-Risk Executable Attachment Reference',
        description: `Dangerous file extension detected (${attachMatch[0]}). Executables, scripts, and disk image files are the primary vectors for trojans and ransomware.`,
        snippet: attachMatch[0]
      });
    }

    // -------------------------------------------------------------------------
    // 4. TOTAL SCORE CALCULATION & VERDICT
    // -------------------------------------------------------------------------
    // Cap vector scores
    const capSender = Math.min(100, Math.round(senderVectorScore * 1.5));
    const capLinks = Math.min(100, Math.round(linksVectorScore * 1.6));
    const capUrgency = Math.min(100, Math.round(urgencyVectorScore * 1.8));
    const capCreds = Math.min(100, Math.round(credsVectorScore * 1.5));

    // Weighted composite
    const rawTotal = (senderVectorScore * 1.2) + (linksVectorScore * 1.1) + (urgencyVectorScore * 0.7) + (credsVectorScore * 1.0);
    let finalScore = Math.min(100, Math.round(rawTotal));

    // If there is an explicit High-severity flag, floor the score appropriately
    const highSeverityCount = flags.filter(f => f.severity === 'high').length;
    if (highSeverityCount >= 2 && finalScore < 75) {
      finalScore = Math.max(finalScore, 85);
    } else if (highSeverityCount === 1 && finalScore < 50) {
      finalScore = Math.max(finalScore, 65);
    }

    // If completely clean
    if (flags.length === 0) {
      finalScore = Math.min(finalScore, 5);
      flags.push({
        id: 'CLEAN-SCAN',
        severity: 'safe',
        category: 'clean',
        title: 'No Malicious Indicators Detected',
        description: 'No known spoofing patterns, deceptive link redirects, or psychological pressure lures were identified in this sample.',
        snippet: 'Status: Clean'
      });
    }

    // Verdict determination
    let verdict = 'SAFE';
    let badgeClass = 'safe';
    let verdictTitle = 'Minimal or No Threat Indicators';
    let summaryDesc = 'This email appears consistent with typical correspondence. No known spoofing vectors or malicious anchors detected.';

    if (finalScore >= 70) {
      verdict = 'CRITICAL THREAT';
      badgeClass = 'danger';
      verdictTitle = 'High-Confidence Scam / Phishing Attack';
      summaryDesc = 'DANGER: Multiple severe indicators detected. Highly likely to be a credential theft attempt, BEC fraud, or malware distribution.';
    } else if (finalScore >= 40) {
      verdict = 'SUSPICIOUS';
      badgeClass = 'warning';
      verdictTitle = 'Suspicious Elements Detected';
      summaryDesc = 'Exercise extreme caution: This message contains deceptive characteristics such as artificial urgency or anomalous sender details.';
    } else if (finalScore > 15) {
      verdict = 'LOW RISK';
      badgeClass = 'warning';
      verdictTitle = 'Minor Anomalies Present';
      summaryDesc = 'A few minor flags were identified (e.g., generic salutation or URL shortener). Verify sender before clicking links.';
    }

    // Defensive recommendations
    const recommendations = [];
    if (finalScore >= 40) {
      recommendations.push({
        title: 'Do NOT Click Any Links or Open Attachments',
        desc: 'Navigating to the links in this email may lead to credential harvesting portals or trigger malware downloads.'
      });
      recommendations.push({
        title: 'Verify Out-of-Band Directly with the Organization',
        desc: 'If this email claims to be your bank, employer, or a service like PayPal/Netflix, navigate manually to their official website in a separate browser tab or mobile app.'
      });
      recommendations.push({
        title: 'Do Not Call Phone Numbers Listed in the Email',
        desc: 'Call-back numbers in unverified invoice or renewal emails connect directly to fraud call centers.'
      });
    } else {
      recommendations.push({
        title: 'Standard Precaution',
        desc: 'Ensure URLs in the link inspector correspond to official domains you recognize.'
      });
      recommendations.push({
        title: 'Sender Verification',
        desc: 'Confirm the sender address matches previous correspondence from this contact.'
      });
    }

    return {
      score: finalScore,
      verdict,
      badgeClass,
      verdictTitle,
      summary: summaryDesc,
      vectors: {
        sender: capSender,
        links: capLinks,
        urgency: capUrgency,
        credentials: capCreds
      },
      flags,
      links: linkFindings,
      headers: headers['_display'] || headers,
      parsed: {
        from: fromInfo,
        replyTo: replyToInfo,
        subject,
        body
      },
      recommendations
    };
  }

  // Export globally for browser usage
  global.PhishGuardDetector = {
    analyze,
    parseEmail,
    extractAddressInfo,
    extractLinks,
    detectHomoglyphs
  };

})(typeof window !== 'undefined' ? window : globalThis);
