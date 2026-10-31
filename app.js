/**
 * PhishGuard AI — Application Controller & UI Binder
 * Handles user interactions, file ingestion, theme toggling, and animated visualizations.
 */

(function () {
  'use strict';

  // DOM Elements
  const themeToggleBtn = document.getElementById('themeToggleBtn');
  const themeIcon = document.getElementById('themeIcon');

  const tabFull = document.getElementById('tabFull');
  const tabBody = document.getElementById('tabBody');
  const tabFields = document.getElementById('tabFields');
  const rawInputContainer = document.getElementById('rawInputContainer');
  const structuredInputContainer = document.getElementById('structuredInputContainer');

  const emailRawInput = document.getElementById('emailRawInput');
  const clearBtn = document.getElementById('clearBtn');
  const analyzeBtn = document.getElementById('analyzeBtn');
  const exportReportBtn = document.getElementById('exportReportBtn');

  // Structured fields
  const structSender = document.getElementById('structSender');
  const structReplyTo = document.getElementById('structReplyTo');
  const structSubject = document.getElementById('structSubject');
  const structDate = document.getElementById('structDate');
  const structBody = document.getElementById('structBody');

  // Dropzone
  const dropZone = document.getElementById('dropZone');
  const fileInput = document.getElementById('fileInput');
  const browseFileBtn = document.getElementById('browseFileBtn');

  // Results elements
  const resultsEmptyState = document.getElementById('resultsEmptyState');
  const resultsActiveView = document.getElementById('resultsActiveView');
  const resultsPanel = document.getElementById('resultsPanel');

  const scoreValue = document.getElementById('scoreValue');
  const gaugeProgressCircle = document.getElementById('gaugeProgressCircle');
  const riskVerdictBadge = document.getElementById('riskVerdictBadge');
  const threatLevelSubtext = document.getElementById('threatLevelSubtext');
  const riskSummaryDesc = document.getElementById('riskSummaryDesc');

  const metaSenderAuth = document.getElementById('metaSenderAuth');
  const metaLinksCount = document.getElementById('metaLinksCount');
  const metaUrgencyScore = document.getElementById('metaUrgencyScore');
  const metaActionNotice = document.getElementById('metaActionNotice');

  // Breakdown bars
  const vecSenderScore = document.getElementById('vecSenderScore');
  const vecSenderBar = document.getElementById('vecSenderBar');
  const vecLinksScore = document.getElementById('vecLinksScore');
  const vecLinksBar = document.getElementById('vecLinksBar');
  const vecUrgencyScore = document.getElementById('vecUrgencyScore');
  const vecUrgencyBar = document.getElementById('vecUrgencyBar');
  const vecCredScore = document.getElementById('vecCredScore');
  const vecCredBar = document.getElementById('vecCredBar');

  // Tabbed details
  const detailTabs = document.querySelectorAll('.nav-tab');
  const tabPanes = document.querySelectorAll('.tab-pane');
  const flagsCount = document.getElementById('flagsCount');
  const linksFoundCount = document.getElementById('linksFoundCount');
  const findingsList = document.getElementById('findingsList');
  const linksTableBody = document.getElementById('linksTableBody');
  const linksEmptyMsg = document.getElementById('linksEmptyMsg');
  const headersGrid = document.getElementById('headersGrid');
  const safePreviewContainer = document.getElementById('safePreviewContainer');
  const guidanceContainer = document.getElementById('guidanceContainer');

  // Mobile nav
  const mobNavInput = document.getElementById('mobNavInput');
  const mobNavScan = document.getElementById('mobNavScan');
  const mobNavResults = document.getElementById('mobNavResults');

  // Toast
  const toast = document.getElementById('toastNotification');

  // State
  let currentMode = 'full'; // 'full' | 'body' | 'fields'
  let lastAnalysisResult = null;

  // Initialize
  function init() {
    setupTheme();
    setupModeTabs();
    setupDropZone();
    setupPresetChips();
    setupDetailTabs();
    setupMobileNav();

    // Button event listeners
    analyzeBtn.addEventListener('click', runAnalysis);
    clearBtn.addEventListener('click', clearInputs);
    exportReportBtn.addEventListener('click', exportReport);

    // Auto-load first sample for immediate exploratory testing
    if (window.PhishGuardSamples && window.PhishGuardSamples.paypal) {
      emailRawInput.value = window.PhishGuardSamples.paypal.raw;
    }
  }

  // ---------------------------------------------------------------------------
  // Theme Management
  // ---------------------------------------------------------------------------
  function setupTheme() {
    const savedTheme = localStorage.getItem('phishguard_theme') || 'dark';
    if (savedTheme === 'light') {
      document.body.classList.remove('theme-dark');
      document.body.classList.add('theme-light');
      updateThemeIcon(true);
    } else {
      document.body.classList.remove('theme-light');
      document.body.classList.add('theme-dark');
      updateThemeIcon(false);
    }

    themeToggleBtn.addEventListener('click', () => {
      const isLight = document.body.classList.toggle('theme-light');
      document.body.classList.toggle('theme-dark', !isLight);
      localStorage.setItem('phishguard_theme', isLight ? 'light' : 'dark');
      updateThemeIcon(isLight);
      showToast(isLight ? 'Light theme activated' : 'Dark SOC theme activated');
    });
  }

  function updateThemeIcon(isLight) {
    if (isLight) {
      themeIcon.innerHTML = `<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>`;
    } else {
      themeIcon.innerHTML = `
        <circle cx="12" cy="12" r="5"></circle>
        <line x1="12" y1="1" x2="12" y2="3"></line>
        <line x1="12" y1="21" x2="12" y2="23"></line>
        <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line>
        <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line>
        <line x1="1" y1="12" x2="3" y2="12"></line>
        <line x1="21" y1="12" x2="23" y2="12"></line>
        <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line>
        <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>`;
    }
  }

  // ---------------------------------------------------------------------------
  // Input Modes (Full Raw vs Body Only vs Structured Form)
  // ---------------------------------------------------------------------------
  function setupModeTabs() {
    const tabs = [tabFull, tabBody, tabFields];
    tabs.forEach(tab => {
      tab.addEventListener('click', () => {
        tabs.forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        currentMode = tab.dataset.mode;

        if (currentMode === 'fields') {
          rawInputContainer.style.display = 'none';
          structuredInputContainer.style.display = 'block';
        } else {
          rawInputContainer.style.display = 'flex';
          structuredInputContainer.style.display = 'none';
          if (currentMode === 'body') {
            emailRawInput.placeholder = 'Paste email body text or HTML here...';
          } else {
            emailRawInput.placeholder = 'Paste full email RFC headers and body here...';
          }
        }
      });
    });
  }

  // ---------------------------------------------------------------------------
  // Presets Bar
  // ---------------------------------------------------------------------------
  function setupPresetChips() {
    const chips = document.querySelectorAll('.preset-chip');
    chips.forEach(chip => {
      chip.addEventListener('click', () => {
        const sampleKey = chip.dataset.sample;
        const sample = window.PhishGuardSamples && window.PhishGuardSamples[sampleKey];
        if (sample) {
          // Switch to raw mode
          tabFull.click();
          emailRawInput.value = sample.raw;
          showToast(`Loaded test sample: ${sample.name}`);
          runAnalysis();
        }
      });
    });
  }

  // ---------------------------------------------------------------------------
  // Drag & Drop File Ingestion
  // ---------------------------------------------------------------------------
  function setupDropZone() {
    browseFileBtn.addEventListener('click', () => fileInput.click());
    dropZone.addEventListener('click', (e) => {
      if (e.target !== browseFileBtn) fileInput.click();
    });

    fileInput.addEventListener('change', (e) => {
      if (e.target.files && e.target.files[0]) {
        handleFile(e.target.files[0]);
      }
    });

    ['dragenter', 'dragover'].forEach(name => {
      dropZone.addEventListener(name, (e) => {
        e.preventDefault();
        dropZone.classList.add('drag-active');
      });
    });

    ['dragleave', 'drop'].forEach(name => {
      dropZone.addEventListener(name, (e) => {
        e.preventDefault();
        dropZone.classList.remove('drag-active');
      });
    });

    dropZone.addEventListener('drop', (e) => {
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]) {
        handleFile(e.dataTransfer.files[0]);
      }
    });
  }

  function handleFile(file) {
    const reader = new FileReader();
    reader.onload = function (event) {
      tabFull.click();
      emailRawInput.value = event.target.result;
      showToast(`Ingested file: ${file.name}`);
      runAnalysis();
    };
    reader.onerror = function () {
      showToast('Error reading file. Please try pasting the content directly.');
    };
    reader.readAsText(file);
  }

  function clearInputs() {
    emailRawInput.value = '';
    structSender.value = '';
    structReplyTo.value = '';
    structSubject.value = '';
    structDate.value = '';
    structBody.value = '';
    resultsEmptyState.style.display = 'flex';
    resultsActiveView.style.display = 'none';
    lastAnalysisResult = null;
    showToast('Inputs cleared');
  }

  // ---------------------------------------------------------------------------
  // Details Tab Navigation
  // ---------------------------------------------------------------------------
  function setupDetailTabs() {
    detailTabs.forEach(tab => {
      tab.addEventListener('click', () => {
        detailTabs.forEach(t => t.classList.remove('active'));
        tabPanes.forEach(p => p.classList.remove('active'));

        tab.classList.add('active');
        const targetId = 'tab' + tab.dataset.tab.charAt(0).toUpperCase() + tab.dataset.tab.slice(1);
        const targetPane = document.getElementById(targetId);
        if (targetPane) targetPane.classList.add('active');
      });
    });
  }

  // ---------------------------------------------------------------------------
  // Mobile Bottom Navigation
  // ---------------------------------------------------------------------------
  function setupMobileNav() {
    mobNavInput.addEventListener('click', () => {
      document.querySelector('.input-panel').scrollIntoView({ behavior: 'smooth' });
      setActiveMobBtn(mobNavInput);
    });

    mobNavScan.addEventListener('click', () => {
      runAnalysis();
      resultsPanel.scrollIntoView({ behavior: 'smooth' });
      setActiveMobBtn(mobNavResults);
    });

    mobNavResults.addEventListener('click', () => {
      resultsPanel.scrollIntoView({ behavior: 'smooth' });
      setActiveMobBtn(mobNavResults);
    });
  }

  function setActiveMobBtn(activeBtn) {
    [mobNavInput, mobNavScan, mobNavResults].forEach(btn => btn.classList.remove('active'));
    activeBtn.classList.add('active');
  }

  // ---------------------------------------------------------------------------
  // Analysis Execution & Rendering
  // ---------------------------------------------------------------------------
  function runAnalysis() {
    let inputContent = '';
    let options = {};

    if (currentMode === 'fields') {
      options = {
        from: structSender.value.trim(),
        replyTo: structReplyTo.value.trim(),
        subject: structSubject.value.trim(),
        auth: structDate.value.trim()
      };
      inputContent = structBody.value.trim();
      if (!inputContent && !options.from && !options.subject) {
        showToast('Please enter an email body or sender to analyze.');
        return;
      }
    } else {
      inputContent = emailRawInput.value.trim();
      if (!inputContent) {
        showToast('Please enter or paste email content to analyze.');
        return;
      }
    }

    // Call detector
    const result = window.PhishGuardDetector.analyze(inputContent, options);
    lastAnalysisResult = result;

    renderResults(result);

    // On mobile, scroll to results
    if (window.innerWidth <= 1100) {
      resultsPanel.scrollIntoView({ behavior: 'smooth' });
      setActiveMobBtn(mobNavResults);
    }
  }

  function renderResults(result) {
    resultsEmptyState.style.display = 'none';
    resultsActiveView.style.display = 'block';

    // 1. Animated Score Gauge
    const circumference = 2 * Math.PI * 42; // r=42 -> ~263.89
    const offset = circumference - (result.score / 100) * circumference;
    gaugeProgressCircle.style.strokeDashoffset = offset;

    // Pick score color
    let strokeColor = 'var(--color-safe)';
    if (result.score >= 70) {
      strokeColor = 'var(--color-danger)';
    } else if (result.score >= 40) {
      strokeColor = 'var(--color-warning)';
    } else if (result.score > 20) {
      strokeColor = 'var(--accent-blue)';
    }
    gaugeProgressCircle.style.stroke = strokeColor;

    // Counter animation
    animateScoreCounter(result.score);

    // 2. Verdict Badges
    riskVerdictBadge.textContent = result.verdict;
    riskVerdictBadge.className = `verdict-badge ${result.badgeClass}`;
    threatLevelSubtext.textContent = result.verdictTitle;
    riskSummaryDesc.textContent = result.summary;

    // 3. Quick Meta Grid
    if (result.parsed.from && result.parsed.from.domain) {
      const isSpoofed = result.flags.some(f => f.category === 'sender' && f.severity === 'high');
      metaSenderAuth.textContent = isSpoofed ? `Spoofed (@${result.parsed.from.domain})` : `@${result.parsed.from.domain}`;
      metaSenderAuth.className = `meta-val ${isSpoofed ? 'text-danger' : 'text-safe'}`;
    } else {
      metaSenderAuth.textContent = 'Unspecified';
      metaSenderAuth.className = 'meta-val';
    }

    metaLinksCount.textContent = result.links.length;
    metaUrgencyScore.textContent = `${result.vectors.urgency}%`;
    metaUrgencyScore.className = `meta-val ${result.vectors.urgency > 50 ? 'text-danger' : (result.vectors.urgency > 20 ? 'text-warning' : 'text-safe')}`;

    if (result.score >= 70) {
      metaActionNotice.textContent = 'BLOCK & DELETE';
      metaActionNotice.className = 'meta-val text-danger';
    } else if (result.score >= 40) {
      metaActionNotice.textContent = 'VERIFY SENDER';
      metaActionNotice.className = 'meta-val text-warning';
    } else {
      metaActionNotice.textContent = 'SAFE TO OPEN';
      metaActionNotice.className = 'meta-val text-safe';
    }

    // 4. Vector Breakdown Bars
    updateBar(vecSenderScore, vecSenderBar, result.vectors.sender);
    updateBar(vecLinksScore, vecLinksBar, result.vectors.links);
    updateBar(vecUrgencyScore, vecUrgencyBar, result.vectors.urgency);
    updateBar(vecCredScore, vecCredBar, result.vectors.credentials);

    // 5. Findings Tab
    flagsCount.textContent = result.flags.length;
    renderFindings(result.flags);

    // 6. Links Inspector Tab
    linksFoundCount.textContent = result.links.length;
    renderLinks(result.links);

    // 7. Parsed Headers Tab
    renderHeaders(result.headers);

    // 8. Safe Preview Tab
    renderSafePreview(result.parsed.body);

    // 9. Guidance Defense Tab
    renderGuidance(result.recommendations, result.score);
  }

  function animateScoreCounter(targetScore) {
    let current = 0;
    const duration = 800; // ms
    const stepTime = 16;
    const totalSteps = duration / stepTime;
    const stepIncrement = targetScore / totalSteps;

    const timer = setInterval(() => {
      current += stepIncrement;
      if (current >= targetScore) {
        current = targetScore;
        clearInterval(timer);
      }
      scoreValue.textContent = Math.round(current);
    }, stepTime);
  }

  function updateBar(labelEl, barEl, value) {
    labelEl.textContent = `${value}%`;
    barEl.style.width = `${value}%`;

    if (value >= 70) {
      barEl.style.backgroundColor = 'var(--color-danger)';
    } else if (value >= 35) {
      barEl.style.backgroundColor = 'var(--color-warning)';
    } else {
      barEl.style.backgroundColor = 'var(--color-safe)';
    }
  }

  function renderFindings(flags) {
    findingsList.innerHTML = '';
    flags.forEach(flag => {
      const card = document.createElement('div');
      card.className = `finding-card severity-${flag.severity}`;

      let badgeBadgeClass = 'safe';
      if (flag.severity === 'high') badgeBadgeClass = 'danger';
      else if (flag.severity === 'medium') badgeBadgeClass = 'warning';
      else if (flag.severity === 'low') badgeBadgeClass = 'info';

      card.innerHTML = `
        <div class="finding-header">
          <div class="finding-title-wrap">
            <span class="badge-flag ${badgeBadgeClass}">${flag.severity.toUpperCase()}</span>
            <span>${escapeHtml(flag.title)}</span>
          </div>
        </div>
        <p class="finding-desc">${escapeHtml(flag.description)}</p>
        ${flag.snippet ? `<div class="finding-context">Trigger: ${escapeHtml(flag.snippet)}</div>` : ''}
      `;
      findingsList.appendChild(card);
    });
  }

  function renderLinks(links) {
    linksTableBody.innerHTML = '';
    if (!links || links.length === 0) {
      linksEmptyMsg.style.display = 'block';
      return;
    }
    linksEmptyMsg.style.display = 'none';

    links.forEach(l => {
      const tr = document.createElement('tr');
      const badgeClass = l.risk === 'danger' ? 'danger' : (l.risk === 'warning' ? 'warning' : 'safe');
      const badgeText = l.risk === 'danger' ? 'MALICIOUS' : (l.risk === 'warning' ? 'SUSPICIOUS' : 'CLEAN');

      tr.innerHTML = `
        <td><span class="badge-flag ${badgeClass}">${badgeText}</span></td>
        <td class="url-anchor">${escapeHtml(l.text || l.href)}</td>
        <td class="url-destination">
          <span>${escapeHtml(l.href)}</span>
          ${l.risk === 'danger' && l.reasons.includes('DECEPTIVE') ? '<span class="url-mismatch-flag">⚠️ Anchor Mismatch Trapping User</span>' : ''}
        </td>
        <td>${escapeHtml(l.reasons)}</td>
      `;
      linksTableBody.appendChild(tr);
    });
  }

  function renderHeaders(headers) {
    headersGrid.innerHTML = '';
    const keys = Object.keys(headers || {});
    if (keys.length === 0) {
      headersGrid.innerHTML = '<div class="empty-sub">No RFC headers provided (body-only analysis).</div>';
      return;
    }

    keys.forEach(key => {
      if (key === '_display') return;
      const row = document.createElement('div');
      row.className = 'header-entry';
      row.innerHTML = `
        <div class="header-key">${escapeHtml(key)}</div>
        <div class="header-value">${escapeHtml(headers[key])}</div>
      `;
      headersGrid.appendChild(row);
    });
  }

  function renderSafePreview(bodyContent) {
    if (!bodyContent) {
      safePreviewContainer.textContent = '(No message body provided)';
      return;
    }
    // Neutralize dangerous tags and preserve sanitized whitespace
    safePreviewContainer.textContent = bodyContent;
  }

  function renderGuidance(recommendations, score) {
    guidanceContainer.innerHTML = '';
    recommendations.forEach((rec, idx) => {
      const card = document.createElement('div');
      card.className = 'guidance-card';
      card.innerHTML = `
        <h5>
          <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="${score >= 50 ? 'var(--color-danger)' : 'var(--color-safe)'}" stroke-width="2">
            <polyline points="9 11 12 14 22 4"></polyline>
            <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"></path>
          </svg>
          Step ${idx + 1}: ${escapeHtml(rec.title)}
        </h5>
        <p>${escapeHtml(rec.desc)}</p>
      `;
      guidanceContainer.appendChild(card);
    });

    // Add generic cyber security tip
    const generalCard = document.createElement('div');
    generalCard.className = 'guidance-card';
    generalCard.innerHTML = `
      <h5>
        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="var(--accent-blue)" stroke-width="2">
          <circle cx="12" cy="12" r="10"></circle>
          <line x1="12" y1="16" x2="12" y2="12"></line>
          <line x1="12" y1="8" x2="12.01" y2="8"></line>
        </svg>
        Golden Rule of Phishing Defense
      </h5>
      <p>Never authenticate, approve transactions, or share credentials based on an incoming email. Always open a fresh browser window and independently browse to the verified domain.</p>
    `;
    guidanceContainer.appendChild(generalCard);
  }

  // ---------------------------------------------------------------------------
  // Export Report
  // ---------------------------------------------------------------------------
  function exportReport() {
    if (!lastAnalysisResult) {
      showToast('Please analyze an email first to export a report.');
      return;
    }

    const reportData = {
      phishguard_version: '2.4',
      generated_at: new Date().toISOString(),
      threat_score: lastAnalysisResult.score,
      verdict: lastAnalysisResult.verdict,
      verdict_summary: lastAnalysisResult.summary,
      vectors: lastAnalysisResult.vectors,
      detected_flags: lastAnalysisResult.flags,
      hyperlinks_analyzed: lastAnalysisResult.links,
      headers_parsed: lastAnalysisResult.headers,
      recommendations: lastAnalysisResult.recommendations
    };

    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishguard-report-${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast('Threat intelligence report exported (JSON).');
  }

  // ---------------------------------------------------------------------------
  // Utilities
  // ---------------------------------------------------------------------------
  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function showToast(message) {
    toast.textContent = message;
    toast.classList.add('show');
    clearTimeout(toast._timeout);
    toast._timeout = setTimeout(() => {
      toast.classList.remove('show');
    }, 3200);
  }

  // Run on DOM load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
