// Outlook Email Evaluator - Content Script
let sidebar = null;
let lastEmailId = null;
let observer = null;

// --- Gift Card Fraud Detection (pre-check before API call) ---
const GIFT_CARD_KEYWORDS = [
  'gift card', 'gift cards', 'itunes card', 'google play card', 'amazon gift card',
  'steam card', 'ebay gift card', 'visa gift card', 'buy gift cards', 'purchase gift cards',
  'get gift cards', 'send gift cards', 'gift card number', 'gift card code',
  'scratch the card', 'scratch card', 'card balance', 'redeem the card',
  'send me the codes', 'send the codes', 'send the numbers'
];

function checkForGiftCardFraud(email) {
  const combined = ((email.subject || '') + ' ' + (email.body || '')).toLowerCase();
  return GIFT_CARD_KEYWORDS.some(kw => combined.includes(kw));
}

// --- XSS-safe HTML / URLs (never interpolate raw strings into innerHTML) ---
function escapeHtml(s) {
  if (s == null || s === '') return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Returns https? URL string or null — never javascript:, data:, etc. */
function safeHttpUrl(raw) {
  if (raw == null || raw === '') return null;
  const trimmed = String(raw).trim().slice(0, 2048);
  try {
    const u = new URL(trimmed);
    if (u.protocol === 'http:' || u.protocol === 'https:') return u.href;
  } catch {
    return null;
  }
  return null;
}

function buildLinkRowHtml(l) {
  const display = escapeHtml(l.display);
  const href = safeHttpUrl(l.fullUrl);
  const mismatch = l.mismatch
    ? ' <span style="color:#cc0000;font-weight:bold;">DESTINATION MISMATCH</span>'
    : '';
  if (href) {
    const eh = escapeHtml(href);
    return `<div class="oe-link ${l.mismatch ? 'oe-link-mismatch' : ''}">
      <span class="oe-link-display">${display}</span>
      <span class="oe-link-dest" style="display:block;word-break:break-all;font-size:0.82em;margin-top:3px;color:#555;">→ <a href="${eh}" rel="noopener noreferrer" target="_blank" style="color:#1a6eb5;text-decoration:none;" title="${eh}">${eh}</a>${mismatch}</span>
    </div>`;
  }
  const fallback = escapeHtml(String(l.fullUrl || l.href || '').trim().slice(0, 2048));
  return `<div class="oe-link ${l.mismatch ? 'oe-link-mismatch' : ''}">
    <span class="oe-link-display">${display}</span>
    <span class="oe-link-dest" style="display:block;word-break:break-all;font-size:0.82em;margin-top:3px;color:#555;">${fallback}${mismatch}</span>
  </div>`;
}

// --- Sidebar Injection ---
function createSidebar() {
  if (document.getElementById('oe-sidebar')) return;
  sidebar = document.createElement('div');
  sidebar.id = 'oe-sidebar';
  sidebar.innerHTML = `
    <div id="oe-tab"><span>📧</span><span>EVALUATOR</span></div>
    <div id="oe-panel">
      <div id="oe-header">
        <span>📧 Email Evaluator</span>
        <div style="display:flex;gap:4px;align-items:center;">
          <button id="oe-dark-toggle" title="Toggle dark mode">🌙</button>
          <button id="oe-close">&#x27E9;</button>
        </div>
      </div>
      <div id="oe-body"><p>Select or open an email to analyze it.</p></div>
      <button id="oe-analyze-btn">🔍 Analyze Email</button>
    </div>
  `;
  document.body.appendChild(sidebar);

  document.getElementById('oe-close').addEventListener('click', () => {
    sidebar.classList.add('oe-collapsed');
  });

  // Dark mode - restore saved preference
  try {
    if (localStorage.getItem('oe-dark-mode') === 'true') {
      sidebar.classList.add('oe-dark');
      document.getElementById('oe-dark-toggle').textContent = '☀️';
    }
  } catch(e) {}
  document.getElementById('oe-dark-toggle').addEventListener('click', () => {
    const isDark = sidebar.classList.toggle('oe-dark');
    document.getElementById('oe-dark-toggle').textContent = isDark ? '☀️' : '🌙';
    try { localStorage.setItem('oe-dark-mode', isDark ? 'true' : 'false'); } catch(e) {}
  });
  document.getElementById('oe-tab').addEventListener('click', () => {
    sidebar.classList.remove('oe-collapsed');
  });

  // Ping service worker to wake it, then analyze
  document.getElementById('oe-analyze-btn').addEventListener('click', () => {
    try { chrome.runtime.sendMessage({ type: 'PING' }); } catch(e) {}
    setTimeout(analyzeCurrentEmail, 100);
  });

  // Event delegation for finding card toggles
  document.getElementById('oe-body').addEventListener('click', (e) => {
    const header = e.target.closest('.oe-finding-header');
    if (header) header.parentElement.classList.toggle('oe-finding-open');
  });
}

// --- SafeLinks / URL-wrapper decoder ---
function decodeWrappedUrl(href) {
  if (!href) return href;
  try {
    // Unescape HTML entities Outlook may inject into href attributes (e.g. &amp; -> &)
    href = href.replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"');
    // Microsoft SafeLinks: safelinks.protection.outlook.com?url=...
    if (href.includes('safelinks.protection.outlook.com')) {
      const u = new URL(href);
      const decoded = u.searchParams.get('url');
      if (decoded) return decodeURIComponent(decoded);
    }
    // Trend Micro IMSVA / Email Security: various param names
    if (href.includes('trendmicro') || href.includes('imsva') || href.includes('tmase')) {
      const u = new URL(href);
      const decoded = u.searchParams.get('url') || u.searchParams.get('u') || u.searchParams.get('__u');
      if (decoded) return decodeURIComponent(decoded);
      // Trend Micro path-encoded: /redirect?url=BASE64
      const b64 = u.searchParams.get('redirectUrl') || u.searchParams.get('r');
      if (b64) { try { return atob(b64); } catch(e) {} }
    }
    // Proofpoint URLDefense v2: urldefense.proofpoint.com/v2/url?u=...
    if (href.includes('urldefense') && href.includes('/v2/')) {
      const u = new URL(href);
      let raw = u.searchParams.get('u');
      if (raw) {
        raw = raw.replace(/-/g, '%').replace(/_/g, '/');
        return decodeURIComponent(raw);
      }
    }
    // Proofpoint URLDefense v3: urldefense.com/v3/__https://...
    if (href.includes('urldefense') && href.includes('/v3/')) {
      const match = href.match(/\/v3\/__([^_]+)__/);
      if (match) return decodeURIComponent(match[1]);
    }
    // Mimecast: protect2.mimecast.com/s/...?domain=...&url=...
    if (href.includes('mimecast.com')) {
      const u = new URL(href);
      const decoded = u.searchParams.get('url') || u.searchParams.get('u');
      if (decoded) return decodeURIComponent(decoded);
    }
    // Generic: any URL with a ?url= or ?u= param that looks like a full URL
    if (href.includes('?')) {
      const u = new URL(href);
      const decoded = u.searchParams.get('url') || u.searchParams.get('u');
      if (decoded && (decoded.startsWith('http') || decoded.startsWith('%68%74'))) {
        return decodeURIComponent(decoded);
      }
    }
  } catch(e) {}
  return href;
}
// --- Email Extraction ---
function getReadingPane() {
  const candidates = [
    document.querySelector('[aria-label="Reading Pane"]'),
    document.querySelector('[aria-label="reading pane"]'),
    document.querySelector('[class*="ReadingPane"]'),
    document.querySelector('[class*="readingPane"]'),
    document.querySelector('[data-testid="reading-pane"]'),
  ];
  return candidates.find(el => el !== null) || document.body;
}

function findTextIn(container, selectorList) {
  for (const sel of selectorList) {
    try {
      const el = container.querySelector(sel);
      if (el && el.innerText && el.innerText.trim().length > 0) return el.innerText.trim();
    } catch(e) {}
  }
  return null;
}

function extractEmail() {
  const pane = getReadingPane();
  const subject = findTextIn(pane, [
    '[data-testid="subject"]', '[aria-label="Message subject"]',
    'h1', 'h2', '[role="heading"]', '[class*="subject" i]'
  ]) || '(No subject found)';

  // --- Sender extraction - multiple strategies to handle regular + system emails ---
  let sender = '(No sender found)';
  try {
    const allBtns = Array.from(pane.querySelectorAll('button[aria-label]'));
    const fromBtn = allBtns.find(b => b.getAttribute('aria-label').startsWith('From:'));
    if (fromBtn) sender = fromBtn.getAttribute('aria-label').replace(/^From:\s*/i, '').trim();
  } catch(e) {}

  if (sender === '(No sender found)') {
    try {
      const allEls = Array.from(pane.querySelectorAll('[aria-label]'));
      const emailEl = allEls.find(el => {
        const label = el.getAttribute('aria-label') || '';
        return label.includes('@') && label.length < 200;
      });
      if (emailEl) sender = emailEl.getAttribute('aria-label').trim();
    } catch(e) {}
  }

  if (sender === '(No sender found)') {
    sender = findTextIn(pane, [
      '[data-testid="senderName"]', '[class*="sender" i]', '[class*="Sender"]',
      '[class*="from" i]', '[class*="From"]',
    ]) || '(No sender found)';
  }

  if (sender === '(No sender found)') {
    try {
      const allText = pane.innerText || '';
      const emailMatch = allText.match(/[\w.+-]+@[\w-]+\.[\w.]+/);
      if (emailMatch) sender = emailMatch[0];
    } catch(e) {}
  }

  const body = findTextIn(pane, [
    '[aria-label="Message body"]', '[data-testid="message-body"]',
    'div[class*="UniqueMessageBody"]', '[id*="UniqueMessageBody"]',
    'div[class*="messageBody"]', 'div[class*="MessageBody"]',
    '[class*="ReadingPaneContent"]', '[class*="readingPaneContent"]'
  ]) || '(No body found)';

  const links = [];
  const bodyEl = pane.querySelector('[aria-label="Message body"]') ||
    pane.querySelector('div[class*="UniqueMessageBody"]') ||
    pane.querySelector('[id*="UniqueMessageBody"]') ||
    pane.querySelector('div[class*="messageBody"]') || pane;

  if (bodyEl) {
    const seen = new Set();
    bodyEl.querySelectorAll('a[href]').forEach(a => {
      try {
        const displayText = a.innerText.trim();
        let href = a.getAttribute('href') || '';
        href = decodeWrappedUrl(href);
        if (!href || href.startsWith('mailto:') || href.startsWith('#') || href.length < 10) return;
        let hrefDomain = '';
        try { hrefDomain = new URL(href).hostname.toLowerCase(); } catch(e) { hrefDomain = href.slice(0, 60); }
        if (seen.has(hrefDomain)) return;
        seen.add(hrefDomain);
        let displayDomain = '';
        const urlPattern = displayText.match(/(?:https?:\/\/|www\.)([\w.-]+)/i);
        if (urlPattern) {
          try {
            const normalized = displayText.startsWith('http') ? displayText : 'https://' + displayText;
            displayDomain = new URL(normalized).hostname.toLowerCase();
          } catch(e) { displayDomain = urlPattern[1].toLowerCase(); }
        }
        const mismatch = displayDomain && hrefDomain &&
          !hrefDomain.includes(displayDomain.replace(/^www\./, '')) &&
          !displayDomain.includes(hrefDomain.replace(/^www\./, ''));
        links.push({ display: displayText.slice(0, 80) || '(no text)', href: hrefDomain, fullUrl: href, mismatch });
      } catch(e) {}
    });
  }

  const attachments = [];
  try {
    pane.querySelectorAll('[aria-label*="attachment" i],[class*="attachment" i],[class*="Attachment" i]').forEach(el => {
      const name = el.getAttribute('aria-label') || el.innerText || '';
      if (name.trim()) attachments.push(name.trim().toLowerCase());
    });
    pane.querySelectorAll('[class*="attachmentName" i],[class*="fileName" i],[data-testid*="attachment" i]').forEach(el => {
      const name = el.innerText || '';
      if (name.trim()) attachments.push(name.trim().toLowerCase());
    });
  } catch(e) {}

  const HIGH_RISK_EXTENSIONS = ['.htm','.html','.js','.vbs','.vbe','.ps1','.wsf','.wsh','.jar','.hta'];
  const SUSPICIOUS_EXTENSIONS = ['.exe','.msi','.bat','.cmd','.iso','.img','.zip','.rar','.7z','.docm','.xlsm','.pptm','.lnk'];
  const hasHighRiskAttachment = attachments.some(a => HIGH_RISK_EXTENSIONS.some(ext => a.endsWith(ext)));
  const hasSuspiciousAttachment = attachments.some(a => SUSPICIOUS_EXTENSIONS.some(ext => a.endsWith(ext)));
  const highRiskFiles = attachments.filter(a => HIGH_RISK_EXTENSIONS.some(ext => a.endsWith(ext)));
  const suspiciousFiles = attachments.filter(a => SUSPICIOUS_EXTENSIONS.some(ext => a.endsWith(ext)));

  let recipient = '(No recipient found)';
  try {
    const toBtn = Array.from(pane.querySelectorAll('button[aria-label]'))
      .find(b => (b.getAttribute('aria-label') || '').startsWith('To:'));
    if (toBtn) recipient = toBtn.getAttribute('aria-label').replace(/^To:\s*/i, '').trim();
  } catch(e) {}
  if (recipient === '(No recipient found)') {
    recipient = findTextIn(pane, [
      '[data-testid="recipientName"]', '[class*="recipient" i]', '[class*="toLine" i]'
    ]) || '(No recipient found)';
  }

  const senderHasEmail = sender !== '(No sender found)' && sender.includes('@');
  return { subject, sender, senderHasEmail, recipient, body: body.slice(0, 3000), links: links.slice(0, 20), attachments, hasHighRiskAttachment, hasSuspiciousAttachment, highRiskFiles, suspiciousFiles };
}

// --- Link Revelation ---
function revealLinks() {
  const pane = getReadingPane();
  const bodyEl = pane.querySelector('[aria-label="Message body"]') ||
    pane.querySelector('div[class*="UniqueMessageBody"]') ||
    pane.querySelector('[id*="UniqueMessageBody"]') ||
    pane.querySelector('div[class*="messageBody"]');
  if (!bodyEl) return;

  bodyEl.querySelectorAll('a[href]').forEach(a => {
    if (a.getAttribute('data-oe-revealed')) return;
    a.setAttribute('data-oe-revealed', '1');
    try {
      let href = a.getAttribute('href') || '';
      href = decodeWrappedUrl(href);
      if (!href || href.startsWith('mailto:') || href.startsWith('#') || href.length < 10) return;
      let domain = '';
      try { domain = new URL(href).hostname.toLowerCase(); } catch(e) { return; }
      const displayText = a.innerText.trim().toLowerCase();
      if (displayText.includes(domain)) return;
      const label = document.createElement('span');
      label.style.cssText = 'color:#888;font-size:0.85em;font-weight:normal;user-select:text;';
      label.textContent = ' [' + domain + ']';
      const urlPattern = displayText.match(/(?:https?:\/\/|www\.)([\w.-]+)/i);
      if (urlPattern) {
        const dd = urlPattern[1].replace(/^www\./, '');
        const rd = domain.replace(/^www\./, '');
        if (!rd.includes(dd) && !dd.includes(rd)) {
          label.style.color = '#cc0000';
          label.style.fontWeight = 'bold';
          label.textContent = ' WARNING [GOES TO: ' + domain + ']';
        }
      }
      a.insertAdjacentElement('afterend', label);
    } catch(e) {}
  });
}

// --- Analysis ---
async function analyzeCurrentEmail() {
  const email = extractEmail();
  setLoading();

  // --- GIFT CARD FRAUD: hard pre-check, bypass API ---
  if (checkForGiftCardFraud(email)) {
    showResult({
      verdict: 'PHISHING',
      phishing_score: 99,
      spam_score: 10,
      summary: 'This email contains a request for gift cards. This is one of the most common fraud tactics used against businesses — it is almost certainly a scam.',
      findings: [
        {
          flag: 'Gift card request detected',
          explanation: 'Fraudsters impersonate managers, executives, or colleagues and ask employees to buy gift cards (iTunes, Google Play, Amazon, Visa, etc.) urgently. They always claim it is for a surprise, a client, or an emergency. No legitimate business request will ever ask for gift card payments — this is a well-known scam that costs businesses millions every year.',
          howToSpotIt: 'If ANY email asks you to buy gift cards and send the codes — stop immediately. It does not matter if it appears to come from your boss or a senior executive. Call that person directly on a known phone number to verify before doing anything.'
        }
      ],
      lesson: 'No legitimate business transaction is ever completed with gift cards. If someone asks you to buy gift cards and send the codes, it is a scam — 100% of the time.',
      suggested_action: 'Do NOT purchase any gift cards. Report this email to your IT security team and your manager immediately. If you have already purchased cards, contact the card issuer right away to try to stop the transaction.'
    }, email);
    return;
  }

  let isOutlookExternal = false;
  try {
    const paneForExternal = getReadingPane();
    const candidates = [
      ...paneForExternal.querySelectorAll('[role="alert"]'),
      ...paneForExternal.querySelectorAll('[role="status"]'),
      ...paneForExternal.querySelectorAll('[class*="InfoBar" i]'),
      ...paneForExternal.querySelectorAll('[class*="infoBar" i]'),
      ...paneForExternal.querySelectorAll('[class*="banner" i]'),
      ...paneForExternal.querySelectorAll('[class*="warning" i]'),
    ];
    for (const el of candidates) {
      const text = el.innerText || '';
      if (text.length < 200 && text.toLowerCase().includes('external organization')) {
        isOutlookExternal = true;
        break;
      }
    }
  } catch(e) {}

  const emailData = {
    subject: email.subject,
    sender: email.sender,
    senderHasEmail: email.senderHasEmail,
    body: email.body,
    links: email.links,
    attachments: email.attachments,
    hasHighRiskAttachment: email.hasHighRiskAttachment,
    hasSuspiciousAttachment: email.hasSuspiciousAttachment,
    highRiskFiles: email.highRiskFiles,
    suspiciousFiles: email.suspiciousFiles,
    isOutlookExternal: isOutlookExternal,
    clientTimestamp: new Date().toISOString(),
    clientTimezone: Intl.DateTimeFormat().resolvedOptions().timeZone
  };

  try {
    chrome.runtime.sendMessage({ type: 'ANALYZE_EMAIL', emailData });
  } catch(e) {
    showError('Extension was reloaded. Please refresh the page and try again.');
    return;
  }

  window._oe_timeout = setTimeout(() => {
    showError('Timed out. Check the service worker console at chrome://extensions.');
  }, 20000);
  window._oe_email = email;
}

// --- UI States ---
function setLoading() {
  document.getElementById('oe-body').innerHTML = `
    <div id="oe-loading" style="text-align:center;padding:20px;color:#555;">
      <div class="oe-spinner"></div>
      <p>Analyzing email...</p>
    </div>`;
  document.getElementById('oe-analyze-btn').style.display = 'none';
}

function showError(msg) {
  document.getElementById('oe-body').innerHTML = `<div style="color:#c00;padding:12px;">⚠️ ${escapeHtml(msg)}</div>`;
  document.getElementById('oe-analyze-btn').style.display = 'block';
}

function showResult(result, email) {
  const verdictClass = {
    'SAFE': 'verdict-safe', 'SUSPICIOUS': 'verdict-suspicious',
    'SPAM': 'verdict-spam', 'PHISHING': 'verdict-phishing'
  }[result.verdict] || 'verdict-suspicious';

  const verdictIcon = {
    'SAFE': '✅', 'SUSPICIOUS': '⚠️', 'SPAM': '🚫', 'PHISHING': '🎣'
  }[result.verdict] || '⚠️';

  const findingsHTML = (result.findings || []).map(f => `
    <div class="oe-finding">
      <div class="oe-finding-header">
        <span class="oe-finding-icon">🚩</span>
        <span class="oe-finding-flag">${escapeHtml(f.flag)}</span>
        <span class="oe-finding-toggle">▼</span>
      </div>
      <div class="oe-finding-body">
        <div class="oe-finding-section">
          <div class="oe-finding-label">What's happening</div>
          <div class="oe-finding-text">${escapeHtml(f.explanation)}</div>
        </div>
        <div class="oe-finding-section oe-tip">
          <div class="oe-finding-label">💡 How to spot this yourself</div>
          <div class="oe-finding-text">${escapeHtml(f.howToSpotIt)}</div>
        </div>
      </div>
    </div>
  `).join('');

  const combined = ((email.body || '') + ' ' + (email.subject || '')).toLowerCase();
  const isLoginOrCode = ['sign in','verification code','one-time','otp','log in','verify your',
    'secure link','reset your password','confirm your','your account','click here to'].some(kw => combined.includes(kw));
  const showWarning = isLoginOrCode || result.verdict === 'PHISHING' || result.phishing_score >= 60;

  document.getElementById('oe-body').innerHTML = `
    <div class="oe-verdict ${verdictClass}">
      <span class="oe-verdict-icon">${verdictIcon}</span>
      <span class="oe-verdict-label">${escapeHtml(result.verdict)}</span>
    </div>
    <div class="oe-scores">
      <div class="oe-score">
        <span class="oe-score-label">Phishing Risk</span>
        <span class="oe-score-val">${escapeHtml(result.phishing_score)}/100</span>
      </div>
      <div class="oe-score">
        <span class="oe-score-label">Spam Score</span>
        <span class="oe-score-val">${escapeHtml(result.spam_score)}/100</span>
      </div>
    </div>
    <div class="oe-section">
      <div class="oe-section-title">Summary</div>
      <p>${escapeHtml(result.summary)}</p>
    </div>
    ${showWarning ? `
    <div class="oe-warning-banner">
      ⚠️ If you did not request this, do not click any links and <strong>report this to your IT security team immediately.</strong>
    </div>` : ''}
    ${findingsHTML ? `
    <div class="oe-section">
      <div class="oe-section-title">🔍 What We Found — tap each to learn more</div>
      ${findingsHTML}
    </div>` : ''}
    ${email.links && email.links.length > 0 ? `
    <div class="oe-section">
      <div class="oe-section-title">🔗 Links in this email (${email.links.length})</div>
      ${email.links.map(l => buildLinkRowHtml(l)).join('')}
    </div>` : ''}
    ${result.lesson ? `
    <div class="oe-lesson">
      <div class="oe-lesson-title">📚 Remember for next time</div>
      <div class="oe-lesson-text">${escapeHtml(result.lesson)}</div>
    </div>` : ''}

    <div class="oe-section">
      <div class="oe-section-title">✅ Suggested Action</div>
      <p>${escapeHtml(result.suggested_action)}</p>
    </div>

    <div class="oe-feedback-section" id="oe-feedback-section">
      <div class="oe-feedback-title">Was this analysis accurate?</div>
      <div class="oe-feedback-buttons">
        <button class="oe-feedback-btn oe-fb-false-positive" id="oe-fb-fp">
          👎 False Positive
        </button>
        <button class="oe-feedback-btn oe-fb-missed-threat" id="oe-fb-mt">
          🚨 Missed Threat
        </button>
      </div>
    </div>
  `;

  window._oe_lastResult = result;

  const fpBtn = document.getElementById('oe-fb-fp');
  const mtBtn = document.getElementById('oe-fb-mt');

  fpBtn.addEventListener('click', () => showFeedbackForm('false_positive', result, email));
  mtBtn.addEventListener('click', () => showFeedbackForm('missed_threat', result, email));

  const btn = document.getElementById('oe-analyze-btn');
  btn.style.display = 'block';
  btn.textContent = 'Analyze Another';
  btn.disabled = false;
}

function showFeedbackForm(feedbackType, result, email) {
  const section = document.getElementById('oe-feedback-section');
  const label = feedbackType === 'false_positive'
    ? 'This email was flagged but is actually safe'
    : 'This email is spam or phishing but was not caught';

  section.innerHTML = `
    <div class="oe-feedback-title">${label}</div>
    <textarea id="oe-fb-comment" class="oe-feedback-comment"
      placeholder="Optional: tell us more about why this was incorrect..."
      maxlength="500" rows="3"></textarea>
    <div class="oe-feedback-actions">
      <button class="oe-feedback-btn oe-fb-submit" id="oe-fb-submit">Send Report</button>
      <button class="oe-feedback-btn oe-fb-cancel" id="oe-fb-cancel">Cancel</button>
    </div>
  `;

  document.getElementById('oe-fb-submit').addEventListener('click', () => {
    const comment = (document.getElementById('oe-fb-comment').value || '').trim();
    submitFeedback(feedbackType, result, email, comment);
  });

  document.getElementById('oe-fb-cancel').addEventListener('click', () => {
    resetFeedbackSection();
  });
}

function submitFeedback(feedbackType, result, email, comment) {
  const section = document.getElementById('oe-feedback-section');
  section.innerHTML = `
    <div class="oe-feedback-title" style="text-align:center;">
      <div class="oe-spinner" style="margin:0 auto 6px;"></div>
      Sending report...
    </div>
  `;

  try {
    chrome.runtime.sendMessage({
      type: 'SUBMIT_FEEDBACK',
      payload: {
        feedbackType,
        originalVerdict: result.verdict,
        originalPhishingScore: result.phishing_score,
        originalSpamScore: result.spam_score,
        emailSubject: (email.subject || '').slice(0, 200),
        emailSender: (email.sender || '').slice(0, 200),
        emailRecipient: (email.recipient || '').slice(0, 200),
        userComment: comment
      }
    });
  } catch(e) {
    section.innerHTML = `<div class="oe-feedback-title oe-feedback-error">Failed to send. Please try again.</div>`;
  }
}

function resetFeedbackSection() {
  const section = document.getElementById('oe-feedback-section');
  if (!section) return;
  section.innerHTML = `
    <div class="oe-feedback-title">Was this analysis accurate?</div>
    <div class="oe-feedback-buttons">
      <button class="oe-feedback-btn oe-fb-false-positive" id="oe-fb-fp">
        👎 False Positive
      </button>
      <button class="oe-feedback-btn oe-fb-missed-threat" id="oe-fb-mt">
        🚨 Missed Threat
      </button>
    </div>
  `;
  const result = window._oe_lastResult || {};
  const email = window._oe_email || {};
  document.getElementById('oe-fb-fp').addEventListener('click', () => showFeedbackForm('false_positive', result, email));
  document.getElementById('oe-fb-mt').addEventListener('click', () => showFeedbackForm('missed_threat', result, email));
}

function showEmailReady(subject) {
  const subj = String(subject || '');
  const short = subj.length > 60 ? subj.slice(0, 60) + '...' : subj;
  document.getElementById('oe-body').innerHTML = `
    <div class="oe-email-ready">
      <p>📨 <strong>${escapeHtml(short)}</strong></p>
      <p>Click Analyze to check this email for threats.</p>
    </div>`;
  document.getElementById('oe-analyze-btn').style.display = 'block';
  document.getElementById('oe-analyze-btn').textContent = 'Analyze Email';
}

// --- Email Change Detection ---
function checkForEmailChange() {
  const pane = getReadingPane();
  const allBtns = Array.from(pane.querySelectorAll('button[aria-label]'));
  const fromBtn = allBtns.find(b => b.getAttribute('aria-label').startsWith('From:'));
  const selectedRow = document.querySelector('[aria-selected="true"]');
  const selectedLabel = selectedRow ? (selectedRow.getAttribute('aria-label') || '') : '';
  const emailId = (fromBtn ? fromBtn.getAttribute('aria-label') : '') + selectedLabel;

  if (emailId && emailId.length > 5 && emailId !== lastEmailId) {
    lastEmailId = emailId;
    const isLoading = !!document.getElementById('oe-loading');
    if (!isLoading) {
      const displaySubject = findTextIn(pane, [
        '[data-testid="subject"]', '[aria-label="Message subject"]', 'h1', '[role="heading"]'
      ]) || selectedLabel.slice(0, 80);
      showEmailReady(displaySubject || 'Email selected');
      setTimeout(revealLinks, 800);

      setTimeout(() => {
        const HIGH_RISK = ['.htm','.html','.js','.vbs','.vbe','.ps1','.wsf','.wsh','.jar','.hta'];
        const SUSPICIOUS = ['.exe','.msi','.bat','.cmd','.iso','.img','.zip','.rar','.7z','.docm','.xlsm','.pptm','.lnk'];
        const p = getReadingPane();
        const attachEls = p.querySelectorAll('[aria-label*="attachment" i],[class*="attachmentName" i],[class*="fileName" i]');
        const highRisk = [];
        const suspicious = [];
        attachEls.forEach(el => {
          const name = (el.getAttribute('aria-label') || el.innerText || '').toLowerCase().trim();
          if (HIGH_RISK.some(ext => name.endsWith(ext))) highRisk.push(name);
          else if (SUSPICIOUS.some(ext => name.endsWith(ext))) suspicious.push(name);
        });
        const bodyEl = document.getElementById('oe-body');
        if (!bodyEl) return;
        const existing = document.getElementById('oe-attach-warning');
        if (existing) existing.remove();
        if (highRisk.length > 0) {
          const warn = document.createElement('div');
          warn.id = 'oe-attach-warning';
          warn.style.cssText = 'background:#cc0000;color:white;padding:10px 12px;border-radius:6px;margin-bottom:8px;font-size:12px;font-weight:bold;line-height:1.5;';
          warn.innerHTML = '⚠️ HIGH RISK ATTACHMENT: ' + escapeHtml(highRisk.join(', ')) + '<br>Do NOT open. Report to IT security immediately.';
          bodyEl.insertBefore(warn, bodyEl.firstChild);
        } else if (suspicious.length > 0) {
          const warn = document.createElement('div');
          warn.id = 'oe-attach-warning';
          warn.style.cssText = 'background:#b45309;color:white;padding:10px 12px;border-radius:6px;margin-bottom:8px;font-size:12px;font-weight:bold;line-height:1.5;';
          warn.innerHTML = '⚠️ SUSPICIOUS ATTACHMENT: ' + escapeHtml(suspicious.join(', ')) + '<br>Verify with sender before opening.';
          bodyEl.insertBefore(warn, bodyEl.firstChild);
        }
      }, 1000);
    }
  }
}

// --- Init ---
function init() {
  createSidebar();
  setTimeout(() => {
    const btn = document.getElementById('oe-analyze-btn');
    if (btn && btn.style.display === 'none') {
      btn.style.display = 'block';
      btn.textContent = 'Analyze Email';
    }
  }, 3000);
  setInterval(checkForEmailChange, 1000);
  observer = new MutationObserver(() => { checkForEmailChange(); });
  observer.observe(document.body, {
    childList: true, subtree: true, attributes: true, attributeFilter: ['aria-selected']
  });
  setTimeout(checkForEmailChange, 2000);
}

// --- Message listener ---
chrome.runtime.onMessage.addListener((message) => {
  if (message.type === 'ANALYSIS_DONE') {
    clearTimeout(window._oe_timeout);
    if (message.error) { showError('Analysis failed: ' + message.error); return; }
    if (!message.result) { showError('No result received. Please try again.'); return; }
    showResult(message.result, window._oe_email || {});
  }

  if (message.type === 'FEEDBACK_RESULT') {
    const section = document.getElementById('oe-feedback-section');
    if (!section) return;
    if (message.success) {
      section.innerHTML = `<div class="oe-feedback-title oe-feedback-success">✅ Thank you! Your report has been submitted for review.</div>`;
    } else {
      section.innerHTML = `
        <div class="oe-feedback-title oe-feedback-error">⚠️ ${escapeHtml(message.error || 'Failed to send report.')}</div>
        <div class="oe-feedback-actions">
          <button class="oe-feedback-btn oe-fb-cancel" id="oe-fb-retry">Try Again</button>
        </div>
      `;
      document.getElementById('oe-fb-retry').addEventListener('click', () => resetFeedbackSection());
    }
  }
});

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  setTimeout(init, 1500);
}
