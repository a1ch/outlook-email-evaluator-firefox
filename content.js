// Outlook Email Evaluator - Content Script

let sidebar = null;
let lastEmailId = null;
let observer = null;

// --- Sidebar Injection ---

function createSidebar() {
  if (document.getElementById('oe-sidebar')) return;

  sidebar = document.createElement('div');
  sidebar.id = 'oe-sidebar';
  sidebar.innerHTML = `
    <div id="oe-tab">
      <span id="oe-tab-icon">&#x1F4E7;</span>
      <span>EVALUATOR</span>
    </div>
    <div id="oe-header">
      <span id="oe-title">&#x1F4E7; Email Evaluator</span>
      <button id="oe-close" title="Minimize">&#x27E9;</button>
    </div>
    <div id="oe-body">
      <div id="oe-idle">
        <p>Select or open an email to analyze it.</p>
      </div>
    </div>
    <div id="oe-footer">
      <button id="oe-analyze-btn" style="display:none">&#x1F50D; Analyze Email</button>
    </div>
  `;
  document.body.appendChild(sidebar);

  document.getElementById('oe-close').addEventListener('click', () => {
    sidebar.classList.add('oe-collapsed');
  });

  document.getElementById('oe-tab').addEventListener('click', () => {
    sidebar.classList.remove('oe-collapsed');
  });

  document.getElementById('oe-analyze-btn').addEventListener('click', () => {
    analyzeCurrentEmail();
  });
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
      if (el && el.innerText && el.innerText.trim().length > 0) {
        return el.innerText.trim();
      }
    } catch(e) {}
  }
  return null;
}

function extractEmail() {
  const pane = getReadingPane();

  // Subject
  const subject = findTextIn(pane, [
    '[data-testid="subject"]',
    '[aria-label="Message subject"]',
    'h1', 'h2', '[role="heading"]',
    '[class*="subject" i]',
  ]) || '(No subject found)';

  // Sender - only match button whose aria-label STARTS with "From:"
  let sender = '(No sender found)';
  try {
    const allBtns = Array.from(pane.querySelectorAll('button[aria-label]'));
    const fromBtn = allBtns.find(b => b.getAttribute('aria-label').startsWith('From:'));
    if (fromBtn) {
      sender = fromBtn.getAttribute('aria-label').replace(/^From:\s*/i, '').trim();
    }
  } catch(e) {}
  if (sender === '(No sender found)') {
    sender = findTextIn(pane, [
      '[data-testid="senderName"]',
      '[class*="sender" i]',
      '[class*="Sender"]',
    ]) || '(No sender found)';
  }

  // Body - specific selectors only, no broad class matches
  const body = findTextIn(pane, [
    '[aria-label="Message body"]',
    '[data-testid="message-body"]',
    'div[class*="UniqueMessageBody"]',
    '[id*="UniqueMessageBody"]',
    'div[class*="messageBody"]',
    'div[class*="MessageBody"]',
    '[class*="ReadingPaneContent"]',
    '[class*="readingPaneContent"]',
  ]) || '(No body found)';

  // Extract hyperlinks with safelinks decoding
  const links = [];
  let bodyEl = pane.querySelector('[aria-label="Message body"]') ||
               pane.querySelector('div[class*="UniqueMessageBody"]') ||
               pane.querySelector('[id*="UniqueMessageBody"]') ||
               pane.querySelector('div[class*="messageBody"]') ||
               pane;

  if (bodyEl) {
    const anchors = bodyEl.querySelectorAll('a[href]');
    const seen = new Set();
    anchors.forEach(a => {
      try {
        const displayText = a.innerText.trim();
        let href = a.getAttribute('href') || '';

        // Decode Trend Micro / Outlook safelinks
        if (href.includes('safelinks.protection.outlook.com') || href.includes('urldefense') || href.includes('trendmicro')) {
          try {
            const u = new URL(href);
            const urlParam = u.searchParams.get('url') || u.searchParams.get('u');
            if (urlParam) href = decodeURIComponent(urlParam);
          } catch(e) {}
        }

        if (!href || href.startsWith('mailto:') || href.startsWith('#') || href.length < 10) return;

        let hrefDomain = '';
        try { hrefDomain = new URL(href).hostname.toLowerCase(); }
        catch(e) { hrefDomain = href.slice(0, 60); }

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

        links.push({
          display: displayText.slice(0, 80) || '(no text)',
          href: hrefDomain,
          mismatch
        });
      } catch(e) {}
    });
  }

  // Extract attachment filenames
  const attachments = [];
  try {
    const attachEls = pane.querySelectorAll('[aria-label*="attachment" i], [class*="attachment" i], [class*="Attachment" i]');
    attachEls.forEach(el => {
      const name = el.getAttribute('aria-label') || el.innerText || '';
      if (name.trim()) attachments.push(name.trim().toLowerCase());
    });
    // Also check for filename-looking text near attachment icons
    const nameEls = pane.querySelectorAll('[class*="attachmentName" i], [class*="fileName" i], [data-testid*="attachment" i]');
    nameEls.forEach(el => {
      const name = el.innerText || '';
      if (name.trim()) attachments.push(name.trim().toLowerCase());
    });
  } catch(e) {}

  const HIGH_RISK_EXTENSIONS = ['.htm', '.html', '.js', '.vbs', '.vbe', '.ps1', '.wsf', '.wsh', '.jar', '.hta'];
  const SUSPICIOUS_EXTENSIONS = ['.exe', '.msi', '.bat', '.cmd', '.iso', '.img', '.zip', '.rar', '.7z', '.docm', '.xlsm', '.pptm', '.lnk'];

  const hasHtmlAttachment = attachments.some(a => a.endsWith('.htm') || a.endsWith('.html'));
  const hasHighRiskAttachment = attachments.some(a => HIGH_RISK_EXTENSIONS.some(ext => a.endsWith(ext)));
  const hasSuspiciousAttachment = attachments.some(a => SUSPICIOUS_EXTENSIONS.some(ext => a.endsWith(ext)));
  const highRiskFiles = attachments.filter(a => HIGH_RISK_EXTENSIONS.some(ext => a.endsWith(ext)));
  const suspiciousFiles = attachments.filter(a => SUSPICIOUS_EXTENSIONS.some(ext => a.endsWith(ext)));

  return { subject, sender, body: body.slice(0, 3000), links: links.slice(0, 20), attachments, hasHtmlAttachment, hasHighRiskAttachment, hasSuspiciousAttachment, highRiskFiles, suspiciousFiles };
}

// --- Link Revelation ---

function revealLinks() {
  const pane = getReadingPane();
  const bodyEl = pane.querySelector('[aria-label="Message body"]') ||
                 pane.querySelector('div[class*="UniqueMessageBody"]') ||
                 pane.querySelector('[id*="UniqueMessageBody"]') ||
                 pane.querySelector('div[class*="messageBody"]');
  if (!bodyEl) return;

  const anchors = bodyEl.querySelectorAll('a[href]');
  anchors.forEach(a => {
    if (a.getAttribute('data-oe-revealed')) return;
    a.setAttribute('data-oe-revealed', '1');
    try {
      let href = a.getAttribute('href') || '';
      if (href.includes('safelinks.protection.outlook.com') || href.includes('urldefense') || href.includes('trendmicro')) {
        try {
          const u = new URL(href);
          const urlParam = u.searchParams.get('url') || u.searchParams.get('u');
          if (urlParam) href = decodeURIComponent(urlParam);
        } catch(e) {}
      }
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

  const now = new Date();
  const utcString = now.toUTCString();
  const localString = now.toLocaleString('en-US', { timeZone: 'America/Edmonton', timeZoneName: 'short' });

  // Check if Outlook shows external org warning banner
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

  const prompt = `You are a cybersecurity expert specializing in email threat analysis. Analyze the following email and respond ONLY with a JSON object - no markdown, no explanation outside the JSON.

IMPORTANT CONTEXT:
- Current date/time: ${utcString} (UTC) / ${localString} (Mountain Time). Do not flag dates as suspicious if they fall within the current day across timezones.
- Recipient organization domain: __TENANT_DOMAIN__
- Sender display name: ${email.sender} (this may be a display name only - look for actual email address in body or signature)
- Outlook external org warning present: ${isOutlookExternal ? 'YES - Microsoft has confirmed this is from an external organization. Flag as external in your reasons.' : 'NO - Microsoft has NOT flagged as external, treat as internal unless you find an external email address in body/signature'}
- If you find sender email in body/signature, check if it ends with __TENANT_DOMAIN__ to confirm internal vs external
- Do NOT assume external based on display name alone
- SharePoint/OneDrive links from __TENANT_DOMAIN__ or sharepoint.com are INTERNAL collaboration links, never flag as suspicious
__CUSTOM_PROMPT__

KEY RULES:
1. NEVER give any email a free pass based on sender domain alone - even internal senders can be compromised.
2. Only flag as external if Outlook shows the warning OR you find an external email address in body/signature.
3. Well-known domains (microsoft.com etc) - don't flag the domain itself, but DO flag suspicious content, urgency, credential requests.
4. Analyze content and intent independently of sender.
5. If email involves adding users, granting access, payments, credential changes, or urgent action - suggested_action MUST include: "Verify this request through official channels other than email before taking action."
6. If email contains a login link, verification code, OTP, security alert, or account notification - suggested_action MUST include: "If you did not request this, do not click any links and report this to your IT security team immediately."
7. If email contains a verification or security code - suggested_action MUST include: "Never share this code with anyone - legitimate services will never ask you for it."

Email details:
Subject: ${email.subject}
From: ${email.sender}
Body:
${email.body}

Attachments found: ${email.attachments && email.attachments.length > 0 ? email.attachments.join(', ') : '(none)'}
${email.hasHighRiskAttachment ? "CRITICAL: HIGH RISK attachment(s) detected: " + email.highRiskFiles.join(', ') + ". These file types are commonly used to deliver malware, phishing pages, or execute malicious code. You MUST set verdict to PHISHING, phishing_score to at least 90, and suggested_action MUST include: Do NOT open this attachment. Report this email to your IT security team immediately." : ""}
${email.hasSuspiciousAttachment && !email.hasHighRiskAttachment ? "WARNING: SUSPICIOUS attachment(s) detected: " + email.suspiciousFiles.join(', ') + ". These file types can contain malware or execute code. Set phishing_score to at least 60 and suggested_action MUST include: Do not open this attachment unless you are certain of its origin. Verify with the sender through a separate channel before opening." : ""}

Note: If body content is limited, base analysis on what is available.

EMBEDDED LINKS (already decoded from Trend Micro/Outlook safelinks wrappers - these are REAL destinations):
${email.links.length > 0 ?
  email.links.map(l => `  - Display: "${l.display}" -> Real domain: ${l.href}${l.mismatch ? ' WARNING: DOMAIN MISMATCH' : ''}`).join('\n')
  : '  (No links found)'}

When analyzing links:
1. Do NOT flag safelinks.protection.outlook.com or urldefense.com - these are security wrappers already decoded above
2. Flag display text showing one domain but real destination is completely different unrelated domain
3. Flag suspicious TLDs or domains impersonating known brands
4. Flag URL shorteners (bit.ly, tinyurl, t.co)

Respond with this exact JSON structure:
{
  "verdict": "SAFE" | "SUSPICIOUS" | "SPAM" | "PHISHING",
  "phishing_score": <number 0-100>,
  "spam_score": <number 0-100>,
  "reasons": [<string>, <string>, ...],
  "suggested_action": "<string>",
  "summary": "<1-2 sentence summary of findings>"
}`;

  chrome.runtime.sendMessage({ type: 'ANALYZE_EMAIL', prompt });

  const timeoutId = setTimeout(() => {
    showError('Timed out. Check the service worker console at chrome://extensions.');
  }, 20000);

  window._oe_timeout = timeoutId;
  window._oe_email = email;
}

// --- UI States ---

function setLoading() {
  document.getElementById('oe-body').innerHTML = `
    <div id="oe-loading">
      <div class="oe-spinner"></div>
      <p>Analyzing email...</p>
    </div>
  `;
  document.getElementById('oe-analyze-btn').style.display = 'none';
}

function showError(msg) {
  document.getElementById('oe-body').innerHTML = `
    <div class="oe-error">
      <span>&#x26A0;&#xFE0F;</span>
      <p>${msg}</p>
    </div>
  `;
  document.getElementById('oe-analyze-btn').style.display = 'block';
}

function showResult(result, email) {
  const verdictClass = {
    'SAFE': 'verdict-safe',
    'SUSPICIOUS': 'verdict-suspicious',
    'SPAM': 'verdict-spam',
    'PHISHING': 'verdict-phishing'
  }[result.verdict] || 'verdict-suspicious';

  const verdictIcon = {
    'SAFE': '&#x2705;',
    'SUSPICIOUS': '&#x26A0;&#xFE0F;',
    'SPAM': '&#x1F6AB;',
    'PHISHING': '&#x1F3A3;'
  }[result.verdict] || '&#x26A0;&#xFE0F;';

  const reasonsHTML = (result.reasons || []).map(r => `<li>${r}</li>`).join('');

  // Warning banner logic
  const body = (email.body || '').toLowerCase();
  const subject = (email.subject || '').toLowerCase();
  const combined = body + ' ' + subject;
  const isLoginOrCode = combined.includes('sign in') || combined.includes('verification code') ||
    combined.includes('one-time') || combined.includes('otp') || combined.includes('log in') ||
    combined.includes('verify your') || combined.includes('secure link') ||
    combined.includes('reset your password') || combined.includes('confirm your') ||
    combined.includes('your account') || combined.includes('click here to');
  const isHighRisk = result.verdict === 'PHISHING' || result.phishing_score >= 60;
  const showWarning = isLoginOrCode || isHighRisk;

  document.getElementById('oe-body').innerHTML = `
    <div class="oe-result">
      <div class="oe-verdict ${verdictClass}">
        <span class="oe-verdict-icon">${verdictIcon}</span>
        <span class="oe-verdict-label">${result.verdict}</span>
      </div>

      <div class="oe-scores">
        <div class="oe-score">
          <label>Phishing Risk</label>
          <div class="oe-bar-wrap">
            <div class="oe-bar phishing-bar" style="width:${result.phishing_score}%"></div>
          </div>
          <span>${result.phishing_score}/100</span>
        </div>
        <div class="oe-score">
          <label>Spam Score</label>
          <div class="oe-bar-wrap">
            <div class="oe-bar spam-bar" style="width:${result.spam_score}%"></div>
          </div>
          <span>${result.spam_score}/100</span>
        </div>
      </div>

      <div class="oe-section">
        <h4>Summary</h4>
        <p>${result.summary}</p>
      </div>

      ${reasonsHTML ? `
      <div class="oe-section">
        <h4>Why it's suspicious</h4>
        <ul>${reasonsHTML}</ul>
      </div>` : ''}

      ${email.links && email.links.length > 0 ? `
      <div class="oe-section ${email.links.some(l => l.mismatch) ? 'oe-links-danger' : ''}">
        <h4>&#x1F517; Links (${email.links.length})</h4>
        ${email.links.map(l => `
          <div class="oe-link-row ${l.mismatch ? 'oe-link-mismatch' : ''}">
            <div class="oe-link-display">${l.display}</div>
            <div class="oe-link-href">-> ${l.href}${l.mismatch ? ' &#x26A0;&#xFE0F;' : ''}</div>
          </div>
        `).join('')}
      </div>` : ''}

      ${showWarning ? `
      <div class="oe-section oe-warning-banner">
        <p>&#x26A0;&#xFE0F; If you did not request this, do not click any links and <strong>report this to your IT security team immediately.</strong></p>
      </div>` : ''}

      <div class="oe-section oe-action">
        <h4>Suggested Action</h4>
        <p>${result.suggested_action}</p>
      </div>
    </div>
  `;

  const btn = document.getElementById('oe-analyze-btn');
  btn.style.display = 'block';
  btn.textContent = 'Analyze Another';
  btn.disabled = false;
}

function showEmailReady(subject) {
  document.getElementById('oe-body').innerHTML = `
    <div id="oe-idle">
      <p class="oe-email-subject">&#x1F4E8; ${subject.slice(0, 60)}${subject.length > 60 ? '...' : ''}</p>
      <p class="oe-hint">Click Analyze to check this email for threats.</p>
    </div>
  `;
  document.getElementById('oe-analyze-btn').style.display = 'block';
  document.getElementById('oe-analyze-btn').textContent = 'Analyze Email';
}

// --- Email Change Detection ---

function checkForEmailChange() {
  const pane = getReadingPane();
  const allBtns = Array.from(pane.querySelectorAll('button[aria-label]'));
  const fromBtn = allBtns.find(b => b.getAttribute('aria-label').startsWith('From:'));
  const selectedRow = document.querySelector('[aria-selected="true"]');
  const selectedLabel = selectedRow?.getAttribute('aria-label') || '';
  const emailId = (fromBtn?.getAttribute('aria-label') || '') + selectedLabel;

  if (emailId && emailId.length > 5 && emailId !== lastEmailId) {
    lastEmailId = emailId;
    // Do not reset sidebar if currently analyzing
    const isLoading = !!document.getElementById('oe-loading');
    if (!isLoading) {
      const displaySubject = findTextIn(pane, [
        '[data-testid="subject"]',
        '[aria-label="Message subject"]',
        'h1', '[role="heading"]',
      ]) || selectedLabel.slice(0, 80);
      showEmailReady(displaySubject || 'Email selected');
      setTimeout(revealLinks, 800);
      // Check for risky attachments immediately and warn
      setTimeout(() => {
        const HIGH_RISK = ['.htm', '.html', '.js', '.vbs', '.vbe', '.ps1', '.wsf', '.wsh', '.jar', '.hta'];
        const SUSPICIOUS = ['.exe', '.msi', '.bat', '.cmd', '.iso', '.img', '.zip', '.rar', '.7z', '.docm', '.xlsm', '.pptm', '.lnk'];
        const pane = getReadingPane();
        const attachEls = pane.querySelectorAll('[aria-label*="attachment" i], [class*="attachmentName" i], [class*="fileName" i]');
        let highRisk = [], suspicious = [];
        attachEls.forEach(el => {
          const name = (el.getAttribute('aria-label') || el.innerText || '').toLowerCase().trim();
          if (HIGH_RISK.some(ext => name.endsWith(ext))) highRisk.push(name);
          else if (SUSPICIOUS.some(ext => name.endsWith(ext))) suspicious.push(name);
        });
        const bodyEl = document.getElementById('oe-body');
        if (!bodyEl) return;
        document.getElementById('oe-attach-warning') && document.getElementById('oe-attach-warning').remove();
        if (highRisk.length > 0) {
          const warn = document.createElement('div');
          warn.id = 'oe-attach-warning';
          warn.style.cssText = 'background:#cc0000;color:white;padding:10px 12px;border-radius:6px;margin-bottom:8px;font-size:12px;font-weight:bold;line-height:1.5;';
          warn.innerHTML = '&#x26A0;&#xFE0F; HIGH RISK ATTACHMENT: ' + highRisk.join(', ') + '<br><span style="font-weight:normal">Do NOT open. Report to IT security immediately.</span>';
          bodyEl.insertBefore(warn, bodyEl.firstChild);
        } else if (suspicious.length > 0) {
          const warn = document.createElement('div');
          warn.id = 'oe-attach-warning';
          warn.style.cssText = 'background:#b45309;color:white;padding:10px 12px;border-radius:6px;margin-bottom:8px;font-size:12px;font-weight:bold;line-height:1.5;';
          warn.innerHTML = '&#x26A0;&#xFE0F; SUSPICIOUS ATTACHMENT: ' + suspicious.join(', ') + '<br><span style="font-weight:normal">Verify with sender before opening.</span>';
          bodyEl.insertBefore(warn, bodyEl.firstChild);
        }
      }, 1000);
    }
  }
}

// --- Init ---

function init() {
  createSidebar();

  // Always show the analyze button after a short delay regardless of detection
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
    childList: true, subtree: true, attributes: true,
    attributeFilter: ['aria-selected']
  });
  setTimeout(checkForEmailChange, 2000);
}

// Listen for analysis results from background worker
chrome.runtime.onMessage.addListener((message) => {
  if (message.type === 'ANALYSIS_DONE') {
    clearTimeout(window._oe_timeout);
    if (message.error) {
      showError('Analysis failed: ' + message.error);
      return;
    }
    if (!message.result) {
      showError('No result received. Please try again.');
      return;
    }
    showResult(message.result, window._oe_email || {});
  }
});

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  setTimeout(init, 1500);
}
