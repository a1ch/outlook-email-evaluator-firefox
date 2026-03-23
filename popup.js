// ─── Tabs ─────────────────────────────────────────────────────────────────────
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
  });
});

// ─── API Key Tab ──────────────────────────────────────────────────────────────
chrome.storage.local.get('apiKey', ({ apiKey }) => {
  if (apiKey) document.getElementById('apiKey').value = apiKey;
});

document.getElementById('toggleShow').addEventListener('click', () => {
  const input = document.getElementById('apiKey');
  const btn = document.getElementById('toggleShow');
  input.type = input.type === 'password' ? 'text' : 'password';
  btn.textContent = input.type === 'password' ? 'Show key' : 'Hide key';
});

document.getElementById('saveBtn').addEventListener('click', () => {
  const apiKey = document.getElementById('apiKey').value.trim();
  const status = document.getElementById('status');

  if (!apiKey) { showStatus(status, 'Please enter an API key.', false); return; }
  if (!apiKey.startsWith('sk-ant-')) { showStatus(status, 'Key should start with sk-ant-...', false); return; }

  chrome.storage.local.set({ apiKey }, () => {
    showStatus(status, '✅ API key saved!', true);
  });
});

// ─── Settings Tab ─────────────────────────────────────────────────────────────
chrome.storage.local.get(['tenantDomain', 'customPrompt'], (data) => {
  if (data.tenantDomain) document.getElementById('tenantDomain').value = data.tenantDomain;
  if (data.customPrompt) document.getElementById('customPrompt').value = data.customPrompt;
});

document.getElementById('saveSettings').addEventListener('click', () => {
  const tenantDomain = document.getElementById('tenantDomain').value.trim();
  const customPrompt = document.getElementById('customPrompt').value.trim();
  const status = document.getElementById('settingsStatus');

  chrome.storage.local.set({ tenantDomain, customPrompt }, () => {
    showStatus(status, '✅ Settings saved! Takes effect on next analysis.', true);
  });
});

// ─── Helpers ──────────────────────────────────────────────────────────────────
function showStatus(el, msg, success) {
  el.textContent = msg;
  el.className = success ? 'success' : 'error';
  setTimeout(() => { el.style.display = 'none'; }, 4000);
}
