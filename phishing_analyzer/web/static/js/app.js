/* ─────────────────────────────────────────────────────────────────────────
   Phishing Email Analyzer – Frontend JavaScript
   ───────────────────────────────────────────────────────────────────────── */

'use strict';

// ── State ──────────────────────────────────────────────────────────────────
let activeTab  = 'paste';   // 'paste' | 'upload'
let uploadedFile = null;
let hasResults   = false;

// Built-in sample email content (mirrors server-side sample files)
const SAMPLES = {
  1: {
    subject: "Urgent action required: Your account is suspended!",
    body: `From: paypal-support@secure-update.xyz

Dear Customer,

We noticed some unauthorized login attempts to your PayPal account from a location outside your home country. For your security, we have temporarily suspended your account.

To restore access, you must verify your identity. Please click on the link below and update your information immediately:

http://paypal.com.verification-center.xyz/login.php

Failure to update your account details within 24 hours will result in permanent account termination.

Thank you,
PayPal Security Team`
  },
  2: {
    subject: "Final Notice: Claim your tax refund now!",
    body: `From: irs-refunds@tax-gov-portal.xyz

Dear User,

Our records indicate that you are eligible for an outstanding tax refund of $485.20 from the previous fiscal year.

Due to a billing error, the transfer was not processed. To claim your reward, you must confirm your bank details and submit your bank account information.

Please use the secure link below to verify your account and process the payment:

https://bit.ly/tax-refund-claim-2026

If you do not claim your refund within 48 hours, the funds will be returned to the treasury and legal action may be initiated.

IRS Billing Information Support`
  },
  3: {
    subject: "Security Alert: Unauthorized password change request",
    body: `From: security-admin@microsoft-office-alert.fit

Dear Client,

We received an immediate request to change the password for your corporate login.

If this was not you, your account may have been compromised by an unauthorized party. You must log in to our verification center to cancel the request and reset your credentials.

Click here to verify your account:
http://192.168.4.15/microsoft/login

You must enter your current password, PIN, and OTP code to authenticate. If you do not perform identity verification, your email access will be shut down and restricted immediately.

Office Admin Center`
  },
  4: {
    subject: "Engineering Team Synchronization - July 2026",
    body: `Hi Everyone,

Just a quick reminder that our weekly engineering team synchronization is scheduled for tomorrow at 10:00 AM in Conference Room B.

We will cover the project updates, review the release timeline for the next version, and address any roadblocks you are currently facing.

Please update the shared spreadsheet with your current status before the meeting starts.

See you all there!

Best regards,
Sarah Jenkins
Engineering Lead`
  },
  5: {
    subject: "GitHub Security Advisory update for dependency-check",
    body: `Hello,

This is an automated notification regarding the security advisory GHSA-xxxx-yyyy-zzzz.

A vulnerability has been identified in a dependency used by one of your repositories. Maintainers have released a new version that addresses this issue.

Please review the details of this advisory and update your dependencies to the latest recommended version. You can find full details on the GitHub Advisory Database page.

No action is needed if you have already updated your repository dependencies.

Thank you,
The GitHub Security Team`
  }
};

// ── DOM refs ───────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

// ── Tab Switching ──────────────────────────────────────────────────────────
function switchTab(name) {
  activeTab = name;
  ['paste', 'upload'].forEach(t => {
    $(`tab-${t}`).classList.toggle('active', t === name);
    $(`content-${t}`).classList.toggle('active', t === name);
  });
  hidePdfHint(); // clear image-only hint when switching tabs
}

// ── Char Counter ──────────────────────────────────────────────────────────
$('bodyInput').addEventListener('input', () => {
  const n = $('bodyInput').value.length;
  $('charCount').textContent = n.toLocaleString() + ' characters';
});

// ── File Drag & Drop ───────────────────────────────────────────────────────
const dz = $('dropZone');
dz.addEventListener('dragover',  e => { e.preventDefault(); dz.classList.add('drag-over'); });
dz.addEventListener('dragleave', () => dz.classList.remove('drag-over'));
dz.addEventListener('drop', e => {
  e.preventDefault();
  dz.classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file) applyFile(file);
});

function handleFileSelect(input) {
  if (input.files[0]) applyFile(input.files[0]);
}

function applyFile(file) {
  const allowed = ['.txt', '.pdf'];
  const ext = file.name.slice(file.name.lastIndexOf('.')).toLowerCase();
  if (!allowed.includes(ext)) { showToast('Only .txt and .pdf files are accepted.'); return; }
  if (file.size > 5 * 1024 * 1024) { showToast('File exceeds 5 MB limit.'); return; }

  uploadedFile = file;
  $('fileName').textContent = file.name;
  $('fileSize').textContent = formatBytes(file.size);
  $('filePreview').style.display = 'block';
  $('dropZone').style.display    = 'none';
}

function clearFile() {
  uploadedFile = null;
  $('fileInput').value = '';
  $('filePreview').style.display = 'none';
  $('dropZone').style.display    = 'flex';
  hidePdfHint();
}

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1024 / 1024).toFixed(2) + ' MB';
}

// ── PDF Hints ──────────────────────────────────────────────────────────────
function showPdfHint(msg) {
  const h = $('pdfHint');
  h.innerHTML = `${msg} <button onclick="switchTab('paste')">Switch to Paste Mode</button>`;
  h.style.display = 'block';
}

function hidePdfHint() {
  $('pdfHint').style.display = 'none';
}

// ── Sample Quick-Load ──────────────────────────────────────────────────────
function loadSample(n) {
  const s = SAMPLES[n];
  if (!s) return;
  switchTab('paste');
  $('subjectInput').value = s.subject;
  $('bodyInput').value    = s.body;
  $('charCount').textContent = s.body.length.toLocaleString() + ' characters';
}

// ── Run Analysis ───────────────────────────────────────────────────────────
async function runAnalysis() {
  const btn = $('analyzeBtn');

  // Gather input based on active tab
  let formData;

  if (activeTab === 'upload') {
    if (!uploadedFile) { showToast('Please select a file to upload.'); return; }
    formData = new FormData();
    formData.append('email_file', uploadedFile);
  } else {
    const body = $('bodyInput').value.trim();
    if (!body) { showToast('Please paste email content first.'); return; }
    const subject = $('subjectInput').value.trim();
    // Combine into raw text that the server's parse_email_text can handle
    const raw = subject ? `Subject: ${subject}\n\n${body}` : body;
    formData = new FormData();
    formData.append('email_text', raw);
  }

  hidePdfHint();

  // Show spinner
  btn.querySelector('.btn-text').style.display    = 'none';
  btn.querySelector('.btn-spinner').style.display = 'flex';
  btn.disabled = true;

  try {
    const resp = await fetch('/analyze', { method: 'POST', body: formData });
    const data = await resp.json();

    if (!resp.ok) {
      // Special case: PDF has no text layer (image-only / Print-to-PDF)
      if (data.hint === 'switch_to_paste') {
        showPdfHint(data.error);
      } else {
        showToast(data.error || 'Analysis failed. Please try again.');
      }
      return;
    }

    hasResults = true;
    renderResults(data);
    await refreshLogs();

  } catch (err) {
    showToast('Network error – is the server running?');
  } finally {
    btn.querySelector('.btn-text').style.display    = 'flex';
    btn.querySelector('.btn-spinner').style.display = 'none';
    btn.disabled = false;
  }
}

// ── Render Results ─────────────────────────────────────────────────────────
function renderResults(data) {
  $('emptyState').style.display      = 'none';
  $('resultsContainer').style.display = 'flex';

  const score     = data.final_score || 0;
  const riskLevel = data.risk_level  || 'Safe';
  const riskKey   = riskLevel.toLowerCase().replace(' ', '-');
  const indicators = data.indicators || [];

  // -- Gauge Animation --
  animateGauge(score, riskKey);

  // -- Risk Badge --
  const badge = $('riskBadge');
  badge.textContent = riskLevel.toUpperCase();
  badge.className   = `risk-badge risk-${riskKey}`;

  // -- Category Bars --
  const catScores = data.category_scores || {};
  const catLabels = {
    urgency:            { label: 'Urgency',            max: 22.5 },
    suspicious_url:     { label: 'Suspicious URLs',    max: 37.5 },
    generic_greeting:   { label: 'Generic Greeting',   max: 15   },
    sensitive_request:  { label: 'Credential Request', max: 37.5 },
    social_engineering: { label: 'Social Engineering', max: 37.5 },
  };

  const barsHtml = Object.entries(catLabels).map(([key, meta]) => {
    const val     = catScores[key] || 0;
    const pct     = Math.min(100, Math.round((val / meta.max) * 100));
    return `
      <div class="cat-bar-row">
        <div class="cat-bar-header">
          <span>${meta.label}</span>
          <span>${val.toFixed(0)} pts</span>
        </div>
        <div class="cat-bar-track">
          <div class="cat-bar-fill" style="width:${pct}%; background:${riskColour(riskKey)}"></div>
        </div>
      </div>`;
  }).join('');
  $('categoryBars').innerHTML = barsHtml;

  // -- Summary Cards --
  $('summaryRow').innerHTML = `
    <div class="summary-card">
      <div class="summary-card-value">${score}</div>
      <div class="summary-card-label">Risk Score</div>
    </div>
    <div class="summary-card">
      <div class="summary-card-value">${indicators.length}</div>
      <div class="summary-card-label">Indicators Found</div>
    </div>
    <div class="summary-card">
      <div class="summary-card-value" style="font-size:15px; color:${riskColour(riskKey)}">${riskLevel}</div>
      <div class="summary-card-label">Risk Level</div>
    </div>`;

  // -- Indicators --
  $('indicatorCount').textContent = indicators.length + ' found';
  if (indicators.length === 0) {
    $('indicatorsList').innerHTML = `<div class="no-indicators">No phishing indicators detected — this email appears safe.</div>`;
  } else {
    $('indicatorsList').innerHTML = indicators.map((ind, i) => `
      <div class="indicator-card ${ind.raw_category}" style="animation-delay:${i * 0.06}s">
        <div class="indicator-header">
          <span class="indicator-tag">${ind.category}</span>
          <span class="indicator-location">${ind.location}</span>
        </div>
        <div class="indicator-match">"${escapeHtml(ind.matched_text)}"</div>
        <div class="indicator-explanation">${escapeHtml(ind.explanation)}</div>
      </div>`).join('');
  }
}

// ── Animated Gauge ─────────────────────────────────────────────────────────
function animateGauge(targetScore, riskKey) {
  const ARC_LENGTH = 283; // length of the semi-circle path (approx)
  const bar  = $('gaugeBar');
  const text = $('gaugeScore');
  const colour = riskColour(riskKey);

  bar.style.stroke = colour;
  bar.style.filter = `drop-shadow(0 0 8px ${colour}80)`;

  let current = 0;
  const step = () => {
    current = Math.min(current + 1.5, targetScore);
    const offset = ARC_LENGTH - (current / 100) * ARC_LENGTH;
    bar.style.strokeDashoffset = offset;
    text.textContent = Math.round(current);
    if (current < targetScore) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

function riskColour(riskKey) {
  const map = {
    'safe': '#10b981', 'low': '#84cc16',
    'medium': '#f59e0b', 'high': '#ef4444', 'very-high': '#dc2626'
  };
  return map[riskKey] || '#3d7dff';
}

// ── Logs ──────────────────────────────────────────────────────────────────
async function refreshLogs() {
  try {
    const resp  = await fetch('/logs');
    const data  = await resp.json();
    const lines = data.lines || [];

    if (!lines.length) { $('logConsole').innerHTML = '<div class="log-line">No log entries yet.</div>'; return; }

    $('logConsole').innerHTML = lines.map(line => {
      let cls = 'log-line';
      if (line.includes('[INFO]'))    cls += ' info';
      if (line.includes('[WARNING]')) cls += ' warn';
      if (line.includes('[ERROR]'))   cls += ' error';
      return `<div class="${cls}">${escapeHtml(line)}</div>`;
    }).join('');

    // Scroll to bottom
    const c = $('logConsole');
    c.scrollTop = c.scrollHeight;

  } catch { /* silent */ }
}

// ── Download ──────────────────────────────────────────────────────────────
function downloadReport(fmt) {
  if (!hasResults) { showToast('Run an analysis first.'); return; }
  window.location.href = `/download/${fmt}`;
}

// ── Toast ─────────────────────────────────────────────────────────────────
let toastTimer;
function showToast(msg) {
  const t = $('toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 3500);
}

// ── Helpers ───────────────────────────────────────────────────────────────
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ── Auto-refresh logs every 10s after first analysis ──────────────────────
setInterval(() => { if (hasResults) refreshLogs(); }, 10000);
