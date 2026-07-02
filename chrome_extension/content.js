/* ─────────────────────────────────────────────────────────────────────────
   Gmail Phishing Extension – Content Script
   ───────────────────────────────────────────────────────────────────────── */

'use strict';

// Avoid global naming conflicts
(function() {
  let scanButton = null;
  let resultsOverlay = null;

  // Poll for Gmail DOM initialization
  const initInterval = setInterval(checkAndInject, 1000);

  function checkAndInject() {
    // Gmail subject line container
    const subjectEl = document.querySelector('.hP');
    
    if (subjectEl) {
      // Inject button if not present
      if (!document.getElementById('pea-scan-button')) {
        injectScanButton(subjectEl);
      }
    } else {
      // Clean up button if we are no longer viewing an email thread
      removeScanButton();
    }
  }

  function injectScanButton(parent) {
    scanButton = document.createElement('button');
    scanButton.id = 'pea-scan-button';
    scanButton.className = 'pea-scan-btn';
    scanButton.innerHTML = `
      <svg viewBox="0 0 24 24">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
      Scan Email
    `;
    scanButton.addEventListener('click', handleScanClick);
    parent.appendChild(scanButton);
  }

  function removeScanButton() {
    const btn = document.getElementById('pea-scan-button');
    if (btn) btn.remove();
  }

  function handleScanClick(e) {
    e.stopPropagation();
    
    // Extract Email Subject
    const subjectEl = document.querySelector('.hP');
    const subject = subjectEl ? subjectEl.innerText.replace("Scan Email", "").trim() : "";

    // Extract Email Body (Gmail uses .a3s for message contents)
    const bodyEls = document.querySelectorAll('.a3s');
    let body = "";
    
    if (bodyEls.length > 0) {
      // Grab the last one in thread (most recent email)
      const targetBody = bodyEls[bodyEls.length - 1];
      // Keep formatting intact, retrieve plain text
      body = targetBody.innerText || targetBody.textContent || "";
    }

    if (!body.trim()) {
      alert("Could not extract email body. Make sure the email is fully loaded.");
      return;
    }

    // Call Local Server
    scanButton.disabled = true;
    scanButton.innerText = "Analyzing...";

    const formData = new FormData();
    const rawContent = `Subject: ${subject}\n\n${body}`;
    formData.append('email_text', rawContent);

    fetch('http://127.0.0.1:7777/analyze', {
      method: 'POST',
      body: formData
    })
    .then(resp => {
      if (!resp.ok) throw new Error("Server error");
      return resp.json();
    })
    .then(data => {
      showResultsOverlay(data);
    })
    .catch(err => {
      alert("Error connecting to Phishing Analyzer. Is the Python server running on port 7777?");
    })
    .finally(() => {
      scanButton.disabled = false;
      scanButton.innerHTML = `
        <svg viewBox="0 0 24 24">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
        Scan Email
      `;
    });
  }

  function showResultsOverlay(data) {
    // Remove old overlay if exists
    if (resultsOverlay) resultsOverlay.remove();

    resultsOverlay = document.createElement('div');
    resultsOverlay.className = 'pea-overlay';

    const score = data.final_score || 0;
    const riskLevel = data.risk_level || 'Safe';
    const riskKey = riskLevel.toLowerCase().replace(' ', '-');
    const indicators = data.indicators || [];

    const listHtml = indicators.length === 0
      ? `<div class="pea-no-flags">No suspicious indicators found. This email seems safe.</div>`
      : indicators.map(ind => `
          <div class="pea-card ${ind.raw_category}">
            <div class="pea-card-header">
              <span class="pea-card-tag">${ind.category}</span>
              <span class="pea-card-loc">${ind.location}</span>
            </div>
            <div class="pea-card-match">"${escapeHtml(ind.matched_text)}"</div>
            <div class="pea-card-exp">${escapeHtml(ind.explanation)}</div>
          </div>
        `).join('');

    resultsOverlay.innerHTML = `
      <div class="pea-header">
        <div class="pea-header-title">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
          Phishing Scan Result
        </div>
        <button class="pea-close-btn" id="pea-close-overlay">✕</button>
      </div>
      <div class="pea-content">
        <div class="pea-score-row">
          <div class="pea-score-left">
            <span class="pea-score-label">Phishing Score</span>
            <span class="pea-score-val">${score} / 100</span>
          </div>
          <span class="pea-badge pea-${riskKey}">${riskLevel}</span>
        </div>
        <div class="pea-sub-title">Flagged Indicators (${indicators.length})</div>
        <div class="pea-list">${listHtml}</div>
      </div>
    `;

    document.body.appendChild(resultsOverlay);

    document.getElementById('pea-close-overlay').addEventListener('click', () => {
      resultsOverlay.remove();
      resultsOverlay = null;
    });
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }
})();
