/* ─────────────────────────────────────────────────────────────────────────
   Phishing Extension – Popup Script
   ───────────────────────────────────────────────────────────────────────── */

'use strict';

document.addEventListener('DOMContentLoaded', () => {
  const dot  = document.getElementById('statusDot');
  const text = document.getElementById('statusText');
  const btn  = document.getElementById('recheckBtn');

  async function checkServer() {
    text.textContent = 'Checking...';
    dot.className = 'dot';
    
    try {
      // Fetch index page or logs as connection test
      const resp = await fetch('http://127.0.0.1:7777/logs');
      if (resp.ok) {
        text.textContent = 'Online';
        text.style.color = '#10b981';
        dot.className = 'dot online';
      } else {
        throw new Error('Not OK');
      }
    } catch (err) {
      text.textContent = 'Offline';
      text.style.color = '#ef4444';
      dot.className = 'dot';
    }
  }

  btn.addEventListener('click', checkServer);
  checkServer();
});
