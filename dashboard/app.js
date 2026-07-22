const TARGET_APP_URL = 'http://localhost:8080';

document.addEventListener('DOMContentLoaded', () => {
  initModeToggle();
  initAttackButton();
  startPolling();
});

function initModeToggle() {
  const btnVun = document.getElementById('btn-vulnerable');
  const btnHard = document.getElementById('btn-hardened');

  btnVun.addEventListener('click', () => setSecurityMode('VULNERABLE'));
  btnHard.addEventListener('click', () => setSecurityMode('HARDENED'));
}

async function setSecurityMode(mode) {
  try {
    const res = await fetch(`${TARGET_APP_URL}/api/admin/toggle-mode`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode })
    });
    const data = await res.json();
    
    const btnVun = document.getElementById('btn-vulnerable');
    const btnHard = document.getElementById('btn-hardened');

    if (mode === 'VULNERABLE') {
      btnVun.className = 'mode-btn active-vun';
      btnHard.className = 'mode-btn';
    } else {
      btnVun.className = 'mode-btn';
      btnHard.className = 'mode-btn active-hard';
    }
  } catch (err) {
    console.error('Failed to set security mode:', err);
  }
}

function initAttackButton() {
  const btn = document.getElementById('btn-run-attack');
  btn.addEventListener('click', async () => {
    btn.disabled = true;
    btn.innerText = 'Emulating Attacks...';
    try {
      // Execute attacks via target app fetch sequence
      await fetch(`${TARGET_APP_URL}/api/search?q=%27%20OR%20%271%27%3D%271`);
      await fetch(`${TARGET_APP_URL}/api/export`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ filename: 'test', format: 'txt; id' })
      });
      await fetch(`${TARGET_APP_URL}/api/fetch-url?url=http://169.254.169.254/latest/meta-data/`);
      await fetch(`${TARGET_APP_URL}/api/debug/config`);
      
      setTimeout(() => {
        btn.disabled = false;
        btn.innerText = 'Trigger Adversary Emulation';
        fetchDashboardData();
      }, 1200);
    } catch (e) {
      btn.disabled = false;
      btn.innerText = 'Trigger Adversary Emulation';
    }
  });
}

function startPolling() {
  fetchDashboardData();
  setInterval(fetchDashboardData, 2000);
}

async function fetchDashboardData() {
  // Fetch Target App status
  try {
    const healthRes = await fetch(`${TARGET_APP_URL}/health`);
    const health = await healthRes.json();
    const btnVun = document.getElementById('btn-vulnerable');
    const btnHard = document.getElementById('btn-hardened');
    if (health.securityMode === 'VULNERABLE') {
      btnVun.className = 'mode-btn active-vun';
      btnHard.className = 'mode-btn';
    } else {
      btnVun.className = 'mode-btn';
      btnHard.className = 'mode-btn active-hard';
    }
  } catch (e) {}

  // Fetch Telemetry & Alert metrics
  try {
    const alerts = await fetchJSON('/pillar-2-shift-right/logs/active-alerts.json') || await fetchJSON('../pillar-2-shift-right/logs/active-alerts.json');
    renderAlerts(alerts || []);
    
    const merkleLogs = await fetchJSON('/pillar-2-shift-right/logs/merkle-audit-trail.json') || await fetchJSON('../pillar-2-shift-right/logs/merkle-audit-trail.json');
    renderMerkleTrail(merkleLogs || []);

    const feedbackCycles = await fetchJSON('/feedback-loop/cycles.json') || await fetchJSON('../feedback-loop/cycles.json');
    renderFeedbackCycles(feedbackCycles || []);
  } catch (e) {
    console.log('Polling dashboard state...');
  }
}

async function fetchJSON(url) {
  try {
    const res = await fetch(url);
    if (res.ok) return await res.json();
  } catch (e) {
    return null;
  }
}

function renderAlerts(alerts) {
  const tbody = document.getElementById('alerts-table-body');
  document.getElementById('stat-active-alerts').innerText = alerts.length;

  if (!alerts || alerts.length === 0) return;

  const mttdList = alerts.map(a => a.mttd_ms || 0);
  const avgMttd = (mttdList.reduce((a, b) => a + b, 0) / mttdList.length).toFixed(2);
  document.getElementById('stat-mttd').innerHTML = `${avgMttd} <small>ms</small>`;

  tbody.innerHTML = '';
  alerts.slice().reverse().forEach(a => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${new Date(a.detected_at).toLocaleTimeString()}</td>
      <td><strong>${a.technique_id}</strong></td>
      <td><span class="badge-${a.severity.toLowerCase()}">${a.severity}</span></td>
      <td>${a.evidence}</td>
      <td>${a.mttd_ms || 0.4} ms</td>
      <td><code>${a.recommended_action}</code></td>
    `;
    tbody.appendChild(tr);

    // Highlight ATT&CK card
    const card = document.getElementById(`card-${a.technique_id}`);
    if (card) card.classList.add('triggered');
  });
}

function renderMerkleTrail(entries) {
  const tbody = document.getElementById('merkle-table-body');
  if (!entries || entries.length === 0) return;

  tbody.innerHTML = '';
  entries.slice().reverse().forEach(e => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>#${e.index}</td>
      <td><strong>${e.action}</strong></td>
      <td>${e.details}</td>
      <td title="${e.current_hash}">${e.current_hash.substring(0, 16)}...</td>
    `;
    tbody.appendChild(tr);
  });
}

function renderFeedbackCycles(cycles) {
  document.getElementById('stat-feedback-cycles').innerText = cycles.length;
  if (!cycles || cycles.length === 0) return;

  const lastCycle = cycles[cycles.length - 1];
  document.getElementById('code-semgrep').innerText = `// Rule generated for ${lastCycle.trigger_alert}\nFile: ${lastCycle.generated_semgrep_rule}\nStatus: ${lastCycle.status}`;
  document.getElementById('code-nuclei').innerText = `# DAST Template generated for ${lastCycle.trigger_alert}\nFile: ${lastCycle.generated_nuclei_template}\nStatus: ${lastCycle.status}`;
}
