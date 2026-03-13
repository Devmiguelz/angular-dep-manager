// ─── DEV DASHBOARD ────────────────────────────────────────────────────────
// Shortcut: Ctrl + Shift + D
// También clickeable en "Developer: devMiguelz" del header

let _devChartInstance = null;

document.addEventListener('keydown', e => {
  if (e.ctrlKey && e.shiftKey && e.key === 'D') {
    e.preventDefault();
    openDevModal();
  }
});

async function openDevModal() {
  document.getElementById('devModal').classList.add('open');
  await _loadDevStats();
}

function closeDevModal() {
  document.getElementById('devModal').classList.remove('open');
}

async function _loadDevStats() {
  // Necesita STATS_URL definido en stats-client.js
  const base = typeof STATS_URL !== 'undefined' ? STATS_URL : null;
  if (!base) {
    _renderDevFallback();
    return;
  }

  try {
    const [statsRes, histRes] = await Promise.all([
      fetch(`${base}/stats`),
      fetch(`${base}/stats/history`)
    ]);
    const s = await statsRes.json();
    const h = histRes.ok ? await histRes.json() : { byDay: [] };
    _renderDevKpis(s);
    _renderDevLine(h.byDay || []);
    _renderDevDist('devAngularDist', s.byAngularVersion || {}, 'v', '#dd0031');
    _renderDevDist('devSeverityDist', s.bySeverity || {}, '', '#ff5252',
      { critical:'#ff5252', high:'#ffab40', moderate:'#40c4ff', low:'#888899' });
    if (s.lastSeen) {
      document.getElementById('devLastSeen').textContent =
        'última actividad: ' + new Date(s.lastSeen).toLocaleString('es-CO');
    }
  } catch(err) {
    _renderDevFallback();
  }
}

function _renderDevKpis(s) {
  const set = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.textContent = (val ?? 0).toLocaleString();
  };
  set('dv-visits',    s.visits);
  set('dv-runs',      s.analysisRuns);
  set('dv-pkgs',      s.packageAnalyzed);
  set('dv-overrides', s.overridesDetected);
  set('dv-outdated',  s.outdatedFound);
  set('dv-audit',     s.auditFilesLoaded);
  set('dv-expDl',     s.exportsDownloaded);
  set('dv-repDl',     s.reportDownloaded);
}

function _renderDevLine(byDay) {
  const canvas = document.getElementById('devLineChart');
  if (!canvas) return;
  if (_devChartInstance) { _devChartInstance.destroy(); _devChartInstance = null; }

  // Generar últimos 30 días
  const days = [];
  for (let i = 29; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    days.push(d.toISOString().slice(0, 10));
  }
  const map = Object.fromEntries(byDay.map(e => [e.date, e.count]));
  const data = days.map(d => map[d] || 0);
  const labels = days.map(d => {
    const [, m, day] = d.split('-');
    return `${parseInt(day)}/${parseInt(m)}`;
  });

  if (!window.Chart) {
    canvas.style.display = 'none';
    const msg = document.createElement('div');
    msg.style.cssText = 'font-family:var(--mono);font-size:11px;color:var(--text3);text-align:center;padding:20px';
    msg.textContent = 'Chart.js no disponible — agrega el script CDN';
    canvas.parentNode.appendChild(msg);
    return;
  }

  _devChartInstance = new Chart(canvas, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        data,
        borderColor: '#dd0031',
        backgroundColor: 'rgba(221,0,49,0.08)',
        borderWidth: 2,
        pointRadius: 3,
        pointBackgroundColor: '#dd0031',
        fill: true,
        tension: 0.35
      }]
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false }, tooltip: {
        backgroundColor: '#16161f',
        borderColor: '#2a2a3e',
        borderWidth: 1,
        titleColor: '#888899',
        bodyColor: '#e8e8f0',
        callbacks: { title: items => items[0].label, label: i => ` ${i.raw} análisis` }
      }},
      scales: {
        x: { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#555566', font: { family: 'JetBrains Mono', size: 10 }, maxRotation: 0, autoSkip: true, maxTicksLimit: 10 } },
        y: { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#555566', font: { family: 'JetBrains Mono', size: 10 }, stepSize: 1 }, beginAtZero: true }
      }
    }
  });
}

function _renderDevDist(elId, obj, prefix, defaultColor, colorMap) {
  const el = document.getElementById(elId);
  if (!el) return;
  const entries = Object.entries(obj).sort((a, b) => b[1] - a[1]);
  if (!entries.length) {
    el.innerHTML = '<div style="font-family:var(--mono);font-size:11px;color:var(--text3);padding:8px 0">Sin datos aún</div>';
    return;
  }
  el.innerHTML = entries.map(([k, v]) => {
    const color = colorMap ? (colorMap[k] || defaultColor) : defaultColor;
    return `<div class="dev-dist-item">
      <span class="k" style="color:${color}">${prefix}${k}</span>
      <span class="v">${v.toLocaleString()}</span>
    </div>`;
  }).join('');
}

function _renderDevFallback() {
  document.querySelectorAll('#devKpis .value').forEach(el => el.textContent = 'N/A');
  const canvas = document.getElementById('devLineChart');
  if (canvas) {
    canvas.style.display = 'none';
    const msg = document.createElement('div');
    msg.style.cssText = 'font-family:var(--mono);font-size:11px;color:var(--text3);text-align:center;padding:20px';
    msg.textContent = 'Backend no configurado — completa STATS_URL en stats-client.js';
    canvas.parentNode.appendChild(msg);
  }
}

