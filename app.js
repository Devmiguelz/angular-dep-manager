document.addEventListener('contextmenu', e => e.preventDefault());

/* BLOQUEAR TECLAS */
document.onkeydown = function(e) {
    if (e.key === "F12") return false;
    if (e.ctrlKey && e.shiftKey && e.key === "I") return false;
    if (e.ctrlKey && e.shiftKey && e.key === "J") return false;
    if (e.ctrlKey && e.shiftKey && e.key === "C") return false;
    if (e.ctrlKey && e.key === "u") return false;
};

/* BLOQUEAR COPIAR */
document.addEventListener('copy', function(e) {
    e.preventDefault();
});

/* DETECTAR DEVTOOLS */
function detectDevTools() {
    const threshold = 160;
    if (
        window.outerWidth - window.innerWidth > threshold ||
        window.outerHeight - window.innerHeight > threshold
    ) {
        document.body.innerHTML = "";
        document.body.style.background = "#000";
    }
}

setInterval(detectDevTools, 1000);

/* DETECTAR INSPECT ELEMENT */
setInterval(function(){
    const start = new Date();
    debugger;
    const end = new Date();
    if(end - start > 100){
        document.body.innerHTML = "";
    }
},1000);


// ─── STATE ────────────────────────────────────────────────────────────────
let state = {
  rawJson: null,
  auditJson: null,
  packages: [],
  overrides: [],
  exportMode: 'updated'
};

let currentFilter = 'all';
let currentSearch = '';

const STATS_URL   = 'https://angular-dep-manager-back.onrender.com';   
const _SECRET_KEY = 'dev-secret';             

// ─── DATE ─────────────────────────────────────────────────────────────────
document.getElementById('currentDate').textContent = new Date().toLocaleDateString('es-ES', {
  weekday: 'long', year: 'numeric', month: 'long', day: 'numeric'
});

// ─── FILE HANDLING ────────────────────────────────────────────────────────
const dropZone = document.getElementById('dropZone');
dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('dragover'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
dropZone.addEventListener('drop', e => {
  e.preventDefault();
  dropZone.classList.remove('dragover');
  const file = e.dataTransfer.files[0];
  if (file && file.name.endsWith('.json')) loadFile(file);
});

const auditDropZone = document.getElementById('auditDropZone');
auditDropZone.addEventListener('click', e => {
  if (e.target.closest('button') || e.target.closest('code') || e.target.tagName === 'INPUT') return;
  document.getElementById('auditFileInput').click();
});
auditDropZone.addEventListener('dragover', e => { e.preventDefault(); auditDropZone.classList.add('dragover'); });
auditDropZone.addEventListener('dragleave', () => auditDropZone.classList.remove('dragover'));
auditDropZone.addEventListener('drop', e => {
  e.preventDefault();
  auditDropZone.classList.remove('dragover');
  const file = e.dataTransfer.files[0];
  if (file && file.name.endsWith('.json')) loadAuditFile(file);
});

function handleFileSelect(e) {
  const file = e.target.files[0];
  if (file) loadFile(file);
}

function loadFile(file) {
  const reader = new FileReader();
  reader.onload = e => {
    try {
      const json = JSON.parse(e.target.result);
      state.rawJson = json;
      const count = countDeps(json);
      document.getElementById('fileName').textContent = file.name;

      document.getElementById('pkgStatus').style.display = 'block';
      document.getElementById('pkgStatusName').textContent = `${file.name} · ${count} deps`;
      document.getElementById('dropZone').style.borderColor = 'var(--ok)';
      document.getElementById('configBar').classList.add('visible');
      toast(`✓ ${file.name} cargado — ${count} dependencias encontradas`);
    } catch {
      toast('❌ JSON inválido', 'danger');
    }
  };
  reader.readAsText(file);
}

function handleAuditFileSelect(e) {
  const file = e.target.files[0];
  if (file) loadAuditFile(file);
}

function loadAuditFile(file) {
  const reader = new FileReader();
  reader.onload = e => {
    try {
      const json = JSON.parse(e.target.result);

      if (!json.advisories && !json.vulnerabilities) {
        toast('❌ No parece un npm audit --json válido', 'danger');
        return;
      }
      state.auditJson = json;
      const count = Object.keys(json.advisories || json.vulnerabilities || {}).length;
      document.getElementById('auditStatus').style.display = 'block';
      document.getElementById('auditMissing').style.display = 'none';
      document.getElementById('auditStatusName').textContent = file.name;
      document.getElementById('auditStatusCount').textContent = `${count} vulnerabilidad${count !== 1 ? 'es' : ''}`;
      document.getElementById('auditDropZone').style.borderColor = 'var(--warn)';
      toast(`✓ ${file.name} cargado — ${count} vulnerabilidades`);
    } catch {
      toast('❌ JSON inválido', 'danger');
    }
  };
  reader.readAsText(file);
}

function copyAuditCmd(btn) {
  navigator.clipboard.writeText('npm audit --json > audit.json').then(() => {
    btn.textContent = '✓';
    setTimeout(() => btn.textContent = '📋', 2000);
  });
}

function countDeps(json) {
  return Object.keys(json.dependencies || {}).length + Object.keys(json.devDependencies || {}).length;
}

// ─── ANALYSIS ─────────────────────────────────────────────────────────────
function getExcludedScopes() {
  const raw = document.getElementById('excludedScopes').value || '';
  return raw.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
}

function isExcluded(pkgName) {
  const excluded = getExcludedScopes();
  if (!excluded.length) return false;
  return excluded.some(scope => {

    const normalized = scope.startsWith('@') ? scope : '@' + scope;
    return pkgName.toLowerCase().startsWith(normalized + '/') || pkgName.toLowerCase() === normalized;
  });
}

async function startAnalysis() {
  if (!state.rawJson) return;

  const btn = document.getElementById('analyzeBtn');
  btn.disabled = true;
  document.getElementById('btnSpinner').style.display = 'inline-block';
  document.getElementById('btnText').textContent = 'Analizando...';

  const majorVersion = document.getElementById('majorVersion').value;
  const json = state.rawJson;


  const allPkgs = [];
  for (const [name, ver] of Object.entries(json.dependencies || {}))
    allPkgs.push({ name, currentVersion: cleanVer(ver), isDev: false, excluded: isExcluded(name) });
  for (const [name, ver] of Object.entries(json.devDependencies || {}))
    allPkgs.push({ name, currentVersion: cleanVer(ver), isDev: true, excluded: isExcluded(name) });


  const toAnalyze = allPkgs.filter(p => !p.excluded);
  const excluded = allPkgs.filter(p => p.excluded);

  const pb = document.getElementById('progressBar');
  pb.classList.add('visible');

  state.packages = [];
  state.excludedPackages = excluded;
  let done = 0;


  excluded.forEach(pkg => {
    state.packages.push({
      name: pkg.name,
      currentVersion: pkg.currentVersion,
      latestVersion: '—',
      type: pkg.isDev ? 'dev' : 'prod',
      isAngular: pkg.name.startsWith('@angular/'),
      isDev: pkg.isDev,
      excluded: true,
      status: 'excluded'
    });
  });


  const BATCH = 8;
  for (let i = 0; i < toAnalyze.length; i += BATCH) {
    const batch = toAnalyze.slice(i, i + BATCH);
    await Promise.all(batch.map(async pkg => {
      try {
        const info = await fetchNpmInfo(pkg.name);
        const latest = getBestVersion(info, pkg.name, majorVersion);
        const pkgData = {
          name: pkg.name,
          currentVersion: pkg.currentVersion,
          latestVersion: latest,
          allVersions: info ? Object.keys(info.versions || {}) : [],
          type: pkg.isDev ? 'dev' : 'prod',
          isAngular: pkg.name.startsWith('@angular/'),
          isDev: pkg.isDev,
          excluded: false,
          status: compareVersions(pkg.currentVersion, latest)
        };
        state.packages.push(pkgData);
      } catch {
        state.packages.push({
          name: pkg.name,
          currentVersion: pkg.currentVersion,
          latestVersion: '?',
          type: pkg.isDev ? 'dev' : 'prod',
          isAngular: pkg.name.startsWith('@angular/'),
          isDev: pkg.isDev,
          excluded: false,
          status: 'error'
        });
      }
      done++;
      updateProgress(done, toAnalyze.length, pkg.name);
    }));
  }


  document.getElementById('progressStatus').textContent = 'Consultando npm audit...';
  await detectOverrides();

  pb.classList.remove('visible');
  btn.disabled = false;
  document.getElementById('btnSpinner').style.display = 'none';
  document.getElementById('btnText').textContent = '🔍 Re-analizar';

  renderAll();
  toast(`✓ Análisis completado · ${excluded.length} excluidos`);
}

function updateProgress(done, total, currentPkg) {
  const pct = Math.round((done / total) * 100);
  document.getElementById('progressFill').style.width = pct + '%';
  document.getElementById('progressStatus').textContent = 'Consultando npm registry...';
  document.getElementById('progressCount').textContent = `${done}/${total}`;
  document.getElementById('progressPkg').textContent = currentPkg;
}

async function fetchNpmInfo(pkgName) {
  const encoded = pkgName.replace('/', '%2F');
  const r = await fetch(`https://registry.npmjs.org/${encoded}`, {
    headers: { 'Accept': 'application/json' }
  });
  if (!r.ok) return null;
  return await r.json();
}

function cleanVer(v) {
  return (v || '').replace(/[\^~>=<]/g, '').trim();
}

function getBestVersion(info, pkgName, majorVersion) {
  if (!info) return '?';
  const distTags = info['dist-tags'] || {};

  if (majorVersion === 'latest') return distTags.latest || '?';
  if (majorVersion === 'any') return distTags.latest || '?';


  const major = parseInt(majorVersion);
  const versions = Object.keys(info.versions || {});
  const matching = versions.filter(v => {
    const parts = v.split('.');
    return parseInt(parts[0]) === major && !v.includes('-');
  });

  if (!matching.length) return distTags.latest || '?';


  matching.sort((a, b) => semverCompare(b, a));
  return matching[0];
}

function semverCompare(a, b) {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] || 0) > (pb[i] || 0)) return 1;
    if ((pa[i] || 0) < (pb[i] || 0)) return -1;
  }
  return 0;
}

function compareVersions(current, latest) {
  if (latest === '?' || latest === 'error') return 'error';
  if (current === latest) return 'ok';
  return semverCompare(latest, current) > 0 ? 'outdated' : 'ok';
}

// ─── OVERRIDE DETECTION — REAL npm audit API + CVE database ──────────────
// CVE database built from real overrides observed in projects
const KNOWN_VULNS = [
  { name: 'ajv',                   fixVersion: '8.18.0',  severity: 'high',     cve: null,               reason: 'Schema validation bypass — observado en tus proyectos' },
  { name: 'rollup',                fixVersion: '4.59.0',  severity: 'high',     cve: 'CVE-2024-47068',   reason: 'Prototype pollution en bundler' },
  { name: 'serialize-javascript',  fixVersion: '7.0.3',   severity: 'high',     cve: 'CVE-2020-7660',    reason: 'XSS / code injection en serialización' },
  { name: '@hono/node-server',     fixVersion: '1.19.10', severity: 'moderate', cve: null,               reason: 'Versión con fix de seguridad — observado en tus proyectos' },
  { name: '@tootallnate/once',     fixVersion: '3.0.1',   severity: 'moderate', cve: null,               reason: 'Dependencia transitiva con fix — observado en tus proyectos' },
  { name: 'express-rate-limit',    fixVersion: '8.2.2',   severity: 'moderate', cve: null,               reason: 'Bypass de rate limiting — observado en tus proyectos' },
  { name: 'tar',                   fixVersion: '7.5.10',  severity: 'high',     cve: 'CVE-2024-28863',   reason: 'Path traversal en extracción de archivos' },
  { name: 'hono',                  fixVersion: '4.12.5',  severity: 'moderate', cve: null,               reason: 'Fix de seguridad en framework HTTP' },
  { name: 'immutable',             fixVersion: '5.1.5',   severity: 'low',      cve: null,               reason: 'Actualización de seguridad — observado en tus proyectos' },
  { name: 'minimatch',             fixVersion: '10.2.4',  severity: 'high',     cve: 'CVE-2022-3517',    reason: 'ReDoS en glob matching' },
  { name: 'test-exclude',          fixVersion: '8.0.0',   severity: 'low',      cve: null,               reason: 'Fix de dependencias transitivas' },
  { name: 'semver',                fixVersion: '7.5.4',   severity: 'high',     cve: 'CVE-2022-25883',   reason: 'ReDoS en parsing de versiones' },
  { name: 'braces',                fixVersion: '3.0.3',   severity: 'high',     cve: 'CVE-2024-4068',    reason: 'ReDoS vulnerability' },
  { name: 'word-wrap',             fixVersion: '1.2.4',   severity: 'moderate', cve: 'CVE-2023-26115',   reason: 'ReDoS vulnerability' },
  { name: 'tough-cookie',          fixVersion: '4.1.3',   severity: 'moderate', cve: 'CVE-2023-26136',   reason: 'Prototype pollution' },
  { name: 'nth-check',             fixVersion: '2.0.1',   severity: 'high',     cve: 'CVE-2021-3803',    reason: 'ReDoS vulnerability' },
  { name: 'postcss',               fixVersion: '8.4.31',  severity: 'moderate', cve: 'CVE-2023-44270',   reason: 'Line return parsing error' },
  { name: 'webpack',               fixVersion: '5.94.0',  severity: 'high',     cve: 'CVE-2024-43788',   reason: 'DOM Clobbering' },
  { name: 'micromatch',            fixVersion: '4.0.8',   severity: 'high',     cve: 'CVE-2024-4067',    reason: 'ReDoS vulnerability' },
  { name: 'ip',                    fixVersion: '2.0.1',   severity: 'high',     cve: 'CVE-2024-29415',   reason: 'SSRF vulnerability' },
  { name: 'lodash',                fixVersion: '4.17.21', severity: 'high',     cve: 'CVE-2021-23337',   reason: 'Prototype pollution' },
  { name: 'follow-redirects',      fixVersion: '1.15.6',  severity: 'moderate', cve: 'CVE-2024-28849',   reason: 'Credentials leak en redirecciones' },
  { name: 'vite',                  fixVersion: '5.4.6',   severity: 'high',     cve: 'CVE-2024-45812',   reason: 'Path traversal en dev server' },
  { name: 'express',               fixVersion: '4.21.1',  severity: 'moderate', cve: 'CVE-2024-29041',   reason: 'Open redirect' },
  { name: 'axios',                 fixVersion: '1.7.4',   severity: 'moderate', cve: 'CVE-2024-39338',   reason: 'SSRF en server-side requests' },
];

// ─── NPM AUDIT VIA SERVER ─────────────────────────────────────────────────
async function fetchServerAudit() {
  if (typeof STATS_URL === 'undefined' || !state.rawJson) return null;
  try {
    const res = await fetch(`${STATS_URL}/audit`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', 'x-secret-key': _SECRET_KEY },
      body:    JSON.stringify(state.rawJson)
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    toast('⚠ npm audit no disponible — usando base CVE local', 'warn');
    return null;
  }
}

async function detectOverrides() {
  state.overrides = [];
  state.auditResults = null;

  const nonExcluded = state.packages.filter(p => !p.excluded);

  // ── 0. Intentar audit via server (si no hay audit.json cargado manualmente) ──
  if (!state.auditJson) {
    document.getElementById('progressStatus').textContent = 'Consultando npm audit API...';
    const serverAudit = await fetchServerAudit();
    if (serverAudit) {
      state.auditJson = serverAudit;
      state._auditFromServer = true;
    }
  }

  if (state.auditJson) {
    const auditData = state.auditJson;
    state.auditResults = auditData;
    const added = new Set();

    const advisories = auditData.advisories || {};
    const vulnerabilities = auditData.vulnerabilities || {};

    for (const advisory of Object.values(advisories)) {
      const pkgName = advisory.module_name;
      if (!pkgName || added.has(pkgName)) continue;
      added.add(pkgName);

      let fixVersion = advisory.patched_versions || '>=0.0.0';
      if (fixVersion === '<0.0.0' || fixVersion === '') fixVersion = 'sin-fix-disponible';

      state.overrides.push({
        name: pkgName,
        currentVersion: nonExcluded.find(p => p.name === pkgName)?.currentVersion || advisory.findings?.[0]?.version || '?',
        fixVersion,
        reason: advisory.title || 'Vulnerabilidad detectada por npm audit',
        severity: advisory.severity || 'moderate',
        cve: (advisory.cves || []).join(', ') || null,
        source: 'npm-audit-file',
        url: advisory.url || null,
        overview: advisory.overview?.slice(0, 200) || null
      });
    }

    const v7pending = [];
    for (const [pkgName, vuln] of Object.entries(vulnerabilities)) {
      if (added.has(pkgName)) continue;
      added.add(pkgName);

      const via = Array.isArray(vuln.via) ? vuln.via.filter(v => typeof v === 'object') : [];
      const firstVia = via[0] || {};

      let fixVersion = null;
      if (vuln.fixAvailable && typeof vuln.fixAvailable === 'object' && vuln.fixAvailable.version) {
        fixVersion = vuln.fixAvailable.version;
      } else if (vuln.fixAvailable === true) {
        fixVersion = null;
      } else {
        fixVersion = 'SIN-FIX';
      }

      v7pending.push({
        name: pkgName,
        currentVersion: nonExcluded.find(p => p.name === pkgName)?.currentVersion || '?',
        fixVersion,
        needsLookup: fixVersion === null,
        reason: firstVia.title || `Vulnerabilidad en ${pkgName}`,
        severity: vuln.severity || 'moderate',
        cve: firstVia.cves?.join(', ') || null,
        source: 'npm-audit-file',
        url: firstVia.url || null,
        vulnRange: vuln.range || null
      });
    }

    document.getElementById('progressStatus').textContent = 'Resolviendo versiones de fix desde npm...';
    const needLookup = v7pending.filter(p => p.needsLookup);
    if (needLookup.length) {
      await Promise.all(needLookup.map(async entry => {
        try {
          const info = await fetchNpmInfo(entry.name);
          if (info && info['dist-tags'] && info['dist-tags'].latest) {
            entry.fixVersion = info['dist-tags'].latest;
          } else {
            entry.fixVersion = 'SIN-FIX';
          }
        } catch {
          entry.fixVersion = 'SIN-FIX';
        }
      }));
    }

    for (const entry of v7pending) {
      const { needsLookup, vulnRange, ...override } = entry;
      state.overrides.push(override);
    }
  }

  const auditNames = new Set(state.overrides.map(o => o.name));
  const allDepNames = new Set(nonExcluded.map(p => p.name));

  for (const vuln of KNOWN_VULNS) {
    if (auditNames.has(vuln.name)) continue;
    if (!allDepNames.has(vuln.name)) continue;

    const pkg = nonExcluded.find(p => p.name === vuln.name);
    if (!pkg) continue;

    const fixClean = vuln.fixVersion.replace(/[>=<^~]/g, '');
    if (semverCompare(pkg.currentVersion, fixClean) >= 0) continue;

    state.overrides.push({
      name: vuln.name,
      currentVersion: pkg.currentVersion,
      fixVersion: '>=' + vuln.fixVersion,
      reason: vuln.reason,
      severity: vuln.severity,
      cve: vuln.cve,
      source: 'known-cve'
    });
  }

  if (state.rawJson.overrides) {
    state.existingOverrides = state.rawJson.overrides;
  } else {
    state.existingOverrides = {};
  }

  const severityOrder = { high: 0, moderate: 1, low: 2 };
  state.overrides.sort((a, b) =>
    (severityOrder[a.severity] ?? 3) - (severityOrder[b.severity] ?? 3)
  );
}

// ─── RENDER ───────────────────────────────────────────────────────────────
function renderAll() {
  const pkgs = state.packages;
  const analyzable = pkgs.filter(p => !p.excluded && p.status !== 'excluded');
  const outdated = analyzable.filter(p => p.status === 'outdated');
  const excl = pkgs.filter(p => p.excluded || p.status === 'excluded');

  document.getElementById('sumTotal').textContent = analyzable.length;
  document.getElementById('sumOk').textContent = analyzable.filter(p => p.status === 'ok').length;
  document.getElementById('sumOutdated').textContent = outdated.length;
  document.getElementById('sumVuln').textContent = state.overrides.filter(o => !state.existingOverrides?.[o.name]).length;
  document.getElementById('summaryGrid').classList.add('visible');
  const auditBtn = document.getElementById('auditBtn');
  if (auditBtn) auditBtn.style.display = 'inline-flex';

  document.getElementById('tabAllBadge').textContent = pkgs.length + (excl.length ? ` (${excl.length} excl.)` : '');
  document.getElementById('tabOutdatedBadge').textContent = outdated.length;
  document.getElementById('tabOverridesBadge').textContent = state.overrides.length;
  document.getElementById('tabs').classList.add('visible');

  renderTable('depsTableBody', pkgs);
  renderTable('outdatedTableBody', outdated);
  renderOverrides();
  renderCommands();
  renderExport();
}

function renderTable(tbodyId, pkgs) {
  const tbody = document.getElementById(tbodyId);
  if (!pkgs.length) {
    tbody.innerHTML = '<tr><td colspan="6"><div class="empty">✓ Todo al día</div></td></tr>';
    return;
  }

  tbody.innerHTML = pkgs.map(pkg => {
    const isExcl = pkg.excluded || pkg.status === 'excluded';
    const dotClass = isExcl ? 'dot-skip' : pkg.status === 'ok' ? 'dot-ok' : pkg.status === 'outdated' ? 'dot-warn' : 'dot-skip';
    const [scope, name] = pkg.name.startsWith('@') ? [pkg.name.split('/')[0] + '/', pkg.name.split('/')[1]] : ['', pkg.name];

    let typeLabel, typeClass;
    if (isExcl) { typeLabel = 'excluido'; typeClass = 'type-excluded'; }
    else if (pkg.isAngular) { typeLabel = '@angular'; typeClass = 'type-angular'; }
    else if (pkg.isDev) { typeLabel = 'dev'; typeClass = 'type-dev'; }
    else { typeLabel = 'prod'; typeClass = ''; }

    const latestClass = isExcl ? 'ver-same' : pkg.status === 'outdated' ? 'ver-new' : pkg.status === 'error' ? 'ver-warn' : 'ver-same';

    let statusText = '';
    if (isExcl) statusText = '<span style="color:var(--text3);font-size:11px">— privado</span>';
    else if (pkg.status === 'ok') statusText = '<span style="color:var(--ok);font-size:11px">✓ Al día</span>';
    else if (pkg.status === 'outdated') statusText = '<span style="color:var(--warn);font-size:11px">↑ Actualizable</span>';
    else statusText = '<span style="color:var(--text3);font-size:11px">? Error</span>';

    const rowStyle = isExcl ? 'opacity:0.45' : '';

    return `<tr data-name="${pkg.name}" data-type="${pkg.isDev ? 'dev' : 'prod'}" data-angular="${pkg.isAngular}" data-excluded="${isExcl}" style="${rowStyle}">
      <td><span class="status-dot ${dotClass}"></span></td>
      <td><div class="pkg-name"><span class="pkg-scope">${scope}</span>${name || pkg.name}</div></td>
      <td><span class="type-tag ${typeClass}">${typeLabel}</span></td>
      <td><span class="ver-badge ver-current">${pkg.currentVersion || '?'}</span></td>
      <td><span class="ver-badge ${latestClass}">${pkg.latestVersion || '?'}</span></td>
      <td>${statusText}</td>
    </tr>`;
  }).join('');
}

function renderOverrides() {
  const cont = document.getElementById('overridesContent');

  if (!state.overrides.length) {
    cont.innerHTML = '<div class="empty">🛡️ No se detectaron vulnerabilidades — ¡proyecto limpio!</div>';
    return;
  }

  const existing = state.existingOverrides || {};
  const alreadyApplied = state.overrides.filter(o => existing[o.name]);
  const newSuggestions = state.overrides.filter(o => !existing[o.name]);
  const auditCount = state.overrides.filter(o => o.source === 'npm-audit').length;

  const recommendedBlock = {};
  Object.assign(recommendedBlock, existing);
  newSuggestions.forEach(o => {
    if (o.fixVersion && o.fixVersion !== 'SIN-FIX') {
      recommendedBlock[o.name] = o.fixVersion;
    }
  });

  const overridesJson = JSON.stringify(recommendedBlock, null, 2);

  const sourceInfo = auditCount > 0
    ? `<span class="audit-source npm-audit">npm audit API</span> ${auditCount} via npm audit`
    : `<span class="audit-source known-cve">Base CVE local</span>`;

  cont.innerHTML = `
    <div style="display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap;align-items:center">
      <div style="font-family:var(--mono);font-size:11px;color:var(--text3)">
        Fuente: ${sourceInfo}
        &nbsp;·&nbsp; ${newSuggestions.length} nuevos &nbsp;·&nbsp;
        <span style="color:var(--ok)">${alreadyApplied.length} ya aplicados</span>
      </div>
    </div>

    ${newSuggestions.length ? `
    <div style="margin-bottom:20px">
      <div class="cmd-block">
        <div class="cmd-header">
          <span>📋 Bloque "overrides" recomendado para tu package.json</span>
          <button class="cmd-copy" onclick="copyText(this, document.getElementById('overridesJson').textContent)">Copiar</button>
        </div>
        <div class="cmd-body">
          <pre id="overridesJson" style="color:var(--ok);font-size:11px">"overrides": ${overridesJson}</pre>
        </div>
      </div>
    </div>` : ''}

    ${newSuggestions.length ? '<div style="font-family:var(--mono);font-size:10px;color:var(--text3);margin-bottom:12px;text-transform:uppercase;letter-spacing:1px">⚠ Nuevos overrides sugeridos</div>' : ''}

    ${newSuggestions.map(o => renderOverrideCard(o, false)).join('')}

    ${alreadyApplied.length ? `
      <div style="font-family:var(--mono);font-size:10px;color:var(--text3);margin:20px 0 12px;text-transform:uppercase;letter-spacing:1px">✓ Ya aplicados en tu package.json</div>
      ${alreadyApplied.map(o => renderOverrideCard(o, true)).join('')}
    ` : ''}
  `;
}

function renderOverrideCard(o, applied) {
  const severityColor = o.severity === 'high' ? 'var(--danger)' : o.severity === 'moderate' ? 'var(--warn)' : 'var(--text3)';
  const severityBg = o.severity === 'high' ? 'rgba(255,82,82,0.12)' : o.severity === 'moderate' ? 'rgba(255,171,64,0.12)' : 'rgba(85,85,102,0.15)';
  const sourceBadge = o.source === 'npm-audit'
    ? '<span class="audit-source npm-audit">npm audit</span>'
    : '<span class="audit-source known-cve">CVE local</span>';
  const cveBadge = o.cve ? `<span style="font-family:var(--mono);font-size:9px;color:var(--text3);margin-left:6px">${o.cve}</span>` : '';
  const urlLink = o.url ? `<a href="${o.url}" target="_blank" style="color:var(--info);font-size:10px;font-family:var(--mono);margin-left:6px">ver advisory ↗</a>` : '';
  const appliedStyle = applied ? 'opacity:0.55;border-left-color:var(--ok)' : '';

  return `
    <div class="override-card" style="${appliedStyle}">
      <div class="override-header">
        <div>
          <div class="pkg" style="${applied ? 'text-decoration:line-through;color:var(--text2)' : ''}">
            ${o.name}
            ${sourceBadge}${cveBadge}${urlLink}
          </div>
          <div class="reason">${o.reason}</div>
        </div>
        <div style="display:flex;align-items:center;gap:8px">
          ${applied ? '<span style="font-size:10px;color:var(--ok);font-family:var(--mono)">✓ aplicado</span>' : ''}
          <span class="ver-badge" style="font-size:10px;background:${severityBg};color:${severityColor}">
            ${o.severity.toUpperCase()}
          </span>
        </div>
      </div>
      <div class="override-body">
        <p>Versión actual: <code style="color:var(--warn)">${o.currentVersion}</code>
           &nbsp;→&nbsp; Fix: <code style="color:var(--ok)">${o.fixVersion === 'SIN-FIX' ? '⚠ sin fix disponible' : o.fixVersion}</code>
           ${applied ? `&nbsp;<span style="font-size:10px;color:var(--ok)">(ya en tu package.json: "${state.existingOverrides[o.name]}")</span>` : ''}
        </p>
        <div class="json-block">
          <span class="json-str">"overrides"</span>: {<br>
          &nbsp;&nbsp;<span class="json-str">"${o.name}"</span>: <span class="json-val">"${o.fixVersion}"</span><br>
          }
        </div>
      </div>
    </div>`;
}

function renderCommands() {
  const cont = document.getElementById('commandsContent');
  const flag = document.getElementById('installFlag').value;
  const outdated = state.packages.filter(p => p.status === 'outdated');

  if (!state.packages.length) {
    cont.innerHTML = '<div class="empty">Analiza tus dependencias primero</div>';
    return;
  }

  const flagStr = flag ? ` ${flag}` : '';
  const angularPkgs = outdated.filter(p => p.isAngular);
  const otherPkgs = outdated.filter(p => !p.isAngular);

  let html = '';

  if (angularPkgs.length) {
    const cmd = 'npm install ' + angularPkgs.map(p => `${p.name}@${p.latestVersion}`).join(' ') + flagStr;
    html += `
      <div class="cmd-section">
        <h3>🔴 Paquetes Angular</h3>
        <div class="cmd-block">
          <div class="cmd-header"><span>bash</span><button class="cmd-copy" onclick="copyText(this, \`${escHtml(cmd)}\`)">Copiar</button></div>
          <div class="cmd-body">${formatCmd(cmd)}</div>
        </div>
      </div>`;
  }

  if (otherPkgs.length) {
    const cmd = 'npm install ' + otherPkgs.map(p => `${p.name}@${p.latestVersion}`).join(' ') + flagStr;
    html += `
      <div class="cmd-section">
        <h3>📦 Otros paquetes</h3>
        <div class="cmd-block">
          <div class="cmd-header"><span>bash</span><button class="cmd-copy" onclick="copyText(this, \`${escHtml(cmd)}\`)">Copiar</button></div>
          <div class="cmd-body">${formatCmd(cmd)}</div>
        </div>
      </div>`;
  }

  if (!outdated.length) {
    html += '<div class="empty" style="padding:30px">✓ Todo al día — no hay comandos de actualización pendientes</div>';
  }

  if (state.overrides.length) {
    const overridesBlock = state.overrides.reduce((acc, o) => { if (o.fixVersion && o.fixVersion !== 'SIN-FIX') acc[o.name] = o.fixVersion; return acc; }, {});
    const overridesStr = JSON.stringify(overridesBlock, null, 2);
    html += `
      <div class="cmd-section">
        <h3>🛡️ Agregar overrides en package.json</h3>
        <div class="cmd-block">
          <div class="cmd-header"><span>json — agregar dentro de package.json</span><button class="cmd-copy" onclick="copyText(this, document.getElementById('cmdOverride').textContent)">Copiar</button></div>
          <div class="cmd-body"><pre id="cmdOverride" style="font-size:11px;color:var(--ok)">"overrides": ${overridesStr}</pre></div>
        </div>
        <div style="margin-top:8px">
          <div class="cmd-block">
            <div class="cmd-header"><span>bash — después de editar package.json</span><button class="cmd-copy" onclick="copyText(this, 'npm install${flagStr}')">Copiar</button></div>
            <div class="cmd-body">npm install${flagStr}</div>
          </div>
        </div>
      </div>`;
  }

  if (outdated.length) {
    const allCmd = 'npm install ' + outdated.map(p => `${p.name}@${p.latestVersion}`).join(' ') + flagStr;
    html += `
      <div class="cmd-section">
        <h3>⚡ Todo en un solo comando</h3>
        <div class="cmd-block">
          <div class="cmd-header"><span>bash — actualiza todos a la vez</span><button class="cmd-copy" onclick="copyText(this, \`${escHtml(allCmd)}\`)">Copiar</button></div>
          <div class="cmd-body">${formatCmd(allCmd)}</div>
        </div>
      </div>`;
  }

  cont.innerHTML = html;
}

function formatCmd(cmd) {
  return cmd
    .replace(/--legacy-peer-deps|--force/g, m => `<span class="cmd-flag">${m}</span>`)
    .replace(/@[\d^~>=<.*]+/g, m => `<span class="cmd-ver">${m}</span>`);
}

function escHtml(str) {
  return str.replace(/`/g, '\\`').replace(/\$/g, '\\$');
}

function renderExport() {
  buildJsonPreview(state.exportMode);
}

function selectExport(mode, el) {
  state.exportMode = mode;
  document.querySelectorAll('.export-card').forEach(c => c.classList.remove('selected'));
  el.classList.add('selected');
  buildJsonPreview(mode);
}

function buildJsonPreview(mode) {
  if (!state.rawJson) return;

  const json = JSON.parse(JSON.stringify(state.rawJson));

  if (mode === 'updated' || mode === 'overrides') {
    state.packages.forEach(pkg => {
      if (pkg.status === 'outdated' && pkg.latestVersion !== '?') {
        if (!pkg.isDev && json.dependencies && json.dependencies[pkg.name] !== undefined) {
          json.dependencies[pkg.name] = pkg.latestVersion;
        }
        if (pkg.isDev && json.devDependencies && json.devDependencies[pkg.name] !== undefined) {
          json.devDependencies[pkg.name] = pkg.latestVersion;
        }
      }
    });

    if (mode === 'overrides' && state.overrides.length) {
      json.overrides = state.overrides.reduce((acc, o) => {
        if (!o.isGeneric || o.severity !== 'low') acc[o.name] = o.fixVersion;
        return acc;
      }, {});
    }
  }

  if (mode === 'latest') {
    state.packages.forEach(pkg => {
      if (pkg.latestVersion && pkg.latestVersion !== '?') {
        if (!pkg.isDev && json.dependencies && json.dependencies[pkg.name] !== undefined) {
          json.dependencies[pkg.name] = pkg.latestVersion;
        }
        if (pkg.isDev && json.devDependencies && json.devDependencies[pkg.name] !== undefined) {
          json.devDependencies[pkg.name] = pkg.latestVersion;
        }
      }
    });
  }

  state.currentExportJson = json;
  const pretty = JSON.stringify(json, null, 2);
  document.getElementById('jsonPreview').innerHTML = syntaxHighlight(pretty);
}

function syntaxHighlight(json) {
  return json
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"([^"]+)":/g, '<span class="jk">"$1"</span>:')
    .replace(/: "([^"]+)"/g, ': <span class="js">"$1"</span>')
    .replace(/: (\d+)/g, ': <span class="jv">$1</span>');
}

function downloadJson() {
  if (!state.currentExportJson) { toast('Selecciona un modo de exportación'); return; }
  const blob = new Blob([JSON.stringify(state.currentExportJson, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'package.json';
  a.click();
  toast('✓ package.json descargado');
}

function copyJson() {
  if (!state.currentExportJson) return;
  copyText(null, JSON.stringify(state.currentExportJson, null, 2));
}

// ─── ANALYSIS REPORT ─────────────────────────────────────────────────────
function buildAnalysisReport() {
  if (!state.packages.length) return null;

  const analyzable = state.packages.filter(p => !p.excluded && p.status !== 'excluded');
  const excluded   = state.packages.filter(p =>  p.excluded || p.status === 'excluded');
  const upToDate   = analyzable.filter(p => p.status === 'ok');
  const outdated   = analyzable.filter(p => p.status === 'outdated');
  const errors     = analyzable.filter(p => p.status === 'error');
  const newOverrides    = state.overrides.filter(o => !state.existingOverrides?.[o.name]);
  const appliedOverrides = state.overrides.filter(o =>  state.existingOverrides?.[o.name]);

  const flag = document.getElementById('installFlag').value;
  const flagStr = flag ? ` ${flag}` : '';
  const projectName = state.rawJson?.name || 'project';

  return {
    meta: {
      project:        projectName,
      analyzedAt:     new Date().toISOString(),
      majorVersion:   document.getElementById('majorVersion').value,
      installFlag:    flag || null,
      excludedScopes: getExcludedScopes(),
      auditSource:    state.auditResults ? 'npm-audit-api' : 'local-cve-db'
    },

    summary: {
      total:              analyzable.length,
      upToDate:           upToDate.length,
      outdated:           outdated.length,
      errors:             errors.length,
      excluded:           excluded.length,
      overridesNew:       newOverrides.length,
      overridesApplied:   appliedOverrides.length
    },

    dependencies: analyzable.map(p => ({
      name:           p.name,
      type:           p.isDev ? 'devDependency' : 'dependency',
      isAngular:      p.isAngular,
      currentVersion: p.currentVersion,
      latestVersion:  p.latestVersion,
      status:         p.status
    })),

    excluded: excluded.map(p => ({
      name:           p.name,
      type:           p.isDev ? 'devDependency' : 'dependency',
      currentVersion: p.currentVersion,
      reason:         'scope excluido de análisis'
    })),

    updates: {
      angular: outdated
        .filter(p => p.isAngular)
        .map(p => ({
          name:           p.name,
          from:           p.currentVersion,
          to:             p.latestVersion,
          command:        `npm install ${p.name}@${p.latestVersion}${flagStr}`
        })),
      other: outdated
        .filter(p => !p.isAngular)
        .map(p => ({
          name:           p.name,
          from:           p.currentVersion,
          to:             p.latestVersion,
          command:        `npm install ${p.name}@${p.latestVersion}${flagStr}`
        })),
      bulkCommand: outdated.length
        ? `npm install ${outdated.map(p => `${p.name}@${p.latestVersion}`).join(' ')}${flagStr}`
        : null
    },

    overrides: {
      suggested: newOverrides.map(o => ({
        name:           o.name,
        currentVersion: o.currentVersion,
        fixVersion:     o.fixVersion,
        severity:       o.severity,
        cve:            o.cve || null,
        reason:         o.reason,
        source:         o.source
      })),
      alreadyApplied: appliedOverrides.map(o => ({
        name:           o.name,
        appliedVersion: state.existingOverrides[o.name],
        severity:       o.severity,
        cve:            o.cve || null
      })),
      packageJsonBlock: newOverrides.length
        ? newOverrides.filter(o => o.fixVersion && o.fixVersion !== 'SIN-FIX').reduce((acc, o) => { acc[o.name] = o.fixVersion; return acc; }, {})
        : null
    },

    commands: {
      installAll: outdated.length
        ? `npm install ${outdated.map(p => `${p.name}@${p.latestVersion}`).join(' ')}${flagStr}`
        : null,
      installAngular: outdated.filter(p => p.isAngular).length
        ? `npm install ${outdated.filter(p => p.isAngular).map(p => `${p.name}@${p.latestVersion}`).join(' ')}${flagStr}`
        : null,
      installOthers: outdated.filter(p => !p.isAngular).length
        ? `npm install ${outdated.filter(p => !p.isAngular).map(p => `${p.name}@${p.latestVersion}`).join(' ')}${flagStr}`
        : null,
      afterOverrides: newOverrides.length ? `npm install${flagStr}` : null
    }
  };
}

function downloadAnalysisReport() {
  const report = buildAnalysisReport();
  if (!report) { toast('Analiza un package.json primero', 'danger'); return; }
  const filename = `analysis-report_${report.meta.project}_${new Date().toISOString().slice(0,10)}.json`;
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  toast(`✓ ${filename} descargado`);
}

function copyAnalysisReport() {
  const report = buildAnalysisReport();
  if (!report) { toast('Analiza un package.json primero', 'danger'); return; }
  copyText(null, JSON.stringify(report, null, 2));
}

function previewReport() {
  const report = buildAnalysisReport();
  if (!report) { toast('Analiza un package.json primero', 'danger'); return; }
  const el = document.getElementById('reportPreview');
  el.style.display = el.style.display === 'none' ? 'block' : 'none';
  if (el.style.display === 'block') {
    el.innerHTML = syntaxHighlight(JSON.stringify(report, null, 2));
  }
}

// ─── FILTERS ─────────────────────────────────────────────────────────────
function setFilter(type, el) {
  currentFilter = type;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  el.classList.add('active');
  applyFilters();
}

function filterSearch(val) {
  currentSearch = val.toLowerCase();
  applyFilters();
}

function applyFilters() {
  const rows = document.querySelectorAll('#depsTableBody tr[data-name]');
  rows.forEach(row => {
    const name = (row.dataset.name || '').toLowerCase();
    const type = row.dataset.type;
    const isAngular = row.dataset.angular === 'true';
    const isExcluded = row.dataset.excluded === 'true';

    const matchSearch = !currentSearch || name.includes(currentSearch);
    const matchFilter =
      currentFilter === 'all' ||
      (currentFilter === 'angular' && isAngular && !isExcluded) ||
      (currentFilter === 'dev' && type === 'dev' && !isExcluded) ||
      (currentFilter === 'prod' && type === 'prod' && !isExcluded) ||
      (currentFilter === 'excluded' && isExcluded);

    row.style.display = matchSearch && matchFilter ? '' : 'none';
  });
}

// ─── TABS ─────────────────────────────────────────────────────────────────
function showTab(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));

  const panelId = name === 'all' ? 'panel-all' :
    name === 'outdated' ? 'panel-outdated' :
    name === 'overrides' ? 'panel-overrides' :
    name === 'commands' ? 'panel-commands' : 'panel-export';

  document.getElementById(panelId).classList.add('active');
  event.currentTarget.classList.add('active');
}

// ─── UTILS ───────────────────────────────────────────────────────────────
function copyText(btn, text) {
  navigator.clipboard.writeText(text).then(() => {
    toast('✓ Copiado al portapapeles');
    if (btn) {
      btn.textContent = '✓ Copiado';
      btn.classList.add('copied');
      setTimeout(() => { btn.textContent = 'Copiar'; btn.classList.remove('copied'); }, 2000);
    }
  });
}

function toast(msg, type = 'ok') {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.style.borderLeftColor = type === 'danger' ? 'var(--danger)' : 'var(--ok)';
  t.style.color = type === 'danger' ? 'var(--danger)' : 'var(--ok)';
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 3000);
}

function resetTool() {
  state = { rawJson: null, auditJson: null, packages: [], overrides: [], exportMode: 'updated', excludedPackages: [], existingOverrides: {}, auditResults: null };
  const azEl = document.getElementById('auditStatus');
  if (azEl) azEl.style.display = 'none';
  const amEl = document.getElementById('auditMissing');
  if (amEl) amEl.style.display = 'block';
  const adEl = document.getElementById('auditDropZone');
  if (adEl) adEl.style.borderColor = 'rgba(255,171,64,0.3)';
  const pkEl = document.getElementById('pkgStatus');
  if (pkEl) pkEl.style.display = 'none';
  const dzEl = document.getElementById('dropZone');
  if (dzEl) { dzEl.style.display = ''; dzEl.style.borderColor = ''; }
  document.getElementById('dropZone').style.display = '';
  document.getElementById('configBar').classList.remove('visible');
  document.getElementById('summaryGrid').classList.remove('visible');
  document.getElementById('tabs').classList.remove('visible');
  document.getElementById('progressBar').classList.remove('visible');
  document.getElementById('fileName').textContent = '';
  document.getElementById('fileInput').value = '';
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.getElementById('panel-all').classList.add('active');
  document.querySelectorAll('.tab').forEach((t, i) => { t.classList.toggle('active', i === 0); });
  document.getElementById('depsTableBody').innerHTML = '<tr><td colspan="6"><div class="empty">Carga un package.json para comenzar</div></td></tr>';
  document.getElementById('btnText').textContent = '🔍 Analizar';
  state._auditFromServer = false;
  const auditBtnR = document.getElementById('auditBtn');
  if (auditBtnR) auditBtnR.style.display = 'none';
}

// ─── RE-AUDIT MANUAL ────────────────────────────────────────────────────────────────
async function reAudit() {
  if (!state.rawJson || !state.packages.length) {
    toast('Analiza un package.json primero', 'warn');
    return;
  }
  const btn = document.getElementById('auditBtn');
  if (btn) { btn.disabled = true; btn.textContent = '⧑ Auditando...'; }

  // Si el audit anterior vino del server, limpiar para forzar re-consulta
  if (state._auditFromServer) state.auditJson = null;

  document.getElementById('progressBar').classList.add('visible');
  document.getElementById('progressStatus').textContent = 'Consultando npm audit API...';

  await detectOverrides();

  document.getElementById('progressBar').classList.remove('visible');
  renderAll();
  toast('✓ Auditoría completada');

  if (btn) { btn.disabled = false; btn.textContent = '🛡️ Re-auditar'; }
}