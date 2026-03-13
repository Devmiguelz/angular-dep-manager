// ─── Enviar evento (fire-and-forget, nunca rompe la app) ─────────────────────
async function trackEvent(type, meta = {}) {
  try {
    await fetch(`${STATS_URL}/event`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', 'x-secret-key': _SECRET_KEY },
      body:    JSON.stringify({ type, meta }),
    });
  } catch { /* silencioso */ }
}

// ─── Cargar y mostrar stats en el header ─────────────────────────────────────
// ─── 1. Registrar visita al cargar ───────────────────────────────────────────
window.addEventListener('DOMContentLoaded', () => {
  trackEvent('visit');
});

// ─── 2. Hook sobre startAnalysis ─────────────────────────────────────────────
const _origStartAnalysis = startAnalysis;
startAnalysis = async function () {
  await _origStartAnalysis.apply(this, arguments);

  // Calcular métricas post-análisis desde state
  const analyzable = state.packages.filter(p => !p.excluded && p.status !== 'excluded');
  const outdated   = analyzable.filter(p => p.status === 'outdated');
  const newOverrides = state.overrides.filter(o => !state.existingOverrides?.[o.name]);

  const bySeverity = { critical: 0, high: 0, moderate: 0, low: 0 };
  newOverrides.forEach(o => {
    const sev = (o.severity || '').toLowerCase();
    if (bySeverity[sev] !== undefined) bySeverity[sev]++;
  });

  // Detectar versión Angular principal del proyecto
  const angularCore = state.packages.find(p => p.name === '@angular/core');
  const angularVersion = angularCore
    ? (angularCore.currentVersion || '').split('.')[0].replace(/\D/g,'')
    : null;

  trackEvent('analysis', {
    project:        state.rawJson?.name || 'unknown',
    totalPackages:  analyzable.length,
    outdated:       outdated.length,
    overrides:      newOverrides.length,
    angularVersion,
    hasAudit:       !!state.auditResults,
    majorTarget:    document.getElementById('majorVersion')?.value || null,
    bySeverity,
  });
};

// ─── 3. Hook sobre loadAuditFile ─────────────────────────────────────────────
const _origLoadAuditFile = loadAuditFile;
loadAuditFile = function () {
  _origLoadAuditFile.apply(this, arguments);
  trackEvent('auditLoaded');
};

// ─── 4. Hook sobre downloadJson ──────────────────────────────────────────────
const _origDownloadJson = downloadJson;
downloadJson = function () {
  _origDownloadJson.apply(this, arguments);
  trackEvent('export', { mode: state.exportMode, action: 'download' });
};

// ─── 5. Hook sobre copyJson ──────────────────────────────────────────────────
const _origCopyJson = copyJson;
copyJson = function () {
  _origCopyJson.apply(this, arguments);
  trackEvent('export', { mode: state.exportMode, action: 'copy' });
};

// ─── 6. Hook sobre downloadAnalysisReport ────────────────────────────────────
const _origDownloadReport = downloadAnalysisReport;
downloadAnalysisReport = function () {
  _origDownloadReport.apply(this, arguments);
  trackEvent('report', { action: 'download' });
};

// ─── 7. Hook sobre copyAnalysisReport ────────────────────────────────────────
const _origCopyReport = copyAnalysisReport;
copyAnalysisReport = function () {
  _origCopyReport.apply(this, arguments);
  trackEvent('report', { action: 'copy' });
};

