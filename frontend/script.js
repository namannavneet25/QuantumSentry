/* ──────────────────────────────────────────────────────────
   QuantumSentry — Dashboard Script
   
   Sections:
   0. Authentication (JWT login/logout, role-based UI)
   1. PQC Classification Constants
   2. PQC Verdict Engine
   3. Recommendations Engine (new)
   4. Export Functions (JSON + PDF)
   5. Render Engine
   6. Tab / UI Helpers
   7. Scan Function
   8. History & Audit Functions
   9. Bulk Scan Functions
────────────────────────────────────────────────────────── */

/* ── 0. Authentication ──────────────────────────────────────── */

const TOKEN_KEY = 'qs_token';
const USER_KEY  = 'qs_user';

/** Return stored JWT or null */
function getToken() { return localStorage.getItem(TOKEN_KEY); }

/** Return stored user object {username, role} or null */
function getUser()  {
  try { return JSON.parse(localStorage.getItem(USER_KEY)); }
  catch { return null; }
}

/** Add Authorization header to a fetch options object */
function authHeaders(opts = {}) {
  const token = getToken();
  return {
    ...opts,
    headers: { ...(opts.headers || {}), Authorization: `Bearer ${token}` },
  };
}

/** Authenticated fetch — injects Bearer token automatically */
function authFetch(url, opts = {}) {
  return fetch(url, authHeaders(opts));
}

/** Perform login — POST /auth/login */
async function doLogin() {
  const username = document.getElementById('loginUser').value.trim();
  const password = document.getElementById('loginPass').value;
  const errEl    = document.getElementById('loginError');
  const btn      = document.getElementById('loginBtn');

  if (!username || !password) {
    showLoginError('Please enter username and password.');
    return;
  }

  btn.disabled    = true;
  btn.textContent = 'Signing in…';
  errEl.classList.add('hidden');

  try {
    const res  = await fetch('http://localhost:8080/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();

    if (!res.ok) {
      showLoginError(data.error || 'Login failed.');
      btn.disabled = false; btn.textContent = 'Sign In';
      return;
    }

    // Store token + user info
    localStorage.setItem(TOKEN_KEY, data.token);
    localStorage.setItem(USER_KEY, JSON.stringify({ username: data.username, role: data.role }));

    // Hide login modal and show dashboard
    document.getElementById('loginModal').classList.add('hidden');
    applyRoleUI(data.role);
    renderUserBadge(data.username, data.role);

  } catch (err) {
    showLoginError('Connection error: ' + err.message);
    btn.disabled = false; btn.textContent = 'Sign In';
  }
}

/** Show login error message */
function showLoginError(msg) {
  const el = document.getElementById('loginError');
  el.textContent = msg;
  el.classList.remove('hidden');
}

/** Log out — clear token and reload */
function doLogout() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
  location.reload();
}

/** Render user badge + logout button in the header */
function renderUserBadge(username, role) {
  const roleColors = { admin: '#818cf8', auditor: '#f59e0b', viewer: '#10b981' };
  const color = roleColors[role] || '#6b7280';
  const badge = document.createElement('div');
  badge.id    = 'userBadge';
  badge.style.cssText = 'display:flex;gap:8px;align-items:center;';
  badge.innerHTML = `
    <span style="font-size:.78rem;color:var(--muted)">Signed in as</span>
    <span style="font-weight:600;font-size:.82rem;color:${color}">${username}</span>
    <span style="font-size:.65rem;background:${color}22;color:${color};padding:2px 7px;border-radius:5px;font-weight:700;text-transform:uppercase">${role}</span>
    <button class="export-btn" onclick="doLogout()" style="color:#ef4444">Sign Out</button>`;

  // Insert into header before the header-badge
  const hdr = document.querySelector('.header-inner');
  const live = hdr.querySelector('.header-badge').parentElement;
  live.insertBefore(badge, live.querySelector('.header-badge'));
}

/** Apply role-based UI restrictions */
function applyRoleUI(role) {
  if (role === 'auditor') {
    // Auditor cannot trigger scans
    const scanBtn = document.getElementById('scanBtn');
    if (scanBtn) { scanBtn.disabled = true; scanBtn.title = 'Auditor role cannot trigger scans'; }
    const bulkBtn = document.querySelector('.scan-btn-bulk');
    if (bulkBtn) { bulkBtn.disabled = true; }
  }
}

/** Init auth on page load — show login if no valid token */
async function initAuth() {
  const token = getToken();
  const user  = getUser();

  if (!token || !user) {
    // No token — show login modal
    document.getElementById('loginModal').classList.remove('hidden');
    // Allow Enter key in login fields
    ['loginUser','loginPass'].forEach(id =>
      document.getElementById(id).addEventListener('keydown', e => { if (e.key==='Enter') doLogin(); })
    );
    return;
  }

  // Verify token is still valid
  try {
    const res = await fetch('http://localhost:8080/auth/me', authHeaders());
    if (!res.ok) throw new Error('invalid');
    document.getElementById('loginModal').classList.add('hidden');
    applyRoleUI(user.role);
    renderUserBadge(user.username, user.role);
  } catch {
    // Token expired — clear and show login
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    document.getElementById('loginModal').classList.remove('hidden');
  }
}

/* ── 1. PQC Classification Constants ─────────────────────────── */

// Pure Post-Quantum ML-KEM groups (NIST FIPS 203)
const PURE_PQ_GROUPS = ['MLKEM512', 'MLKEM768', 'MLKEM1024'];

// Hybrid groups — one classical + one PQ component fused together
const HYBRID_GROUPS = [
  'X25519MLKEM768',
  'SecP256r1MLKEM768',
  'SecP384r1MLKEM1024',
];

// All PQC-capable groups (union of above)
const ALL_PQ_GROUPS = [...PURE_PQ_GROUPS, ...HYBRID_GROUPS];

// Signature algorithms that are quantum-safe (post-NIST PQC standards)
const PQ_SIG_ALGOS = ['ML-DSA', 'SLH-DSA', 'Falcon', 'Dilithium', 'SPHINCS'];

// Classical algorithms broken by Shor's algorithm on a CRQC
const VULN_KEY_ALGOS = ['RSA', 'ECDSA', 'ECDH', 'DSA', 'Ed25519', 'Ed448', 'DH'];

/* ── 2. PQC Verdict Engine ───────────────────────────────────── */

/**
 * Computes the quantum safety verdict for one asset.
 * @param {Object} tls  - Protocol object from CBOM
 * @param {Object} cert - Certificate object from CBOM
 * @returns {{ cls: string, icon: string, label: string }}
 */
function computeVerdict(tls, cert) {
  const selected  = tls.selected_group   || '';
  const supported = tls.supported_groups || [];
  const sigAlgo   = cert.signature_algorithm       || '';
  const pubKey    = cert.public_key_algorithm       || '';

  const hasPQ     = ALL_PQ_GROUPS.some(g => selected === g || supported.includes(g));
  const isPurePQ  = PURE_PQ_GROUPS.some(g => selected === g || supported.includes(g));
  const isHybrid  = HYBRID_GROUPS.some(g =>  selected === g || supported.includes(g));
  const hasPQSig  = PQ_SIG_ALGOS.some(a => sigAlgo.includes(a));
  const hasVulnSig = VULN_KEY_ALGOS.some(a =>
    pubKey.toUpperCase().includes(a.toUpperCase()) ||
    sigAlgo.toUpperCase().includes(a.toUpperCase())
  );

  if (isPurePQ && !hasVulnSig && hasPQSig) {
    return { cls: 'safe',   icon: '🟢', label: 'Fully Post-Quantum Safe' };
  }
  if ((isPurePQ || isHybrid) && !hasVulnSig) {
    return { cls: 'safe',   icon: '🟢', label: 'Post-Quantum Safe' };
  }
  if (isHybrid && hasVulnSig) {
    return { cls: 'hybrid', icon: '🟡', label: 'Hybrid PQ — Partially Safe' };
  }
  if (isPurePQ && hasVulnSig) {
    return { cls: 'hybrid', icon: '🟡', label: 'Hybrid KEM — Cert Vulnerable' };
  }
  return { cls: 'vuln', icon: '🔴', label: 'Quantum Vulnerable' };
}

/* ── 3. Recommendations Engine ───────────────────────────────── */

/**
 * Returns a list of actionable remediation recommendations for an asset.
 * Each item has: severity ('critical'|'high'|'medium'), issue, fix, command.
 */
function getRecommendations(tls, cert) {
  const recs = [];
  const selected = tls.selected_group   || '';
  const version  = tls.version          || '';
  const pubKey   = cert.public_key_algorithm || '';
  const sigAlgo  = cert.signature_algorithm  || '';

  // ── TLS Version ────────────────────────────────────────────────────────────
  if (version === 'TLS 1.2' || version === 'TLS 1.1' || version === 'TLS 1.0') {
    recs.push({
      severity: 'high',
      issue: `Outdated TLS version: ${version}`,
      fix: 'Enforce TLS 1.3 as the minimum. TLS 1.3 is mandatory for hybrid PQC key exchange.',
      command: '# nginx:\nssl_protocols TLSv1.3;\n\n# Apache:\nSSLProtocol -all +TLSv1.3',
    });
  }

  // ── Key Exchange Group ─────────────────────────────────────────────────────
  if (!ALL_PQ_GROUPS.some(g => selected === g)) {
    const best = version === 'TLS 1.3' ? 'X25519MLKEM768' : 'Upgrade TLS first';
    recs.push({
      severity: 'critical',
      issue: `Classical key exchange only: ${selected || 'unknown'}`,
      fix: 'Enable a hybrid or pure PQ key exchange group. X25519MLKEM768 is the IETF-recommended hybrid group (NIST ML-KEM-768 + X25519).',
      command: `# nginx:\nssl_ecdh_curve ${best}:X25519:prime256v1;\n\n# OpenSSL:\nopenssl s_server -groups ${best}:X25519`,
    });
  } else if (HYBRID_GROUPS.includes(selected) && !PURE_PQ_GROUPS.includes(selected)) {
    recs.push({
      severity: 'medium',
      issue: 'Hybrid PQ key exchange — classical component still present',
      fix: 'Hybrid mode provides good protection today. Plan migration to pure ML-KEM when the ecosystem matures (post-2027).',
      command: '# Current setup is acceptable per NIST transition guidelines.',
    });
  }

  // ── Certificate Signature ──────────────────────────────────────────────────
  const isClassicalCert = VULN_KEY_ALGOS.some(a =>
    pubKey.toUpperCase().includes(a.toUpperCase()) ||
    sigAlgo.toUpperCase().includes(a.toUpperCase())
  );

  if (isClassicalCert) {
    let certalgo = 'RSA-2048';
    if (pubKey.includes('ECDSA')) certalgo = 'ECDSA-P256';

    recs.push({
      severity: 'high',
      issue: `Classical certificate signature: ${pubKey} / ${sigAlgo}`,
      fix: `The certificate uses a quantum-vulnerable algorithm. Replace with ML-DSA-65 (CRYSTALS-Dilithium Level 2) or wait for CA support. Currently ${certalgo} is broken by Shor's algorithm on a CRQC.`,
      command: '# Generate ML-DSA CSR (when OpenSSL 3.3+ with PQC support):\nopenssl req -new -newkey mldsa65 -out server.csr -keyout server.key\n\n# Alternatively use a PQC-capable CA (e.g. ISARA, DigiCert PQC labs)',
    });
  }

  // ── TLS 1.3 cipher best practice ──────────────────────────────────────────
  const cipher = tls.cipher_suite || '';
  if (cipher.includes('AES_128') && version === 'TLS 1.3') {
    recs.push({
      severity: 'low',
      issue: 'Using AES-128 — consider AES-256 for higher security margin',
      fix: 'TLS_AES_256_GCM_SHA384 provides 256-bit symmetric security, hardening against Grover\'s algorithm which halves symmetric key security.',
      command: '# nginx — prefer AES-256 cipher:\nssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;',
    });
  }

  // ── No issues found ────────────────────────────────────────────────────────
  if (recs.length === 0) {
    recs.push({
      severity: 'info',
      issue: 'No critical issues found',
      fix: 'This asset is using post-quantum resistant cryptography. Monitor for PQC standard updates (NIST FIPS 203/204/205) and plan certificate renewals accordingly.',
      command: '# No immediate action required. Schedule periodic re-scan.',
    });
  }

  return recs;
}

/** Renders a single recommendation card */
function recCard(rec) {
  const colors = {
    critical: { bg: 'rgba(239,68,68,.1)',   border: 'rgba(239,68,68,.35)',   txt: '#ef4444', icon: '🚨' },
    high:     { bg: 'rgba(239,68,68,.08)',  border: 'rgba(239,68,68,.25)',   txt: '#f87171', icon: '⚠️' },
    medium:   { bg: 'rgba(245,158,11,.08)', border: 'rgba(245,158,11,.25)',  txt: '#f59e0b', icon: '🔶' },
    low:      { bg: 'rgba(99,102,241,.08)', border: 'rgba(99,102,241,.25)',  txt: '#818cf8', icon: 'ℹ️' },
    info:     { bg: 'rgba(16,185,129,.08)', border: 'rgba(16,185,129,.25)',  txt: '#10b981', icon: '✅' },
  };
  const c = colors[rec.severity] || colors.low;

  return `
  <div style="background:${c.bg};border:1px solid ${c.border};border-radius:10px;padding:14px 16px;margin-bottom:12px;">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
      <span>${c.icon}</span>
      <span style="color:${c.txt};font-weight:600;font-size:.85rem;text-transform:uppercase;letter-spacing:.04em">${rec.severity}</span>
    </div>
    <div style="font-size:.9rem;font-weight:500;color:var(--text);margin-bottom:4px;">${rec.issue}</div>
    <div style="font-size:.82rem;color:var(--muted);margin-bottom:10px;line-height:1.6;">${rec.fix}</div>
    <details style="cursor:pointer;">
      <summary style="font-size:.75rem;color:var(--accent2);user-select:none;">Show remediation commands</summary>
      <pre style="margin-top:8px;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:10px;font-size:.72rem;color:var(--text);overflow-x:auto;white-space:pre-wrap;">${rec.command}</pre>
    </details>
  </div>`;
}

/* ── 4. Export Functions ─────────────────────────────────────── */

/** Download the full CBOM as a JSON file */
function downloadJSON(data) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `cbom-${(data.target || 'scan').replace(/[^a-z0-9]/gi, '_')}-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

/** Generate a "Quantum Safety Certificate" PDF for the given asset */
function downloadPDF(asset, verdict, scanData) {
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });

  const tls  = (asset.protocols    || [])[0] || {};
  const cert = (asset.certificates || [])[0] || {};
  const keys = (asset.keys         || [])[0] || {};

  // ── Header ──────────────────────────────────────────────────────────────
  doc.setFillColor(10, 12, 20);
  doc.rect(0, 0, 210, 40, 'F');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(20);
  doc.setTextColor(129, 140, 248);
  doc.text('QuantumSentry', 14, 18);

  doc.setFontSize(9);
  doc.setTextColor(107, 120, 153);
  doc.text('Post-Quantum Cryptography Readiness Report', 14, 26);
  doc.text(`Generated: ${new Date().toISOString()}`, 14, 33);

  // ── Verdict Banner ──────────────────────────────────────────────────────
  const vColors = { safe: [16,185,129], hybrid: [245,158,11], vuln: [239,68,68] };
  const vc = vColors[verdict.cls] || vColors.vuln;

  doc.setFillColor(...vc);
  doc.rect(0, 42, 210, 18, 'F');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(13);
  doc.setTextColor(255, 255, 255);
  doc.text(`${verdict.icon}  ${verdict.label}`, 14, 54);
  doc.setFontSize(9);
  doc.text(`Target: ${asset.host || scanData.target}`, 150, 54);

  // ── Section helper ──────────────────────────────────────────────────────
  let y = 72;
  const sectionTitle = (title) => {
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(99, 102, 241);
    doc.text(title, 14, y);
    doc.setDrawColor(99, 102, 241);
    doc.setLineWidth(0.3);
    doc.line(14, y + 2, 196, y + 2);
    y += 10;
  };

  const row = (label, value) => {
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9);
    doc.setTextColor(107, 120, 153);
    doc.text(label, 14, y);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(226, 232, 248);
    doc.text(String(value || '—').substring(0, 90), 70, y);
    y += 7;
  };

  doc.setFillColor(17, 20, 34);
  doc.rect(0, 62, 210, 297, 'F');

  // ── Network ────────────────────────────────────────────────────────────
  sectionTitle('Network Information');
  const net = asset.network || {};
  row('Source IP',      net.source_ip);
  row('Destination IP', net.destination_ip);
  row('SNI',            net.sni);
  row('ALPN',           tls.alpn);
  y += 4;

  // ── TLS / Protocol ─────────────────────────────────────────────────────
  sectionTitle('Protocol (TLS)');
  row('Asset Type',      tls.asset_type || 'protocol');
  row('TLS Version',     tls.version);
  row('Protocol OID',    tls.oid);
  row('Cipher Suite',    tls.cipher_suite);
  row('Selected KEM',    tls.selected_group);
  row('Supported Groups',(tls.supported_groups || []).join(', ') || '—');
  y += 4;

  // ── Certificate ────────────────────────────────────────────────────────
  sectionTitle('Certificate');
  row('Asset Type',         cert.asset_type || 'certificate');
  row('Subject',            cert.subject);
  row('Issuer',             cert.issuer);
  row('Valid From',         cert.valid_from);
  row('Valid To',           cert.valid_to);
  row('Serial Number',      cert.serial_number);
  row('Sig Algorithm',      cert.signature_algorithm);
  row('Sig Algorithm OID',  cert.signature_algorithm_ref);
  row('Public Key',         `${cert.public_key_algorithm} (${cert.public_key_size} bits)`);
  row('Certificate Format', cert.certificate_format);
  y += 4;

  // ── Keys ────────────────────────────────────────────────────────────────
  if (y < 240) {
    sectionTitle('Cryptographic Key');
    row('Asset Type',       keys.asset_type || 'key');
    row('Name',             keys.name);
    row('ID / Fingerprint', keys.id);
    row('Algorithm',        keys.algorithm);
    row('Key Size',         keys.size ? `${keys.size} bits` : '—');
    row('State',            keys.state);
    row('Creation Date',    keys.creation_date);
    y += 4;
  }

  // ── Footer ──────────────────────────────────────────────────────────────
  doc.setFont('helvetica', 'italic');
  doc.setFontSize(7);
  doc.setTextColor(107, 120, 153);
  doc.text(
    'This report was generated by QuantumSentry. Based on NIST FIPS 203/204/205 and CERT-In CBOM guidelines.',
    14, 285
  );
  doc.text(`Scan ID: ${scanData.scan_id || '—'}`, 14, 290);

  doc.save(`quantum-safety-certificate-${(asset.host||'').replace(/[^a-z0-9]/gi,'_')}.pdf`);
}

/* ── 5. Render Engine ────────────────────────────────────────── */

let _lastScanData = null; // stored for export

function render(data) {
  _lastScanData = data;
  const container = document.getElementById('result');
  container.innerHTML = '';

  (data.assets || []).forEach((asset, idx) => {
    const net  = asset.network       || {};
    const tls  = (asset.protocols    || [])[0] || {};
    const cert = (asset.certificates || [])[0] || {};
    const keys = (asset.keys         || [])[0] || {};
    const id   = `asset-${idx}`;

    const verdict = computeVerdict(tls, cert);
    const recs    = getRecommendations(tls, cert);

    // ── Group tags ────────────────────────────────────────────────────────
    const groupTags = (tls.supported_groups || []).map(g =>
      `<span class="tag ${groupClass(g)}">${g}</span>`
    ).join('') || '<span class="tag classic">none captured</span>';

    // ── Algorithm cards ───────────────────────────────────────────────────
    const algoCards = (tls.algorithms || []).map(a => `
      <div class="algo-card">
        <div class="algo-name">${a.name}</div>
        <div class="algo-mode">${a.mode ? a.mode + ' mode' : a.primitive}</div>
        ${a.oid ? `<div class="algo-bits" style="color:var(--muted);font-size:.68rem">${a.oid}</div>` : ''}
        <div class="algo-bits">${a.security_bits ? a.security_bits + ' bits classical' : ''}</div>
      </div>`).join('') || '<span style="color:var(--muted);font-size:.85rem">No algorithms parsed</span>';

    // ── OID pills ─────────────────────────────────────────────────────────
    const oidPills = (cert.oids || []).map(o =>
      `<span class="oid-pill">${o}</span>`).join('');

    // ── DNS list ──────────────────────────────────────────────────────────
    const dnsList = (cert.dns_names || []).map(d =>
      `<div class="dns-item">${d}</div>`).join('');

    // ── Selected group color ──────────────────────────────────────────────
    const selectedGroupColor =
      PURE_PQ_GROUPS.includes(tls.selected_group) ? 'safe'  :
      HYBRID_GROUPS.includes(tls.selected_group)  ? 'hybrid': 'vuln';

    // ── Recommendations HTML ──────────────────────────────────────────────
    const recsHTML = recs.map(recCard).join('');

    // ── Key info panel ────────────────────────────────────────────────────
    const keyPanel = keys.name ? `
      <div class="info-grid" style="margin-top:12px">
        <div class="info-item"><div class="info-label">Asset Type</div><div class="info-value">${keys.asset_type||'key'}</div></div>
        <div class="info-item"><div class="info-label">Key Name</div><div class="info-value highlight">${keys.name||'—'}</div></div>
        <div class="info-item"><div class="info-label">Algorithm</div><div class="info-value">${keys.algorithm||'—'}</div></div>
        <div class="info-item"><div class="info-label">Size</div><div class="info-value">${keys.size ? keys.size+' bits' : '—'}</div></div>
        <div class="info-item"><div class="info-label">State</div>
          <div class="info-value ${keys.state==='active'?'safe':keys.state==='expired'?'vuln':''}">${keys.state||'—'}</div></div>
        <div class="info-item"><div class="info-label">ID / Fingerprint</div><div class="info-value" style="font-size:.72rem">${keys.id||'—'}</div></div>
        <div class="info-item"><div class="info-label">Creation Date</div><div class="info-value">${fmt(keys.creation_date)}</div></div>
        <div class="info-item"><div class="info-label">Activation Date</div><div class="info-value">${fmt(keys.activation_date)}</div></div>
      </div>` : '<span style="color:var(--muted);font-size:.85rem">Key data not available</span>';

    container.innerHTML += `
    <div class="asset-card">

      <!-- Header -->
      <div class="card-header">
        <div>
          <div class="card-title">Asset ${idx + 1}</div>
          <div class="card-host">${asset.host || data.target || '—'}</div>
        </div>
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;justify-content:flex-end;">
          <div class="verdict ${verdict.cls}">
            <span class="verdict-dot"></span>
            ${verdict.icon} ${verdict.label}
          </div>
          <!-- Export buttons -->
          <button class="export-btn" onclick="downloadJSON(window._lastScanData)" title="Download CBOM JSON">
            ⬇ JSON
          </button>
          <button class="export-btn export-pdf" onclick="downloadPDF(window._lastScanData.assets[${idx}], ${JSON.stringify(verdict)}, window._lastScanData)" title="Download PDF Certificate">
            📄 PDF
          </button>
        </div>
      </div>

      <!-- Tabs -->
      <div class="tabs">
        <button class="tab-btn active" id="tab-network-${id}" onclick="switchTab('${id}','network')">🌐 Network</button>
        <button class="tab-btn"        id="tab-tls-${id}"     onclick="switchTab('${id}','tls')">🔐 TLS</button>
        <button class="tab-btn"        id="tab-cert-${id}"    onclick="switchTab('${id}','cert')">📜 Certificate</button>
        <button class="tab-btn"        id="tab-keys-${id}"    onclick="switchTab('${id}','keys')">🔑 Keys</button>
        <button class="tab-btn rec-tab ${verdict.cls==='vuln'?'tab-urgent':''}" 
                id="tab-rec-${id}" onclick="switchTab('${id}','rec')">
          🔧 Recommendations ${verdict.cls==='vuln'?'<span class="urgency-dot"></span>':''}
        </button>
      </div>

      <!-- NETWORK panel -->
      <div class="tab-panel active" id="network-${id}">
        <div class="info-grid">
          <div class="info-item"><div class="info-label">Source IP</div><div class="info-value">${val(net.source_ip)}</div></div>
          <div class="info-item"><div class="info-label">Destination IP</div><div class="info-value">${val(net.destination_ip)}</div></div>
          <div class="info-item"><div class="info-label">SNI</div><div class="info-value highlight">${val(net.sni)}</div></div>
          <div class="info-item"><div class="info-label">ALPN Protocol</div><div class="info-value">${val(tls.alpn)}</div></div>
        </div>
      </div>

      <!-- TLS panel -->
      <div class="tab-panel" id="tls-${id}">
        <div class="info-grid">
          <div class="info-item"><div class="info-label">Asset Type</div><div class="info-value">${val(tls.asset_type)}</div></div>
          <div class="info-item"><div class="info-label">TLS Version</div><div class="info-value highlight">${val(tls.version)}</div></div>
          <div class="info-item"><div class="info-label">Protocol OID</div><div class="info-value" style="font-size:.78rem">${val(tls.oid)}</div></div>
          <div class="info-item"><div class="info-label">Cipher Suite</div><div class="info-value" style="font-size:.8rem">${val(tls.cipher_suite)}</div></div>
          <div class="info-item" style="grid-column:1/-1">
            <div class="info-label">Selected Key Exchange Group (KEM)</div>
            <div class="info-value ${selectedGroupColor}">${val(tls.selected_group)}</div>
          </div>
        </div>
        <div class="section-label">Supported Groups (advertised in ClientHello)</div>
        <div class="tags">${groupTags}</div>
        <div class="section-label">Algorithms in Cipher Suite</div>
        <div class="algo-grid">${algoCards}</div>
      </div>

      <!-- CERT panel -->
      <div class="tab-panel" id="cert-${id}">
        <div class="info-grid">
          <div class="info-item"><div class="info-label">Asset Type</div><div class="info-value">${val(cert.asset_type)}</div></div>
          <div class="info-item"><div class="info-label">Certificate Format</div><div class="info-value">${val(cert.certificate_format)}</div></div>
          <div class="info-item" style="grid-column:1/-1">
            <div class="info-label">Subject</div>
            <div class="info-value highlight">${val(cert.subject)}</div>
          </div>
          <div class="info-item" style="grid-column:1/-1">
            <div class="info-label">Issuer</div>
            <div class="info-value">${val(cert.issuer)}</div>
          </div>
          <div class="info-item"><div class="info-label">Public Key Algorithm</div><div class="info-value">${val(cert.public_key_algorithm)} (${cert.public_key_size || '?'} bits)</div></div>
          <div class="info-item"><div class="info-label">Signature Algorithm</div><div class="info-value">${val(cert.signature_algorithm)}</div></div>
          <div class="info-item"><div class="info-label">Signature Algo OID</div><div class="info-value" style="font-size:.78rem">${val(cert.signature_algorithm_ref)}</div></div>
          <div class="info-item"><div class="info-label">Public Key Ref</div><div class="info-value" style="font-size:.72rem">${val(cert.public_key_ref)}</div></div>
          <div class="info-item"><div class="info-label">Valid From</div><div class="info-value">${fmt(cert.valid_from)}</div></div>
          <div class="info-item"><div class="info-label">Valid To (Not After)</div><div class="info-value">${fmt(cert.valid_to)}</div></div>
          <div class="info-item"><div class="info-label">Serial Number</div><div class="info-value" style="font-size:.75rem">${val(cert.serial_number)}</div></div>
          <div class="info-item"><div class="info-label">Is CA</div><div class="info-value">${cert.is_ca ? '✅ Yes' : '— No'}</div></div>
        </div>

        <div class="section-label">Key Usage</div>
        <div class="tags">${(cert.key_usage || []).map(k => `<span class="tag">${k}</span>`).join('') || '—'}</div>

        <div class="section-label">Extension OIDs</div>
        <div class="tags">${oidPills || '—'}</div>

        <div class="divider"></div>

        <div class="section-label">DNS Names (${(cert.dns_names || []).length})</div>
        <input class="dns-search" placeholder="Search DNS names…" oninput="filterDNS('dns-${id}', this.value)" />
        <div class="dns-list" id="dns-${id}">${dnsList}</div>
      </div>

      <!-- KEYS panel -->
      <div class="tab-panel" id="keys-${id}">
        <p style="font-size:.8rem;color:var(--muted);margin-bottom:14px;">
          Cryptographic key derived from the server certificate public key.<br/>
          <em>Private key values are never stored or transmitted.</em>
        </p>
        ${keyPanel}
      </div>

      <!-- RECOMMENDATIONS panel -->
      <div class="tab-panel" id="rec-${id}">
        <p style="font-size:.8rem;color:var(--muted);margin-bottom:16px;">
          Actionable remediation steps to improve quantum-readiness for this asset.
        </p>
        ${recsHTML}
      </div>

    </div>`;
  });

  // expose for global export button
  window._lastScanData = data;
}

/* ── 6. Tab & UI Helpers ─────────────────────────────────────── */

function switchTab(cardId, tab) {
  ['network','tls','cert','keys','rec'].forEach(t => {
    const panel = document.getElementById(`${t}-${cardId}`);
    const btn   = document.getElementById(`tab-${t}-${cardId}`);
    if (panel) panel.classList.remove('active');
    if (btn)   btn.classList.remove('active');
  });
  const activePanel = document.getElementById(`${tab}-${cardId}`);
  const activeBtn   = document.getElementById(`tab-${tab}-${cardId}`);
  if (activePanel) activePanel.classList.add('active');
  if (activeBtn)   activeBtn.classList.add('active');
}

function filterDNS(id, q) {
  const list = document.getElementById(id);
  if (!list) return;
  for (const item of list.children) {
    item.style.display = item.textContent.toLowerCase().includes(q.toLowerCase()) ? '' : 'none';
  }
}

function groupClass(g) {
  if (PURE_PQ_GROUPS.includes(g)) return 'pq';
  if (HYBRID_GROUPS.includes(g))  return 'hybrid';
  return 'classic';
}

function fmt(d) {
  if (!d) return '—';
  return new Date(d).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
}
function val(v) { return v || '<span style="color:var(--muted)">—</span>'; }

function quickScan(target) {
  document.getElementById('target').value = target;
  scan();
}

function setScanning(yes) {
  const btn    = document.getElementById('scanBtn');
  const text   = document.getElementById('btnText');
  const loader = document.getElementById('btnLoader');
  btn.disabled = yes;
  text.classList.toggle('hidden', yes);
  loader.classList.toggle('hidden', !yes);
}

function setStatus(msg, type) {
  const el = document.getElementById('status');
  el.className = `status-bar ${type}`;
  el.classList.remove('hidden');
  el.innerHTML = msg;
}

/* ── 7. Scan Function ────────────────────────────────────────── */

async function scan() {
  const target = document.getElementById('target').value.trim();
  if (!target) return;

  document.getElementById('result').innerHTML = '';
  setScanning(true);
  setStatus(`⏳ &nbsp;Scanning <b>${target}</b>…`, 'scanning');

  try {
    const res  = await authFetch(`http://localhost:8080/scan?target=${encodeURIComponent(target)}`);
    const data = await res.json();

    if (data.error) {
      setStatus(`❌ &nbsp;${data.error}`, 'error');
      setScanning(false);
      return;
    }

    setStatus(`✅ &nbsp;Scan complete — <b>${(data.assets || []).length}</b> asset(s) found`, 'success');
    render(data);
  } catch (err) {
    console.error(err);
    setStatus(`❌ &nbsp;Request failed: ${err.message}`, 'error');
  } finally {
    setScanning(false);
  }
}

/* ── Enter key support ───────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('target').addEventListener('keydown', e => {
    if (e.key === 'Enter') scan();
  });
  initAuth(); // check token, show login modal if needed
});

/* ── 9. Bulk Scan Functions ──────────────────────────────── */

let _bulkData = null; // stored for JSON export

/** Toggle the bulk scan section open/closed */
function toggleBulk() {
  const body    = document.getElementById('bulkBody');
  const chevron = document.getElementById('bulkChevron');
  const isHidden = body.classList.contains('hidden');
  body.classList.toggle('hidden', !isHidden);
  chevron.textContent = isHidden ? '▲ collapse' : '▼ expand';
}

/** Populate textarea from uploaded CSV/TXT file */
function loadCSV(input) {
  const file = input.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = e => {
    // Accept comma-separated or newline-separated targets
    const text = e.target.result
      .replace(/,/g, '\n')
      .split('\n')
      .map(t => t.trim())
      .filter(t => t && t.includes(':'))
      .join('\n');
    document.getElementById('bulkTargets').value = text;
  };
  reader.readAsText(file);
}

/** Run bulk scan against all targets in the textarea */
async function bulkScan() {
  const raw = document.getElementById('bulkTargets').value.trim();
  if (!raw) { alert('Please enter at least one target (host:port).'); return; }

  const targets = [...new Set(
    raw.split('\n').map(t => t.trim()).filter(t => t && t.includes(':'))
  )].slice(0, 20);

  if (targets.length === 0) {
    alert('No valid targets found. Each line should be host:port (e.g. google.com:443)');
    return;
  }

  // Show progress
  const prog    = document.getElementById('bulkProgress');
  const bar     = document.getElementById('bulkProgressBar');
  const txt     = document.getElementById('bulkProgressText');
  const resDiv  = document.getElementById('bulkResults');

  prog.classList.remove('hidden');
  bar.style.width = '5%';
  txt.textContent = `0 / ${targets.length}`;
  resDiv.innerHTML = '';

  document.getElementById('clearBulkBtn').style.display     = 'none';
  document.getElementById('bulkDownloadBtn').style.display  = 'none';

  try {
    const res  = await authFetch('http://localhost:8080/scan/bulk', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ targets }),
    });
    const data = await res.json();
    _bulkData = data;

    bar.style.width  = '100%';
    txt.textContent  = `${data.total} / ${data.total}`;

    renderBulkResults(data.results || []);

    document.getElementById('clearBulkBtn').style.display    = 'inline-flex';
    document.getElementById('bulkDownloadBtn').style.display = 'inline-flex';

  } catch (err) {
    resDiv.innerHTML = `<div style="color:var(--vuln);font-size:.85rem;padding:12px 0">❌ Request failed: ${err.message}</div>`;
    bar.style.width  = '100%';
    bar.style.background = 'var(--vuln)';
  }
}

/** Render the bulk scan results as a summary table */
function renderBulkResults(results) {
  const vIcon  = { safe: '🟢', hybrid: '🟡', vuln: '🔴', error: '⚠️', unknown: '⚪' };
  const vColor = { safe: 'var(--safe)', hybrid: '#f59e0b', vuln: 'var(--vuln)', error: '#ef4444', unknown: 'var(--muted)' };

  const rows = results.map((r, i) => {
    if (r.status === 'error') {
      return `<tr>
        <td style="color:var(--muted)">${i+1}</td>
        <td style="font-weight:500">${r.target}</td>
        <td colspan="3" style="color:var(--vuln);font-size:.8rem">⚠️ ${r.error}</td>
      </tr>`;
    }
    const cbom     = r.cbom || {};
    const asset    = (cbom.assets || [])[0] || {};
    const tls      = (asset.protocols || [])[0] || {};
    const cert     = (asset.certificates || [])[0] || {};
    const keys     = (asset.keys || [])[0] || {};

    const verdict  = computeVerdict(tls, cert);
    const icon     = vIcon[verdict.cls]  || vIcon.unknown;
    const color    = vColor[verdict.cls] || vColor.unknown;
    const kem      = tls.selected_group  || '—';
    const tlsVer   = tls.version         || '—';
    const keySize  = keys.size ? `${keys.size} bits` : '—';

    return `<tr class="bulk-row" onclick="loadBulkDetail(${i})" title="Click to view full CBOM">
      <td style="color:var(--muted)">${i+1}</td>
      <td style="font-weight:600">${r.target}</td>
      <td><span style="color:${color}">${icon} ${verdict.label}</span></td>
      <td style="font-size:.78rem;color:var(--text)">${tlsVer} · ${kem}</td>
      <td style="font-size:.76rem;color:var(--muted)">${keySize}</td>
    </tr>`;
  }).join('');

  document.getElementById('bulkResults').innerHTML = `
  <table class="bulk-table">
    <thead>
      <tr>
        <th>#</th><th>Target</th><th>PQC Verdict</th><th>TLS / KEM</th><th>Key Size</th>
      </tr>
    </thead>
    <tbody>${rows}</tbody>
  </table>
  <p style="font-size:.75rem;color:var(--muted);margin-top:8px">Click any row to load its full CBOM below.</p>`;
}

/** Load a bulk result's CBOM into the main result area */
function loadBulkDetail(idx) {
  if (!_bulkData || !_bulkData.results[idx]) return;
  const r = _bulkData.results[idx];
  if (r.status === 'error') return;
  document.getElementById('target').value = r.target;
  setStatus(`✅ Loaded bulk scan result for <b>${r.target}</b>`, 'success');
  render(r.cbom);
  window.scrollTo({ top: document.getElementById('result').offsetTop - 20, behavior: 'smooth' });
}

/** Download all bulk CBOM results as a single JSON file */
function downloadBulkJSON() {
  if (!_bulkData) return;
  const blob = new Blob([JSON.stringify(_bulkData, null, 2)], { type: 'application/json' });
  const a    = document.createElement('a');
  a.href     = URL.createObjectURL(blob);
  a.download = `bulk-cbom-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
}

/** Clear bulk results */
function clearBulkResults() {
  _bulkData = null;
  document.getElementById('bulkResults').innerHTML = '';
  document.getElementById('bulkProgress').classList.add('hidden');
  document.getElementById('bulkProgressBar').style.width = '0%';
  document.getElementById('clearBulkBtn').style.display    = 'none';
  document.getElementById('bulkDownloadBtn').style.display = 'none';
}


/* ── 8. History & Audit Functions ───────────────────────────── */

/** Toggle the history panel open/closed */
function toggleHistory() {
  const panel = document.getElementById('historyPanel');
  const isHidden = panel.classList.contains('hidden');
  panel.classList.toggle('hidden', !isHidden);
  if (isHidden) loadHistory();
}

/** Load scan history from the backend and render it */
async function loadHistory() {
  const list = document.getElementById('historyList');
  list.innerHTML = '<span style="color:var(--muted);font-size:.85rem">Loading…</span>';

  try {
    const res  = await authFetch('http://localhost:8080/history');
    const data = await res.json();
    const scans = data.scans || [];

    if (scans.length === 0) {
      list.innerHTML = '<span style="color:var(--muted);font-size:.85rem">No scans yet. Run your first scan above.</span>';
      return;
    }

    list.innerHTML = scans.map(s => {
      const vColors = { safe: '#10b981', hybrid: '#f59e0b', vuln: '#ef4444', unknown: '#6b7280' };
      const vIcons  = { safe: '🟢', hybrid: '🟡', vuln: '🔴', unknown: '⚪' };
      const color   = vColors[s.verdict] || vColors.unknown;
      const icon    = vIcons[s.verdict]  || vIcons.unknown;
      const date    = new Date(s.timestamp).toLocaleString('en-GB', { dateStyle:'short', timeStyle:'short' });

      return `
      <div class="history-item" onclick="loadHistoryScan('${s.id}', '${s.target}')" title="Click to load this scan">
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <span style="font-weight:600;font-size:.85rem;color:var(--text)">${s.target}</span>
          <span style="font-size:.75rem;color:var(--muted)">${date}</span>
        </div>
        <div style="display:flex;gap:8px;align-items:center;margin-top:4px;">
          <span style="font-size:.8rem;color:${color}">${icon} ${s.verdict_label}</span>
          <span style="font-size:.72rem;color:var(--muted);margin-left:auto">${s.tls_version} · ${s.selected_group || 'classical'}</span>
        </div>
      </div>`;
    }).join('');

  } catch (err) {
    list.innerHTML = `<span style="color:var(--vuln);font-size:.85rem">Failed: ${err.message}</span>`;
  }
}

/** Re-load a historical scan result by fetching its CBOM */
async function loadHistoryScan(id, target) {
  document.getElementById('target').value = target;
  setStatus(`⏳ Loading scan <b>${target}</b>…`, 'scanning');
  document.getElementById('result').innerHTML = '';

  try {
    const res  = await authFetch(`http://localhost:8080/history/${encodeURIComponent(id)}`);
    const data = await res.json();
    setStatus(`✅ Loaded historical scan for <b>${target}</b>`, 'success');
    render(data);
  } catch (err) {
    setStatus(`❌ Failed to load: ${err.message}`, 'error');
  }
}

/** Open audit trail modal and load entries */
async function openAudit() {
  document.getElementById('auditModal').classList.remove('hidden');
  document.body.style.overflow = 'hidden';
  await loadAudit();
}

/** Close audit modal by clicking the overlay */
function closeAudit(e) {
  if (e.target.id === 'auditModal') closeAuditBtn();
}
function closeAuditBtn() {
  document.getElementById('auditModal').classList.add('hidden');
  document.body.style.overflow = '';
}

/** Fetch and render the audit log table */
async function loadAudit() {
  const wrap = document.getElementById('auditTableWrap');
  wrap.innerHTML = '<span style="color:var(--muted);font-size:.85rem">Loading…</span>';

  let entries = [];
  try {
    const data = await authFetch('http://localhost:8080/audit').then(r => r.json());
    entries = data.entries || [];
  } catch (err) {
    wrap.innerHTML = `<span style="color:var(--vuln);font-size:.85rem">❌ ${err.message}</span>`;
    return;
  }

  if (entries.length === 0) {
    wrap.innerHTML = '<span style="color:var(--muted);font-size:.85rem">No audit entries yet.</span>';
    return;
  }

  const statusBadge = s =>
    s === 'OK'
      ? `<span class="audit-badge ok">OK</span>`
      : `<span class="audit-badge err">ERROR</span>`;

  const rows = entries.map(e => `
    <tr>
      <td style="color:var(--muted);font-size:.72rem;white-space:nowrap">${new Date(e.timestamp).toLocaleString('en-GB',{dateStyle:'short',timeStyle:'medium'})}</td>
      <td><span class="audit-action">${e.action}</span></td>
      <td style="font-size:.8rem;color:var(--text);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${e.target}">${e.target || '—'}</td>
      <td>${statusBadge(e.status)}</td>
      <td style="font-size:.75rem;color:var(--muted)">${e.detail || ''}</td>
    </tr>`).join('');

  wrap.innerHTML = `
  <table class="audit-table">
    <thead>
      <tr>
        <th>Timestamp</th><th>Action</th><th>Target</th><th>Status</th><th>Detail</th>
      </tr>
    </thead>
    <tbody>${rows}</tbody>
  </table>`;

  // store for CSV export
  window._auditEntries = entries;
}

/** Export audit log as CSV download */
function downloadAuditCSV() {
  const entries = window._auditEntries || [];
  if (!entries.length) return;

  const header = 'ID,Timestamp,Action,Target,Status,Detail';
  const csvRows = entries.map(e =>
    [e.id, e.timestamp, e.action,
     `"${(e.target||'').replace(/"/g,'""')}"`,
     e.status,
     `"${(e.detail||'').replace(/"/g,'""')}"`
    ].join(',')
  );

  const blob = new Blob([[header, ...csvRows].join('\n')], { type: 'text/csv' });
  const a    = document.createElement('a');
  a.href     = URL.createObjectURL(blob);
  a.download = `audit-log-${Date.now()}.csv`;
  a.click();
  URL.revokeObjectURL(a.href);
}