let _proxyEco = '';
let _proxyDecision = '';
let _proxyQ = '';
let _proxyRules = null;   // rule id -> { action, detail }, plus name rules by pattern
let _proxyRequestId = 0;
let _proxyController = null;

function _proxyFmtTime(s) { try { return new Date(s).toLocaleString(); } catch { return s || ''; } }
function _proxyFirstPage() { pageState('proxy').page = 1; }

// The policy says what each rule id in a verdict is called and why it fires.
// Best effort: without it the ids still show, just without their reason text.
async function _proxyLoadRules() {
  try {
    const response = await fetch('/api/policy');
    if (!response.ok) return;
    const body = (await readJson(response)).body || {};
    const rules = new Map((body.rules || []).map(r => [r.id, { action: r.action, detail: r.detail || '' }]));
    const names = new Map();
    for (const action of ['deny', 'allow'])
      for (const item of body.exceptions?.[action] || []) {
        const entry = typeof item === 'string' ? { pattern: item } : item;
        names.set(entry.pattern, { action, detail: entry.reason || '' });
      }
    _proxyRules = { rules, names };
  } catch { /* keep the previous map */ }
}

async function renderProxy() {
  const host = document.getElementById('proxyContent');
  if (!host) return;
  host.innerHTML = '<div class="panel-note">Loading…</div>';

  let summary = { overall: { total: 0, denied: 0 }, byEcosystem: [] };
  try {
    const response = await fetch('/api/proxy/summary');
    if (!response.ok) throw new Error(`Proxy summary failed (HTTP ${response.status})`);
    summary = await readJson(response);
  } catch (e) {
    host.innerHTML = `<div class="proxy-error">${esc(e.message)}</div>`;
    return;
  }

  const tabs = [{ ecosystem: '', total: summary.overall?.total || 0, denied: summary.overall?.denied || 0, label: 'All' }]
    .concat((summary.byEcosystem || []).map(e => ({ ...e, label: e.ecosystem || '—' })));

  const tabsHtml = tabs.map(t =>
    `<button class="proxy-tab ${t.ecosystem === _proxyEco ? 'active' : ''}" data-proxy-eco="${esc(t.ecosystem)}">
       ${esc(t.label)} <span class="pt-count">${t.total || 0}</span>${t.denied ? `<span class="pt-deny">${t.denied}</span>` : ''}
     </button>`).join('');

  host.innerHTML = `
    <div class="proxy-tabs">${tabsHtml}</div>
    <div class="proxy-controls">
       <input id="proxyQ" placeholder="filter package name…" value="${esc(_proxyQ)}"/>
       <select id="proxyDecision">
        <option value=""${_proxyDecision === '' ? ' selected' : ''}>all verdicts</option>
        <option value="allow"${_proxyDecision === 'allow' ? ' selected' : ''}>allow</option>
        <option value="deny"${_proxyDecision === 'deny' ? ' selected' : ''}>deny</option>
        <option value="error"${_proxyDecision === 'error' ? ' selected' : ''}>error</option>
      </select>
       <button id="proxySearch">Search</button>
       <button class="proxy-clear" id="proxyClear" title="Delete all proxy history">Clear</button>
       <button id="proxyRefresh">↻ Refresh</button>
    </div>
    <div id="proxyTable"></div>`;
  host.querySelectorAll('[data-proxy-eco]').forEach(button => button.addEventListener('click', () => proxyPick(button.dataset.proxyEco)));
  host.querySelector('#proxyQ').addEventListener('input', event => { _proxyQ = event.target.value; });
  host.querySelector('#proxyQ').addEventListener('keydown', event => { if (event.key === 'Enter') { _proxyFirstPage(); proxyLoadTable(); } });
  host.querySelector('#proxyDecision').addEventListener('change', event => { _proxyDecision = event.target.value; _proxyFirstPage(); proxyLoadTable(); });
  host.querySelector('#proxySearch').addEventListener('click', () => { _proxyFirstPage(); proxyLoadTable(); });
  host.querySelector('#proxyClear').addEventListener('click', proxyClear);
  host.querySelector('#proxyRefresh').addEventListener('click', renderProxy);
  await _proxyLoadRules();
  await proxyLoadTable();
}

function proxyPick(eco) { _proxyEco = eco; _proxyFirstPage(); renderProxy(); }

async function proxyClear() {
  if (!confirm('Delete ALL proxy history (events, blocks, artifact map)? This cannot be undone.')) return;
  try {
    const r = await fetch('/api/cache?type=proxy', { method: 'DELETE' });
    if (!r.ok) throw new Error((await r.json()).error || r.statusText);
    _proxyFirstPage(); _proxyEco = ''; renderProxy();
  } catch (e) { alert('Clear failed: ' + e.message); }
}

// The Reason column names the rule that decided, the way the Rules view names
// it: a scan rule by its id, a name rule by the package pattern it matched.
// Each name links to that rule; its own reason text is the tooltip.
const PROXY_SYSTEM_REASONS = new Set(['policy', 'gate-error', 'scan data unavailable', 'unparseable-artifact']);

function _proxyReasonLinks(e) {
  const ids = String(e.reasons || '').split(',').map(s => s.trim()).filter(Boolean);
  if (!ids.length) return '';
  return ids.map(raw => {
    const [id, encoded] = raw.split('=');
    const byName = id === 'denylist' || id === 'allowlist';
    if (byName) {
      let pattern = null;
      try { pattern = encoded ? decodeURIComponent(encoded) : null; } catch { pattern = encoded; }
      // Verdicts logged before patterns were recorded only say "denylist";
      // the rule named after the package itself is the best guess.
      const label = pattern || (e.name ? `${e.name} (by name)` : 'name rule');
      const known = _proxyRules?.names.get(pattern ?? e.name);
      const tip = known?.detail || `${id === 'denylist' ? 'Blocked' : 'Allowed'} by name rule`;
      if (!pattern && !e.name) return `<span title="${esc(tip)}">${esc(label)}</span>`;
      return `<a class="reason-link" href="#" data-rule-target="${esc(`name:${pattern ?? e.name}`)}"
         title="${esc(tip)}">${esc(label)}</a>`;
    }
    if (PROXY_SYSTEM_REASONS.has(id)) return `<span class="reason-system">${esc(id)}</span>`;
    const rule = _proxyRules?.rules.get(id);
    if (_proxyRules && !rule)  // deleted or renamed since this verdict
      return `<span class="reason-gone" title="This rule is no longer in the policy">${esc(id)}</span>`;
    return `<a class="reason-link" href="#" data-rule-target="${esc(`rule:${id}`)}"
       title="${esc(rule?.detail || 'Open this rule')}">${esc(id)}</a>`;
  }).join(', ');
}

async function proxyLoadTable() {
  const t = document.getElementById('proxyTable');
  if (!t) return;
  const requestId = ++_proxyRequestId;
  _proxyController?.abort();
  _proxyController = new AbortController();
  t.innerHTML = '<div class="panel-note tight">Loading…</div>';
  // Changing a filter starts again on page one.
  const pager = pageState('proxy', `${_proxyEco}|${_proxyDecision}|${_proxyQ}`);
  pager.rerender = proxyLoadTable;
  const p = new URLSearchParams();
  if (_proxyEco) p.set('ecosystem', _proxyEco);
  if (_proxyDecision) p.set('decision', _proxyDecision);
  if (_proxyQ) p.set('q', _proxyQ);
  p.set('page', String(pager.page));
  p.set('pageSize', String(pager.size));
  let d = { events: [], page: 1, pages: 1, total: 0 };
  try {
    const response = await fetch('/api/proxy/events?' + p.toString(), { signal: _proxyController.signal });
    if (!response.ok) throw new Error(`Proxy events failed (HTTP ${response.status})`);
    d = await readJson(response);
  }
  catch (e) {
    if (e.name === 'AbortError' || requestId !== _proxyRequestId) return;
    t.innerHTML = `<div class="panel-note tight error">${esc(e.message)}</div>`;
    return;
  }
  if (requestId !== _proxyRequestId || !document.getElementById('proxyTable')) return;
  pager.page = d.page || 1;
  if (!d.events || !d.events.length) {
    t.innerHTML = '<div class="panel-note">No packages passed through the gate yet.</div>';
    return;
  }
  const rows = d.events.map(e => `<tr>
    <td>${esc(_proxyFmtTime(e.at))}</td>
    <td><span class="eco-pill">${esc(e.ecosystem || '—')}</span></td>
    <td>${esc(e.name || '—')}</td>
    <td>${esc(e.version || '')}</td>
    <td><span class="verdict ${e.decision === 'deny' ? 'deny' : e.decision === 'error' ? 'err' : 'allow'}">${esc(e.decision)}</span></td>
    <td class="reasons">${_proxyReasonLinks(e)}</td>
    <td class="ip">${esc(e.client_ip || '')}</td>
  </tr>`).join('');
  const pagerHtml_ = pagerHtml('proxy', { page: d.page || 1, pages: d.pages || 1, total: d.total || 0, size: d.pageSize || pager.size });
  t.innerHTML = `<table class="proxy-table">
    <thead><tr><th>Time</th><th>Ecosystem</th><th>Package</th><th>Version</th><th>Verdict</th><th>Reason</th><th>Client IP</th></tr></thead>
    <tbody>${rows}</tbody></table>
     ${pagerHtml_ || `<div class="pager"><span class="pager-range">${d.total} total</span></div>`}`;
  t.querySelectorAll('[data-rule-target]').forEach(link => link.addEventListener('click', event => {
    event.preventDefault();
    // Jump to the rule that produced this verdict instead of making the
    // operator find it by eye in the policy.
    if (typeof rulesFocusOn === 'function') rulesFocusOn(link.dataset.ruleTarget);
    navTo('rules');
  }));
}
