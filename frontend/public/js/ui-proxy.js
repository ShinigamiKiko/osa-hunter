let _proxyEco = '';
let _proxyDecision = '';
let _proxyQ = '';
let _proxyPage = 1;
let _proxyRequestId = 0;
let _proxyController = null;

function _proxyFmtTime(s) { try { return new Date(s).toLocaleString(); } catch { return s || ''; } }

async function renderProxy() {
  const host = document.getElementById('proxyContent');
  if (!host) return;
  host.innerHTML = '<div style="padding:24px;color:var(--muted)">Loading…</div>';

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
      </select>
       <button id="proxySearch">Search</button>
       <button class="proxy-clear" id="proxyClear" title="Delete all proxy history">Clear</button>
       <button id="proxyRefresh">↻ Refresh</button>
    </div>
    <div id="proxyTable"></div>`;
  host.querySelectorAll('[data-proxy-eco]').forEach(button => button.addEventListener('click', () => proxyPick(button.dataset.proxyEco)));
  host.querySelector('#proxyQ').addEventListener('input', event => { _proxyQ = event.target.value; });
  host.querySelector('#proxyQ').addEventListener('keydown', event => { if (event.key === 'Enter') { _proxyPage = 1; proxyLoadTable(); } });
  host.querySelector('#proxyDecision').addEventListener('change', event => { _proxyDecision = event.target.value; _proxyPage = 1; proxyLoadTable(); });
  host.querySelector('#proxySearch').addEventListener('click', () => { _proxyPage = 1; proxyLoadTable(); });
  host.querySelector('#proxyClear').addEventListener('click', proxyClear);
  host.querySelector('#proxyRefresh').addEventListener('click', renderProxy);
  await proxyLoadTable();
}

function proxyPick(eco) { _proxyEco = eco; _proxyPage = 1; renderProxy(); }
function proxyGoPage(n) { _proxyPage = n; proxyLoadTable(); }

async function proxyClear() {
  if (!confirm('Delete ALL proxy history (events, blocks, artifact map)? This cannot be undone.')) return;
  try {
    const r = await fetch('/api/cache?type=proxy', { method: 'DELETE' });
    if (!r.ok) throw new Error((await r.json()).error || r.statusText);
    _proxyPage = 1; _proxyEco = ''; renderProxy();
  } catch (e) { alert('Clear failed: ' + e.message); }
}

function _proxyPager(page, pages, total) {
  if (pages <= 1) return `<div class="proxy-pager"><span class="pp-info">${total} total</span></div>`;
  const btn = (n, label, active, disabled) =>
    `<button class="proxy-page ${active ? 'active' : ''}" data-proxy-page="${n}" ${disabled ? 'disabled' : ''}>${label}</button>`;
  const nums = [];
  const from = Math.max(1, page - 3), to = Math.min(pages, page + 3);
  if (from > 1) { nums.push(btn(1, '1', page === 1, false)); if (from > 2) nums.push('<span>…</span>'); }
  for (let i = from; i <= to; i++) nums.push(btn(i, String(i), i === page, false));
  if (to < pages) { if (to < pages - 1) nums.push('<span>…</span>'); nums.push(btn(pages, String(pages), page === pages, false)); }
  return `<div class="proxy-pager" id="proxyPager">
    ${btn(page - 1, '‹', false, page <= 1)}
    ${nums.join('')}
    ${btn(page + 1, '›', false, page >= pages)}
    <span class="pp-info">${total} total · page ${page}/${pages}</span>
  </div>`;
}

async function proxyLoadTable() {
  const t = document.getElementById('proxyTable');
  if (!t) return;
  const requestId = ++_proxyRequestId;
  _proxyController?.abort();
  _proxyController = new AbortController();
  t.innerHTML = '<div style="padding:16px;color:var(--muted)">Loading…</div>';
  const p = new URLSearchParams();
  if (_proxyEco) p.set('ecosystem', _proxyEco);
  if (_proxyDecision) p.set('decision', _proxyDecision);
  if (_proxyQ) p.set('q', _proxyQ);
  p.set('page', String(_proxyPage));
  let d = { events: [], page: 1, pages: 1, total: 0 };
  try {
    const response = await fetch('/api/proxy/events?' + p.toString(), { signal: _proxyController.signal });
    if (!response.ok) throw new Error(`Proxy events failed (HTTP ${response.status})`);
    d = await readJson(response);
  }
  catch (e) {
    if (e.name === 'AbortError' || requestId !== _proxyRequestId) return;
    t.innerHTML = `<div style="padding:16px;color:#ff5f56">${esc(e.message)}</div>`;
    return;
  }
  if (requestId !== _proxyRequestId || !document.getElementById('proxyTable')) return;
  _proxyPage = d.page || 1;
  if (!d.events || !d.events.length) {
    t.innerHTML = '<div style="padding:24px;color:var(--muted)">No packages passed through the gate yet.</div>';
    return;
  }
  const rows = d.events.map(e => `<tr>
    <td>${esc(_proxyFmtTime(e.at))}</td>
    <td><span class="eco-pill">${esc(e.ecosystem || '—')}</span></td>
    <td>${esc(e.name || '—')}</td>
    <td>${esc(e.version || '')}</td>
    <td><span class="verdict ${e.decision === 'deny' ? 'deny' : 'allow'}">${esc(e.decision)}</span></td>
    <td class="reasons">${esc(e.reasons || '')}</td>
    <td class="ip">${esc(e.client_ip || '')}</td>
  </tr>`).join('');
  t.innerHTML = `<table class="proxy-table">
    <thead><tr><th>Time</th><th>Ecosystem</th><th>Package</th><th>Version</th><th>Verdict</th><th>Reason</th><th>Client IP</th></tr></thead>
    <tbody>${rows}</tbody></table>
     ${_proxyPager(d.page, d.pages, d.total)}`;
  t.querySelectorAll('[data-proxy-page]').forEach(button => button.addEventListener('click', () => proxyGoPage(Number(button.dataset.proxyPage))));
}
