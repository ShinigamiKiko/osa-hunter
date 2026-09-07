// Gate policy editor. The stored format is the same YAML shape policy.yaml
// uses; this screen just builds it with dropdowns so nobody has to remember
// the syntax. Anything too nested for the form (all/any inside all/any) is
// shown read-only and stays editable through Import YAML.

let _rulesState = null;   // { revision, body, dirty }
let _rulesRevisions = [];
let _rulesFacts = [];
let _draft = null;        // rule being filled in the New rule dialog

const RULES_OPS = [
  { v: '>=', l: '≥' }, { v: '>', l: '>' }, { v: '<=', l: '≤' },
  { v: '<', l: '<' }, { v: '==', l: '=' }, { v: '!=', l: '≠' },
];

function _factMeta(key) {
  return _rulesFacts.find(f => f.key === key) || { key, label: key, type: 'pattern' };
}

// ── model <-> form ────────────────────────────────────────────
// A rule's `when` is either {fact: expr}, {all:[…]} or {any:[…]}. Flatten the
// simple shapes into rows the form can render; flag the rest as advanced.
function _whenToRows(when) {
  if (!when || typeof when !== 'object') return { match: 'all', rows: [], advanced: true };
  const entries = Object.entries(when);
  if (entries.length === 1 && (entries[0][0] === 'all' || entries[0][0] === 'any')) {
    const rows = [];
    for (const item of entries[0][1]) {
      const pairs = Object.entries(item || {});
      if (pairs.length !== 1 || pairs[0][0] === 'all' || pairs[0][0] === 'any') {
        return { match: entries[0][0], rows: [], advanced: true };
      }
      rows.push(_pairToRow(pairs[0]));
    }
    return { match: entries[0][0], rows, advanced: false };
  }
  if (entries.some(([k]) => k === 'all' || k === 'any')) return { match: 'all', rows: [], advanced: true };
  return { match: 'all', rows: entries.map(_pairToRow), advanced: false };
}

function _pairToRow([fact, expr]) {
  const raw = String(expr);
  const cmp = raw.match(/^(>=|<=|>|<|==|!=)\s*(.+)$/);
  if (cmp) return { fact, op: cmp[1], value: cmp[2] };
  if (['yes', 'no', 'true', 'false', 'on', 'off'].includes(raw.toLowerCase())) {
    return { fact, op: 'is', value: ['yes', 'true', 'on'].includes(raw.toLowerCase()) ? 'yes' : 'no' };
  }
  return { fact, op: 'match', value: raw };
}

function _rowToPair(row) {
  const value = row.op === 'is' ? row.value
    : row.op === 'match' ? row.value
    : `${row.op} ${row.value}`;
  return { [row.fact]: value };
}

function _rowsToWhen(match, rows) {
  const pairs = rows.filter(r => r.fact && String(r.value).length).map(_rowToPair);
  if (!pairs.length) return {};
  if (pairs.length === 1 && match === 'all') return pairs[0];
  return { [match]: pairs };
}

// ── loading ───────────────────────────────────────────────────
async function renderRules() {
  const host = document.getElementById('rulesContent');
  if (!host) return;
  host.innerHTML = '<div style="padding:24px;color:var(--muted)">Loading…</div>';
  try {
    const [factsRes, activeRes, revsRes] = await Promise.all([
      fetch('/api/policy/facts'), fetch('/api/policy/active'), fetch('/api/policy/revisions'),
    ]);
    if (!activeRes.ok) throw new Error(`No active policy (HTTP ${activeRes.status})`);
    _rulesFacts = (await readJson(factsRes)).facts || [];
    const active = await readJson(activeRes);
    _rulesRevisions = (await readJson(revsRes)).revisions || [];
    _rulesState = { revision: active.revision, body: active.body, dirty: false };
  } catch (e) {
    host.innerHTML = `<div class="proxy-error">${esc(e.message)}</div>`;
    return;
  }
  rulesPaint();
}

function rulesPaint() {
  const host = document.getElementById('rulesContent');
  const b = _rulesState.body;
  const rules = b.rules || [];
  host.innerHTML = `
    <div class="rules-bar">
      <div class="rules-meta">
        <span class="rev-pill">revision ${esc(String(_rulesState.revision))}</span>
        <span class="rules-count">${rules.length} rule${rules.length === 1 ? '' : 's'}</span>
        ${_rulesState.dirty ? '<span class="rules-dirty">unsaved changes</span>' : ''}
      </div>
      <div class="rules-actions">
        <button id="rulesAdd">+ Rule</button>
        <button id="rulesExport">Export YAML</button>
        <button id="rulesImport">Import YAML</button>
        <button id="rulesSave" class="primary" ${_rulesState.dirty ? '' : 'disabled'}>Save revision</button>
      </div>
    </div>

    <div class="rules-defaults">
      <label>When no rule matches
        <select id="defDecision">
          ${['allow', 'warn', 'deny'].map(d => `<option value="${d}"${b.defaults?.decision === d ? ' selected' : ''}>${d}</option>`).join('')}
        </select>
      </label>
      <label>If the scan itself fails
        <select id="defError">
          ${['deny', 'allow'].map(d => `<option value="${d}"${b.defaults?.on_gate_error === d ? ' selected' : ''}>${d}</option>`).join('')}
        </select>
      </label>
    </div>

    <div id="rulesList">${rules.map((r, i) => _ruleCard(r, i)).join('') || '<div class="rules-empty">No rules yet — everything falls through to the default.</div>'}</div>

    ${_exceptionsBlock('deny', b.exceptions?.deny || [])}
    ${_exceptionsBlock('allow', b.exceptions?.allow || [])}

    <div class="rules-revs">
      <h3>Revisions</h3>
      <table class="proxy-table">
        <thead><tr><th>#</th><th>Source</th><th>Rules</th><th>Author</th><th>When</th><th>Note</th><th></th></tr></thead>
        <tbody>${_rulesRevisions.map(r => `<tr class="${r.active ? 'rev-active' : ''}">
          <td>${r.revision}${r.active ? ' <span class="rev-live">active</span>' : ''}</td>
          <td><span class="eco-pill">${esc(r.source)}</span></td>
          <td>${r.rule_count}</td>
          <td>${esc(r.created_by || '—')}</td>
          <td>${esc(new Date(r.created_at).toLocaleString())}</td>
          <td>${esc(r.note || '')}</td>
          <td>${r.active ? '' : `<button class="rev-btn" data-activate="${r.revision}">Activate</button>`}
              <button class="rev-btn" data-view="${r.revision}">View</button></td>
        </tr>`).join('')}</tbody>
      </table>
    </div>`;

  rulesBind();
}

function _ruleCard(rule, index) {
  const { match, rows, advanced } = _whenToRows(rule.when);
  const disabled = rule.enabled === false;
  const conditions = advanced
    ? `<div class="rule-advanced">Advanced condition — edit via Import YAML.
         <code>${esc(JSON.stringify(rule.when))}</code></div>`
    : rows.map((row, ri) => _conditionRow(row, index, ri)).join('')
      + `<button class="cond-add" data-add-cond="${index}">+ condition</button>`;

  return `<div class="rule-card ${disabled ? 'off' : ''}" data-rule="${index}">
    <div class="rule-head">
      <input class="rule-id" data-field="id" data-rule="${index}" value="${esc(rule.id || '')}" placeholder="rule-id"/>
      <select class="rule-action ${rule.action}" data-field="action" data-rule="${index}">
        ${['deny', 'warn', 'allow'].map(a => `<option value="${a}"${rule.action === a ? ' selected' : ''}>${a}</option>`).join('')}
      </select>
      <label class="rule-toggle"><input type="checkbox" data-field="enabled" data-rule="${index}" ${disabled ? '' : 'checked'}/> enabled</label>
      <button class="rule-del" data-del="${index}" title="Delete rule">✕</button>
    </div>
    <div class="rule-when">
      <span class="when-lead">${advanced ? 'when' : `match <select class="cond-match" data-rule="${index}">
        <option value="all"${match === 'all' ? ' selected' : ''}>all of</option>
        <option value="any"${match === 'any' ? ' selected' : ''}>any of</option>
      </select>`}</span>
      ${conditions}
    </div>
    <input class="rule-detail" data-field="detail" data-rule="${index}"
           value="${esc(rule.detail || '')}" placeholder="message shown to the blocked client"/>
  </div>`;
}

function _conditionRow(row, ruleIndex, condIndex) {
  const meta = _factMeta(row.fact);
  const factSelect = `<select class="cond-fact" data-rule="${ruleIndex}" data-cond="${condIndex}">
    ${_rulesFacts.map(f => `<option value="${esc(f.key)}"${f.key === row.fact ? ' selected' : ''}>${esc(f.label)}</option>`).join('')}
  </select>`;

  let control;
  if (meta.type === 'boolean') {
    control = `<select class="cond-value" data-rule="${ruleIndex}" data-cond="${condIndex}" data-op="is">
      <option value="yes"${row.value === 'yes' ? ' selected' : ''}>yes</option>
      <option value="no"${row.value === 'no' ? ' selected' : ''}>no</option>
    </select>`;
  } else if (meta.type === 'enum') {
    control = `<select class="cond-op" data-rule="${ruleIndex}" data-cond="${condIndex}">
        ${['==', '!='].map(o => `<option value="${o}"${row.op === o ? ' selected' : ''}>${o === '==' ? 'is' : 'is not'}</option>`).join('')}
      </select>
      <select class="cond-value" data-rule="${ruleIndex}" data-cond="${condIndex}">
        ${(meta.values || []).map(v => `<option value="${esc(v)}"${row.value === v ? ' selected' : ''}>${esc(v)}</option>`).join('')}
      </select>`;
  } else if (meta.type === 'number') {
    control = `<select class="cond-op" data-rule="${ruleIndex}" data-cond="${condIndex}">
        ${RULES_OPS.map(o => `<option value="${o.v}"${row.op === o.v ? ' selected' : ''}>${o.l}</option>`).join('')}
      </select>
      <input class="cond-value" type="number" step="any" data-rule="${ruleIndex}" data-cond="${condIndex}" value="${esc(String(row.value))}"/>`;
  } else {
    control = `<span class="cond-op-fixed" data-op="match">matches</span>
      <input class="cond-value" data-rule="${ruleIndex}" data-cond="${condIndex}"
             value="${esc(String(row.value))}" placeholder="${esc(meta.example || 'value or glob*')}"/>`;
  }

  return `<div class="cond-row">${factSelect}${control}
    <button class="cond-del" data-rule="${ruleIndex}" data-del-cond="${condIndex}">✕</button></div>`;
}

function _exceptionsBlock(kind, list) {
  return `<div class="rules-exc" data-exc="${kind}">
    <h3>${kind === 'deny' ? 'Always block by name' : 'Always allow by name'}</h3>
    <p class="exc-hint">Checked before any scan. A bare name applies to every ecosystem
       (<code>curl</code>), or scope it: <code>npm/left-pad</code>, <code>npm/left-pad@1.3.0</code>, <code>crossenv*</code>.</p>
    <div class="exc-list">${list.map((v, i) =>
      `<span class="exc-chip">${esc(v)}<button data-exc-del="${kind}" data-i="${i}">✕</button></span>`).join('') || '<span class="exc-none">none</span>'}</div>
    <div class="exc-add">
      <input id="excInput-${kind}" placeholder="package name…"/>
      <button data-exc-add="${kind}">Add</button>
    </div>
  </div>`;
}

// ── editing ───────────────────────────────────────────────────
function _touch() { _rulesState.dirty = true; }

function rulesBind() {
  const host = document.getElementById('rulesContent');
  const body = _rulesState.body;

  host.querySelector('#defDecision').addEventListener('change', e => {
    body.defaults = { ...body.defaults, decision: e.target.value }; _touch(); rulesPaint();
  });
  host.querySelector('#defError').addEventListener('change', e => {
    body.defaults = { ...body.defaults, on_gate_error: e.target.value }; _touch(); rulesPaint();
  });

  host.querySelectorAll('[data-field]').forEach(el => el.addEventListener('change', () => {
    const rule = body.rules[Number(el.dataset.rule)];
    const field = el.dataset.field;
    if (field === 'enabled') { if (el.checked) delete rule.enabled; else rule.enabled = false; }
    else rule[field] = el.value;
    _touch(); rulesPaint();
  }));

  host.querySelectorAll('.cond-match, .cond-fact, .cond-op, .cond-value').forEach(el =>
    el.addEventListener('change', () => rulesSyncConditions(Number(el.dataset.rule))));

  host.querySelectorAll('[data-add-cond]').forEach(b => b.addEventListener('click', () => {
    const i = Number(b.dataset.addCond);
    const { match, rows } = _whenToRows(body.rules[i].when);
    rows.push({ fact: _rulesFacts[0].key, op: '>=', value: '1' });
    body.rules[i].when = _rowsToWhen(match, rows);
    _touch(); rulesPaint();
  }));

  host.querySelectorAll('[data-del-cond]').forEach(b => b.addEventListener('click', () => {
    const i = Number(b.dataset.rule);
    const { match, rows } = _whenToRows(body.rules[i].when);
    rows.splice(Number(b.dataset.delCond), 1);
    body.rules[i].when = _rowsToWhen(match, rows);
    _touch(); rulesPaint();
  }));

  host.querySelectorAll('[data-del]').forEach(b => b.addEventListener('click', () => {
    if (!confirm(`Delete rule "${body.rules[Number(b.dataset.del)].id}"?`)) return;
    body.rules.splice(Number(b.dataset.del), 1); _touch(); rulesPaint();
  }));

  host.querySelector('#rulesAdd').addEventListener('click', rulesNewRule);

  host.querySelectorAll('[data-exc-add]').forEach(b => b.addEventListener('click', () => {
    const kind = b.dataset.excAdd;
    const input = document.getElementById('excInput-' + kind);
    const v = input.value.trim();
    if (!v) return;
    body.exceptions = body.exceptions || { allow: [], deny: [] };
    body.exceptions[kind] = body.exceptions[kind] || [];
    if (!body.exceptions[kind].includes(v)) body.exceptions[kind].push(v);
    _touch(); rulesPaint();
  }));
  host.querySelectorAll('[data-exc-del]').forEach(b => b.addEventListener('click', () => {
    body.exceptions[b.dataset.excDel].splice(Number(b.dataset.i), 1); _touch(); rulesPaint();
  }));

  host.querySelector('#rulesSave').addEventListener('click', rulesSave);
  host.querySelector('#rulesExport').addEventListener('click', rulesExport);
  host.querySelector('#rulesImport').addEventListener('click', rulesImport);

  host.querySelectorAll('[data-activate]').forEach(b => b.addEventListener('click', () => rulesActivate(b.dataset.activate)));
  host.querySelectorAll('[data-view]').forEach(b => b.addEventListener('click', () => rulesView(b.dataset.view)));
}

// Read every condition control inside a container back into row objects.
// Shared by the inline cards and the New rule dialog.
function _readRows(scope) {
  return [...scope.querySelectorAll('.cond-row')].map(row => {
    const fact = row.querySelector('.cond-fact').value;
    const meta = _factMeta(fact);
    const valueEl = row.querySelector('.cond-value');
    const op = meta.type === 'boolean' ? 'is'
      : meta.type === 'pattern' ? 'match'
      : (row.querySelector('.cond-op')?.value || '>=');
    return { fact, op, value: valueEl ? valueEl.value : '' };
  });
}

// Rebuild one rule's `when` from every control currently on screen.
function rulesSyncConditions(ruleIndex) {
  const card = document.querySelector(`.rule-card[data-rule="${ruleIndex}"]`);
  if (!card) return;
  const match = card.querySelector('.cond-match')?.value || 'all';
  _rulesState.body.rules[ruleIndex].when = _rowsToWhen(match, _readRows(card));
  _touch();
  rulesPaint();
}

// ── new rule dialog ───────────────────────────────────────────
// A new rule is filled in a dialog and only joins the policy once it is
// complete, so the list never holds a half-written placeholder rule.
function rulesNewRule() {
  _draft = {
    id: '', action: 'deny', match: 'all', detail: '',
    rows: [{ fact: 'counts.CRITICAL', op: '>=', value: '1' }],
  };
  _rulesModal('New rule', '<div id="draftBody"></div>');
  draftPaint();
}

function draftPaint() {
  const host = document.getElementById('draftBody');
  if (!host) return;
  host.innerHTML = `
    <div class="draft-grid">
      <label>Rule name
        <input id="draftId" value="${esc(_draft.id)}" placeholder="no-critical-vulns"/>
        <span class="draft-hint">Appears in the block reason and in the logs.</span>
      </label>
      <label>Verdict
        <select id="draftAction">
          ${['deny', 'warn', 'allow'].map(a => `<option value="${a}"${_draft.action === a ? ' selected' : ''}>${a}</option>`).join('')}
        </select>
        <span class="draft-hint">deny blocks the download; warn only records it.</span>
      </label>
    </div>

    <div class="draft-section">
      <div class="draft-lead">Apply when
        <select id="draftMatch">
          <option value="all"${_draft.match === 'all' ? ' selected' : ''}>all of these are true</option>
          <option value="any"${_draft.match === 'any' ? ' selected' : ''}>any of these is true</option>
        </select>
      </div>
      <div id="draftConds">${_draft.rows.map((r, i) => _conditionRow(r, 'draft', i)).join('')}</div>
      <button class="cond-add" id="draftAddCond">+ condition</button>
    </div>

    <label class="draft-detail">Message shown to the blocked client
      <input id="draftDetail" value="${esc(_draft.detail)}" placeholder="package contains a critical vulnerability"/>
    </label>

    <div id="draftErr" class="draft-err" style="display:none"></div>

    <div class="rules-modal-actions">
      <button id="draftCancel">Cancel</button>
      <button id="draftAdd" class="primary">Add rule</button>
    </div>`;

  host.querySelector('#draftId').addEventListener('input', e => { _draft.id = e.target.value; });
  host.querySelector('#draftDetail').addEventListener('input', e => { _draft.detail = e.target.value; });
  host.querySelector('#draftAction').addEventListener('change', e => { _draft.action = e.target.value; });
  host.querySelector('#draftMatch').addEventListener('change', () => draftSync());
  host.querySelectorAll('#draftConds .cond-fact, #draftConds .cond-op, #draftConds .cond-value')
    .forEach(el => el.addEventListener('change', () => draftSync()));
  host.querySelector('#draftAddCond').addEventListener('click', () => {
    draftSync(false);
    _draft.rows.push({ fact: _rulesFacts[0].key, op: '>=', value: '1' });
    draftPaint();
  });
  host.querySelectorAll('#draftConds [data-del-cond]').forEach(b => b.addEventListener('click', () => {
    draftSync(false);
    _draft.rows.splice(Number(b.dataset.delCond), 1);
    draftPaint();
  }));
  host.querySelector('#draftCancel').addEventListener('click', _rulesCloseModal);
  host.querySelector('#draftAdd').addEventListener('click', draftCommit);
}

// Pull the dialog's values into the draft. Repaint only when the controls
// themselves changed, so typing in a text field never fights the cursor.
function draftSync(repaint = true) {
  const host = document.getElementById('draftBody');
  if (!host) return;
  _draft.id = host.querySelector('#draftId').value;
  _draft.detail = host.querySelector('#draftDetail').value;
  _draft.action = host.querySelector('#draftAction').value;
  _draft.match = host.querySelector('#draftMatch').value;
  _draft.rows = _readRows(host.querySelector('#draftConds'));
  if (repaint) draftPaint();
}

function draftCommit() {
  draftSync(false);
  const err = document.getElementById('draftErr');
  const fail = (msg) => { err.textContent = msg; err.style.display = 'block'; };

  const id = _draft.id.trim();
  if (!id) return fail('Give the rule a name.');
  if ((_rulesState.body.rules || []).some(r => r.id === id)) return fail(`A rule named "${id}" already exists.`);
  const when = _rowsToWhen(_draft.match, _draft.rows);
  if (!Object.keys(when).length) return fail('Add at least one condition.');

  _rulesState.body.rules = _rulesState.body.rules || [];
  _rulesState.body.rules.push({
    id, action: _draft.action, when,
    ...(_draft.detail.trim() ? { detail: _draft.detail.trim() } : {}),
  });
  _touch();
  _rulesCloseModal();
  rulesPaint();
}

// ── server actions ────────────────────────────────────────────
async function rulesSave() {
  const note = prompt('Describe this change (shown in the revision list):', '');
  if (note === null) return;
  const activate = confirm('Activate this revision now?\n\nOK = enforce immediately.\nCancel = save only, so you can simulate first.');
  try {
    const r = await fetch('/api/policy/revisions', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ body: _rulesState.body, note, activate }),
    });
    if (!r.ok) throw new Error((await r.json()).error || r.statusText);
    alert(activate ? 'Saved and activated.' : 'Saved as an inactive revision.');
    renderRules();
  } catch (e) { alert('Save failed: ' + e.message); }
}

async function rulesActivate(revision) {
  if (!confirm(`Activate revision ${revision}? It starts blocking immediately.`)) return;
  try {
    const r = await fetch(`/api/policy/revisions/${revision}/activate`, { method: 'POST' });
    if (!r.ok) throw new Error((await r.json()).error || r.statusText);
    renderRules();
  } catch (e) { alert('Activate failed: ' + e.message); }
}

async function rulesView(revision) {
  try {
    const r = await fetch(`/api/policy/revisions/${revision}/yaml`);
    if (!r.ok) throw new Error(r.statusText);
    _rulesModal(`Revision ${revision}`, `<pre class="rules-yaml">${esc(await r.text())}</pre>`);
  } catch (e) { alert('Load failed: ' + e.message); }
}

async function rulesExport() {
  try {
    const r = await fetch(`/api/policy/revisions/${_rulesState.revision}/yaml`);
    const text = await r.text();
    _rulesModal('policy.yaml', `<pre class="rules-yaml">${esc(text)}</pre>
      <p class="rules-hint">Copy this into <code>policy.yaml</code> to keep the policy in git.</p>`);
  } catch (e) { alert('Export failed: ' + e.message); }
}

function rulesImport() {
  _rulesModal('Import YAML', `
    <textarea id="rulesYamlIn" class="rules-yaml-in" placeholder="paste policy YAML…"></textarea>
    <div class="rules-modal-actions">
      <button id="rulesYamlLoad">Load into editor</button>
      <button id="rulesYamlSave" class="primary">Save as revision</button>
    </div>`);
  document.getElementById('rulesYamlLoad').addEventListener('click', async () => {
    const text = document.getElementById('rulesYamlIn').value;
    try {
      // The server parses and validates with the same compiler the gate uses,
      // so the browser never needs a YAML parser and invalid input can't land
      // in the editor.
      const r = await fetch('/api/policy/normalize', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ yaml: text }),
      });
      if (!r.ok) throw new Error((await r.json()).error || r.statusText);
      _rulesState.body = (await readJson(r)).body;
      _rulesState.dirty = true;
      _rulesCloseModal(); rulesPaint();
    } catch (e) { alert('Invalid policy: ' + e.message); }
  });
  document.getElementById('rulesYamlSave').addEventListener('click', async () => {
    const text = document.getElementById('rulesYamlIn').value;
    const activate = confirm('Activate this policy immediately?');
    try {
      const r = await fetch('/api/policy/revisions', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ yaml: text, note: 'imported YAML', activate }),
      });
      if (!r.ok) throw new Error((await r.json()).error || r.statusText);
      _rulesCloseModal(); renderRules();
    } catch (e) { alert('Import failed: ' + e.message); }
  });
}

// ── modal ─────────────────────────────────────────────────────
function _rulesModal(title, html) {
  _rulesCloseModal();
  const ov = document.createElement('div');
  ov.className = 'ov'; ov.id = 'rulesOv'; ov.style.display = 'flex';
  ov.innerHTML = `<div class="modal rules-modal" onclick="event.stopPropagation()">
      <div class="mhdr"><span class="mtitle">${esc(title)}</span>
        <button class="mclose" id="rulesModalClose">✕</button></div>
      <div class="rules-modal-body">${html}</div>
    </div>`;
  document.body.appendChild(ov);
  ov.addEventListener('click', e => { if (e.target === ov) _rulesCloseModal(); });
  document.getElementById('rulesModalClose').addEventListener('click', _rulesCloseModal);
}
function _rulesCloseModal() { document.getElementById('rulesOv')?.remove(); _draft = null; }
