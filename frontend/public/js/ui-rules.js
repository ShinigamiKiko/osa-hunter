// Gate policy editor. The stored format is the same YAML shape policy.yaml
// uses; this screen just builds it with dropdowns so nobody has to remember
// the syntax. Anything too nested for the form (all/any inside all/any) is
// shown read-only and stays editable through Import YAML.

let _rulesState = null;   // { source, body, dirty }
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
    const [factsRes, policyRes] = await Promise.all([
      fetch('/api/policy/facts'), fetch('/api/policy'),
    ]);
    if (!policyRes.ok) throw new Error(`No policy stored (HTTP ${policyRes.status})`);
    _rulesFacts = (await readJson(factsRes)).facts || [];
    const policy = await readJson(policyRes);
    _rulesState = { source: policy.source, body: policy.body, dirty: false };
  } catch (e) {
    host.innerHTML = `<div class="proxy-error">${esc(e.message)}</div>`;
    return;
  }
  rulesPaint();
}

// An entry is a bare string while it is plain, or { pattern, enabled?, reason? }
// once switched off or given its own message - the same two things a scan rule
// carries, so both kinds of rule edit the same way.
function _nameEntries(body) {
  const out = [];
  for (const action of ['deny', 'allow']) {
    (body.exceptions?.[action] || []).forEach((item, i) => {
      const obj = typeof item === 'string' ? { pattern: item } : item;
      out.push({
        kind: 'name', action, index: i,
        pattern: obj.pattern,
        reason: obj.reason || '',
        enabled: obj.enabled !== false,
      });
    });
  }
  return out;
}

function rulesPaint() {
  const host = document.getElementById('rulesContent');
  const b = _rulesState.body;
  const rules = b.rules || [];
  const names = _nameEntries(b);
  const total = rules.length + names.length;
  host.innerHTML = `
    <div class="rules-bar">
      <div class="rules-meta">
        <span class="rules-count">${total} rule${total === 1 ? '' : 's'}</span>
        ${_rulesState.source === 'yaml' ? '<span class="rev-pill" title="Loaded from the policy file on the server">import</span>' : ''}
        ${_rulesState.dirty ? '<span class="rules-dirty">unsaved changes</span>' : ''}
      </div>
      <div class="rules-actions">
        <button id="rulesAdd">+ Rule</button>
        <button id="rulesExport">Export YAML</button>
        <button id="rulesImport">Import YAML</button>
        <button id="rulesSave" class="primary" ${_rulesState.dirty ? '' : 'disabled'}>Save</button>
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

    <div id="rulesList">${
      names.map(_nameCard).join('')
      + rules.map((r, i) => _ruleCard(r, i)).join('')
      || '<div class="rules-empty">No rules yet — everything falls through to the default.</div>'}</div>`;

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
      <span class="rule-lead">name</span>
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
    <div class="rule-detail-row">
      <span class="rule-detail-lead">reason</span>
      <input class="rule-detail" data-field="detail" data-rule="${index}"
             value="${esc(rule.detail || '')}" placeholder="${esc(rule.id || 'shown to the blocked developer')}"/>
    </div>
  </div>`;
}

// A name entry is a rule too, just one the gate can settle without scanning:
// the package never reaches OSV, so it works for every ecosystem and does not
// depend on any feed being reachable. Shown as the same card, minus the parts
// that only make sense after a scan.
function _nameCard(entry) {
  const { action, pattern, index, enabled, reason } = entry;
  const ref = `${action}:${index}`;
  return `<div class="rule-card name-card ${enabled ? '' : 'off'}" data-name="${ref}">
    <div class="rule-head">
      <span class="rule-lead">name</span>
      <input class="rule-id" data-name-field="pattern" data-name="${ref}"
             value="${esc(pattern)}" placeholder="curl"/>
      <select class="rule-action ${action}" data-name-field="action" data-name="${ref}">
        ${['deny', 'allow'].map(a => `<option value="${a}"${action === a ? ' selected' : ''}>${a}</option>`).join('')}
      </select>
      <label class="rule-toggle"><input type="checkbox" data-name-field="enabled" data-name="${ref}" ${enabled ? 'checked' : ''}/> enabled</label>
      <button class="rule-del" data-name-del="${ref}" title="Delete rule">✕</button>
    </div>
    <div class="rule-when">
      <span class="when-lead">match</span>
      <div class="cond-row name-row">
        <span class="cond-op-fixed">package name is</span>
        <code class="name-pattern">${esc(pattern)}</code>
        <span class="name-scope">before scanning${pattern.includes('/') ? ' — scoped' : ''}${pattern.includes('*') ? ' — wildcard' : ''}</span>
      </div>
    </div>
    <div class="rule-detail-row">
      <span class="rule-detail-lead">reason</span>
      <input class="rule-detail" data-name-field="reason" data-name="${ref}"
             value="${esc(reason)}" placeholder="${esc(action === 'deny' ? `blocked by name: ${pattern}` : `allowed by name: ${pattern}`)}"/>
    </div>
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

  // Name cards edit policy.exceptions. Changing the verdict moves the entry
  // between the deny and allow lists.
  host.querySelectorAll('[data-name-field]').forEach(el => el.addEventListener('change', () => {
    const [action, raw] = el.dataset.name.split(':');
    const i = Number(raw);
    const list = body.exceptions[action];
    const cur = typeof list[i] === 'string' ? { pattern: list[i] } : { ...list[i] };
    // A plain entry stays a plain string; only an off switch or a reason needs
    // the object form, so an exported policy.yaml keeps its usual shape.
    const write = ({ pattern, enabled = true, reason = '' }) =>
      (enabled && !reason ? pattern
        : { pattern, ...(enabled ? {} : { enabled: false }), ...(reason ? { reason } : {}) });

    const field = el.dataset.nameField;
    if (field === 'pattern') {
      const v = el.value.trim();
      if (!v) return;
      list[i] = write({ ...cur, pattern: v, enabled: cur.enabled !== false });
    } else if (field === 'enabled') {
      list[i] = write({ ...cur, enabled: el.checked });
    } else if (field === 'reason') {
      list[i] = write({ ...cur, reason: el.value.trim(), enabled: cur.enabled !== false });
    } else {
      list.splice(i, 1);
      body.exceptions[el.value] = body.exceptions[el.value] || [];
      body.exceptions[el.value].push(write({ ...cur, enabled: cur.enabled !== false }));
    }
    _touch(); rulesPaint();
  }));

  host.querySelectorAll('[data-name-del]').forEach(b => b.addEventListener('click', () => {
    const [action, raw] = b.dataset.nameDel.split(':');
    const item = body.exceptions[action][Number(raw)];
    if (!confirm(`Delete rule "${typeof item === 'string' ? item : item.pattern}"?`)) return;
    body.exceptions[action].splice(Number(raw), 1); _touch(); rulesPaint();
  }));

  host.querySelector('#rulesSave').addEventListener('click', rulesSave);
  host.querySelector('#rulesExport').addEventListener('click', rulesExport);
  host.querySelector('#rulesImport').addEventListener('click', rulesImport);
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
  // Open first: _rulesModal() closes whatever is open, and closing discards the
  // draft. Seeding it before that would wipe the draft we just made.
  _rulesModal('New rule', '<div id="draftBody"></div>');
  _draft = {
    kind: 'scan', id: '', action: 'deny', match: 'all', detail: '', pattern: '',
    rows: [{ fact: 'counts.CRITICAL', op: '>=', value: '1' }],
  };
  draftPaint();
}

function draftPaint() {
  const host = document.getElementById('draftBody');
  if (!host || !_draft) return;
  const byName = _draft.kind === 'name';
  host.innerHTML = `
    <div class="draft-step">
      <span class="draft-num">1</span>
      <div class="draft-field">
        <label for="draftKind">What should this rule look at?</label>
        <select id="draftKind">
          <option value="scan"${byName ? '' : ' selected'}>The scan result — vulnerabilities, KEV, EPSS</option>
          <option value="name"${byName ? ' selected' : ''}>The package name — decided before scanning</option>
        </select>
        <span class="draft-hint">${byName
          ? 'The package never reaches OSV, so this works in every ecosystem and never depends on a feed being up.'
          : 'The package is scanned first, then these conditions are checked against the findings.'}</span>
      </div>
    </div>

    ${byName ? `
    <div class="draft-step">
      <span class="draft-num">2</span>
      <div class="draft-field">
        <label for="draftPattern">Package name</label>
        <input id="draftPattern" value="${esc(_draft.pattern)}" placeholder="curl"/>
        <span class="draft-hint">A bare name covers every ecosystem. Narrow it with
          <code>npm/left-pad</code>, pin it with <code>npm/left-pad@1.3.0</code>,
          or use a wildcard like <code>crossenv*</code>.</span>
      </div>
    </div>` : `
    <div class="draft-step">
      <span class="draft-num">2</span>
      <div class="draft-field">
        <label for="draftId">Name this rule</label>
        <input id="draftId" value="${esc(_draft.id)}" placeholder="no-critical-vulns"/>
        <span class="draft-hint">A short identifier — lowercase with dashes, no spaces.</span>
      </div>
    </div>

    <div class="draft-step">
      <span class="draft-num">3</span>
      <div class="draft-field">
        <label>Match a package when
          <select id="draftMatch">
            <option value="all"${_draft.match === 'all' ? ' selected' : ''}>all of these are true</option>
            <option value="any"${_draft.match === 'any' ? ' selected' : ''}>any of these is true</option>
          </select>
        </label>
        <div id="draftConds">${_draft.rows.map((r, i) => _conditionRow(r, 'draft', i)).join('')}</div>
        <button class="cond-add" id="draftAddCond">+ condition</button>
      </div>
    </div>`}

    <div class="draft-step">
      <span class="draft-num">${byName ? '3' : '4'}</span>
      <div class="draft-field">
        <label for="draftAction">Then</label>
        <select id="draftAction" class="rule-action ${_draft.action}">
          ${(byName ? ['deny', 'allow'] : ['deny', 'warn', 'allow'])
            .map(a => `<option value="${a}"${_draft.action === a ? ' selected' : ''}>${a}</option>`).join('')}
        </select>
        <span class="draft-hint">${_draft.action === 'deny' ? 'The download is blocked.'
          : _draft.action === 'warn' ? 'The download goes through and the match is recorded.'
          : 'The package is allowed even when another rule would block it.'}</span>
      </div>
    </div>

    <div class="draft-step">
      <span class="draft-num">${byName ? '4' : '5'}</span>
      <div class="draft-field">
        <label for="draftDetail">Reason text <span class="draft-optional">optional</span></label>
        <input id="draftDetail" value="${esc(_draft.detail)}" placeholder="${esc(byName
          ? `${_draft.action === 'deny' ? 'blocked' : 'allowed'} by name: ${_draft.pattern.trim() || '…'}`
          : (_draft.id.trim() || 'defaults to the rule name'))}"/>
        <span class="draft-hint">What the developer sees instead of the package.
          Leave it empty for the default message.</span>
      </div>
    </div>

    <div id="draftErr" class="draft-err" style="display:none"></div>

    <div class="rules-modal-actions">
      <button id="draftCancel">Cancel</button>
      <button id="draftAdd" class="primary">Add rule</button>
    </div>`;

  // The kind switch rebuilds the form, so read the current values across first.
  host.querySelector('#draftKind').addEventListener('change', e => {
    draftSync(false);
    _draft.kind = e.target.value;
    if (_draft.kind === 'name' && _draft.action === 'warn') _draft.action = 'deny';
    draftPaint();
  });
  host.querySelector('#draftAction').addEventListener('change', () => draftSync());
  host.querySelector('#draftCancel').addEventListener('click', _rulesCloseModal);
  host.querySelector('#draftAdd').addEventListener('click', draftCommit);
  host.querySelector('#draftDetail').addEventListener('input', e => { _draft.detail = e.target.value; });

  if (byName) {
    host.querySelector('#draftPattern').addEventListener('input', e => { _draft.pattern = e.target.value; });
    return;
  }

  host.querySelector('#draftId').addEventListener('input', e => { _draft.id = e.target.value; });
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
}

// Pull the dialog's values into the draft. Repaint only when the controls
// themselves changed, so typing in a text field never fights the cursor.
function draftSync(repaint = true) {
  const host = document.getElementById('draftBody');
  if (!host || !_draft) return;
  _draft.action = host.querySelector('#draftAction').value;
  _draft.detail = host.querySelector('#draftDetail').value;
  const pattern = host.querySelector('#draftPattern');
  if (pattern) _draft.pattern = pattern.value;
  const id = host.querySelector('#draftId');
  if (id) {
    _draft.id = id.value;
    _draft.match = host.querySelector('#draftMatch').value;
    _draft.rows = _readRows(host.querySelector('#draftConds'));
  }
  if (repaint) draftPaint();
}

function draftCommit() {
  draftSync(false);
  const body = _rulesState.body;
  const err = document.getElementById('draftErr');
  const fail = (msg) => { err.textContent = msg; err.style.display = 'block'; };

  if (_draft.kind === 'name') {
    const pattern = _draft.pattern.trim();
    if (!pattern) return fail('Enter a package name.');
    body.exceptions = body.exceptions || { allow: [], deny: [] };
    const list = body.exceptions[_draft.action] = body.exceptions[_draft.action] || [];
    const has = list.some(e => (typeof e === 'string' ? e : e.pattern) === pattern);
    if (has) return fail(`"${pattern}" is already in the list.`);
    const reason = _draft.detail.trim();
    list.push(reason ? { pattern, reason } : pattern);
  } else {
    const id = _draft.id.trim();
    if (!id) return fail('Give the rule a name.');
    if ((body.rules || []).some(r => r.id === id)) return fail(`A rule named "${id}" already exists.`);
    const when = _rowsToWhen(_draft.match, _draft.rows);
    if (!Object.keys(when).length) return fail('Add at least one condition.');
    body.rules = body.rules || [];
    body.rules.push({
      id, action: _draft.action, when,
      ...(_draft.detail.trim() ? { detail: _draft.detail.trim() } : {}),
    });
  }

  _touch();
  _rulesCloseModal();
  rulesPaint();
}

// ── server actions ────────────────────────────────────────────
async function rulesSave() {
  if (!confirm('Save this policy? It starts being enforced immediately.')) return;
  try {
    const r = await fetch('/api/policy', {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ body: _rulesState.body }),
    });
    if (!r.ok) throw new Error((await r.json()).error || r.statusText);
    renderRules();
  } catch (e) { alert('Save failed: ' + e.message); }
}

async function rulesExport() {
  try {
    const r = await fetch('/api/policy/yaml');
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
      <button id="rulesYamlSave" class="primary">Save and enforce</button>
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
    if (!confirm('Replace the policy with this YAML? It is enforced immediately.')) return;
    try {
      const r = await fetch('/api/policy', {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ yaml: text }),
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
