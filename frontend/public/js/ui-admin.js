
function renderAdmin() {
  const el = document.getElementById('adminContent');
  if (!el) return;
  el.innerHTML = `
    <div class="admin">
      <div class="admin-head">
        <div>
          <div class="admin-title">User Management</div>
          <div class="admin-sub">Create and manage OSA Hunter accounts</div>
        </div>
        <button class="btn-primary" onclick="showCreateUser()">+ New User</button>
      </div>

      <div id="createUserForm" class="admin-form">
        <div class="admin-form-title">New Account</div>
        <div class="admin-form-grid">
          <div>
            <div class="field-label">Username</div>
            <input id="newUsername" class="field-input" type="text" placeholder="john_doe"/>
          </div>
          <div>
            <div class="field-label">Password</div>
            <input id="newPassword" class="field-input" type="password" placeholder="••••••••"/>
          </div>
          <div>
            <div class="field-label">Role</div>
            <select id="newRole" class="field-input">
              <option value="user">User</option>
              <option value="admin">Admin</option>
            </select>
          </div>
          <div class="admin-form-actions">
            <button class="btn-primary btn-sm" onclick="createUser()">Create</button>
            <button class="btn-secondary btn-sm" onclick="hideCreateUser()">Cancel</button>
          </div>
        </div>
        <div id="createErr" class="form-error" hidden></div>
      </div>

      <div class="admin-panel">
        <div id="usersTableWrap">
          <div class="admin-empty">Loading…</div>
        </div>
      </div>

      <div id="apiKeysSection"></div>
    </div>
  `;
  loadUsers();
  renderApiKeys();
}

function showCreateUser() {
  document.getElementById('createUserForm').classList.add('open');
  document.getElementById('newUsername').focus();
}
function hideCreateUser() {
  document.getElementById('createUserForm').classList.remove('open');
  document.getElementById('newUsername').value = '';
  document.getElementById('newPassword').value = '';
  document.getElementById('createErr').hidden=true;
}

const dateOnly = d => new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: '2-digit' });

function userRowHtml(u) {
  const self = u.id === window._authUser?.id;
  return `
    <tr id="urow-${u.id}">
      <td>
        <div class="user-cell">
          <span class="user-avatar">${esc(u.username[0].toUpperCase())}</span>
          <span class="cell-strong">${esc(u.username)}</span>
          ${self ? '<span class="user-you">(you)</span>' : ''}
        </div>
      </td>
      <td><span class="role-badge${u.role === 'admin' ? ' admin' : ''}">${esc(u.role.toUpperCase())}</span></td>
      <td class="cell-muted">${dateOnly(u.created_at)}</td>
      <td>${self ? '' : `<button class="btn-row-action" data-uid="${u.id}" data-uname="${esc(u.username)}" onclick="deleteUser(+this.dataset.uid,this.dataset.uname)">Remove</button>`}</td>
    </tr>`;
}

async function loadUsers() {
  const wrap = document.getElementById('usersTableWrap');
  if (!wrap) return;
  try {
    const r = await fetch('/api/auth/users', { credentials: 'same-origin' });
    const { users } = await readJson(r);
    const page = paginate('admin-users', users, loadUsers);
    if (!users.length) {
      wrap.innerHTML = '<div class="admin-empty">No users yet</div>';
      return;
    }
    wrap.innerHTML = `
      <table class="admin-table">
        <thead>
          <tr><th>Username</th><th>Role</th><th>Created</th><th class="actions"></th></tr>
        </thead>
        <tbody>${page.rows.map(([u]) => userRowHtml(u)).join('')}</tbody>
      </table>${page.html}`;
  } catch (e) {
    wrap.innerHTML = '<div class="admin-empty error">Failed to load users</div>';
  }
}

async function createUser() {
  const username = document.getElementById('newUsername').value.trim();
  const password = document.getElementById('newPassword').value;
  const role     = document.getElementById('newRole').value;
  const errEl    = document.getElementById('createErr');
  errEl.hidden=true;
  if (!username || !password) { errEl.textContent = 'Username and password required'; errEl.hidden=false; return; }
  try {
    const r = await fetch('/api/auth/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, role }),
      credentials: 'same-origin',
    });
    const data = await readJson(r);
    if (!r.ok) { errEl.textContent = data.error || 'Failed to create user'; errEl.hidden=false; return; }
    hideCreateUser();
    loadUsers();
  } catch (e) {
    errEl.textContent = 'Connection error'; errEl.hidden=false;
  }
}

async function deleteUser(id, username) {
  if (!confirm(`Remove user "${username}"? This cannot be undone.`)) return;
  try {
    const r = await fetch(`/api/auth/users/${id}`, {
      method: 'DELETE',
      credentials: 'same-origin',
    });
    if (!r.ok) { const d = await r.json(); alert(d.error || 'Failed to delete'); return; }
    const row = document.getElementById(`urow-${id}`);
    if (row) row.remove();
  } catch (e) {
    alert('Connection error');
  }
}

async function renderApiKeys() {
  const el = document.getElementById('apiKeysSection');
  if (!el) return;

  let keys;
  try {
    const r = await fetch('/api/auth/api-keys', { credentials: 'same-origin' });
    ({ keys } = await readJson(r));
  } catch (e) {
    el.innerHTML = `<div class="admin-empty error tight">Failed to load API keys: ${esc(e.message)}</div>`;
    return;
  }
  const keyPage = paginate('api-keys', keys || [], renderApiKeys);

  const isAdmin = window._authUser?.role === 'admin';
  const lastUsed = k => k.last_used
    ? new Date(k.last_used).toLocaleString('en-US', { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' })
    : 'Never';
  const rows = keyPage.rows.map(([k]) => `
    <tr id="krow-${k.id}">
      <td class="cell-strong">${esc(k.name)}</td>
      <td><code class="key-prefix">${esc(k.key_prefix)}…</code></td>
      ${isAdmin ? `<td class="cell-dim">${esc(k.owner || '—')}</td>` : ''}
      <td class="cell-muted">${lastUsed(k)}</td>
      <td><button class="btn-row-action" onclick="deleteApiKey(${k.id})">Revoke</button></td>
    </tr>`).join('');

  el.innerHTML = `
    <div class="admin-panel spaced">
      <div class="admin-panel-head">
        <div>
          <div class="admin-panel-title">API Keys</div>
          <div class="admin-panel-sub">Use <code>X-Api-Key: &lt;key&gt;</code> header to authenticate API requests</div>
        </div>
        <button class="btn-primary btn-xs" onclick="showNewKeyForm()">+ New Key</button>
      </div>

      <div id="newKeyForm" class="key-form">
        <div class="admin-form-row">
          <div class="grow">
            <div class="field-label plain">Key Name</div>
            <input id="newKeyName" class="field-input on-panel" type="text" placeholder='e.g. "CI pipeline", "Local dev"'/>
          </div>
          <button class="btn-primary btn-sm" onclick="createApiKey()">Generate</button>
          <button class="btn-secondary btn-sm" onclick="hideNewKeyForm()">Cancel</button>
        </div>
        <div id="newKeyErr" class="form-error tight" hidden></div>
      </div>

      ${!keys.length
        ? '<div class="admin-empty compact">No API keys yet</div>'
        : `<table class="admin-table">
          <thead>
            <tr><th>Name</th><th>Key Prefix</th>${isAdmin ? '<th>Owner</th>' : ''}<th>Last Used</th><th class="actions"></th></tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>${keyPage.html}`}
    </div>
  `;
}

function showNewKeyForm() {
  document.getElementById('newKeyForm').classList.add('open');
  document.getElementById('newKeyName').focus();
}
function hideNewKeyForm() {
  document.getElementById('newKeyForm').classList.remove('open');
  document.getElementById('newKeyName').value = '';
}

async function createApiKey() {
  const name  = document.getElementById('newKeyName').value.trim();
  const errEl = document.getElementById('newKeyErr');
  errEl.hidden=true;
  if (!name) { errEl.textContent = 'Name is required'; errEl.hidden=false; return; }

  const r = await fetch('/api/auth/api-keys', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name }),
    credentials: 'same-origin',
  });
  const data = await r.json();
  if (!r.ok) { errEl.textContent = data.error || 'Failed'; errEl.hidden = false; return; }

  hideNewKeyForm();
  showKeyModal(data.key, data.name);
  renderApiKeys();
}

// No click-outside close: the key is shown only once.
function showKeyModal(key, name) {
  document.getElementById('keyModal')?.remove();

  const modal = document.createElement('div');
  modal.id = 'keyModal';
  modal.className = 'key-modal';
  modal.innerHTML = `
    <div class="key-modal-card">
      <button class="key-modal-close" onclick="closeKeyModal()" aria-label="Close">✕</button>
      <div class="key-modal-head">
        <span class="key-modal-icon">🔑</span>
        <span class="key-modal-title">API Key Created</span>
      </div>
      <div class="key-modal-note">Key <b>${esc(name)}</b> — copy it now, it will never be shown again.</div>
      <div class="key-modal-box">
        <div class="key-modal-label">Your API Key</div>
        <code id="modalKeyVal" class="key-modal-value">${esc(key)}</code>
      </div>
      <div class="key-modal-usage">Use as header: <code>X-Api-Key: ${esc(key)}</code></div>
      <div class="key-modal-actions">
        <button id="copyModalBtn" class="key-modal-copy" onclick="copyModalKey()">Copy Key</button>
      </div>
    </div>`;

  document.body.appendChild(modal);
}

function copyModalKey() {
  const key = document.getElementById('modalKeyVal').textContent.trim();
  navigator.clipboard.writeText(key).then(() => {
    const btn = document.getElementById('copyModalBtn');
    btn.textContent = '✓ Copied!';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = 'Copy Key'; btn.classList.remove('copied'); }, 2000);
  });
}

function closeKeyModal() {
  document.getElementById('keyModal')?.remove();
}

async function deleteApiKey(id) {
  if (!confirm('Revoke this API key? It will stop working immediately.')) return;
  const r = await fetch(`/api/auth/api-keys/${id}`, { method: 'DELETE', credentials: 'same-origin' });
  if (!r.ok) { alert('Failed to revoke'); return; }
  document.getElementById(`krow-${id}`)?.remove();
}
