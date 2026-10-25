// A session can expire while the page is open (idle or absolute limit). Send
// the user to sign in instead of letting every action fail with Unauthorized.
(function () {
  const nativeFetch = window.fetch.bind(window);
  window.fetch = async (input, init) => {
    const response = await nativeFetch(input, init);
    const path = new URL(typeof input === 'string' ? input : input.url, location.href).pathname;
    if (response.status === 401 && path.startsWith('/api/') && path !== '/api/auth/login')
      window.location.replace('/login.html?expired=1');
    return response;
  };
})();

(function () {
  fetch('/api/auth/me', { credentials: 'same-origin' })
    .then(r => r.ok ? r.json() : Promise.reject())
    .then(({ user }) => {
      window._authUser = user;
      injectUserChip(user);
      document.documentElement.classList.remove('auth-pending');
      navTo('lib-list');
    })
    .catch(() => {
      window.location.replace('/login.html');
    });

  function injectUserChip(user) {
    const ta = document.getElementById('topbarActions');
    if (!ta) return;

    function renderChip() {
      if (document.getElementById('authChip')) return;

      const chip = document.createElement('div');
      chip.id = 'authChip';
      chip.className = 'user-chip';
      chip.innerHTML = `
        <div class="user-chip-btn" onclick="document.getElementById('authMenu').classList.toggle('open')">
          <span class="user-chip-avatar">${esc(user.username[0].toUpperCase())}</span>
          <span class="user-chip-name">${esc(user.username)}</span>
          ${user.role === 'admin' ? '<span class="user-chip-role">ADMIN</span>' : ''}
          <span class="user-chip-caret">${icon('chevron-down')}</span>
        </div>
        <div id="authMenu" class="user-menu">
          ${user.role === 'admin' ? `
          <div class="user-menu-item" onclick="navTo('admin');document.getElementById('authMenu')?.classList.remove('open')">
            ${icon('users')} Manage Users
          </div>` : ''}
          <div class="user-menu-item" onclick="openPasswordModal();document.getElementById('authMenu')?.classList.remove('open')">
            Change password
          </div>
          <div class="user-menu-item danger" onclick="doLogout()">
            ${icon('log-out')} Sign Out
          </div>
          <div class="user-menu-version app-version" hidden></div>
        </div>
      `;

      ta.appendChild(chip);
      showAppVersion();

      document.addEventListener('click', e => {
        if (!document.getElementById('authChip')?.contains(e.target)) {
          document.getElementById('authMenu')?.classList.remove('open');
        }
      });
    }

    renderChip();

    const observer = new MutationObserver(() => renderChip());
    observer.observe(ta, { childList: true });
  }

  // Any user can change their own password; an admin reset lives in Manage Users
  // and is a different thing - it does not ask for the current password.
  window.openPasswordModal = function () {
    document.getElementById('pwOv')?.remove();
    const ov = document.createElement('div');
    ov.className = 'ov'; ov.id = 'pwOv';
    ov.innerHTML = `
      <div class="modal pw-modal" onclick="event.stopPropagation()">
        <div class="mhdr"><span class="mtitle">Change password</span>
          <button class="mclose" id="pwClose">${icon('x')}</button></div>
        <div class="pw-body">
          <label>Current password
            <input id="pwCur" type="password" autocomplete="current-password"/>
          </label>
          <label>New password
            <input id="pwNew" type="password" autocomplete="new-password"/>
            <span class="pw-hint">At least 8 characters.</span>
          </label>
          <label>Repeat new password
            <input id="pwRep" type="password" autocomplete="new-password"/>
          </label>
          <div id="pwErr" class="pw-err" hidden></div>
          <div class="pw-actions">
            <button id="pwCancel">Cancel</button>
            <button id="pwSave" class="primary">Change password</button>
          </div>
        </div>
      </div>`;
    document.body.appendChild(ov);

    const close = () => ov.remove();
    ov.addEventListener('click', e => { if (e.target === ov) close(); });
    document.getElementById('pwClose').addEventListener('click', close);
    document.getElementById('pwCancel').addEventListener('click', close);

    const err = document.getElementById('pwErr');
    const fail = msg => { err.textContent = msg; err.hidden = false; };

    document.getElementById('pwSave').addEventListener('click', async () => {
      const cur = document.getElementById('pwCur').value;
      const next = document.getElementById('pwNew').value;
      const rep = document.getElementById('pwRep').value;
      if (!cur || !next) return fail('Fill in both passwords.');
      if (next !== rep) return fail('The new passwords do not match.');
      if (next.length < 8) return fail('The new password must be at least 8 characters.');
      try {
        const r = await fetch('/api/auth/password', {
          method: 'POST', credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ currentPassword: cur, newPassword: next }),
        });
        if (!r.ok) return fail((await r.json().catch(() => ({}))).error || `Failed (HTTP ${r.status})`);
        close();
        alert('Password changed.');
      } catch (e) { fail(e.message); }
    });

    document.getElementById('pwCur').focus();
  };

  window.doLogout = async function () {
    await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' });
    window.location.replace('/login.html');
  };
})();
