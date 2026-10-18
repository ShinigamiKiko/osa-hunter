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
      chip.style.cssText = 'position:relative;display:flex;align-items:center;margin-left:auto';
      chip.innerHTML = `
        <div style="display:flex;align-items:center;gap:6px;background:#0b0f18;border:1px solid #1a2030;
                    border-radius:999px;padding:5px 12px 5px 8px;cursor:pointer;user-select:none;
                    transition:border-color .15s"
             onmouseover="this.style.borderColor='#2a3450'"
             onmouseout="this.style.borderColor='#1a2030'"
             onclick="document.getElementById('authMenu').classList.toggle('open')">
          <span style="width:22px;height:22px;border-radius:50%;background:#5ef0c8;color:#07090f;
                       font-size:10px;font-weight:900;display:flex;align-items:center;justify-content:center;flex-shrink:0">
            ${escHtml(user.username[0].toUpperCase())}
          </span>
          <span style="font-size:12px;color:#e5e7eb;font-weight:600">${escHtml(user.username)}</span>
          ${user.role === 'admin' ? '<span style="font-size:9px;color:#5ef0c8;font-weight:800;letter-spacing:.04em">ADMIN</span>' : ''}
          <span style="font-size:9px;color:#5a6478;margin-left:2px">▼</span>
        </div>
        <div id="authMenu"
             style="display:none;position:absolute;top:calc(100% + 6px);right:0;
                    background:#0b0f18;border:1px solid #1a2030;border-radius:10px;
                    min-width:160px;overflow:hidden;box-shadow:0 8px 24px rgba(0,0,0,.5);z-index:9999">
          ${user.role === 'admin' ? `
          <div onclick="navTo('admin');document.getElementById('authMenu')?.classList.remove('open')"
               style="padding:10px 14px;font-size:12px;color:#8a9ab0;cursor:pointer;
                      display:flex;align-items:center;gap:8px"
               onmouseover="this.style.background='#111827'"
               onmouseout="this.style.background=''">
            👥 Manage Users
          </div>
          <div style="border-top:1px solid #1a2030"></div>
          ` : ''}
          <div onclick="openPasswordModal();document.getElementById('authMenu')?.classList.remove('open')"
               style="padding:10px 14px;font-size:12px;color:#8a9ab0;cursor:pointer;
                      display:flex;align-items:center;gap:8px"
               onmouseover="this.style.background='#111827'"
               onmouseout="this.style.background=''">
            Change password
          </div>
          <div style="border-top:1px solid #1a2030"></div>
          <div onclick="doLogout()"
               style="padding:10px 14px;font-size:12px;color:#ff6b6b;cursor:pointer;
                      display:flex;align-items:center;gap:8px"
               onmouseover="this.style.background='#1a0808'"
               onmouseout="this.style.background=''">
            ⎋ Sign Out
          </div>
        </div>
      `;

      ta.appendChild(chip);

      document.addEventListener('click', e => {
        if (!document.getElementById('authChip')?.contains(e.target)) {
          document.getElementById('authMenu')?.classList.remove('open');
        }
      });
    }

    renderChip();

    const observer = new MutationObserver(() => renderChip());
    observer.observe(ta, { childList: true });

    const style = document.createElement('style');
    style.textContent = '#authMenu.open{display:block!important}';
    document.head.appendChild(style);
  }

  // Any user can change their own password; an admin reset lives in Manage Users
  // and is a different thing - it does not ask for the current password.
  window.openPasswordModal = function () {
    document.getElementById('pwOv')?.remove();
    const ov = document.createElement('div');
    ov.className = 'ov'; ov.id = 'pwOv'; ov.style.display = 'flex';
    ov.innerHTML = `
      <div class="modal pw-modal" onclick="event.stopPropagation()">
        <div class="mhdr"><span class="mtitle">Change password</span>
          <button class="mclose" id="pwClose">✕</button></div>
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
          <div id="pwErr" class="pw-err" style="display:none"></div>
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
    const fail = msg => { err.textContent = msg; err.style.display = 'block'; };

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

  function escHtml(s) {
    return String(s).replace(/[&<>"']/g, c =>
      ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c])
    );
  }
})();
