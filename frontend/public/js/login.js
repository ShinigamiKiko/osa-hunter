fetch('/api/auth/me', { credentials: 'same-origin' }).then(r => {
  if (r.ok) window.location.replace('/');
});

document.getElementById('password').addEventListener('keydown', e => {
  if (e.key === 'Enter') doLogin();
});

async function doLogin() {
  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value;
  const btn = document.getElementById('btnLogin');
  document.getElementById('errMsg').hidden = true;
  if (!username || !password) { showErr('Enter username and password'); return; }
  btn.disabled = true; btn.textContent = 'Signing in…';
  try {
    const r = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
      credentials: 'same-origin',
    });
    const data = await r.json();
    if (!r.ok) { showErr(data.error || 'Login failed'); return; }
    window.location.replace('/');
  } catch (e) { showErr('Connection error'); }
  finally { btn.disabled = false; btn.textContent = 'Sign In'; }
}

function showErr(msg) {
  const el = document.getElementById('errMsg');
  el.textContent = msg;
  el.hidden = false;
}
