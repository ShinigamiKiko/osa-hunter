(() => {
  const sidebar = document.querySelector('.sidebar');
  const toggle = document.getElementById('sidebarToggle');
  if (!sidebar || !toggle) return;

  const storageKey = 'osa.sidebar.expanded';
  function setExpanded(expanded, persist = true) {
    sidebar.classList.toggle('is-expanded', expanded);
    toggle.setAttribute('aria-expanded', String(expanded));
    const label = expanded ? 'Collapse navigation' : 'Expand navigation';
    toggle.setAttribute('aria-label', label);
    toggle.title = label;
    if (persist) {
      try { localStorage.setItem(storageKey, String(expanded)); } catch {}
    }
  }

  let expanded = false;
  try { expanded = localStorage.getItem(storageKey) === 'true'; } catch {}
  setExpanded(expanded, false);
  toggle.addEventListener('click', () => setExpanded(!sidebar.classList.contains('is-expanded')));
  sidebar.addEventListener('keydown', event => {
    if (event.key === 'Escape' && sidebar.classList.contains('is-expanded')) {
      setExpanded(false);
      toggle.focus();
    }
  });
})();
