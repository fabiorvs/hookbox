document.addEventListener('click', async (event) => {
  const copy = event.target.closest('[data-copy]');
  if (copy) {
    await navigator.clipboard.writeText(copy.dataset.copy);
    const old = copy.textContent; copy.textContent = 'Copiado!';
    setTimeout(() => copy.textContent = old, 1400);
  }
  const toggle = event.target.closest('[data-toggle]');
  if (toggle) document.getElementById(toggle.dataset.toggle)?.classList.toggle('hidden');
  const tab = event.target.closest('[data-tab]');
  if (tab) {
    document.querySelectorAll('[data-tab]').forEach(item => item.classList.toggle('active', item === tab));
    document.querySelectorAll('[data-panel]').forEach(item => item.classList.toggle('active', item.dataset.panel === tab.dataset.tab));
  }
});

document.getElementById('request-filter')?.addEventListener('input', (event) => {
  const term = event.target.value.trim().toLowerCase();
  document.querySelectorAll('.request-row').forEach(row => row.hidden = !row.dataset.search.toLowerCase().includes(term));
});

const layout = document.querySelector('[data-endpoint]');
if (layout) {
  let newest = Math.max(0, ...[...document.querySelectorAll('.request-row')].map(a => Number(new URL(a.href).searchParams.get('request'))));
  setInterval(async () => {
    if (document.hidden) return;
    try {
      const response = await fetch(`/api/endpoints/${layout.dataset.endpoint}/requests?after=${newest}`);
      const rows = await response.json();
      if (rows.length) location.reload();
    } catch (_) { /* próxima tentativa atualiza */ }
  }, 2500);
}
