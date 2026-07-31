document.addEventListener('click', async (event) => {
  const copy = event.target.closest('[data-copy]');
  if (copy) {
    event.preventDefault();
    event.stopPropagation();
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

document.getElementById('endpoint-filter')?.addEventListener('input', (event) => {
  const term = event.target.value.trim().toLowerCase();
  document.querySelectorAll('[data-endpoint-search]').forEach(card => card.hidden = !card.dataset.endpointSearch.toLowerCase().includes(term));
});

document.addEventListener('submit', (event) => {
  if (event.target.dataset.confirm && !window.confirm(event.target.dataset.confirm)) event.preventDefault();
});

const layout = document.querySelector('[data-endpoint]');
if (layout) {
  let newest = Math.max(0, ...[...document.querySelectorAll('.request-row')].map(a => Number(new URL(a.href).searchParams.get('request'))));
  const events = new EventSource(`/api/endpoints/${layout.dataset.endpoint}/events?after=${newest}`);
  events.addEventListener('request', (event) => {
    const incoming = JSON.parse(event.data);
    if (incoming.id > newest) location.reload();
  });
}
