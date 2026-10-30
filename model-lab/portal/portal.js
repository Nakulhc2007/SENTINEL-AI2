const domainNames = {
  banking: 'Banking', healthcare: 'Healthcare', education: 'Education', government: 'Government',
  corporate: 'Corporate', manufacturing: 'Manufacturing', retail: 'Retail', public_services: 'Public Services'
};
const domainPrefixes = {
  banking: 'BNK', healthcare: 'HLT', education: 'EDU', government: 'GOV',
  corporate: 'COR', manufacturing: 'MFG', retail: 'RTL', public_services: 'PUB'
};
const pageSize = document.querySelector('#pageSize');
const state = { rows: [], model: null, evaluation: null, filtered: [], page: 0 };
const byId = id => document.getElementById(id);
const escapeHtml = value => String(value).replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));

function parseCsv(text) {
  const lines = text.trim().split(/\r?\n/);
  const parseLine = line => {
    const cells = [];
    let value = '', quoted = false;
    for (let i = 0; i < line.length; i++) {
      const character = line[i];
      if (character === '"' && quoted && line[i + 1] === '"') { value += '"'; i++; }
      else if (character === '"') quoted = !quoted;
      else if (character === ',' && !quoted) { cells.push(value); value = ''; }
      else value += character;
    }
    cells.push(value);
    return cells;
  };
  const headers = parseLine(lines.shift());
  return lines.filter(Boolean).map(line => {
    const values = parseLine(line);
    return Object.fromEntries(headers.map((header, index) => [header, values[index]]));
  });
}

function featureVector(row, model) {
  return model.features.map(name => name.startsWith('domain_')
    ? (row.domain === name.slice(7) ? 1 : 0)
    : Number(row[name] || 0));
}
function treeScore(tree, values) {
  let node = tree;
  while (node.left && node.right) node = values[node.f] <= node.t ? node.left : node.right;
  return node.p;
}
function predict(row) {
  const values = featureVector(row, state.model);
  return state.model.trees.reduce((sum, tree) => sum + treeScore(tree, values), 0) / state.model.trees.length;
}
function percentage(value) { return `${(value * 100).toFixed(2)}%`; }
function getDomainRows() {
  const selected = byId('domainSelect').value;
  return selected === 'all' ? state.rows : state.rows.filter(row => row.domain === selected);
}
function getSignals(row) {
  const signals = [];
  if (Number(row.failed_logins) >= 5) signals.push(`${row.failed_logins} failed logins`);
  if (Number(row.success_after_failures)) signals.push('success after failures');
  if (Number(row.unfamiliar_region)) signals.push('unfamiliar region');
  if (Number(row.after_hours)) signals.push('after-hours activity');
  if (Number(row.restricted_access_attempts)) signals.push('restricted access attempts');
  if (Number(row.request_rate_ratio) >= 4) signals.push(`${Number(row.request_rate_ratio).toFixed(1)}x request rate`);
  if (Number(row.malware_alerts)) signals.push('malware alert');
  if (Number(row.document_hash_mismatch)) signals.push('document hash mismatch');
  if (Number(row.sensitive_resource_access)) signals.push('sensitive resource access');
  if (Number(row.privilege_changes)) signals.push('privilege change');
  if (Number(row.unique_source_ips) >= 6) signals.push(`${row.unique_source_ips} source IPs`);
  if (Number(row.source_reputation) <= 30) signals.push('low source reputation');
  if (!Number(row.managed_device)) signals.push('unmanaged device');
  if (Number(row.events_in_5m) >= 70) signals.push(`${row.events_in_5m} events in 5 min`);
  return signals.length ? signals : ['No prominent signal'];
}

function renderDomainControls() {
  const entries = Object.entries(domainNames);
  byId('domainSelect').insertAdjacentHTML('beforeend', entries.map(([id, name]) => `<option value="${id}">${name}</option>`).join(''));
  byId('domainGrid').innerHTML = entries.map(([id, name]) => {
    const rows = state.rows.filter(row => row.domain === id);
    const suspicious = rows.filter(row => Number(row.suspicious)).length;
    return `<button class="domain-card" type="button" data-domain="${id}" aria-pressed="false"><span class="domain-initial">${domainPrefixes[id]}</span><span><b>${name}</b><small>${rows.length.toLocaleString()} generated events · ${suspicious} labeled suspicious</small></span></button>`;
  }).join('');
}

function renderSummary() {
  const rows = getDomainRows();
  const selected = byId('domainSelect').value;
  const testRows = rows.filter(row => row.split === 'test');
  const flagged = rows.filter(row => row.probability >= state.model.threshold).length;
  const metrics = selected === 'all' ? state.evaluation.overall : state.evaluation.by_domain[selected];
  byId('totalEvents').textContent = rows.length.toLocaleString();
  byId('datasetSize').textContent = selected === 'all' ? '800 generated events for each domain' : `${domainNames[selected]} synthetic event records`;
  byId('flaggedEvents').textContent = flagged.toLocaleString();
  byId('holdoutAccuracy').textContent = percentage(metrics.accuracy);
  byId('holdoutRecall').textContent = percentage(metrics.recall);
  byId('eventHeading').textContent = selected === 'all' ? 'All domain events' : `${domainNames[selected]} events`;
  byId('downloadDomain').href = selected === 'all' ? '/data/all_domains.csv' : `/data/by_domain/${selected}.csv`;
  byId('downloadDomain').download = selected === 'all' ? 'sentinel-all-domain-synthetic-events.csv' : `sentinel-${selected}-synthetic-events.csv`;
  document.querySelectorAll('.domain-card').forEach(card => {
    const active = card.dataset.domain === selected;
    card.classList.toggle('active', active);
    card.setAttribute('aria-pressed', String(active));
  });
  return testRows;
}

function filterRows() {
  renderSummary();
  const query = byId('searchInput').value.trim().toLowerCase();
  const split = byId('splitSelect').value;
  const result = byId('resultSelect').value;
  state.filtered = getDomainRows().filter(row => {
    if (split !== 'all' && row.split !== split) return false;
    const predicted = row.probability >= state.model.threshold;
    if (result === 'flagged' && !predicted) return false;
    if (result === 'clear' && predicted) return false;
    const searchText = `${row.event_id} ${row.domain} ${row.scenario} ${getSignals(row).join(' ')}`.toLowerCase();
    return !query || searchText.includes(query);
  }).sort((a, b) => b.probability - a.probability || a.event_id.localeCompare(b.event_id));
  state.page = 0;
  renderTable();
}

function renderTable() {
  const size = Number(pageSize.value);
  const pages = Math.max(1, Math.ceil(state.filtered.length / size));
  state.page = Math.min(state.page, pages - 1);
  const rows = state.filtered.slice(state.page * size, (state.page + 1) * size);
  byId('eventRows').innerHTML = rows.length ? rows.map(row => {
    const prediction = row.probability;
    const flagged = prediction >= state.model.threshold;
    const widthClass = Math.min(100, Math.round(prediction * 10) * 10);
    const labels = getSignals(row).slice(0, 4).map(signal => `<span class="signal-pill">${escapeHtml(signal)}</span>`).join('');
    return `<tr><td><span class="event-id">${escapeHtml(row.event_id)}</span><span class="event-time">${new Date(row.event_time).toLocaleString()}</span></td><td class="domain-name">${domainNames[row.domain]}</td><td><span class="scenario">${escapeHtml(row.scenario.replaceAll('_', ' '))}</span></td><td><div class="signal-list">${labels}</div></td><td><span class="split-tag split-${row.split}">${row.split.toUpperCase()}</span></td><td><span class="label-tag ${Number(row.suspicious) ? 'label-suspicious' : 'label-routine'}">${Number(row.suspicious) ? 'Suspicious' : 'Routine'}</span></td><td><div class="probability"><span class="probability-track"><i class="${flagged ? 'high' : ''} w${widthClass}"></i></span><strong>${percentage(prediction)}</strong></div><span class="model-tag ${flagged ? 'model-flagged' : 'model-clear'}">${flagged ? 'Flagged' : 'Clear'}</span></td></tr>`;
  }).join('') : '<tr><td colspan="7" class="empty-row">No events match these filters.</td></tr>';
  const first = state.filtered.length ? state.page * size + 1 : 0;
  const last = Math.min((state.page + 1) * size, state.filtered.length);
  byId('resultCount').textContent = `Showing ${first}-${last} of ${state.filtered.length.toLocaleString()} matching events`;
  byId('pageLabel').textContent = `Page ${state.page + 1} of ${pages}`;
  byId('previousPage').disabled = state.page === 0;
  byId('nextPage').disabled = state.page >= pages - 1;
}

async function loadPortal() {
  try {
    const [csvResponse, modelResponse, evaluationResponse] = await Promise.all([
      fetch('/data/all_domains.csv'), fetch('/artifacts/model.json'), fetch('/artifacts/evaluation.json')
    ]);
    if (![csvResponse, modelResponse, evaluationResponse].every(response => response.ok)) throw new Error('The dataset or model files could not be loaded.');
    const [csv, model, evaluation] = await Promise.all([csvResponse.text(), modelResponse.json(), evaluationResponse.json()]);
    state.model = model;
    state.evaluation = evaluation;
    state.rows = parseCsv(csv).map(row => {
      for (const field of model.features) if (!field.startsWith('domain_')) row[field] = Number(row[field]);
      row.suspicious = Number(row.suspicious);
      row.probability = predict(row);
      return row;
    });
    renderDomainControls();
    filterRows();
    byId('datasetSize').textContent = '800 generated events for each domain';
  } catch (error) {
    byId('eventRows').innerHTML = `<tr><td colspan="7" class="empty-row">${escapeHtml(error.message)} Start the local portal server from the model-lab folder.</td></tr>`;
    byId('resultCount').textContent = 'Portal data could not be loaded';
  }
}

byId('domainSelect').addEventListener('change', filterRows);
byId('searchInput').addEventListener('input', filterRows);
byId('splitSelect').addEventListener('change', filterRows);
byId('resultSelect').addEventListener('change', filterRows);
pageSize.addEventListener('change', filterRows);
byId('previousPage').addEventListener('click', () => { state.page--; renderTable(); });
byId('nextPage').addEventListener('click', () => { state.page++; renderTable(); });
byId('domainGrid').addEventListener('click', event => {
  const card = event.target.closest('[data-domain]');
  if (!card) return;
  byId('domainSelect').value = card.dataset.domain;
  filterRows();
  byId('workspace').scrollIntoView({ behavior: 'smooth', block: 'start' });
});

loadPortal();
