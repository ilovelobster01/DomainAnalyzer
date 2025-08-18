const statusEl = document.getElementById('status');
const whoisEl = document.getElementById('whois');
const detailsEl = document.getElementById('details');
const graphEl = document.getElementById('graph');

let lastAnalysis = null;

let cy = cytoscape({
  container: graphEl,
  style: [
    { selector: 'node', style: { 'label': 'data(label)', 'font-size': 8, 'min-zoomed-font-size': 6, 'background-color': '#4F46E5', 'color': '#111827', 'text-background-color': '#ffffff', 'text-background-opacity': 0.8, 'text-background-padding': 1, 'text-valign': 'center', 'text-halign': 'center', 'border-width': 0 }},
    { selector: 'node[type="ip"]', style: { 'background-color': '#059669' }},
    { selector: 'node[type="domain"]', style: { 'background-color': '#4F46E5' }},
    { selector: 'node[type="subdomain"]', style: { 'background-color': '#7C3AED' }},
    { selector: 'node[type="cohost"]', style: { 'background-color': '#6B7280' }},
    { selector: 'edge', style: { 'width': 1, 'line-color': '#9CA3AF', 'target-arrow-color': '#9CA3AF', 'curve-style': 'bezier', 'label': 'data(label)', 'font-size': 7, 'min-zoomed-font-size': 6, 'color': '#374151', 'text-background-color': '#fff', 'text-background-opacity': 0.5, 'text-background-padding': 1, 'text-margin-y': -2 } },
    { selector: '.hidden', style: { 'display': 'none' }},
    { selector: '.faded', style: { 'opacity': 0.15 }},
    { selector: 'edge.faded', style: { 'opacity': 0.1 }},
    { selector: '.highlight', style: { 'border-width': 2, 'border-color': '#F59E0B', 'border-opacity': 1 }},
    { selector: 'edge.highlight', style: { 'width': 2, 'line-color': '#F59E0B' }},
  ],
  layout: { name: 'cose', animate: false }
});

function setStatus(text) {
  statusEl.textContent = text || '';
}

function pretty(obj) {
  try { return JSON.stringify(obj, null, 2); } catch { return String(obj); }
}

function buildGraph(data) {
  addHistory(data);

  lastAnalysis = data;
  window.lastAnalysis = data;
  clearHighlights();
  cy.elements().remove();
  const nodes = new Map();
  const edges = [];

  function addNode(id, label, type) {
    if (!nodes.has(id)) nodes.set(id, { data: { id, label, type } });
  }
  function addEdge(source, target, type, label) {
    const id = `${source}->${target}`;
    edges.push({ data: { id, source, target, type, label }});
  }

  const root = data.domain;
  addNode(root, root, 'domain');

  // Subdomains
  for (const sd of data.subdomains) {
    addNode(sd, sd, 'subdomain');
    addEdge(root, sd, 'subdomain-of', 'subdomain');
  }

  // DNS records
  const hosts = new Set([root, ...data.subdomains]);
  for (const host of hosts) {
    const ips4 = data.dns_a_records?.[host] || [];
    const ips6 = data.dns_aaaa_records?.[host] || [];
    const cnames = data.dns_cname_records?.[host] || [];

    for (const cname of cnames) {
      addNode(cname, cname, 'domain');
      addEdge(host, cname, 'cname', 'CNAME');
    }

    for (const ip of ips4) {
      addNode(ip, ip, 'ip');
      addEdge(host, ip, 'a-record', 'A');
      // reverse IP co-hosts
      const rev = data.reverse_ip?.[ip] || [];
      for (const ch of rev) {
        const type = hosts.has(ch) ? 'subdomain' : 'cohost';
        addNode(ch, ch, type);
        addEdge(ip, ch, 'cohost', 'cohost');
      }
    }

    for (const ip6 of ips6) {
      addNode(ip6, ip6, 'ip');
      addEdge(host, ip6, 'aaaa-record', 'AAAA');
    }
  }

  cy.add([...nodes.values(), ...edges]);
  cy.layout({ name: 'cose', animate: false, nodeOverlap: 4, idealEdgeLength: 80 }).run();

  // Details panel
  const counts = {
    subdomains: data.subdomains.length,
    ips: Object.values(data.dns_a_records).flat().filter((v, i, a) => a.indexOf(v) === i).length,
    cohosts: Object.values(data.reverse_ip).flat().filter((v, i, a) => a.indexOf(v) === i).length
  };
  detailsEl.innerHTML = `
    <ul>
      <li>Subdomains: ${counts.subdomains}</li>
      <li>Unique IPs: ${counts.ips}</li>
      <li>Co-hosted domains: ${counts.cohosts}</li>
    </ul>
  `;

  applyFilters();
}

function applyFilters() {
  const showDomain = document.getElementById('filter-domain')?.checked ?? true;
  const showSubdomain = document.getElementById('filter-subdomain')?.checked ?? true;
  const showIp = document.getElementById('filter-ip')?.checked ?? true;
  const showCohost = document.getElementById('filter-cohost')?.checked ?? true;

  const allowed = new Set();
  if (showDomain) allowed.add('domain');
  if (showSubdomain) allowed.add('subdomain');
  if (showIp) allowed.add('ip');
  if (showCohost) allowed.add('cohost');

  cy.batch(() => {
    cy.nodes().forEach(n => {
      const type = n.data('type');
      if (allowed.has(type)) n.removeClass('hidden'); else n.addClass('hidden');
    });
    // Update edges: hide if either endpoint hidden
    cy.edges().forEach(e => {
      const hidden = e.source().hasClass('hidden') || e.target().hasClass('hidden');
      if (hidden) e.addClass('hidden'); else e.removeClass('hidden');
    });
  });
}

function clearHighlights() {
  cy.elements().removeClass('faded');
  cy.elements().removeClass('highlight');
}

function highlightNeighborhood(node) {
  clearHighlights();
  const hood = node.closedNeighborhood();
  cy.elements().not(hood).addClass('faded');
  node.addClass('highlight');
}

function applySearch(pattern) {
  clearHighlights();
  if (!pattern) return;

  let regex = null;
  try { regex = new RegExp(pattern, 'i'); } catch { regex = null; }

  const visibleNodes = cy.nodes().filter(n => !n.hasClass('hidden'));
  let matched = visibleNodes.filter(n => {
    const label = n.data('label') || '';
    if (regex) return regex.test(label);
    return label.toLowerCase().includes(pattern.toLowerCase());
  });

  const visibleEles = cy.elements().filter(el => {
    if (el.isNode()) return !el.hasClass('hidden');
    return !(el.source().hasClass('hidden') || el.target().hasClass('hidden'));
  });

  const matchedEles = matched.union(matched.connectedEdges()).union(matched.connectedEdges().targets()).union(matched.connectedEdges().sources());
  visibleEles.not(matchedEles).addClass('faded');
  matched.addClass('highlight');
}

function getSettings() {
  // load from localStorage, fallback to defaults
  try { return JSON.parse(localStorage.getItem('webrecon_settings') || '{}'); } catch { return {}; }
}

function persistSettings(s) {
  localStorage.setItem('webrecon_settings', JSON.stringify(s));
}

function uiLoadSettings() {
  const s = Object.assign({ mode: 'passive', providers: { amass: true, sublist3r: true, crtsh: true }, timeouts: { amass: 240, sublist3r: 360, crtsh: 20 } }, getSettings());
  const g = (id) => document.getElementById(id);
  g('opt-mode').value = s.mode;
  g('opt-amass').checked = !!s.providers.amass;
  g('opt-sublist3r').checked = !!s.providers.sublist3r;
  g('opt-crtsh').checked = !!s.providers.crtsh;
  g('opt-t-amass').value = s.timeouts.amass;
  g('opt-t-sublist3r').value = s.timeouts.sublist3r;
  g('opt-t-crtsh').value = s.timeouts.crtsh;
}

function uiCollectSettings() {
  const g = (id) => document.getElementById(id);
  const s = {
    mode: g('opt-mode').value,
    providers: {
      amass: g('opt-amass').checked,
      sublist3r: g('opt-sublist3r').checked,
      crtsh: g('opt-crtsh').checked,
    },
    timeouts: {
      amass: parseInt(g('opt-t-amass').value, 10) || 240,
      sublist3r: parseInt(g('opt-t-sublist3r').value, 10) || 360,
      crtsh: parseInt(g('opt-t-crtsh').value, 10) || 20,
    }
  };
  return s;
}

function showSettings() {
  const modal = document.getElementById('settingsModal');
  uiLoadSettings();
  modal.style.display = 'flex';
}

function hideSettings() {
  const modal = document.getElementById('settingsModal');
  modal.style.display = 'none';
}

async function analyze() {
  const domain = document.getElementById('domain').value.trim();
  if (!domain) { setStatus('Please enter a domain.'); return; }
  setStatus('Analyzing... this can take a minute.');
  whoisEl.textContent = '';
  detailsEl.textContent = '';

  try {
    const res = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain, options: uiCollectSettings() })
    });
    if (!res.ok) {
      const txt = await res.text();
      throw new Error(txt || 'Request failed');
    }
    const data = await res.json();
    setStatus('Done');
    whoisEl.textContent = pretty(data.whois);
    buildGraph(data);
  } catch (e) {
    console.error(e);
    setStatus('Error: ' + e.message);
  }
}

// History management
const HISTORY_KEY = 'webrecon_history_v1';

function loadHistory() {
  try { return JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]'); } catch { return []; }
}

function saveHistory(items) {
  localStorage.setItem(HISTORY_KEY, JSON.stringify(items.slice(-25))); // keep last 25
  renderHistory();
}

function addHistory(analysis) {
  const items = loadHistory();
  const entry = { domain: analysis.domain, at: new Date().toISOString(), whoisBrief: (analysis.whois?.registrar || '') };
  // If same domain exists, replace latest
  const filtered = items.filter(i => i.domain !== entry.domain);
  filtered.push(entry);
  saveHistory(filtered);
}

function renderHistory() {
  const sel = document.getElementById('historySelect');
  if (!sel) return;
  const items = loadHistory();
  sel.innerHTML = '';
  for (const it of items) {
    const opt = document.createElement('option');
    opt.value = it.domain;
    opt.textContent = `${it.domain} (${new Date(it.at).toLocaleString()})`;
    sel.appendChild(opt);
  }
}

renderHistory();

// UI Event bindings

document.getElementById('analyzeBtn').addEventListener('click', analyze);

document.getElementById('domain').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') analyze();
});

const loadHistoryBtn = document.getElementById('loadHistoryBtn');
const clearHistoryBtn = document.getElementById('clearHistoryBtn');
if (loadHistoryBtn) loadHistoryBtn.addEventListener('click', () => {
  const sel = document.getElementById('historySelect');
  const domain = sel?.value;
  if (domain) {
    document.getElementById('domain').value = domain;
    analyze();
  }
});
if (clearHistoryBtn) clearHistoryBtn.addEventListener('click', () => {
  saveHistory([]);
});

['filter-domain','filter-subdomain','filter-ip','filter-cohost'].forEach(id => {
  const el = document.getElementById(id);
  if (el) el.addEventListener('change', applyFilters);
});

const searchInput = document.getElementById('search');
const clearSearchBtn = document.getElementById('clearSearch');
if (searchInput) {
  searchInput.addEventListener('input', () => applySearch(searchInput.value.trim()));
}
if (clearSearchBtn) {
  clearSearchBtn.addEventListener('click', () => { if (searchInput) searchInput.value = ''; clearHighlights(); });
}

const fitBtn = document.getElementById('fitBtn');
if (fitBtn) fitBtn.addEventListener('click', () => cy.fit(cy.elements(), 30));

const settingsBtn = document.getElementById('settingsBtn');
if (settingsBtn) settingsBtn.addEventListener('click', showSettings);

const settingsSave = document.getElementById('settingsSave');
const settingsCancel = document.getElementById('settingsCancel');
if (settingsSave) settingsSave.addEventListener('click', () => { const s = uiCollectSettings(); persistSettings(s); hideSettings(); });
if (settingsCancel) settingsCancel.addEventListener('click', hideSettings);

const exportPngBtn = document.getElementById('exportPngBtn');
if (exportPngBtn) exportPngBtn.addEventListener('click', () => {
  const png = cy.png({ full: true, scale: 2, bg: '#ffffff' });
  const a = document.createElement('a');
  a.href = png;
  const name = (lastAnalysis?.domain || 'graph').replace(/[^a-z0-9.-]+/gi, '_');
  a.download = `${name}.png`;
  document.body.appendChild(a);
  a.click();
  a.remove();
});

const exportJsonBtn = document.getElementById('exportJsonBtn');
if (exportJsonBtn) exportJsonBtn.addEventListener('click', () => {
  const elements = cy.elements().map(el => el.json());
  const payload = { analysis: lastAnalysis, elements };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  const name = (lastAnalysis?.domain || 'graph').replace(/[^a-z0-9.-]+/gi, '_');
  a.download = `${name}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
});

// Graph interactions
cy.on('tap', 'node', (evt) => {
  const n = evt.target;
  const label = n.data('label');
  const type = n.data('type');
  const neighbors = n.neighborhood('node').map(m => m.data('label')).sort();
  let extra = '';
  if (type === 'ip' && window.lastAnalysis?.ip_info) {
    const info = window.lastAnalysis.ip_info[label] || {};
    const ent = (info.entities || []).map(e => {
      const roles = (e.roles || []).join(', ');
      let name = '';
      if (Array.isArray(e.vcardArray)) {
        const vals = e.vcardArray;
      }
      return `- roles: ${roles} handle: ${e.handle}`;
    }).join('\n');
    extra = `
      <h3>IP Info</h3>
      <ul>
        <li><strong>Name:</strong> ${info.name || ''}</li>
        <li><strong>Handle:</strong> ${info.handle || ''}</li>
        <li><strong>Country:</strong> ${info.country || ''}</li>
        <li><strong>Range:</strong> ${info.startAddress || ''} - ${info.endAddress || ''}</li>
      </ul>
      ${ent ? `<h4>Entities</h4><pre>${ent}</pre>` : ''}
    `;
  }
  detailsEl.innerHTML = `
    <h3>Node</h3>
    <ul>
      <li><strong>Label:</strong> ${label}</li>
      <li><strong>Type:</strong> ${type}</li>
      <li><strong>Degree:</strong> ${n.degree()}</li>
    </ul>
    <h3>Neighbors (${neighbors.length})</h3>
    <pre>${neighbors.map(x => `- ${x}`).join('\n')}</pre>
    ${extra}
  `;
  highlightNeighborhood(n);
});

// Context menu for nodes
const ctxMenu = document.getElementById('ctxMenu');
function showCtxMenu(x, y, items) {
  const ul = ctxMenu.querySelector('ul');
  ul.innerHTML = '';
  for (const it of items) {
    const li = document.createElement('li');
    li.textContent = it.label;
    li.addEventListener('click', () => { it.action(); hideCtxMenu(); });
    ul.appendChild(li);
  }
  ctxMenu.style.left = `${x}px`;
  ctxMenu.style.top = `${y}px`;
  ctxMenu.style.display = 'block';
}
function hideCtxMenu() { ctxMenu.style.display = 'none'; }

document.addEventListener('click', () => hideCtxMenu());

yGraph = cy; // debugging hook

cy.on('cxttap', 'node', (evt) => {
  const n = evt.target;
  const label = n.data('label');
  const type = n.data('type');

  const items = [
    { label: 'Copy label', action: () => navigator.clipboard.writeText(label) },
  ];

  if (type === 'ip') {
    items.push({ label: 'Open IP WHOIS (ARIN)', action: () => window.open(`https://search.arin.net/rdap/?query=${encodeURIComponent(label)}`, '_blank')});
    items.push({ label: 'Open Shodan', action: () => window.open(`https://www.shodan.io/host/${encodeURIComponent(label)}`, '_blank')});
    items.push({ label: 'Open Censys', action: () => window.open(`https://search.censys.io/hosts/${encodeURIComponent(label)}`, '_blank')});
  } else if (type === 'domain' || type === 'subdomain' || type === 'cohost') {
    items.push({ label: 'Open in browser', action: () => window.open(`http://${encodeURIComponent(label)}`, '_blank')});
    items.push({ label: 'View DNS on dnslytics', action: () => window.open(`https://dnslytics.com/domain/${encodeURIComponent(label)}`, '_blank')});
    items.push({ label: 'View crt.sh', action: () => window.open(`https://crt.sh/?q=%25.${encodeURIComponent(label)}`, '_blank')});
  }

  const pos = evt.renderedPosition || evt.position;
  showCtxMenu(pos.x + graphEl.getBoundingClientRect().left, pos.y + graphEl.getBoundingClientRect().top, items);
});

cy.on('tap', (evt) => {
  if (evt.target === cy) {
    clearHighlights();
  }
});
