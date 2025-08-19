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
    { selector: 'node[type="subdomain"]', style: { 'background-color': '#7C3AED', 'background-image': 'data(bgPie)', 'background-fit': 'cover' }},
    { selector: 'node[type="cohost"]', style: { 'background-color': '#6B7280' }},
    { selector: 'node[type="port"]', style: { 'background-color': '#10B981' } },
    { selector: 'edge', style: { 'width': 1, 'line-color': '#9CA3AF', 'target-arrow-color': '#9CA3AF', 'curve-style': 'bezier', 'label': 'data(label)', 'font-size': 7, 'min-zoomed-font-size': 6, 'color': '#374151', 'text-background-color': '#fff', 'text-background-opacity': 0.5, 'text-background-padding': 1, 'text-margin-y': -2 } },
    { selector: '.hidden', style: { 'display': 'none' }},
    { selector: '.faded', style: { 'opacity': 0.15 }},
    { selector: 'edge.faded', style: { 'opacity': 0.1 }},
    { selector: '.highlight', style: { 'border-width': 2, 'border-color': '#F59E0B', 'border-opacity': 1 }},
    { selector: 'edge.highlight', style: { 'width': 2, 'line-color': '#F59E0B' }},
  ],
  layout: { name: 'cose', animate: false }
});

function setStatus(text, { spinning=false } = {}) {
  statusEl.innerHTML = '';
  if (text) {
    const span = document.createElement('span');
    span.textContent = text;
    statusEl.appendChild(span);
  }
  const old = statusEl.querySelector('.spinner');
  if (old) old.remove();
  if (spinning) {
    const sp = document.createElement('span');
    sp.className = 'spinner';
    statusEl.appendChild(sp);
  }
}

function pretty(obj) {
  try { return JSON.stringify(obj, null, 2); } catch { return String(obj); }
}

function buildGraph(data) {
  _uiAddNode = addNode;
  _uiAddEdge = addEdge;
  // Build provider map: subdomain -> [providers]
  const bySource = data.subdomains_by_source || {};
  const providerMap = new Map();
  for (const [prov, list] of Object.entries(bySource)) {
    for (const sd of list) {
      if (!providerMap.has(sd)) providerMap.set(sd, new Set());
      providerMap.get(sd).add(prov);
    }
  }

  addHistory(data);

  lastAnalysis = data;
  window.lastAnalysis = data;
  clearHighlights();
  cy.elements().remove();
  const nodes = new Map();
  const edges = [];

  function addNode(id, label, type, extraData={}) {
    if (!nodes.has(id)) nodes.set(id, { data: Object.assign({ id, label, type }, extraData) });
  }
  function addEdge(source, target, type, label) {
    const id = `${source}->${target}`;
    edges.push({ data: { id, source, target, type, label }});
  }

  const root = data.domain;
  addNode(root, root, 'domain');

  // Subdomains
  const provTags = { amass: 'A', subfinder: 'SF', sublist3r: 'SL', crtsh: 'CRT', securitytrails: 'ST' };
  const provColors = { amass: '#4F46E5', subfinder: '#0EA5E9', sublist3r: '#F59E0B', crtsh: '#10B981', securitytrails: '#EF4444' };
  function providerBg(provs) {
    if (!provs || !provs.length) return null;
    const colors = provs.slice(0,5).map(p => provColors[p] || '#999');
    const w = 24, h = 24;
    const n = colors.length;
    const barW = Math.ceil(w / n);
    let svg = `<svg xmlns='http://www.w3.org/2000/svg' width='${w}' height='${h}' viewBox='0 0 ${w} ${h}'>`;
    for (let i=0;i<n;i++) {
      const x = i*barW;
      svg += `<rect x='${x}' y='0' width='${barW}' height='${h}' fill='${colors[i]}'/>`;
    }
    svg += `</svg>`;
    return 'data:image/svg+xml;utf8,' + encodeURIComponent(svg);
  }
  for (const sd of data.subdomains) {
    const provs = Array.from(providerMap.get(sd) || []);
    const tag = provs.length ? ` [${provs.map(p=>provTags[p]||p).join(',')}]` : '';
    const extra = {};
    const bg = providerBg(provs);
    if (bg) extra.bgPie = bg;
    addNode(sd, sd + tag, 'subdomain', extra);
    addEdge(root, sd, 'subdomain-of', 'subdomain');
  }

  // DNS records
  const hosts = new Set([root, ...data.subdomains]);
  for (const host of hosts) {
    const ips4 = data.dns_a_records?.[host] || [];
    const ips6 = data.dns_aaaa_records?.[host] || [];
    const cnames = data.dns_cname_records?.[host] || [];
    const mxrecs = data.dns_mx_records?.[host] || [];
    const nsrecs = data.dns_ns_records?.[host] || [];
    const txtrecs = data.dns_txt_records?.[host] || [];

    for (const cname of cnames) {
      addNode(cname, cname, 'domain');
      addEdge(host, cname, 'cname', 'CNAME');
    }

    // MX
    for (const mx of mxrecs) {
      const [pref, exch] = (mx.split(' ') || [null, mx]);
      addNode(exch, exch, 'domain');
      addEdge(host, exch, 'mx', 'MX');
    }
    // NS
    for (const ns of nsrecs) {
      addNode(ns, ns, 'domain');
      addEdge(host, ns, 'ns', 'NS');
    }
    // TXT (do not add nodes, but show in details on click of host)

    for (const ip of ips4) {
      // Build IP label with port summary
      const ports = data.ip_ports?.[ip]?.ports || [];
      const topPorts = ports.slice(0,3).map(p => `${p.port}/${p.protocol}`).join(', ');
      const more = ports.length > 3 ? ` +${ports.length-3}` : '';
      const ipLabel = ports.length ? `${ip} (${topPorts}${more})` : ip;
      addNode(ip, ipLabel, 'ip');
      addEdge(host, ip, 'a-record', 'A');
      // Nmap ports nodes
      const nmap = ports;
      for (const p of nmap) {
        const portId = `${ip}:${p.protocol}/${p.port}`;
        const portLabel = `${p.protocol}/${p.port} ${p.service || ''}`.trim();
        addNode(portId, portLabel, 'port');
        addEdge(ip, portId, 'port', p.protocol.toUpperCase());
      }
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
    cohosts: Object.values(data.reverse_ip).flat().filter((v, i, a) => a.indexOf(v) === i).length,
    bySource: Object.fromEntries(Object.entries(data.subdomains_by_source || {}).map(([k,v]) => [k, (v||[]).length]))
  };
  const srcList = Object.entries(counts.bySource).map(([k,v]) => `${k}: ${v}`).join(', ');

  // Build top subdomains table data
  const ipCountMap = {};
  for (const [host, ips] of Object.entries(data.dns_a_records || {})) {
    ipCountMap[host] = (ips || []).length;
  }
  const topRows = (data.subdomains || []).map(sd => {
    const provs = providerMap.get(sd) || new Set();
    return { sd, providers: provs.size, ips: ipCountMap[sd] || 0 };
  }).sort((a,b) => b.providers - a.providers || b.ips - a.ips).slice(0, 15);

  const legend = `
    <div class="legend">
      <span><span class="dot" style="background:#4F46E5"></span>Amass</span>
      <span><span class="dot" style="background:#0EA5E9"></span>Subfinder</span>
      <span><span class="dot" style="background:#F59E0B"></span>Sublist3r</span>
      <span><span class="dot" style="background:#10B981"></span>crt.sh</span>
      <span><span class="dot" style="background:#EF4444"></span>SecurityTrails</span>
    </div>`;

  const topTable = `
    <h3>Top subdomains</h3>
    <table>
      <thead><tr><th>Subdomain</th><th>Providers</th><th>IPs</th></tr></thead>
      <tbody>
        ${topRows.map(r => `<tr><td>${r.sd}</td><td>${r.providers}</td><td>${r.ips}</td></tr>`).join('')}
      </tbody>
    </table>`;

  detailsEl.innerHTML = `
    ${legend}
    <ul>
      <li>Subdomains: ${counts.subdomains}</li>
      <li>Unique IPs: ${counts.ips}</li>
      <li>Co-hosted domains: ${counts.cohosts}</li>
      ${srcList ? `<li>By source: ${srcList}</li>` : ''}
    </ul>
    ${topTable}
  `;

  applyFilters();
}

function applyFilters() {
  const showDomain = document.getElementById('filter-domain')?.checked ?? true;
  const showSubdomain = document.getElementById('filter-subdomain')?.checked ?? true;
  const showIp = document.getElementById('filter-ip')?.checked ?? true;
  const showCohost = document.getElementById('filter-cohost')?.checked ?? true;
  const showPort = document.getElementById('filter-port')?.checked ?? true;

  const allowed = new Set();
  if (showDomain) allowed.add('domain');
  if (showSubdomain) allowed.add('subdomain');
  if (showIp) allowed.add('ip');
  if (showCohost) allowed.add('cohost');
  if (showPort) allowed.add('port');

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
  // prefetch status to discover TOR availability and default socks URL
  fetch('/api/status').then(r => r.json()).then(js => {
    window.__torStatus = js.tor || { available: false, socks_url: null };
    window.__proxychainsAvailable = !!js.proxychains;
    const el = document.getElementById('opt-proxy-enabled');
    if (el) el.disabled = !window.__torStatus.available;
    const txt = document.getElementById('opt-proxy-socks');
    if (txt && !txt.value) txt.value = window.__torStatus.socks_url || '';
    const nvt = document.getElementById('opt-nmap-via-tor');
    if (nvt) nvt.disabled = !window.__proxychainsAvailable;
    if (nvt && !window.__proxychainsAvailable) nvt.title = 'proxychains not detected on server';
    const hint = document.getElementById('proxychainsHint');
    if (hint) hint.textContent = window.__proxychainsAvailable ? '' : 'proxychains not detected on server';
  }).catch(()=>{});

  const s = Object.assign({ mode: 'passive', providers: { amass: true, sublist3r: true, crtsh: true }, timeouts: { amass: 240, sublist3r: 360, crtsh: 20 }, nmap: { enabled: false, top_ports: 100, timing: 'T4', skip_host_discovery: true, udp: false, timeout_per_host: 60, concurrency: 3, ports_spec: null }, proxy: { enabled: false, socks_url: null, require: false, nmap_via_tor: false } }, getSettings());
  const g = (id) => document.getElementById(id);
  g('opt-mode').value = s.mode;
  g('opt-amass').checked = !!s.providers.amass;
  g('opt-sublist3r').checked = !!s.providers.sublist3r;
  g('opt-crtsh').checked = !!s.providers.crtsh;
  g('opt-subfinder').checked = !!s.providers.subfinder;
  g('opt-securitytrails').checked = !!s.providers.securitytrails;
  g('opt-shodan').checked = !!s.providers.shodan;
  g('opt-censys').checked = !!s.providers.censys;
  g('opt-t-amass').value = s.timeouts.amass;
  g('opt-t-sublist3r').value = s.timeouts.sublist3r;
  g('opt-t-crtsh').value = s.timeouts.crtsh;
  g('opt-nmap-enabled').checked = !!s.nmap.enabled;
  g('opt-nmap-topports').value = s.nmap.top_ports;
  g('opt-nmap-timing').value = s.nmap.timing;
  g('opt-nmap-pn').checked = !!s.nmap.skip_host_discovery;
  g('opt-nmap-udp').checked = !!s.nmap.udp;
  g('opt-nmap-timeout').value = s.nmap.timeout_per_host;
  g('opt-nmap-conc').value = s.nmap.concurrency;
  const portsTxt = document.getElementById('opt-nmap-ports');
  if (portsTxt && s.nmap.ports_spec) portsTxt.value = s.nmap.ports_spec;
  const torToggle = document.getElementById('opt-proxy-enabled');
  if (torToggle) torToggle.checked = !!(s.proxy && s.proxy.enabled);
  const torReq = document.getElementById('opt-proxy-require');
  if (torReq) torReq.checked = !!(s.proxy && s.proxy.require);
  const nmapViaTor = document.getElementById('opt-nmap-via-tor');
  if (nmapViaTor) nmapViaTor.checked = !!(s.proxy && s.proxy.nmap_via_tor);
  const socksTxt = document.getElementById('opt-proxy-socks');
  if (socksTxt && s.proxy && s.proxy.socks_url) socksTxt.value = s.proxy.socks_url;
}

function uiCollectSettings() {
  const g = (id) => document.getElementById(id);
  function collectPortsSpec() {
    const base = (document.getElementById('opt-nmap-ports')?.value || '').trim();
    const checks = Array.from(document.querySelectorAll('.nmap-port-chk:checked')).map(el => el.value);
    if (base && checks.length) return base + ',' + checks.join(',');
    if (checks.length) return checks.join(',');
    return base || null;
  }

  const s = {
    mode: g('opt-mode').value,
    providers: {
      amass: g('opt-amass').checked,
      sublist3r: g('opt-sublist3r').checked,
      crtsh: g('opt-crtsh').checked,
      subfinder: g('opt-subfinder').checked,
      securitytrails: g('opt-securitytrails').checked,
      shodan: g('opt-shodan').checked,
      censys: g('opt-censys').checked,
    },
    timeouts: {
      amass: parseInt(g('opt-t-amass').value, 10) || 240,
      sublist3r: parseInt(g('opt-t-sublist3r').value, 10) || 360,
      crtsh: parseInt(g('opt-t-crtsh').value, 10) || 20,
    },
    nmap: {
      enabled: g('opt-nmap-enabled').checked,
      top_ports: parseInt(g('opt-nmap-topports').value, 10) || 100,
      timing: g('opt-nmap-timing').value,
      skip_host_discovery: g('opt-nmap-pn').checked,
      udp: g('opt-nmap-udp').checked,
      timeout_per_host: parseInt(g('opt-nmap-timeout').value, 10) || 60,
      concurrency: parseInt(g('opt-nmap-conc').value, 10) || 3,
      ports_spec: collectPortsSpec(),
    }
  };
  const torToggle = document.getElementById('opt-proxy-enabled');
  const torReq = document.getElementById('opt-proxy-require');
  const socksTxt = document.getElementById('opt-proxy-socks');
  const nmapViaTor = document.getElementById('opt-nmap-via-tor');
  s.proxy = {
    enabled: !!(torToggle && torToggle.checked),
    require: !!(torReq && torReq.checked),
    socks_url: (socksTxt && socksTxt.value) ? socksTxt.value.trim() : ((window.__torStatus && window.__torStatus.socks_url) || null),
    nmap_via_tor: !!(nmapViaTor && nmapViaTor.checked),
  };
  return s;
}

function showSettings() {
  const modal = document.getElementById('settingsModal');
  uiLoadSettings();
  modal.style.display = 'flex';
  document.body.classList.add('modal-open');
}

function hideSettings() {
  const modal = document.getElementById('settingsModal');
  modal.style.display = 'none';
  document.body.classList.remove('modal-open');
}

async function analyze() {
  const raw = document.getElementById('domain').value || '';
  const domain = raw.split(/\r?\n/)[0].trim();
  if (!domain) { setStatus('Please enter a domain.'); return; }
  setStatus('Analyzing... this can take a minute.', { spinning: true });
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
  const entry = { domain: analysis.domain, at: new Date().toISOString(), analysis };
  // If same domain exists, replace latest by same domain (keep most recent only)
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

// Update Tor status indicator in header
async function updateTorIndicator() {
 try {
   const res = await fetch('/api/status');
   const js = await res.json();
   const tor = js.tor || { available: false };
   const el = document.getElementById('torStatus');
   const txt = document.getElementById('torStatusText');
   if (!el) return;
   const s = getSettings();
   const enabled = !!(s.proxy && s.proxy.enabled);
   el.classList.remove('tor-on', 'tor-off', 'tor-unknown');
   if (!tor.available) { el.classList.add('tor-unknown'); el.title = 'Tor not detected'; if (txt) txt.textContent = 'Tor: not detected'; }
   else if (enabled) { el.classList.add('tor-on'); el.title = 'Tor available (enabled)'; if (txt) txt.textContent = tor.exit_ip ? `Tor: enabled (${tor.exit_ip}${tor.exit_country ? ' '+tor.exit_country : ''})` : 'Tor: enabled'; }
   else { el.classList.add('tor-off'); el.title = 'Tor available (disabled)'; if (txt) txt.textContent = 'Tor: available'; }
 } catch (e) {}
}
updateTorIndicator();
setInterval(updateTorIndicator, 20000);

// UI Event bindings

document.getElementById('analyzeBtn').addEventListener('click', analyze);

document.getElementById('domain').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') analyze();
});

const loadHistoryBtn = document.getElementById('loadHistoryBtn');
const clearHistoryBtn = document.getElementById('clearHistoryBtn');
const rerunBtn = document.getElementById('rerunBtn');
const exportHistoryBtn = document.getElementById('exportHistoryBtn');
const importHistoryBtn = document.getElementById('importHistoryBtn');
const importHistoryInput = document.getElementById('importHistoryInput');
const clearCacheBtn = document.getElementById('clearCacheBtn');
const createReportBtn = document.getElementById('createReportBtn');
if (loadHistoryBtn) loadHistoryBtn.addEventListener('click', () => {
  const sel = document.getElementById('historySelect');
  const domain = sel?.value;
  if (!domain) return;
  const items = loadHistory();
  const found = items.find(i => i.domain === domain);
  if (found && found.analysis) {
    setStatus('Loaded from history');
    whoisEl.textContent = pretty(found.analysis.whois || {});
    buildGraph(found.analysis);
  } else {
    // fallback to re-run if no cached analysis present (backward compatibility)
    document.getElementById('domain').value = domain;
    analyze();
  }
});
if (clearHistoryBtn) clearHistoryBtn.addEventListener('click', () => {
  saveHistory([]);
});

if (rerunBtn) rerunBtn.addEventListener('click', () => {
  const sel = document.getElementById('historySelect');
  const domain = sel?.value;
  if (!domain) return;
  document.getElementById('domain').value = domain;
  analyze();
});

if (exportHistoryBtn) exportHistoryBtn.addEventListener('click', () => {
  const items = loadHistory();
  const blob = new Blob([JSON.stringify(items, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'webrecon_history.json';
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
});

if (createReportBtn) createReportBtn.addEventListener('click', async () => {
  try {
    const last = window.lastAnalysis || null;
    if (!last || !last.domain) { setStatus('Run an analysis first to create a report'); return; }
    setStatus('Generating PDF report...', { spinning: true });
    // Build tor status from UI + backend cached indicator
    let torEnabled = false, exitIp = null, exitCountry = null;
    try { const st = await (await fetch('/api/status')).json(); torEnabled = !!(getSettings().proxy && getSettings().proxy.enabled); exitIp = st?.tor?.exit_ip || null; exitCountry = st?.tor?.exit_country || null; } catch {}
    // Render current graph to PNG dataURL
    let graphPng = null;
    try { graphPng = cy.png({ full: true, output: 'base64uri', bg: 'white', scale: 2 }); } catch {}
    const payload = Object.assign({}, last, { tor_status: { enabled: torEnabled, exit_ip: exitIp, exit_country: exitCountry }, graph_png: graphPng });
    const res = await fetch('/api/report.pdf', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
    if (!res.ok) { const t = await res.text(); throw new Error(t || 'Report failed'); }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = `report_${last.domain}.pdf`; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
    setStatus('Report created');
  } catch (e) { console.error(e); setStatus('Report failed'); }
});

if (clearCacheBtn) clearCacheBtn.addEventListener('click', async () => {
  try {
    await fetch('/api/cache/clear', { method: 'POST' });
    setStatus('Server cache cleared');
  } catch (e) { setStatus('Failed to clear cache'); }
});

if (importHistoryBtn && importHistoryInput) {
  importHistoryBtn.addEventListener('click', () => importHistoryInput.click());
  importHistoryInput.addEventListener('change', async (e) => {
    const file = importHistoryInput.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      const data = JSON.parse(text);
      if (Array.isArray(data)) {
        saveHistory(data);
        setStatus('Imported history');
      } else {
        setStatus('Invalid history file');
      }
    } catch (err) {
      console.error(err);
      setStatus('Failed to import history');
    } finally {
      importHistoryInput.value = '';
    }
  });
}

['filter-domain','filter-subdomain','filter-ip','filter-cohost','filter-port'].forEach(id => {
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
  const baseLabel = label; // used in some lookups
  const type = n.data('type');
  const neighbors = n.neighborhood('node').map(m => m.data('label')).sort();
  let extra = '';
  if ((type === 'domain' || type === 'subdomain') && window.lastAnalysis?.subdomains_by_source) {
    const provs = Object.entries(window.lastAnalysis.subdomains_by_source).filter(([k, v]) => (v || []).includes(baseLabel)).map(([k]) => k);
    if (provs.length) {
      extra += `\n<h3>Sources</h3>\n<pre>${provs.map(p => `- ${p}`).join('\n')}</pre>`;
    }
  }
  if (type === 'ip' && window.lastAnalysis?.ip_info) {
    // Show Nmap port results list as well
    const ports = (window.lastAnalysis.ip_ports && window.lastAnalysis.ip_ports[label] && window.lastAnalysis.ip_ports[label].ports) || [];
    if (ports.length) {
      const portLines = ports.map(p => `${p.protocol}/${p.port} ${p.service || ''} ${p.product || ''} ${p.version || ''}`.trim());
      extra += `\n<h3>Open Ports</h3>\n<pre>${portLines.map(x => `- ${x}`).join('\n')}</pre>`;
    }
  
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
  // TXT records for domain/subdomain
  if ((type === 'domain' || type === 'subdomain') && window.lastAnalysis?.dns_txt_records) {
    const txts = window.lastAnalysis.dns_txt_records[baseLabel] || [];
    if (txts.length) {
      extra += `\n<h3>TXT</h3>\n<pre>${txts.map(t => `- ${t}`).join('\n')}</pre>`;
    }
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
let _uiAddNode = null;
let _uiAddEdge = null;
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

function showNmapModalForIp(ip) {
  const modal = document.getElementById('nmapModal');
  const targetEl = document.getElementById('nmapTarget');
  const g = (id) => document.getElementById(id);
  targetEl.textContent = ip;
  // load settings defaults
  const s = Object.assign({ nmap: { enabled: true, top_ports: 100, timing: 'T4', skip_host_discovery: true, udp: false, timeout_per_host: 60, concurrency: 1 } }, { nmap: (getSettings().nmap || {}) });
  g('nmap-enabled').checked = !!s.nmap.enabled;
  g('nmap-topports').value = s.nmap.top_ports;
  g('nmap-timing').value = s.nmap.timing;
  g('nmap-pn').checked = !!s.nmap.skip_host_discovery;
  g('nmap-udp').checked = !!s.nmap.udp;
  g('nmap-timeout').value = s.nmap.timeout_per_host;
  g('nmap-conc').value = s.nmap.concurrency || 1;
  modal.style.display = 'flex';
  document.body.classList.add('modal-open');

  const cancel = document.getElementById('nmapCancel');
  const run = document.getElementById('nmapRun');
  const onCancel = () => { modal.style.display = 'none'; document.body.classList.remove('modal-open'); cancel.removeEventListener('click', onCancel); run.removeEventListener('click', onRun); };
  const onRun = async () => {
    const opts = {
      enabled: g('nmap-enabled').checked,
      top_ports: parseInt(g('nmap-topports').value, 10) || 100,
      timing: g('nmap-timing').value,
      skip_host_discovery: g('nmap-pn').checked,
      udp: g('nmap-udp').checked,
      timeout_per_host: parseInt(g('nmap-timeout').value, 10) || 60,
      concurrency: parseInt(g('nmap-conc').value, 10) || 1,
    };
    // persist these back to general settings
    const settings = getSettings(); settings.nmap = Object.assign(settings.nmap || {}, opts); persistSettings(settings);
    try {
      setStatus('Probing ' + ip + '...', { spinning: true });
      const res = await fetch('/api/probe_ip', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip, nmap: opts }) });
      if (!res.ok) {
        const t = await res.text(); throw new Error(t || 'probe failed');
      }
      const js = await res.json();
      const data = js.results || {};
      window.lastAnalysis = window.lastAnalysis || {}; window.lastAnalysis.ip_ports = window.lastAnalysis.ip_ports || {};
      window.lastAnalysis.ip_ports[ip] = data[ip] || { ports: [] };
      const ports = (data[ip] && data[ip].ports) || [];
      // Update IP label with summary
      const ipNode = cy.getElementById(ip);
      if (ipNode && ipNode.length) {
        const topPorts = ports.slice(0,3).map(p => `${p.port}/${p.protocol}`).join(', ');
        const more = ports.length > 3 ? ` +${ports.length-3}` : '';
        const ipLabel = ports.length ? `${ip} (${topPorts}${more})` : ip;
        ipNode.data('label', ipLabel);
      }
      cy.batch(() => {
        for (const p of ports) {
          const portId = `${ip}:${p.protocol}/${p.port}`;
          const portLabel = `${p.protocol}/${p.port} ${p.service || ''}`.trim();
          if (!cy.getElementById(portId).length) {
            cy.add({ data: { id: portId, label: portLabel, type: 'port' } });
          }
          const edgeId = `${ip}->${portId}`;
          if (!cy.getElementById(edgeId).length) {
            cy.add({ data: { id: edgeId, source: ip, target: portId, type: 'port', label: (p.protocol || '').toUpperCase() } });
          }
        }
      });
      setStatus('Probe complete');
    } catch (e) { console.error(e); setStatus('Probe failed'); }
    onCancel();
  };
  cancel.addEventListener('click', onCancel);
  run.addEventListener('click', onRun);
};

cy.on('cxttap', 'node', (evt) => {
  const n = evt.target;
  const label = n.data('label');
  const type = n.data('type');

  const items = [
    { label: 'Copy label', action: () => navigator.clipboard.writeText(label) },
  ];

  if (type === 'ip') {
    items.push({ label: 'Nmap…', action: () => showNmapModalForIp(label) });
    items.push({ label: 'Quick Nmap (use saved settings)', action: async () => {
      try {
        setStatus('Probing ' + label + '...', { spinning: true });
        const settings = getSettings();
        const res = await fetch('/api/probe_ip', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip: label, nmap: settings.nmap || {} }) });
        if (!res.ok) { const t = await res.text(); throw new Error(t || 'probe failed'); }
        const js = await res.json();
        const data = js.results || {};
        // Merge into lastAnalysis
        window.lastAnalysis = window.lastAnalysis || {};
        window.lastAnalysis.ip_ports = window.lastAnalysis.ip_ports || {};
        window.lastAnalysis.ip_ports[label] = data[label] || { ports: [] };
        // Add port nodes to graph
        const ports = (data[label] && data[label].ports) || [];
        // Update IP label with summary
        const ipNode = cy.getElementById(label);
        if (ipNode && ipNode.length) {
          const topPorts = ports.slice(0,3).map(p => `${p.port}/${p.protocol}`).join(', ');
          const more = ports.length > 3 ? ` +${ports.length-3}` : '';
          const ipLabel = ports.length ? `${label} (${topPorts}${more})` : label;
          ipNode.data('label', ipLabel);
        }
        cy.batch(() => {
          for (const p of ports) {
            const portId = `${label}:${p.protocol}/${p.port}`;
            const portLabel = `${p.protocol}/${p.port} ${p.service || ''}`.trim();
            if (!cy.getElementById(portId).length) {
              cy.add({ data: { id: portId, label: portLabel, type: 'port' } });
            }
            const edgeId = `${label}->${portId}`;
            if (!cy.getElementById(edgeId).length) {
              cy.add({ data: { id: edgeId, source: label, target: portId, type: 'port', label: (p.protocol || '').toUpperCase() } });
            }
          }
        });
        setStatus('Probe complete');
      } catch (e) { console.error(e); setStatus('Probe failed'); }
    }});
    items.push({ label: 'Open IP WHOIS (ARIN)', action: () => window.open(`https://search.arin.net/rdap/?query=${encodeURIComponent(label)}`, '_blank')});
    items.push({ label: 'Open Shodan', action: () => window.open(`https://www.shodan.io/host/${encodeURIComponent(label)}`, '_blank')});
    items.push({ label: 'Open Censys', action: () => window.open(`https://search.censys.io/hosts/${encodeURIComponent(label)}`, '_blank')});
  } else if (type === 'domain' || type === 'subdomain' || type === 'cohost') {
    items.push({ label: 'Nmap resolved IPs…', action: async () => {
      try {
        const settings = getSettings();
        const hosts = new Set([label]);
        // Gather resolved IPs from lastAnalysis
        const ips = new Set();
        const a = (window.lastAnalysis && window.lastAnalysis.dns_a_records && window.lastAnalysis.dns_a_records[label]) || [];
        a.forEach(ip => ips.add(ip));
        if (!ips.size) { setStatus('No resolved IPs to probe'); return; }
        setStatus(`Probing ${ips.size} host(s)...`, { spinning: true });
        const res = await fetch('/api/probe_ips', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ips: Array.from(ips), nmap: settings.nmap || {} }) });
        if (!res.ok) { const t = await res.text(); throw new Error(t || 'probe failed'); }
        const js = await res.json();
        const data = js.results || {};
        window.lastAnalysis = window.lastAnalysis || {}; window.lastAnalysis.ip_ports = window.lastAnalysis.ip_ports || {};
        // Merge results and update graph
        cy.batch(() => {
          for (const ip of Object.keys(data)) {
            window.lastAnalysis.ip_ports[ip] = data[ip] || { ports: [] };
            const ports = (data[ip] && data[ip].ports) || [];
            const ipNode = cy.getElementById(ip);
            if (ipNode && ipNode.length) {
              const topPorts = ports.slice(0,3).map(p => `${p.port}/${p.protocol}`).join(', ');
              const more = ports.length > 3 ? ` +${ports.length-3}` : '';
              const ipLabel = ports.length ? `${ip} (${topPorts}${more})` : ip;
              ipNode.data('label', ipLabel);
            }
            for (const p of ports) {
              const portId = `${ip}:${p.protocol}/${p.port}`;
              const portLabel = `${p.protocol}/${p.port} ${p.service || ''}`.trim();
              if (!cy.getElementById(portId).length) cy.add({ data: { id: portId, label: portLabel, type: 'port' } });
              const edgeId = `${ip}->${portId}`;
              if (!cy.getElementById(edgeId).length) cy.add({ data: { id: edgeId, source: ip, target: portId, type: 'port', label: (p.protocol || '').toUpperCase() } });
            }
          }
        });
        setStatus('Probe complete');
      } catch (e) { console.error(e); setStatus('Probe failed'); }
    }});
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
