"""
ingotus/core/html_exporter.py

Gera um dashboard HTML interativo e auto-contido com:
  - Design dark neon / glassmorphism
  - Gráfico donut de distribuição de severidades (Chart.js)
  - Tabela de impactos filtrável por severidade
  - Cards expandíveis com evidência técnica e PoC
  - Inventário completo de hosts
  - Zero dependências externas (apenas Chart.js via CDN)
"""

import json
import os
import html as html_module
from typing import Dict
from core.models import HostResult
from core.config import SEVERITY_ORDER, VERSION


# ── Paleta de cores ────────────────────────────────────────────────────────────
SEV_COLORS = {
    "CRITICAL": "#ff3b5c",
    "HIGH":     "#ff8c42",
    "MEDIUM":   "#ffd166",
    "LOW":      "#06d6a0",
    "INFO":     "#8ecae6",
}

SEV_LABELS_PT = {
    "CRITICAL": "Crítico",
    "HIGH":     "Alto",
    "MEDIUM":   "Médio",
    "LOW":      "Baixo",
    "INFO":     "Informativo",
}


def _esc(s) -> str:
    """HTML-escape a value safely."""
    return html_module.escape(str(s or ""), quote=True)


def _build_html(domain: str, results: Dict[str, HostResult]) -> str:
    # ── Aggregate data ─────────────────────────────────────────────────────────
    all_impacts = []
    for host, res in results.items():
        for imp in res.impacts:
            all_impacts.append({
                "host":        host,
                "severity":    imp.severity,
                "description": imp.description,
                "evidence":    imp.evidence,
                "cvss":        f"{imp.cvss_score:.1f}" if imp.cvss_score > 0 else "N/A",
                "vector":      imp.cvss_vector or "",
            })

    all_impacts.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))

    sev_counts = {s: 0 for s in SEVERITY_ORDER}
    for imp in all_impacts:
        sev_counts[imp["severity"]] = sev_counts.get(imp["severity"], 0) + 1

    total_hosts  = len(results)
    active_hosts = sum(1 for r in results.values() if r.dns.ips or (r.http and r.http.status))
    waf_count    = sum(1 for r in results.values() if "WAF" in r.classification)
    cdn_count    = sum(1 for r in results.values() if "CDN" in r.classification)
    origin_leaks = sum(len(r.leaks) for r in results.values())

    chart_data   = json.dumps([sev_counts.get(s, 0) for s in SEVERITY_ORDER])
    chart_labels = json.dumps([SEV_LABELS_PT.get(s, s) for s in SEVERITY_ORDER])
    chart_colors = json.dumps([SEV_COLORS.get(s, "#888") for s in SEVERITY_ORDER])

    impacts_json = json.dumps([{
        "host":        _esc(i["host"]),
        "severity":    _esc(i["severity"]),
        "description": _esc(i["description"]),
        "evidence":    _esc(i["evidence"]),
        "cvss":        _esc(i["cvss"]),
        "vector":      _esc(i["vector"]),
        "color":       SEV_COLORS.get(i["severity"], "#888"),
    } for i in all_impacts])

    hosts_json = json.dumps([{
        "host":     _esc(host),
        "ips":      _esc(", ".join(res.dns.ips) if res.dns.ips else "—"),
        "cname":    _esc(res.dns.cname or "—"),
        "status":   _esc(str(res.http.status) if res.http and res.http.status else "—"),
        "server":   _esc(res.http.server if res.http and res.http.server else "—"),
        "cls":      _esc(res.classification),
        "impacts":  len(res.impacts),
    } for host, res in sorted(results.items(), key=lambda x: len(x[1].impacts), reverse=True)])

    return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ignotus — {_esc(domain)}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root{{
  --bg:#06060e;--bg2:#0d0d1a;--bg3:#12122a;
  --border:#1e1e3f;--cyan:#00f0ff;--cyan2:#0099cc;
  --critical:#ff3b5c;--high:#ff8c42;--medium:#ffd166;--low:#06d6a0;--info:#8ecae6;
  --text:#e0e0ff;--muted:#6868aa;--card:#0d0d20;
  --radius:12px;--radius-sm:8px;
  font-family:'Segoe UI',system-ui,-apple-system,sans-serif;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);min-height:100vh;overflow-x:hidden}}

/* Neon glow scrollbar */
::-webkit-scrollbar{{width:6px;background:var(--bg2)}}
::-webkit-scrollbar-thumb{{background:var(--cyan2);border-radius:3px}}

/* Header */
.header{{
  background:linear-gradient(135deg,var(--bg2) 0%,#0a0a1e 100%);
  border-bottom:1px solid var(--border);
  padding:1.5rem 2rem;
  display:flex;align-items:center;gap:1rem;
  position:sticky;top:0;z-index:100;
  backdrop-filter:blur(12px);
}}
.logo{{
  font-size:1.6rem;font-weight:800;letter-spacing:-0.5px;
  background:linear-gradient(90deg,var(--cyan),#a78bfa);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
}}
.header-sub{{font-size:.85rem;color:var(--muted)}}
.badge{{
  margin-left:auto;padding:.3rem .8rem;border-radius:20px;font-size:.75rem;
  background:rgba(0,240,255,.1);border:1px solid rgba(0,240,255,.3);
  color:var(--cyan);font-weight:600;
}}

/* Main layout */
.main{{padding:2rem;max-width:1600px;margin:0 auto}}

/* Stats row */
.stats-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1rem;margin-bottom:2rem}}
.stat-card{{
  background:var(--card);border:1px solid var(--border);border-radius:var(--radius);
  padding:1.2rem;text-align:center;
  transition:transform .2s,border-color .2s;
  position:relative;overflow:hidden;
}}
.stat-card::before{{
  content:'';position:absolute;top:0;left:0;right:0;height:2px;
  background:linear-gradient(90deg,var(--cyan),transparent);
}}
.stat-card:hover{{transform:translateY(-3px);border-color:var(--cyan)}}
.stat-num{{font-size:2.2rem;font-weight:800;color:var(--cyan);line-height:1}}
.stat-label{{font-size:.75rem;color:var(--muted);margin-top:.4rem;text-transform:uppercase;letter-spacing:.5px}}

/* Severity stats */
.sev-grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:.75rem;margin-bottom:2rem}}
.sev-card{{
  border-radius:var(--radius-sm);padding:1rem;text-align:center;
  border:1px solid rgba(255,255,255,.08);
  transition:transform .2s;cursor:pointer;
}}
.sev-card:hover{{transform:scale(1.04)}}
.sev-num{{font-size:2rem;font-weight:800;line-height:1}}
.sev-lbl{{font-size:.7rem;color:rgba(255,255,255,.6);text-transform:uppercase;margin-top:.3rem}}

/* Charts + filter row */
.analysis-row{{display:grid;grid-template-columns:300px 1fr;gap:1.5rem;margin-bottom:2rem;align-items:start}}
.chart-card{{
  background:var(--card);border:1px solid var(--border);border-radius:var(--radius);
  padding:1.5rem;text-align:center;
}}
.chart-title{{font-size:.85rem;color:var(--muted);margin-bottom:1rem;text-transform:uppercase;letter-spacing:.5px}}

/* Filter bar */
.filter-bar{{
  background:var(--card);border:1px solid var(--border);border-radius:var(--radius);
  padding:1.5rem;
}}
.filter-title{{font-size:.85rem;color:var(--muted);margin-bottom:1rem;text-transform:uppercase;letter-spacing:.5px}}
.filter-buttons{{display:flex;gap:.5rem;flex-wrap:wrap;margin-bottom:1rem}}
.filter-btn{{
  padding:.4rem 1rem;border-radius:20px;border:1px solid var(--border);
  background:transparent;color:var(--text);cursor:pointer;font-size:.82rem;
  transition:all .15s;
}}
.filter-btn:hover,.filter-btn.active{{background:var(--cyan);color:#000;border-color:var(--cyan);font-weight:600}}
.search-input{{
  width:100%;padding:.6rem 1rem;background:var(--bg2);border:1px solid var(--border);
  border-radius:var(--radius-sm);color:var(--text);font-size:.85rem;outline:none;
}}
.search-input:focus{{border-color:var(--cyan)}}

/* Section headers */
.section-title{{
  font-size:1.1rem;font-weight:700;margin-bottom:1rem;
  display:flex;align-items:center;gap:.6rem;color:var(--text);
}}
.section-title::after{{
  content:'';flex:1;height:1px;background:var(--border);
}}

/* Impacts list */
.impacts-list{{display:flex;flex-direction:column;gap:.75rem;margin-bottom:2rem}}
.impact-card{{
  background:var(--card);border:1px solid var(--border);border-radius:var(--radius-sm);
  overflow:hidden;transition:border-color .15s;
}}
.impact-card:hover{{border-color:rgba(0,240,255,.3)}}
.impact-header{{
  display:grid;grid-template-columns:auto 1fr auto;gap:1rem;align-items:center;
  padding:.8rem 1rem;cursor:pointer;
}}
.sev-badge{{
  padding:.2rem .65rem;border-radius:12px;font-size:.7rem;font-weight:700;
  letter-spacing:.3px;text-transform:uppercase;white-space:nowrap;
}}
.impact-desc{{font-size:.9rem;font-weight:500}}
.impact-host{{font-size:.75rem;color:var(--muted);white-space:nowrap}}
.cvss-badge{{
  padding:.2rem .5rem;border-radius:6px;font-size:.7rem;font-weight:600;
  background:rgba(255,255,255,.08);border:1px solid var(--border);
  white-space:nowrap;
}}
.impact-body{{
  padding:0 1rem;max-height:0;overflow:hidden;transition:max-height .3s ease,padding .3s;
}}
.impact-body.open{{max-height:600px;padding:.8rem 1rem 1rem}}
.evidence-block{{
  background:var(--bg2);border-radius:var(--radius-sm);border:1px solid var(--border);
  padding:.85rem 1rem;font-family:'Consolas','Courier New',monospace;font-size:.78rem;
  white-space:pre-wrap;color:#b0c4ff;max-height:300px;overflow-y:auto;
}}
.poc-block{{
  margin-top:.75rem;
  background:rgba(0,240,255,.04);border:1px solid rgba(0,240,255,.2);
  border-radius:var(--radius-sm);padding:.75rem 1rem;
  font-family:monospace;font-size:.78rem;color:var(--cyan);white-space:pre-wrap;
}}
.poc-label{{font-size:.7rem;color:var(--muted);margin-bottom:.4rem;text-transform:uppercase}}

/* Hosts table */
.hosts-section{{margin-bottom:2rem}}
.hosts-table{{width:100%;border-collapse:collapse;font-size:.82rem}}
.hosts-table th{{
  background:var(--bg3);color:var(--muted);text-align:left;
  padding:.6rem .8rem;font-weight:600;text-transform:uppercase;
  font-size:.7rem;letter-spacing:.5px;border-bottom:1px solid var(--border);
}}
.hosts-table td{{padding:.55rem .8rem;border-bottom:1px solid rgba(255,255,255,.04)}}
.hosts-table tr:hover td{{background:rgba(0,240,255,.03)}}
.cls-badge{{
  padding:.15rem .5rem;border-radius:10px;font-size:.68rem;font-weight:600;
  background:rgba(255,255,255,.08);border:1px solid var(--border);
}}
.impacts-count{{
  display:inline-flex;align-items:center;justify-content:center;
  width:24px;height:24px;border-radius:50%;font-size:.72rem;font-weight:700;
}}
.impacts-count.has-impacts{{background:rgba(255,59,92,.2);color:var(--critical);border:1px solid var(--critical)}}
.impacts-count.no-impacts{{background:rgba(255,255,255,.05);color:var(--muted)}}

/* Pagination */
.pagination{{display:flex;gap:.5rem;justify-content:center;margin-top:1rem}}
.page-btn{{
  padding:.35rem .75rem;border-radius:var(--radius-sm);border:1px solid var(--border);
  background:var(--card);color:var(--text);cursor:pointer;font-size:.8rem;
  transition:all .15s;
}}
.page-btn:hover,.page-btn.active{{background:var(--cyan);color:#000;border-color:var(--cyan)}}

/* Footer */
.footer{{
  text-align:center;padding:2rem;color:var(--muted);font-size:.78rem;
  border-top:1px solid var(--border);
}}

/* Responsive */
@media(max-width:900px){{
  .analysis-row{{grid-template-columns:1fr}}
  .sev-grid{{grid-template-columns:repeat(3,1fr)}}
}}
@media(max-width:600px){{
  .main{{padding:1rem}}
  .sev-grid{{grid-template-columns:repeat(2,1fr)}}
  .stats-grid{{grid-template-columns:repeat(2,1fr)}}
}}

/* Animations */
@keyframes fadeIn{{from{{opacity:0;transform:translateY(8px)}}to{{opacity:1;transform:translateY(0)}}}}
.impact-card{{animation:fadeIn .2s ease both}}
.stat-card{{animation:fadeIn .3s ease both}}
</style>
</head>
<body>

<header class="header">
  <div>
    <div class="logo">⬡ IGNOTUS</div>
    <div class="header-sub">Security Recon &amp; Impact Report</div>
  </div>
  <div style="margin-left:1.5rem;flex:1">
    <div style="font-weight:700;font-size:1.05rem">{_esc(domain)}</div>
    <div class="header-sub" id="scan-time">Processado pelo Ignotus v{VERSION}</div>
  </div>
  <span class="badge">BUG BOUNTY EDITION</span>
</header>

<main class="main">

<!-- ── Stats ───────────────────────────────────────────────────────────── -->
<div class="stats-grid">
  <div class="stat-card"><div class="stat-num">{total_hosts}</div><div class="stat-label">Subdomínios</div></div>
  <div class="stat-card"><div class="stat-num">{active_hosts}</div><div class="stat-label">Hosts Ativos</div></div>
  <div class="stat-card"><div class="stat-num">{len(all_impacts)}</div><div class="stat-label">Impactos</div></div>
  <div class="stat-card"><div class="stat-num">{origin_leaks}</div><div class="stat-label">IP Leaks</div></div>
  <div class="stat-card"><div class="stat-num">{waf_count}</div><div class="stat-label">Com WAF</div></div>
  <div class="stat-card"><div class="stat-num">{cdn_count}</div><div class="stat-label">Com CDN</div></div>
</div>

<!-- ── Severity Cards ─────────────────────────────────────────────────── -->
<div class="sev-grid">
  <div class="sev-card" style="background:rgba(255,59,92,.1);border-color:rgba(255,59,92,.3)" onclick="filterBySev('CRITICAL')">
    <div class="sev-num" style="color:{SEV_COLORS['CRITICAL']}">{sev_counts.get('CRITICAL',0)}</div>
    <div class="sev-lbl">Crítico</div>
  </div>
  <div class="sev-card" style="background:rgba(255,140,66,.1);border-color:rgba(255,140,66,.3)" onclick="filterBySev('HIGH')">
    <div class="sev-num" style="color:{SEV_COLORS['HIGH']}">{sev_counts.get('HIGH',0)}</div>
    <div class="sev-lbl">Alto</div>
  </div>
  <div class="sev-card" style="background:rgba(255,209,102,.1);border-color:rgba(255,209,102,.3)" onclick="filterBySev('MEDIUM')">
    <div class="sev-num" style="color:{SEV_COLORS['MEDIUM']}">{sev_counts.get('MEDIUM',0)}</div>
    <div class="sev-lbl">Médio</div>
  </div>
  <div class="sev-card" style="background:rgba(6,214,160,.1);border-color:rgba(6,214,160,.3)" onclick="filterBySev('LOW')">
    <div class="sev-num" style="color:{SEV_COLORS['LOW']}">{sev_counts.get('LOW',0)}</div>
    <div class="sev-lbl">Baixo</div>
  </div>
  <div class="sev-card" style="background:rgba(142,202,230,.1);border-color:rgba(142,202,230,.3)" onclick="filterBySev('ALL')">
    <div class="sev-num" style="color:{SEV_COLORS['INFO']}">{len(all_impacts)}</div>
    <div class="sev-lbl">Todos</div>
  </div>
</div>

<!-- ── Chart + Filter ─────────────────────────────────────────────────── -->
<div class="analysis-row">
  <div class="chart-card">
    <div class="chart-title">Distribuição de Severidade</div>
    <canvas id="sevChart" height="240"></canvas>
  </div>
  <div class="filter-bar">
    <div class="filter-title">Filtros de Impacto</div>
    <div class="filter-buttons">
      <button class="filter-btn active" onclick="setSevFilter('ALL', this)">Todos ({len(all_impacts)})</button>
      <button class="filter-btn" onclick="setSevFilter('CRITICAL', this)" style="color:{SEV_COLORS['CRITICAL']};border-color:{SEV_COLORS['CRITICAL']}">⬡ Crítico ({sev_counts.get('CRITICAL',0)})</button>
      <button class="filter-btn" onclick="setSevFilter('HIGH', this)" style="color:{SEV_COLORS['HIGH']};border-color:{SEV_COLORS['HIGH']}">⬡ Alto ({sev_counts.get('HIGH',0)})</button>
      <button class="filter-btn" onclick="setSevFilter('MEDIUM', this)" style="color:{SEV_COLORS['MEDIUM']};border-color:{SEV_COLORS['MEDIUM']}">⬡ Médio ({sev_counts.get('MEDIUM',0)})</button>
      <button class="filter-btn" onclick="setSevFilter('LOW', this)" style="color:{SEV_COLORS['LOW']};border-color:{SEV_COLORS['LOW']}">⬡ Baixo ({sev_counts.get('LOW',0)})</button>
    </div>
    <input type="text" class="search-input" id="searchInput" placeholder="🔍 Filtrar por host, descrição ou CVE..." oninput="applySearch()">
    <div style="margin-top:1rem;font-size:.8rem;color:var(--muted)" id="impact-counter">
      Exibindo <span id="showing-count">{len(all_impacts)}</span> de {len(all_impacts)} impactos
    </div>
  </div>
</div>

<!-- ── Impacts ────────────────────────────────────────────────────────── -->
<div class="section-title">📊 Impactos Validados</div>
<div class="impacts-list" id="impacts-list"></div>
<div class="pagination" id="pagination"></div>

<!-- ── Hosts Inventory ────────────────────────────────────────────────── -->
<div class="hosts-section">
  <div class="section-title" style="margin-top:2rem">🗂️ Inventário de Hosts</div>
  <div style="overflow-x:auto;background:var(--card);border:1px solid var(--border);border-radius:var(--radius)">
    <table class="hosts-table" id="hosts-table">
      <thead><tr>
        <th>Host</th><th>IPs</th><th>CNAME</th><th>HTTP</th>
        <th>Servidor</th><th>Classificação</th><th>Impactos</th>
      </tr></thead>
      <tbody id="hosts-body"></tbody>
    </table>
  </div>
</div>

</main>

<footer class="footer">
  Ignotus Recon v{VERSION} — Bug Bounty Edition | Gerado em <span id="gen-time"></span>
  <br><small style="opacity:.5">Autorização obrigatória. Use com responsabilidade.</small>
</footer>

<script>
// ── Data ──────────────────────────────────────────────────────────────────────
const IMPACTS = {impacts_json};
const HOSTS   = {hosts_json};
const SEV_COLORS = {{
  CRITICAL:'{SEV_COLORS["CRITICAL"]}',HIGH:'{SEV_COLORS["HIGH"]}',
  MEDIUM:'{SEV_COLORS["MEDIUM"]}',LOW:'{SEV_COLORS["LOW"]}',INFO:'{SEV_COLORS["INFO"]}'
}};

// ── State ─────────────────────────────────────────────────────────────────────
let currentFilter = 'ALL';
let currentSearch = '';
let currentPage   = 1;
const PAGE_SIZE   = 50;

// ── Chart ─────────────────────────────────────────────────────────────────────
new Chart(document.getElementById('sevChart'), {{
  type: 'doughnut',
  data: {{
    labels: {chart_labels},
    datasets: [{{
      data: {chart_data},
      backgroundColor: {chart_colors},
      borderColor: '#06060e',
      borderWidth: 3,
      hoverOffset: 8,
    }}]
  }},
  options: {{
    cutout: '65%',
    plugins: {{
      legend: {{
        position: 'bottom',
        labels: {{ color: '#aaa', padding: 12, font: {{ size: 11 }} }}
      }}
    }}
  }}
}});

// ── Filtering ─────────────────────────────────────────────────────────────────
function setSevFilter(sev, btn) {{
  currentFilter = sev;
  currentPage   = 1;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  renderImpacts();
}}

function filterBySev(sev) {{
  const btn = document.querySelector(`.filter-btn[onclick*="${{sev}}"]`);
  if(btn) setSevFilter(sev, btn);
  else {{ currentFilter = sev; currentPage = 1; renderImpacts(); }}
}}

function applySearch() {{
  currentSearch = document.getElementById('searchInput').value.toLowerCase();
  currentPage   = 1;
  renderImpacts();
}}

function getFiltered() {{
  return IMPACTS.filter(i => {{
    const sevOk  = currentFilter === 'ALL' || i.severity === currentFilter;
    const query  = currentSearch;
    const textOk = !query || i.host.toLowerCase().includes(query)
      || i.description.toLowerCase().includes(query)
      || i.evidence.toLowerCase().includes(query);
    return sevOk && textOk;
  }});
}}

// ── Render Impacts ─────────────────────────────────────────────────────────────
function renderImpacts() {{
  const filtered = getFiltered();
  const total    = filtered.length;
  const start    = (currentPage - 1) * PAGE_SIZE;
  const page     = filtered.slice(start, start + PAGE_SIZE);

  document.getElementById('showing-count').textContent = total;

  const list = document.getElementById('impacts-list');
  list.innerHTML = '';

  page.forEach((imp, idx) => {{
    const globalIdx = start + idx;
    const card = document.createElement('div');
    card.className = 'impact-card';
    card.style.animationDelay = `${{idx * 0.02}}s`;

    // Extract curl from evidence
    const curlMatch = imp.evidence.match(/curl [^\n]+/);
    const pocHtml = curlMatch
      ? `<div class="poc-block"><div class="poc-label">⚡ PoC Command</div>${{curlMatch[0]}}</div>`
      : '';

    card.innerHTML = `
      <div class="impact-header" onclick="toggleCard(${{globalIdx}})">
        <span class="sev-badge" style="background:${{imp.color}}22;color:${{imp.color}};border:1px solid ${{imp.color}}44">
          ${{imp.severity}}
        </span>
        <div>
          <div class="impact-desc">${{imp.description}}</div>
          <div class="impact-host">🎯 ${{imp.host}}</div>
        </div>
        <span class="cvss-badge">CVSS ${{imp.cvss}}</span>
      </div>
      <div class="impact-body" id="body-${{globalIdx}}">
        <div class="poc-label">📋 Evidência Técnica</div>
        <div class="evidence-block">${{imp.evidence}}</div>
        ${{pocHtml}}
      </div>`;
    list.appendChild(card);
  }});

  renderPagination(total);
}}

function toggleCard(idx) {{
  const body = document.getElementById(`body-${{idx}}`);
  if(body) body.classList.toggle('open');
}}

// ── Pagination ─────────────────────────────────────────────────────────────────
function renderPagination(total) {{
  const pages = Math.ceil(total / PAGE_SIZE);
  const pag   = document.getElementById('pagination');
  pag.innerHTML = '';
  if(pages <= 1) return;

  const range = [];
  for(let i = Math.max(1,currentPage-2); i <= Math.min(pages,currentPage+2); i++) range.push(i);

  if(range[0] > 1) {{
    const b = document.createElement('button');
    b.className='page-btn'; b.textContent='1';
    b.onclick=()=>{{ currentPage=1; renderImpacts(); window.scrollTo(0,300); }};
    pag.appendChild(b);
    if(range[0] > 2) pag.appendChild(Object.assign(document.createElement('span'),{{textContent:'…',style:'color:var(--muted);padding:.35rem .5rem'}}));
  }}

  range.forEach(p => {{
    const b = document.createElement('button');
    b.className = 'page-btn' + (p === currentPage ? ' active' : '');
    b.textContent = p;
    b.onclick = ()=>{{ currentPage=p; renderImpacts(); window.scrollTo(0,300); }};
    pag.appendChild(b);
  }});

  if(range[range.length-1] < pages) {{
    if(range[range.length-1] < pages - 1) pag.appendChild(Object.assign(document.createElement('span'),{{textContent:'…',style:'color:var(--muted);padding:.35rem .5rem'}}));
    const b = document.createElement('button');
    b.className='page-btn'; b.textContent=pages;
    b.onclick=()=>{{ currentPage=pages; renderImpacts(); window.scrollTo(0,300); }};
    pag.appendChild(b);
  }}
}}

// ── Render Hosts ───────────────────────────────────────────────────────────────
function renderHosts() {{
  const tbody = document.getElementById('hosts-body');
  HOSTS.forEach(h => {{
    const cls = h.impacts > 0
      ? `<span class="impacts-count has-impacts">${{h.impacts}}</span>`
      : `<span class="impacts-count no-impacts">0</span>`;
    const row = document.createElement('tr');
    row.innerHTML = `
      <td style="font-family:monospace;font-size:.8rem">${{h.host}}</td>
      <td style="color:var(--muted);font-size:.78rem">${{h.ips}}</td>
      <td style="color:var(--muted);font-size:.78rem">${{h.cname}}</td>
      <td>${{h.status}}</td>
      <td style="font-size:.78rem">${{h.server}}</td>
      <td><span class="cls-badge">${{h.cls}}</span></td>
      <td style="text-align:center">${{cls}}</td>`;
    tbody.appendChild(row);
  }});
}}

// ── Init ───────────────────────────────────────────────────────────────────────
document.getElementById('gen-time').textContent = new Date().toLocaleString('pt-BR');
renderImpacts();
renderHosts();
</script>
</body>
</html>"""


def export_html_report(
    domain: str,
    results: Dict[str, HostResult],
    filepath: str,
) -> None:
    """
    Generate a self-contained interactive HTML dashboard report.
    """
    html_content = _build_html(domain, results)
    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)
    except Exception:
        pass
