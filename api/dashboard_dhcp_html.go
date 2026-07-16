// Copyright 2024-2026 George (earentir) Pantazis (https://earentir.dev)
// SPDX-License-Identifier: GPL-2.0-only

package api

// Shell layout and CSS adapted from dnsplane/api/dashboard_page.go (GPL-2.0-only).
const dhcpDashboardHTMLPart1 = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="dhcplane-api-token" content="">
  <title>dhcplane</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js" crossorigin="anonymous"></script>
  <style>
    :root {
      --bg: #0d1117;
      --surface: #161b22;
      --surface-hover: #21262d;
      --border: #30363d;
      --text: #e6edf3;
      --muted: #8b949e;
      --accent: #58a6ff;
      --accent-soft: rgba(88, 166, 255, 0.12);
      --success: #3fb950;
      --warning: #d29922;
      --danger: #f85149;
      --sidebar-w: 168px;
      --radius: 8px;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
    }
    .app { display: flex; min-height: 100vh; }
    aside {
      width: var(--sidebar-w);
      background: var(--surface);
      border-right: 1px solid var(--border);
      padding: 1.25rem 0;
      flex-shrink: 0;
      display: flex;
      flex-direction: column;
    }
    .brand {
      padding: 0 1.25rem 1.25rem;
      font-weight: 700;
      font-size: 1.1rem;
      color: var(--accent);
      border-bottom: 1px solid var(--border);
      margin-bottom: 1rem;
    }
    nav button.nav-item {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.65rem 1.25rem;
      color: var(--muted);
      width: 100%;
      text-align: left;
      border: none;
      background: none;
      font: inherit;
      cursor: pointer;
      font-size: 0.9rem;
    }
    nav button.nav-item:hover { background: var(--surface-hover); color: var(--text); }
    nav button.nav-item.active {
      background: var(--accent-soft);
      color: var(--accent);
      font-weight: 600;
      border-right: 3px solid var(--accent);
    }
    .nav-external {
      display: flex;
      align-items: center;
      gap: 0.65rem;
      padding: 0.6rem 1.25rem 1rem;
      margin-top: auto;
      border-top: 1px solid var(--border);
      font-size: 0.78rem;
    }
    .nav-external a { color: var(--accent); text-decoration: none; display: inline-flex; align-items: center; }
    .nav-external a:hover { color: var(--text); }
    .nav-external svg { width: 1.1rem; height: 1.1rem; opacity: 0.85; }
    .token-panel {
      padding: 0.75rem 1.25rem;
      border-top: 1px solid var(--border);
      font-size: 0.75rem;
      color: var(--muted);
    }
    .token-panel input {
      width: 100%;
      margin-top: 0.35rem;
      background: var(--surface-hover);
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 0.4rem 0.5rem;
      font-size: 0.8rem;
    }
    .token-panel button {
      margin-top: 0.45rem;
      width: 100%;
      background: var(--accent);
      color: #0d1117;
      border: none;
      border-radius: 6px;
      padding: 0.4rem;
      font-weight: 600;
      cursor: pointer;
      font-size: 0.8rem;
    }
    main.main-shell {
      flex: 1;
      display: flex;
      flex-direction: column;
      min-height: 100vh;
      min-width: 0;
      padding: 1.5rem 1.75rem;
      overflow: hidden;
    }
    .view { flex: 1; display: flex; flex-direction: column; min-height: 0; overflow: auto; }
    .view.hidden { display: none; }
    h1 {
      font-size: 1.35rem;
      font-weight: 600;
      margin: 0 0 1.25rem 0;
    }
    .ws-status { font-size: 0.78rem; color: var(--muted); margin: -0.35rem 0 0.75rem 0; min-height: 1.2em; }
    .muted-link { color: var(--muted); font-size: 0.85rem; }
    .muted-link a { color: var(--accent); }
    .dashboard-section { margin-bottom: 1.5rem; }
    .dashboard-section .section-kicker {
      font-size: 0.7rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--muted);
      margin: 0 0 0.65rem 0;
      display: flex;
      align-items: center;
      gap: 0.45rem;
    }
    .dashboard-section:first-of-type .section-kicker { margin-top: 0; }
    .status-subkicker {
      margin: 0.85rem 0 0.65rem 0;
      font-size: 0.7rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--muted);
      display: flex;
      align-items: center;
      gap: 0.45rem;
    }
    .status-grid {
      display: grid;
      gap: 1rem;
      grid-template-columns: repeat(auto-fill, minmax(min(100%, 220px), 1fr));
    }
    @media (min-width: 1100px) {
      .status-grid { grid-template-columns: repeat(5, 1fr); }
    }
    .status-cell {
      min-height: 5.1rem;
      display: flex;
      flex-direction: column;
      justify-content: flex-start;
      gap: 0.35rem;
    }
    .status-cell .status-pill {
      font-size: 1.15rem;
      font-weight: 700;
      font-variant-numeric: tabular-nums;
      line-height: 1.25;
      word-break: break-word;
    }
    .status-cell .status-pill.ok { color: var(--success); }
    .status-cell .status-pill.fail { color: var(--danger); }
    .status-cell .status-pill.warn { color: var(--warning); }
    .status-cell .status-pill.neutral {
      color: var(--text);
      font-size: 0.92rem;
      font-weight: 500;
    }
    .status-cell .status-pill.mono {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.95rem;
      font-weight: 600;
    }
    .dash-icon-wrap {
      display: inline-flex;
      flex-shrink: 0;
      width: 1rem;
      height: 1rem;
      color: var(--muted);
    }
    .dash-icon-wrap .dash-icon,
    .dash-icon-wrap svg.dash-icon {
      width: 100%;
      height: 100%;
      display: block;
    }
    .metric-row {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 1rem;
      margin-bottom: 1rem;
    }
    .metric-row.metric-row--fluid {
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    }
    @media (max-width: 1100px) { .metric-row { grid-template-columns: repeat(2, 1fr); } }
    @media (max-width: 700px) {
      .app { flex-direction: column; }
      aside { width: 100%; border-right: none; border-bottom: 1px solid var(--border); }
      .metric-row { grid-template-columns: 1fr; }
      .metric-row.metric-row--fluid { grid-template-columns: 1fr; }
    }
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 1rem 1.15rem;
    }
    .card h3 {
      margin: 0 0 0.35rem 0;
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: var(--muted);
      display: flex;
      align-items: center;
      gap: 0.45rem;
    }
    .card .value {
      font-size: 1.75rem;
      font-weight: 700;
      font-variant-numeric: tabular-nums;
      color: var(--text);
    }
    .card .value.sm { font-size: 1.1rem; line-height: 1.3; word-break: break-word; }
    .card .sub { font-size: 0.8rem; color: var(--muted); margin-top: 0.35rem; }
    .charts-row {
      display: grid;
      grid-template-columns: 1fr 380px;
      gap: 1.25rem;
      align-items: start;
    }
    @media (max-width: 1200px) { .charts-row { grid-template-columns: 1fr; } }
    .charts-stack { display: flex; flex-direction: column; gap: 1rem; }
    .chart-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 1rem 1.15rem;
    }
    .chart-card h2 { margin: 0 0 0.75rem 0; font-size: 0.95rem; font-weight: 600; }
    .chart-wrap { position: relative; height: 220px; max-width: 100%; }
    .fs-top-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
      gap: 1rem;
    }
    .fs-top-panel {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      overflow: hidden;
    }
    .fs-top-h {
      margin: 0;
      padding: 0.65rem 0.85rem;
      font-size: 0.78rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: var(--muted);
      border-bottom: 1px solid var(--border);
    }
    .dash-mini-table-wrap {
      max-height: 22rem;
      overflow: auto;
    }
    .dash-mini-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.82rem;
    }
    .dash-mini-table th, .dash-mini-table td {
      padding: 0.45rem 0.65rem;
      text-align: left;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }
    .dash-mini-table th {
      position: sticky;
      top: 0;
      background: var(--surface);
      z-index: 1;
      color: var(--muted);
      font-size: 0.72rem;
      text-transform: uppercase;
      letter-spacing: 0.03em;
    }
    .dash-mini-table td.num { text-align: right; font-variant-numeric: tabular-nums; }
    .dash-mini-table td.mono {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.78rem;
    }
    .dash-mini-table tbody tr:nth-child(even) { background: rgba(255,255,255,0.02); }
    .dash-mini-table tbody tr:hover { background: var(--surface-hover); }
    .activity-panel {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      display: flex;
      flex-direction: column;
      max-height: calc(100vh - 8rem);
      min-height: 280px;
    }
    .activity-head {
      padding: 1rem 1.15rem;
      border-bottom: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .activity-head h2 { margin: 0; font-size: 1rem; font-weight: 600; }
    .activity-head .muted { font-size: 0.8rem; color: var(--muted); }
    .activity-body { overflow-y: auto; flex: 1; padding: 0.5rem 0; }
    .log-item {
      padding: 0.65rem 1.15rem;
      border-bottom: 1px solid var(--border);
      font-size: 0.82rem;
    }
    .log-item:last-child { border-bottom: none; }
    .log-item .top { display: flex; align-items: flex-start; gap: 0.5rem; }
    .dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      margin-top: 0.35rem;
      flex-shrink: 0;
    }
    .dot.ok { background: var(--success); }
    .dot.warn { background: var(--warning); }
    .res-table-wrap {
      flex: 1;
      min-height: 0;
      overflow: auto;
      border: 1px solid var(--border);
      border-radius: var(--radius);
      background: var(--surface);
      max-height: calc(100vh - 11rem);
    }
    .res-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.82rem;
    }
    .res-table th, .res-table td {
      padding: 0.5rem 0.65rem;
      text-align: left;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }
    .res-table th {
      position: sticky;
      top: 0;
      background: var(--surface);
      z-index: 1;
      color: var(--muted);
      font-size: 0.72rem;
      text-transform: uppercase;
      letter-spacing: 0.03em;
    }
    .res-table th.sort-th {
      cursor: pointer;
      user-select: none;
      white-space: nowrap;
    }
    .res-table th.sort-th:hover { color: var(--text); }
    .res-table th.sort-th .sort-ind {
      display: inline-block;
      min-width: 1.1em;
      margin-left: 0.25rem;
      color: var(--accent);
    }
    .res-table tbody tr:nth-child(even) { background: rgba(255,255,255,0.02); }
    .res-table tbody tr:hover { background: var(--surface-hover); }
    .res-table td.mono {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.78rem;
    }
    .err { color: var(--danger); font-size: 0.9rem; margin-top: 0.75rem; }
    .muted { color: var(--muted); font-size: 0.82rem; line-height: 1.45; }
    .res-toolbar {
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem 1.25rem;
      align-items: flex-end;
      margin-bottom: 0.65rem;
    }
    .res-toolbar label {
      display: flex;
      flex-direction: column;
      gap: 0.25rem;
      font-size: 0.8rem;
      color: var(--muted);
    }
    .res-toolbar input {
      min-width: 11rem;
      background: var(--surface);
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 0.4rem 0.55rem;
      font-size: 0.88rem;
    }
    .res-chips {
      display: flex;
      flex-wrap: wrap;
      gap: 0.4rem;
      margin-bottom: 0.65rem;
      min-height: 1.4rem;
      align-items: center;
    }
    .res-chips-label { font-size: 0.78rem; color: var(--muted); margin-right: 0.25rem; }
    .res-chip {
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      padding: 0.28rem 0.55rem;
      border-radius: 6px;
      border: 1px solid var(--border);
      background: var(--surface-hover);
      font-size: 0.8rem;
      color: var(--text);
    }
    .res-chip button {
      background: none;
      border: none;
      color: var(--muted);
      cursor: pointer;
      font-size: 1rem;
      line-height: 1;
      padding: 0 0.15rem;
    }
    .res-chip button:hover { color: var(--danger); }
    .res-count { font-size: 0.85rem; color: var(--muted); margin-bottom: 0.45rem; }
    .res-cell-filter {
      cursor: pointer;
      text-decoration: underline dotted;
      text-underline-offset: 0.12em;
    }
    .res-cell-filter:hover { color: var(--accent); }
    .badge {
      display: inline-flex;
      align-items: center;
      padding: 0.2rem 0.5rem;
      border: 1px solid var(--border);
      border-radius: 999px;
      font-size: 0.72rem;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      background: var(--surface-hover);
      color: var(--text);
    }
    .subnet-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(14px, 1fr));
      gap: 2px;
      margin: 0.75rem 0 1rem 0;
      max-width: 100%;
    }
    .subnet-cell {
      width: 100%;
      aspect-ratio: 1;
      border-radius: 2px;
      border: 1px solid transparent;
      cursor: default;
    }
    .subnet-cell.type-leased { background: #f85149; }
    .subnet-cell.type-reserved { background: #a371f7; }
    .subnet-cell.type-free { background: #3fb950; }
    .subnet-cell.type-unused { background: #30363d; }
    .subnet-cell.type-banned-mac { background: #d29922; }
    .subnet-cell.type-banned-ip { background: #6e7681; }
    .legend-row { display:flex; flex-wrap:wrap; gap:0.75rem 1rem; margin-bottom:0.75rem; font-size:0.78rem; color:var(--muted); }
    .legend-item { display:inline-flex; align-items:center; gap:0.35rem; }
    .legend-swatch { width:0.7rem; height:0.7rem; border-radius:2px; display:inline-block; }
    .admin-actions { display:flex; flex-wrap:wrap; gap:0.65rem; margin-bottom:1rem; }
    .admin-actions button, .btn {
      background: var(--accent);
      color: #0d1117;
      border: none;
      border-radius: 6px;
      padding: 0.45rem 0.8rem;
      font-weight: 600;
      cursor: pointer;
      font-size: 0.85rem;
    }
    .admin-actions button.secondary, .btn.secondary {
      background: var(--surface-hover);
      color: var(--text);
      border: 1px solid var(--border);
    }
    .admin-actions button:disabled, .btn:disabled { opacity: 0.55; cursor: not-allowed; }
    .console-box {
      background: #010409;
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 0.75rem;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.78rem;
      max-height: calc(100vh - 10rem);
      overflow: auto;
      white-space: pre-wrap;
      line-height: 1.45;
    }
    .search-result {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 1rem 1.15rem;
      margin-top: 0.75rem;
    }
    .search-result h3 { margin: 0 0 0.5rem 0; font-size: 0.95rem; }
    .kv { display:grid; grid-template-columns: 10rem 1fr; gap:0.35rem 0.75rem; font-size:0.85rem; }
    .kv .k { color: var(--muted); }
    .kv .v { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
  </style>
</head>
<body>
<div class="app">
  <aside>
    <div class="brand">dhcplane</div>
    <nav>
      <button type="button" class="nav-item active" data-view="status">Status</button>
      <button type="button" class="nav-item" data-view="stats">Statistics</button>
      <button type="button" class="nav-item" data-view="subnet">Address Space</button>
      <button type="button" class="nav-item" data-view="search">Search</button>
      <button type="button" class="nav-item" data-view="network">Network</button>
      <button type="button" class="nav-item" data-view="alerts">Alerts</button>
      <button type="button" class="nav-item" data-view="log">Log</button>
      <button type="button" class="nav-item" data-view="devices">Devices</button>
      <button type="button" class="nav-item" data-view="leases">Leases</button>
      <button type="button" class="nav-item" data-view="console">Console</button>
      <button type="button" class="nav-item" data-view="admin">Admin</button>
    </nav>
    <div class="nav-external" aria-label="Project links">
      <a href="https://github.com/network-plane/dhcplane" target="_blank" rel="noopener noreferrer" title="GitHub" aria-label="dhcplane on GitHub">
        <svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>
      </a>
      <a href="https://earentir.dev" target="_blank" rel="noopener noreferrer" title="earentir.dev" aria-label="earentir.dev">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>
      </a>
    </div>
  </aside>
  <main class="main-shell">
    <div id="err" class="err"></div>
    <div id="ws-status" class="ws-status" aria-live="polite">Updates: —</div>
`

const dhcpDashboardTokenPanel = `
    <div class="token-panel">
      API token
      <input type="password" id="apiTok" placeholder="Bearer token" autocomplete="off">
      <button type="button" id="saveTok">Save to session</button>
    </div>
`

const dhcpDashboardHTMLPart2 = `
    <div id="view-status" class="view">
      <h1>Status</h1>
      <p class="muted-link" style="margin:-0.5rem 0 1rem 0">Listeners, readiness, and feature flags · <a href="/stats/dashboard/data">JSON</a></p>
      <div class="dashboard-section">
        <h2 class="section-kicker"><span class="dash-icon-wrap" aria-hidden="true"><svg class="dash-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 21.35l-1.45-1.32C5.4 15.36 2 12.28 2 8.5 2 5.42 4.42 3 7.5 3c1.74 0 3.41.81 4.5 2.09C13.09 3.81 14.76 3 16.5 3 19.58 3 22 5.42 22 8.5c0 3.78-3.4 6.86-8.55 11.54L12 21.35z"/></svg></span> Core</h2>
        <div class="status-grid" aria-label="Server status">
          <div class="card status-cell">
            <h3>Ready</h3>
            <div class="status-pill fail" id="st-ready">—</div>
          </div>
          <div class="card status-cell">
            <h3>API</h3>
            <div class="status-pill fail" id="st-api">—</div>
          </div>
          <div class="card status-cell">
            <h3>DHCP</h3>
            <div class="status-pill fail" id="st-dhcp">—</div>
          </div>
          <div class="card status-cell">
            <h3>Console</h3>
            <div class="status-pill neutral" id="st-console">—</div>
          </div>
          <div class="card status-cell">
            <h3>DHCP ports</h3>
            <div class="status-pill neutral mono" id="st-dhcp-port">—</div>
          </div>
          <div class="card status-cell">
            <h3>API listen</h3>
            <div class="status-pill neutral mono" id="st-api-port">—</div>
          </div>
          <div class="card status-cell">
            <h3>API enabled</h3>
            <div class="status-pill neutral" id="st-api-en">—</div>
          </div>
          <div class="card status-cell">
            <h3>Client socket</h3>
            <div class="status-pill neutral mono" id="st-sock">—</div>
          </div>
          <div class="card status-cell">
            <h3>Client TCP</h3>
            <div class="status-pill neutral mono" id="st-tcp">—</div>
          </div>
        </div>
        <p class="status-subkicker"><span class="dash-icon-wrap" aria-hidden="true"><svg class="dash-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 15a3 3 0 100-6 3 3 0 000 6z"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 11-2.83-2.83l.06-.06a1.65 1.65 0 00.33-1.82 1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 112.83-2.83l.06.06A1.65 1.65 0 009 4.6V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 112.83 2.83l-.06.06a1.65 1.65 0 00-.33 1.82V9c.26.604.852.997 1.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/></svg></span> Protocols &amp; features</p>
        <div class="status-grid" id="status-features-grid" aria-label="Feature toggles"></div>
      </div>
    </div>

    <div id="view-stats" class="view hidden">
      <h1>Statistics</h1>
      <p class="muted-link" style="margin:-0.5rem 0 1rem 0">Counters, charts, and lease preview · <a href="/stats/dashboard/data">JSON</a></p>
      <div class="dashboard-section">
        <h2 class="section-kicker">Lease activity</h2>
        <div class="metric-row">
          <div class="card"><h3>Allocations 1m</h3><div class="value" id="m-al-1m">—</div><div class="sub">rolling window</div></div>
          <div class="card"><h3>Allocations 1h</h3><div class="value" id="m-al-1h">—</div><div class="sub"></div></div>
          <div class="card"><h3>Leases current</h3><div class="value" id="m-lc">—</div><div class="sub">in lease DB</div></div>
          <div class="card"><h3>Leases expiring</h3><div class="value" id="m-le">—</div><div class="sub"></div></div>
        </div>
        <div class="metric-row metric-row--fluid">
          <div class="card"><h3>Allocations 24h</h3><div class="value" id="m-al-24h">—</div><div class="sub"></div></div>
          <div class="card"><h3>Allocations 7d</h3><div class="value" id="m-al-7d">—</div><div class="sub"></div></div>
          <div class="card"><h3>Allocations 30d</h3><div class="value" id="m-al-30d">—</div><div class="sub"></div></div>
          <div class="card"><h3>Leases expired</h3><div class="value" id="m-lx">—</div><div class="sub"></div></div>
        </div>
      </div>
      <div class="dashboard-section">
        <h2 class="section-kicker">Server</h2>
        <div class="metric-row metric-row--fluid">
          <div class="card"><h3>Interface</h3><div class="value sm" id="m-iface">—</div><div class="sub">bind</div></div>
          <div class="card"><h3>Subnet</h3><div class="value sm" id="m-subnet">—</div><div class="sub">CIDR</div></div>
          <div class="card"><h3>Server IP</h3><div class="value sm" id="m-srvip">—</div><div class="sub"></div></div>
          <div class="card"><h3>Version</h3><div class="value sm" id="m-ver">—</div><div class="sub">build</div></div>
        </div>
      </div>
      <div class="dashboard-section">
        <h2 class="section-kicker">Top preview</h2>
        <p class="muted-link" style="margin:-0.35rem 0 0.85rem 0">Lease database · sorted by IP</p>
        <div class="fs-top-grid">
          <div class="fs-top-panel">
            <div class="fs-top-h">Leases</div>
            <div class="dash-mini-table-wrap">
              <table class="dash-mini-table">
                <thead><tr><th>IP</th><th>MAC</th><th>Hostname</th></tr></thead>
                <tbody id="lease-top-body"></tbody>
              </table>
            </div>
          </div>
          <div class="fs-top-panel">
            <div class="fs-top-h">Subnet</div>
            <div class="dash-mini-table-wrap">
              <table class="dash-mini-table">
                <tbody id="subnet-kv-body"></tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
      <div class="dashboard-section">
        <h2 class="section-kicker">Trends</h2>
        <div class="charts-row">
          <div class="charts-stack">
            <div class="chart-card">
              <h2>Leases by class</h2>
              <div class="chart-wrap"><canvas id="chartLeaseClass"></canvas></div>
            </div>
            <div class="chart-card">
              <h2>Allocations (last hour)</h2>
              <p class="muted" style="margin:-0.35rem 0 0.6rem 0;font-size:0.78rem">One point per lease allocation (derived time); capped at 2000 most recent in the window.</p>
              <div class="chart-wrap"><canvas id="chartAlloc1h"></canvas></div>
            </div>
          </div>
          <div class="activity-panel">
            <div class="activity-head">
              <h2>Leases</h2>
              <span class="muted">preview · newest first</span>
            </div>
            <div class="activity-body" id="lease-feed"></div>
          </div>
        </div>
      </div>
    </div>

    <div id="view-log" class="view hidden">
      <h1>Log</h1>
      <p class="muted" style="margin-top:-0.5rem">Lease preview from the dashboard payload (same rows as Statistics). Filter client-side; use the API for the full database.</p>
      <p class="muted-link" style="margin:-0.5rem 0 1rem 0"><a href="/stats/dashboard/data">JSON</a></p>
      <div class="res-toolbar">
        <label>IP <input type="search" id="log-in-ip" placeholder="Partial match" autocomplete="off" spellcheck="false" aria-label="Filter by IP"></label>
        <label>MAC <input type="search" id="log-in-mac" placeholder="Partial match" autocomplete="off" spellcheck="false" aria-label="Filter by MAC"></label>
        <label>Hostname <input type="search" id="log-in-host" placeholder="Partial match" autocomplete="off" spellcheck="false" aria-label="Filter by hostname"></label>
        <label>Any text <input type="search" id="log-in-any" placeholder="Allocated / expiry / …" autocomplete="off" spellcheck="false" aria-label="Filter any column"></label>
      </div>
      <div class="res-chips"><span class="res-chips-label">Quick filters (click a cell to add):</span><span id="log-chips"></span></div>
      <div class="res-count" id="log-count">—</div>
      <div class="res-table-wrap">
        <table class="res-table">
          <thead><tr><th class="sort-th" data-table-sort="log" data-sort-key="ip">IP <span class="sort-ind"></span></th><th class="sort-th" data-table-sort="log" data-sort-key="mac">MAC <span class="sort-ind"></span></th><th class="sort-th" data-table-sort="log" data-sort-key="hostname">Hostname <span class="sort-ind"></span></th><th class="sort-th" data-table-sort="log" data-sort-key="allocated_ts">Allocated <span class="sort-ind"></span></th><th class="sort-th" data-table-sort="log" data-sort-key="expiry_ts">Expiry <span class="sort-ind"></span></th><th class="sort-th" data-table-sort="log" data-sort-key="first_seen_ts">First seen <span class="sort-ind"></span></th></tr></thead>
          <tbody id="lease-log-body"></tbody>
        </table>
      </div>
    </div>

    <div id="view-devices" class="view hidden">
      <h1>Devices</h1>
      <p class="muted" style="margin-top:-0.5rem">Configured MAC-based entries from reservations and banned MACs. Search and sort locally from the dashboard payload.</p>
      <div class="res-toolbar">
        <label>Kind <input type="search" id="devices-in-kind" placeholder="reservation / banned" autocomplete="off" spellcheck="false" aria-label="Filter by kind"></label>
        <label>MAC <input type="search" id="devices-in-mac" placeholder="aa:bb:cc..." autocomplete="off" spellcheck="false" aria-label="Filter by MAC"></label>
        <label>IP / Host note <input type="search" id="devices-in-ip" placeholder="Reserved IP" autocomplete="off" spellcheck="false" aria-label="Filter by IP"></label>
        <label>Any text <input type="search" id="devices-in-any" placeholder="Note / vendor / management" autocomplete="off" spellcheck="false" aria-label="Filter any device field"></label>
      </div>
      <div class="res-count" id="devices-count">—</div>
      <div class="res-table-wrap">
        <table class="res-table">
          <thead><tr><th class="sort-th" data-table-sort="devices" data-sort-key="kind">Kind <span class="sort-ind"></span></th><th class="sort-th" data-table-sort="devices" data-sort-key="mac">MAC <span class="sort-ind"></span></th><th class="sort-th" data-table-sort="devices" data-sort-key="ip">IP <span class="sort-ind"></span></th><th class="sort-th" data-table-sort="devices" data-sort-key="note">Note <span class="sort-ind"></span></th><th class="sort-th" data-table-sort="devices" data-sort-key="equipment_type">Equipment <span class="sort-ind"></span></th><th class="sort-th" data-table-sort="devices" data-sort-key="manufacturer">Manufacturer <span class="sort-ind"></span></th><th class="sort-th" data-table-sort="devices" data-sort-key="management_type">Management <span class="sort-ind"></span></th><th class="sort-th" data-table-sort="devices" data-sort-key="first_seen_ts">First seen <span class="sort-ind"></span></th></tr></thead>
          <tbody id="devices-body"></tbody>
        </table>
      </div>
    </div>

    <div id="view-leases" class="view hidden">
      <h1>Leases</h1>
      <p class="muted" style="margin-top:-0.5rem">Full dynamic lease database with allocation and first-seen metadata. Search and sort locally; updated with the dashboard feed.</p>
      <div class="res-toolbar">
        <label>IP <input type="search" id="leases-in-ip" placeholder="Partial match" autocomplete="off" spellcheck="false" aria-label="Filter leases by IP"></label>
        <label>MAC <input type="search" id="leases-in-mac" placeholder="Partial match" autocomplete="off" spellcheck="false" aria-label="Filter leases by MAC"></label>
        <label>Hostname <input type="search" id="leases-in-host" placeholder="Partial match" autocomplete="off" spellcheck="false" aria-label="Filter leases by hostname"></label>
        <label>Any text <input type="search" id="leases-in-any" placeholder="Allocated / expiry / first seen" autocomplete="off" spellcheck="false" aria-label="Filter any lease field"></label>
      </div>
      <div class="res-count" id="leases-count">—</div>
      <div class="res-table-wrap">
        <table class="res-table">
          <thead><tr><th class="sort-th" data-table-sort="leases" data-sort-key="ip">IP <span class="sort-ind"></span></th><th class="sort-th" data-table-sort="leases" data-sort-key="mac">MAC <span class="sort-ind"></span></th><th class="sort-th" data-table-sort="leases" data-sort-key="hostname">Hostname <span class="sort-ind"></span></th><th class="sort-th" data-table-sort="leases" data-sort-key="allocated_ts">Allocated <span class="sort-ind"></span></th><th class="sort-th" data-table-sort="leases" data-sort-key="expiry_ts">Expiry <span class="sort-ind"></span></th><th class="sort-th" data-table-sort="leases" data-sort-key="first_seen_ts">First seen <span class="sort-ind"></span></th></tr></thead>
          <tbody id="leases-body"></tbody>
        </table>
      </div>
    </div>

    <div id="view-subnet" class="view hidden">
      <h1>Address Space</h1>
      <p class="muted" style="margin-top:-0.5rem">Full subnet classification (same as <code>stats --details</code> / <code>--grid</code>). Click headers to sort; filter with the search boxes.</p>
      <div class="legend-row" id="subnet-legend"></div>
      <div class="subnet-grid" id="subnet-grid" title="Subnet occupancy grid"></div>
      <div class="res-toolbar">
        <label>Type <input type="search" id="subnet-in-type" placeholder="leased / free / …" autocomplete="off" spellcheck="false"></label>
        <label>IP <input type="search" id="subnet-in-ip" placeholder="Partial match" autocomplete="off" spellcheck="false"></label>
        <label>MAC / Host <input type="search" id="subnet-in-mac" placeholder="MAC or hostname" autocomplete="off" spellcheck="false"></label>
        <label>Any text <input type="search" id="subnet-in-any" placeholder="Any column" autocomplete="off" spellcheck="false"></label>
      </div>
      <div class="res-count" id="subnet-count">—</div>
      <div class="res-table-wrap">
        <table class="res-table">
          <thead><tr><th class="sort-th" data-table-sort="subnet" data-sort-key="ip">IP <span class="sort-ind"></span></th><th class="sort-th" data-table-sort="subnet" data-sort-key="type">Type <span class="sort-ind"></span></th><th class="sort-th" data-table-sort="subnet" data-sort-key="mac">MAC <span class="sort-ind"></span></th><th class="sort-th" data-table-sort="subnet" data-sort-key="hostname">Hostname <span class="sort-ind"></span></th><th class="sort-th" data-table-sort="subnet" data-sort-key="allocated_ts">Allocated <span class="sort-ind"></span></th><th class="sort-th" data-table-sort="subnet" data-sort-key="expiry_ts">Expiry <span class="sort-ind"></span></th></tr></thead>
          <tbody id="subnet-body"></tbody>
        </table>
      </div>
    </div>

    <div id="view-search" class="view hidden">
      <h1>Search</h1>
      <p class="muted" style="margin-top:-0.5rem">Look up an IP in reservations and leases (same as <code>dhcplane search</code>).</p>
      <div class="res-toolbar">
        <label>IP address <input type="search" id="search-ip" placeholder="192.168.178.100" autocomplete="off" spellcheck="false"></label>
        <button type="button" class="btn" id="search-run">Search</button>
      </div>
      <div id="search-out"></div>
    </div>

    <div id="view-network" class="view hidden">
      <h1>Network</h1>
      <p class="muted" style="margin-top:-0.5rem">ARP table from a live scan (same as <code>dhcplane arp</code>). Rate-limited; may require privileges on the host.</p>
      <div class="admin-actions">
        <button type="button" id="arp-scan-btn">Run ARP scan</button>
        <button type="button" class="secondary" id="arp-scan-all-btn">Scan all interfaces</button>
      </div>
      <div class="res-count" id="arp-count">—</div>
      <div class="res-toolbar">
        <label>Any text <input type="search" id="arp-in-any" placeholder="IP / MAC / state / note" autocomplete="off" spellcheck="false"></label>
      </div>
      <div class="res-table-wrap">
        <table class="res-table">
          <thead><tr><th class="sort-th" data-table-sort="arp" data-sort-key="ip">IP <span class="sort-ind"></span></th><th class="sort-th" data-table-sort="arp" data-sort-key="mac">MAC <span class="sort-ind"></span></th><th class="sort-th" data-table-sort="arp" data-sort-key="iface">Iface <span class="sort-ind"></span></th><th class="sort-th" data-table-sort="arp" data-sort-key="state">State <span class="sort-ind"></span></th><th class="sort-th" data-table-sort="arp" data-sort-key="note">Note <span class="sort-ind"></span></th><th class="sort-th" data-table-sort="arp" data-sort-key="source">Source <span class="sort-ind"></span></th></tr></thead>
          <tbody id="arp-body"></tbody>
        </table>
      </div>
    </div>

    <div id="view-alerts" class="view hidden">
      <h1>Alerts</h1>
      <p class="muted" style="margin-top:-0.5rem">Recent ARP anomalies and foreign DHCP server detections from background monitoring.</p>
      <div class="res-toolbar">
        <label>Any text <input type="search" id="alerts-in-any" placeholder="kind / IP / reason" autocomplete="off" spellcheck="false"></label>
      </div>
      <div class="res-count" id="alerts-count">—</div>
      <div class="res-table-wrap">
        <table class="res-table">
          <thead><tr><th class="sort-th" data-table-sort="alerts" data-sort-key="at_unix">When <span class="sort-ind"></span></th><th class="sort-th" data-table-sort="alerts" data-sort-key="kind">Kind <span class="sort-ind"></span></th><th class="sort-th" data-table-sort="alerts" data-sort-key="ip">IP <span class="sort-ind"></span></th><th class="sort-th" data-table-sort="alerts" data-sort-key="mac">MAC <span class="sort-ind"></span></th><th class="sort-th" data-table-sort="alerts" data-sort-key="reason">Reason <span class="sort-ind"></span></th><th class="sort-th" data-table-sort="alerts" data-sort-key="message">Details <span class="sort-ind"></span></th></tr></thead>
          <tbody id="alerts-body"></tbody>
        </table>
      </div>
    </div>

    <div id="view-console" class="view hidden">
      <h1>Console</h1>
      <p class="muted" style="margin-top:-0.5rem">Recent server log lines captured while the API is running (subset of console/file logging).</p>
      <div class="console-box" id="console-box">—</div>
    </div>

    <div id="view-admin" class="view hidden">
      <h1>Admin</h1>
      <p class="muted" style="margin-top:-0.5rem">Operational actions: validate config, reload, and manage reservations. Mutating actions require API auth when configured.</p>
      <div class="admin-actions">
        <button type="button" id="admin-check-btn">Validate config</button>
        <button type="button" id="admin-reload-btn">Reload config</button>
      </div>
      <div id="admin-status" class="muted" style="margin-bottom:1rem">—</div>
      <h2 class="section-kicker">Add / update reservation</h2>
      <div class="res-toolbar">
        <label>MAC <input id="admin-res-mac" placeholder="aa:bb:cc:dd:ee:ff" autocomplete="off" spellcheck="false"></label>
        <label>IP <input id="admin-res-ip" placeholder="192.168.178.55" autocomplete="off" spellcheck="false"></label>
        <label>Note <input id="admin-res-note" placeholder="optional" autocomplete="off" spellcheck="false"></label>
        <button type="button" class="btn" id="admin-res-add">Save reservation</button>
      </div>
      <h2 class="section-kicker">Remove reservation</h2>
      <div class="res-toolbar">
        <label>MAC <input id="admin-res-del-mac" placeholder="aa:bb:cc:dd:ee:ff" autocomplete="off" spellcheck="false"></label>
        <button type="button" class="btn secondary" id="admin-res-del">Remove</button>
      </div>
    </div>
  </main>
</div>
<script>
`

const dhcpDashboardHTMLPart3 = `
(function(){
  var LS='dhcplane_api_token';
  var lastStatusKey='', lastBuildKey='', lastMetricsKey='';
  var lastPreviewJSON='', lastFeaturesJSON='', ws=null;
  var leasePreviewData=[];
  var configMACData=[], leasesAllData=[], subnetData=[], subnetGrid=[], findingsData=[], consoleLines=[], arpData=[];
  var logState={chips:[],sortKey:'ip',sortDir:1};
  var devicesState={sortKey:'kind',sortDir:1};
  var leasesState={sortKey:'ip',sortDir:1};
  var subnetState={sortKey:'ip',sortDir:1};
  var arpState={sortKey:'ip',sortDir:1};
  var alertsState={sortKey:'at_unix',sortDir:-1};
  var chartLeaseClass=null, chartAllocHour=null;
  var trendLabels=[], trendCur=[], trendExp=[], trendExd=[];
  var lastTrendPush=0, lastTrendKey='';
  var trendMaxPoints=56;
  function tok(){ return (sessionStorage.getItem(LS)||'').trim(); }
  function authHeaders(){
    var h={}, t=tok();
    if(t) h['Authorization']='Bearer '+t;
    return h;
  }
  function setErr(msg){
    var el=document.getElementById('err');
    if(el) el.textContent=msg||'';
  }
  function setWsStatus(txt){
    var el=document.getElementById('ws-status');
    if(el) el.textContent=txt;
  }
  function esc(s){
    if(s==null) return '';
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }
  function escAttr(s){
    if(s==null) return '';
    return String(s).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;');
  }
  function lower(s){ return String(s==null?'':s).toLowerCase(); }
  function ipNum(s){
    var m=String(s||'').trim().match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
    if(!m) return Number.MAX_SAFE_INTEGER;
    return (((+m[1])*256+(+m[2]))*256+(+m[3]))*256+(+m[4]);
  }
  function cmpText(a,b){
    a=lower(a); b=lower(b);
    if(a<b) return -1;
    if(a>b) return 1;
    return 0;
  }
  function cmpNum(a,b){
    a=Number(a)||0; b=Number(b)||0;
    if(a<b) return -1;
    if(a>b) return 1;
    return 0;
  }
  function sortRows(rows, state, spec){
    rows.sort(function(a,b){
      var mode=spec[state.sortKey]||'text';
      var av=a[state.sortKey], bv=b[state.sortKey], c=0;
      if(mode==='ip') c=cmpNum(ipNum(av), ipNum(bv));
      else if(mode==='num') c=cmpNum(av, bv);
      else c=cmpText(av, bv);
      if(c===0) c=cmpText(a.ip||a.mac||'', b.ip||b.mac||'');
      return c*state.sortDir;
    });
    return rows;
  }
  function toggleSort(state, key){
    if(state.sortKey===key) state.sortDir=state.sortDir*-1;
    else { state.sortKey=key; state.sortDir=1; }
  }
  function syncSortIndicators(tableName, state){
    document.querySelectorAll('[data-table-sort="'+tableName+'"]').forEach(function(th){
      var ind=th.querySelector('.sort-ind');
      if(!ind) return;
      ind.textContent=th.getAttribute('data-sort-key')===state.sortKey?(state.sortDir>0?'▲':'▼'):'';
    });
  }
  function gid(id){ var el=document.getElementById(id); return el?el.value:''; }
  function showView(name){
    ['status','stats','log','devices','leases','subnet','search','network','alerts','console','admin'].forEach(function(v){
      var el=document.getElementById('view-'+v);
      if(el) el.classList.toggle('hidden', name!==v);
    });
    document.querySelectorAll('nav button.nav-item').forEach(function(b){
      b.classList.toggle('active', b.getAttribute('data-view')===name);
    });
  }
  document.querySelectorAll('nav button.nav-item').forEach(function(b){
    b.onclick=function(){ showView(b.getAttribute('data-view')); };
  });
  var apiTokEl=document.getElementById('apiTok');
  var saveTokEl=document.getElementById('saveTok');
  if(apiTokEl && saveTokEl){
    apiTokEl.value=tok();
    saveTokEl.onclick=function(){
      sessionStorage.setItem(LS, apiTokEl.value.trim());
      location.reload();
    };
  }
  function chartCommon(){
    var grid='#30363d', tick='#8b949e';
    return {
      responsive:true,
      maintainAspectRatio:false,
      animation:false,
      interaction:{mode:'index',intersect:false},
      scales:{
        x:{grid:{color:grid},ticks:{color:tick,maxRotation:45,font:{size:10}}},
        y:{beginAtZero:true,grid:{color:grid},ticks:{color:tick}}
      },
      plugins:{legend:{display:true,labels:{color:'#8b949e',boxWidth:12,font:{size:10}}}}
    };
  }
  function allocScatterOptions(){
    var grid='#30363d', tick='#8b949e';
    return {
      responsive:true,
      maintainAspectRatio:false,
      animation:false,
      plugins:{
        legend:{display:false},
        tooltip:{
          callbacks:{
            label:function(ctx){
              var p=ctx.raw;
              if(!p) return '';
              var d=new Date((p.xAt||0)*1000);
              var ts=('0'+d.getHours()).slice(-2)+':'+('0'+d.getMinutes()).slice(-2)+':'+('0'+d.getSeconds()).slice(-2);
              var line=ts+'  '+String(p.ip||'');
              if(p.mac) line+='  '+String(p.mac);
              return line;
            }
          }
        }
      },
      scales:{
        x:{
          type:'linear',
          min:0,
          max:60,
          title:{display:true,text:'Minutes into last hour (0 = 60m ago → 60 = now)',color:tick,font:{size:10}},
          grid:{color:grid},
          ticks:{color:tick,maxTicksLimit:7, callback:function(val){
            if(val>=59.5) return 'now';
            if(val<=0.5) return '0';
            if(Math.abs(val%15)<0.01||val%15===0) return String(Math.round(val))+'m';
            return '';
          }}
        },
        y:{min:0,max:1,display:false,grid:{display:false},ticks:{display:false}}
      }
    };
  }
  function initTrendCharts(){
    if(!window.Chart) return;
    var el1=document.getElementById('chartLeaseClass');
    var el2=document.getElementById('chartAlloc1h');
    if(!el1||!el2) return;
    var common=chartCommon();
    common.plugins.legend.display=true;
    chartLeaseClass=new Chart(el1.getContext('2d'),{
      type:'line',
      data:{
        labels:[],
        datasets:[
          {label:'Current',data:[],borderColor:'#3fb950',backgroundColor:'rgba(63,185,80,0.14)',fill:true,tension:0.25,pointRadius:0},
          {label:'Expiring',data:[],borderColor:'#d29922',backgroundColor:'rgba(210,153,34,0.12)',fill:true,tension:0.25,pointRadius:0},
          {label:'Expired',data:[],borderColor:'#8b949e',backgroundColor:'rgba(139,148,158,0.1)',fill:true,tension:0.25,pointRadius:0}
        ]
      },
      options:common
    });
    chartAllocHour=new Chart(el2.getContext('2d'),{
      type:'scatter',
      data:{datasets:[{
        label:'Allocations',
        data:[],
        borderColor:'rgba(88,166,255,0.95)',
        backgroundColor:'rgba(88,166,255,0.35)',
        pointRadius:3,
        pointHoverRadius:6
      }]},
      options:allocScatterOptions()
    });
  }
  function shortTimeLabel(){
    var d=new Date();
    return ('0'+d.getHours()).slice(-2)+':'+('0'+d.getMinutes()).slice(-2)+':'+('0'+d.getSeconds()).slice(-2);
  }
  function pushTrendSamplesFromDashboard(d){
    if(!chartLeaseClass) return;
    var lv=d.lease_views||{};
    var cur=(lv.current||[]).length, exp=(lv.expiring||[]).length, exd=(lv.expired||[]).length;
    var k=cur+','+exp+','+exd;
    var t=Date.now();
    if(k===lastTrendKey && (t-lastTrendPush)<5000) return;
    lastTrendKey=k;
    lastTrendPush=t;
    var lab=shortTimeLabel();
    trendLabels.push(lab);
    trendCur.push(cur);
    trendExp.push(exp);
    trendExd.push(exd);
    while(trendLabels.length>trendMaxPoints){
      trendLabels.shift();
      trendCur.shift();
      trendExp.shift();
      trendExd.shift();
    }
    chartLeaseClass.data.labels=trendLabels.slice();
    chartLeaseClass.data.datasets[0].data=trendCur.slice();
    chartLeaseClass.data.datasets[1].data=trendExp.slice();
    chartLeaseClass.data.datasets[2].data=trendExd.slice();
    chartLeaseClass.update('none');
  }
  function updateAllocHourChart(d){
    if(!chartAllocHour) return;
    var nowSec=d.server_now_unix!=null?Number(d.server_now_unix):Math.floor(Date.now()/1000);
    var hourStart=nowSec-3600;
    var ev=d.allocation_events_1h;
    if(!Array.isArray(ev)) ev=[];
    var pts=[];
    for(var i=0;i<ev.length;i++){
      var e=ev[i];
      var at=Number(e.at)||0;
      if(at<=hourStart||at>nowSec) continue;
      var xMin=(at-hourStart)/60;
      var h=0;
      var s=String(e.ip||'')+'|'+String(e.mac||'')+'|'+at;
      for(var k=0;k<s.length;k++) h=((h<<5)-h)+s.charCodeAt(k)|0;
      var j=(Math.abs(h)%1000)/1000;
      pts.push({x:xMin,y:0.06+j*0.88,xAt:at,ip:e.ip,mac:e.mac});
    }
    chartAllocHour.data.datasets[0].data=pts;
    chartAllocHour.update('none');
  }
  function logSubMatch(hay, needle){
    if(!needle||!String(needle).trim()) return true;
    return String(hay||'').toLowerCase().indexOf(String(needle).trim().toLowerCase())>=0;
  }
  function logChipKey(ch){ return ch.kind+'\x00'+ch.val; }
  function logRowMatches(r){
    if(!logSubMatch(r.ip, gid('log-in-ip'))) return false;
    if(!logSubMatch(r.mac, gid('log-in-mac'))) return false;
    if(!logSubMatch(r.hostname, gid('log-in-host'))) return false;
    var blob=(r.ip||'')+' '+(r.mac||'')+' '+(r.hostname||'')+' '+(r.allocated_at||'')+' '+(r.expiry||'')+' '+(r.first_seen||'');
    if(!logSubMatch(blob, gid('log-in-any'))) return false;
    var chips=logState.chips;
    for(var i=0;i<chips.length;i++){
      var ch=chips[i];
      if(ch.kind==='ip' && !logSubMatch(r.ip, ch.val)) return false;
      if(ch.kind==='mac' && !logSubMatch(r.mac, ch.val)) return false;
      if(ch.kind==='host' && !logSubMatch(r.hostname, ch.val)) return false;
      if(ch.kind==='any' && !logSubMatch(blob, ch.val)) return false;
    }
    return true;
  }
  function logRenderChips(){
    var host=document.getElementById('log-chips');
    if(!host) return;
    var h='';
    for(var i=0;i<logState.chips.length;i++){
      var ch=logState.chips[i];
      var lab=ch.kind+': '+ch.val;
      h+='<span class="res-chip">'+esc(lab)+'<button type="button" data-log-chip-idx="'+i+'" title="Remove filter" aria-label="Remove filter">×</button></span>';
    }
    host.innerHTML=h;
  }
  function logAddChip(kind, val){
    var v=String(val==null?'':val).trim();
    if(!v) return;
    var ch={kind:kind,val:v};
    var k=logChipKey(ch);
    for(var i=0;i<logState.chips.length;i++){
      if(logChipKey(logState.chips[i])===k) return;
    }
    logState.chips.push(ch);
    logRenderChips();
    renderLeaseLogFiltered();
  }
  function renderLeaseLogFiltered(){
    var logb=document.getElementById('lease-log-body');
    var cnt=document.getElementById('log-count');
    if(!logb) return;
    var rows=leasePreviewData||[];
    var out=[];
    for(var i=0;i<rows.length;i++){
      if(logRowMatches(rows[i])) out.push(rows[i]);
    }
    sortRows(out, logState, {ip:'ip', mac:'text', hostname:'text', allocated_ts:'num', expiry_ts:'num', first_seen_ts:'num'});
    if(cnt) cnt.textContent='Showing '+out.length+' of '+rows.length+' loaded';
    logb.innerHTML='';
    for(var j=0;j<out.length;j++){
      var r=out[j];
      var tr=document.createElement('tr');
      tr.innerHTML=
        '<td class="mono res-cell-filter" data-log-kind="ip" data-log-val="'+escAttr(r.ip)+'">'+esc(r.ip)+'</td>'+
        '<td class="mono res-cell-filter" data-log-kind="mac" data-log-val="'+escAttr(r.mac)+'">'+esc(r.mac)+'</td>'+
        '<td class="res-cell-filter" data-log-kind="host" data-log-val="'+escAttr(r.hostname)+'">'+esc(r.hostname)+'</td>'+
        '<td class="mono res-cell-filter" data-log-kind="any" data-log-val="'+escAttr(r.allocated_at)+'">'+esc(r.allocated_at)+'</td>'+
        '<td class="mono res-cell-filter" data-log-kind="any" data-log-val="'+escAttr(r.expiry)+'">'+esc(r.expiry)+'</td>'+
        '<td class="mono res-cell-filter" data-log-kind="any" data-log-val="'+escAttr(r.first_seen)+'">'+esc(r.first_seen)+'</td>';
      logb.appendChild(tr);
    }
    if(!out.length){
      var empty=document.createElement('tr');
      empty.innerHTML='<td colspan="6" style="color:var(--muted)">No rows match filters.</td>';
      logb.appendChild(empty);
    }
    syncSortIndicators('log', logState);
  }
  function devicesRowMatches(r){
    if(!logSubMatch(r.kind, gid('devices-in-kind'))) return false;
    if(!logSubMatch(r.mac, gid('devices-in-mac'))) return false;
    if(!logSubMatch(r.ip, gid('devices-in-ip')) && !logSubMatch(r.note, gid('devices-in-ip'))) return false;
    var blob=(r.kind||'')+' '+(r.mac||'')+' '+(r.ip||'')+' '+(r.note||'')+' '+(r.equipment_type||'')+' '+(r.manufacturer||'')+' '+(r.management_type||'')+' '+(r.management_interface||'')+' '+(r.first_seen||'');
    if(!logSubMatch(blob, gid('devices-in-any'))) return false;
    return true;
  }
  function renderDevicesTable(){
    var body=document.getElementById('devices-body');
    var cnt=document.getElementById('devices-count');
    if(!body) return;
    var rows=configMACData||[];
    var out=[];
    for(var i=0;i<rows.length;i++){
      if(devicesRowMatches(rows[i])) out.push(rows[i]);
    }
    sortRows(out, devicesState, {kind:'text', mac:'text', ip:'ip', note:'text', equipment_type:'text', manufacturer:'text', management_type:'text', first_seen_ts:'num'});
    if(cnt) cnt.textContent='Showing '+out.length+' of '+rows.length+' configured MAC entries';
    var h='';
    for(var j=0;j<out.length;j++){
      var r=out[j];
      h+='<tr>'+
        '<td><span class="badge">'+esc(r.kind||'—')+'</span></td>'+
        '<td class="mono">'+esc(r.mac||'')+'</td>'+
        '<td class="mono">'+esc(r.ip||'—')+'</td>'+
        '<td>'+esc(r.note||'')+'</td>'+
        '<td>'+esc(r.equipment_type||'')+'</td>'+
        '<td>'+esc(r.manufacturer||'')+'</td>'+
        '<td>'+esc(r.management_type||'')+(r.management_interface?'<div class="muted mono">'+esc(r.management_interface)+'</div>':'')+'</td>'+
        '<td class="mono">'+esc(r.first_seen||'')+'</td>'+
        '</tr>';
    }
    if(!h) h='<tr><td colspan="8" style="color:var(--muted)">No configured MAC entries match the filters.</td></tr>';
    body.innerHTML=h;
    syncSortIndicators('devices', devicesState);
  }
  function leasesRowMatches(r){
    if(!logSubMatch(r.ip, gid('leases-in-ip'))) return false;
    if(!logSubMatch(r.mac, gid('leases-in-mac'))) return false;
    if(!logSubMatch(r.hostname, gid('leases-in-host'))) return false;
    var blob=(r.ip||'')+' '+(r.mac||'')+' '+(r.hostname||'')+' '+(r.allocated_at||'')+' '+(r.expiry||'')+' '+(r.first_seen||'');
    if(!logSubMatch(blob, gid('leases-in-any'))) return false;
    return true;
  }
  function renderAllLeasesTable(){
    var body=document.getElementById('leases-body');
    var cnt=document.getElementById('leases-count');
    if(!body) return;
    var rows=leasesAllData||[];
    var out=[];
    for(var i=0;i<rows.length;i++){
      if(leasesRowMatches(rows[i])) out.push(rows[i]);
    }
    sortRows(out, leasesState, {ip:'ip', mac:'text', hostname:'text', allocated_ts:'num', expiry_ts:'num', first_seen_ts:'num'});
    if(cnt) cnt.textContent='Showing '+out.length+' of '+rows.length+' active lease records';
    var h='';
    for(var j=0;j<out.length;j++){
      var r=out[j];
      h+='<tr>'+
        '<td class="mono">'+esc(r.ip||'')+'</td>'+
        '<td class="mono">'+esc(r.mac||'')+'</td>'+
        '<td>'+esc(r.hostname||'')+'</td>'+
        '<td class="mono">'+esc(r.allocated_at||'')+'</td>'+
        '<td class="mono">'+esc(r.expiry||'')+'</td>'+
        '<td class="mono">'+esc(r.first_seen||'')+'</td>'+
        '</tr>';
    }
    if(!h) h='<tr><td colspan="6" style="color:var(--muted)">No leases match the filters.</td></tr>';
    body.innerHTML=h;
    syncSortIndicators('leases', leasesState);
  }
  ['log-in-ip','log-in-mac','log-in-host','log-in-any'].forEach(function(id){
    var el=document.getElementById(id);
    if(el) el.addEventListener('input', function(){ renderLeaseLogFiltered(); });
  });
  ['devices-in-kind','devices-in-mac','devices-in-ip','devices-in-any'].forEach(function(id){
    var el=document.getElementById(id);
    if(el) el.addEventListener('input', function(){ renderDevicesTable(); });
  });
  ['leases-in-ip','leases-in-mac','leases-in-host','leases-in-any'].forEach(function(id){
    var el=document.getElementById(id);
    if(el) el.addEventListener('input', function(){ renderAllLeasesTable(); });
  });
  document.querySelectorAll('th[data-table-sort]').forEach(function(th){
    th.addEventListener('click', function(){
      var tableName=th.getAttribute('data-table-sort');
      var key=th.getAttribute('data-sort-key');
      if(!tableName||!key) return;
      if(tableName==='log'){ toggleSort(logState, key); renderLeaseLogFiltered(); return; }
      if(tableName==='devices'){ toggleSort(devicesState, key); renderDevicesTable(); return; }
      if(tableName==='leases'){ toggleSort(leasesState, key); renderAllLeasesTable(); return; }
      if(tableName==='subnet'){ toggleSort(subnetState, key); renderSubnetTable(); return; }
      if(tableName==='arp'){ toggleSort(arpState, key); renderArpTable(); return; }
      if(tableName==='alerts'){ toggleSort(alertsState, key); renderAlertsTable(); return; }
    });
  });
  function renderSubnetGrid(counts){
    var legend=document.getElementById('subnet-legend');
    var grid=document.getElementById('subnet-grid');
    if(legend){
      var order=['leased','reserved','free','unused','banned-mac','banned-ip'];
      var h='';
      for(var i=0;i<order.length;i++){
        var t=order[i];
        var n=(counts&&counts[t])||0;
        h+='<span class="legend-item"><span class="legend-swatch subnet-cell type-'+escAttr(t)+'"></span>'+esc(t)+' ('+n+')</span>';
      }
      legend.innerHTML=h;
    }
    if(!grid) return;
    var cells=subnetGrid||[];
    var gh='';
    for(var j=0;j<cells.length;j++){
      var c=cells[j];
      gh+='<div class="subnet-cell type-'+escAttr(c.type||'unused')+'" title="'+escAttr((c.ip||'')+' · '+(c.type||''))+'"></div>';
    }
    grid.innerHTML=gh||'<div class="muted">No subnet grid data.</div>';
  }
  function subnetRowMatches(r){
    if(!logSubMatch(r.type, gid('subnet-in-type'))) return false;
    if(!logSubMatch(r.ip, gid('subnet-in-ip'))) return false;
    if(!logSubMatch(r.mac, gid('subnet-in-mac')) && !logSubMatch(r.hostname, gid('subnet-in-mac'))) return false;
    var blob=(r.ip||'')+' '+(r.type||'')+' '+(r.mac||'')+' '+(r.hostname||'')+' '+(r.allocated_at||'')+' '+(r.expiry||'');
    if(!logSubMatch(blob, gid('subnet-in-any'))) return false;
    return true;
  }
  function renderSubnetTable(){
    var body=document.getElementById('subnet-body');
    var cnt=document.getElementById('subnet-count');
    if(!body) return;
    var rows=subnetData||[];
    var out=[];
    for(var i=0;i<rows.length;i++){ if(subnetRowMatches(rows[i])) out.push(rows[i]); }
    sortRows(out, subnetState, {ip:'ip', type:'text', mac:'text', hostname:'text', allocated_ts:'num', expiry_ts:'num'});
    if(cnt) cnt.textContent='Showing '+out.length+' of '+rows.length+' addresses';
    var h='';
    for(var j=0;j<out.length;j++){
      var r=out[j];
      h+='<tr><td class="mono">'+esc(r.ip)+'</td><td><span class="badge">'+esc(r.type)+'</span></td><td class="mono">'+esc(r.mac||'')+'</td><td>'+esc(r.hostname||'')+'</td><td class="mono">'+esc(r.allocated_at||'')+'</td><td class="mono">'+esc(r.expiry||'')+'</td></tr>';
    }
    if(!h) h='<tr><td colspan="6" style="color:var(--muted)">No addresses match filters.</td></tr>';
    body.innerHTML=h;
    syncSortIndicators('subnet', subnetState);
  }
  function renderAlertsTable(){
    var body=document.getElementById('alerts-body');
    var cnt=document.getElementById('alerts-count');
    if(!body) return;
    var rows=findingsData||[];
    var q=gid('alerts-in-any');
    var out=[];
    for(var i=0;i<rows.length;i++){
      var r=rows[i];
      var blob=(r.at||'')+' '+(r.kind||'')+' '+(r.ip||'')+' '+(r.mac||'')+' '+(r.reason||'')+' '+(r.server_ip||'')+' '+(r.message||'');
      if(logSubMatch(blob, q)) out.push(r);
    }
    sortRows(out, alertsState, {at_unix:'num', kind:'text', ip:'ip', mac:'text', reason:'text', message:'text'});
    if(cnt) cnt.textContent='Showing '+out.length+' of '+rows.length+' alerts';
    var h='';
    for(var j=0;j<out.length;j++){
      var a=out[j];
      h+='<tr><td class="mono">'+esc(a.at||'')+'</td><td><span class="badge">'+esc(a.kind||'')+'</span></td><td class="mono">'+esc(a.ip||a.server_ip||'')+'</td><td class="mono">'+esc(a.mac||'')+'</td><td>'+esc(a.reason||'')+'</td><td class="mono">'+esc(a.message||'')+'</td></tr>';
    }
    if(!h) h='<tr><td colspan="6" style="color:var(--muted)">No alerts yet. Background ARP/DHCP detection will populate this list.</td></tr>';
    body.innerHTML=h;
    syncSortIndicators('alerts', alertsState);
  }
  function renderConsole(){
    var box=document.getElementById('console-box');
    if(!box) return;
    var lines=consoleLines||[];
    if(!lines.length){ box.textContent='No console lines captured yet.'; return; }
    var t='';
    for(var i=0;i<lines.length;i++){
      t+=(lines[i].at||'')+' '+(lines[i].text||'')+'\n';
    }
    box.textContent=t;
    box.scrollTop=box.scrollHeight;
  }
  function renderArpTable(){
    var body=document.getElementById('arp-body');
    var cnt=document.getElementById('arp-count');
    if(!body) return;
    var rows=arpData||[];
    var q=gid('arp-in-any');
    var out=[];
    for(var i=0;i<rows.length;i++){
      var r=rows[i];
      var blob=(r.ip||'')+' '+(r.mac||'')+' '+(r.iface||'')+' '+(r.state||'')+' '+(r.note||'')+' '+(r.source||'');
      if(logSubMatch(blob, q)) out.push(r);
    }
    sortRows(out, arpState, {ip:'ip', mac:'text', iface:'text', state:'text', note:'text', source:'text'});
    if(cnt) cnt.textContent='Showing '+out.length+' of '+rows.length+' ARP entries';
    var h='';
    for(var j=0;j<out.length;j++){
      var e=out[j];
      h+='<tr><td class="mono">'+esc(e.ip)+'</td><td class="mono">'+esc(e.mac)+'</td><td class="mono">'+esc(e.iface||'')+'</td><td>'+esc(e.state||'')+'</td><td>'+esc(e.note||'')+'</td><td>'+esc(e.source||'')+'</td></tr>';
    }
    if(!h) h='<tr><td colspan="6" style="color:var(--muted)">No ARP data yet. Run a scan.</td></tr>';
    body.innerHTML=h;
    syncSortIndicators('arp', arpState);
  }
  function runSearch(){
    var ip=(document.getElementById('search-ip')||{}).value||'';
    ip=String(ip).trim();
    var out=document.getElementById('search-out');
    if(!out) return;
    if(!ip){ out.innerHTML='<div class="muted">Enter an IPv4 address.</div>'; return; }
    out.innerHTML='<div class="muted">Searching…</div>';
    fetch('/dhcp/search/'+encodeURIComponent(ip),{headers:authHeaders()}).then(function(r){
      if(r.status===401){ setErr('Unauthorized — set API token in the sidebar.'); return null; }
      if(!r.ok) return r.json().then(function(j){ throw new Error((j&&j.error)||('HTTP '+r.status)); });
      return r.json();
    }).then(function(d){
      if(!d) return;
      if(!d.found){ out.innerHTML='<div class="search-result"><h3>Not found</h3><p class="muted">No reservation or lease for '+esc(d.ip)+'.</p></div>'; return; }
      var h='<div class="search-result"><h3>Results for '+esc(d.ip)+'</h3>';
      if(d.mac_mismatch) h+='<p style="color:var(--warning)">MAC mismatch between reservation and lease.</p>';
      if(d.reservation){
        var rv=d.reservation;
        h+='<h3>Reservation</h3><div class="kv">'+
          '<div class="k">MAC</div><div class="v">'+esc(rv.mac)+'</div>'+
          '<div class="k">Note</div><div class="v">'+esc(rv.note||'')+'</div>'+
          '<div class="k">Equipment</div><div class="v">'+esc(rv.equipment_type||'')+'</div>'+
          '<div class="k">Manufacturer</div><div class="v">'+esc(rv.manufacturer||'')+'</div>'+
          '<div class="k">First seen</div><div class="v">'+esc(rv.first_seen||'')+'</div></div>';
      }
      if(d.lease){
        var lv=d.lease;
        h+='<h3 style="margin-top:1rem">Lease</h3><div class="kv">'+
          '<div class="k">MAC</div><div class="v">'+esc(lv.mac)+'</div>'+
          '<div class="k">Hostname</div><div class="v">'+esc(lv.hostname||'')+'</div>'+
          '<div class="k">Allocated</div><div class="v">'+esc(lv.allocated_at||'')+'</div>'+
          '<div class="k">Expiry</div><div class="v">'+esc(lv.expiry||'')+(lv.expired?' (expired)':'')+'</div>'+
          '<div class="k">First seen</div><div class="v">'+esc(lv.first_seen||'')+'</div></div>';
      }
      h+='</div>';
      out.innerHTML=h;
    }).catch(function(e){ out.innerHTML='<div class="err">'+esc(String(e))+'</div>'; });
  }
  function runArpScan(allIfaces){
    var btn=document.getElementById('arp-scan-btn');
    var btn2=document.getElementById('arp-scan-all-btn');
    if(btn) btn.disabled=true;
    if(btn2) btn2.disabled=true;
    var u='/dhcp/arp/scan'+(allIfaces?'?all_ifaces=1':'');
    fetch(u,{method:'POST',headers:authHeaders()}).then(function(r){
      if(r.status===401){ setErr('Unauthorized — set API token in the sidebar.'); return null; }
      return r.json().then(function(j){ if(!r.ok) throw new Error((j&&j.error)||('HTTP '+r.status)); return j; });
    }).then(function(d){
      if(!d) return;
      arpData=Array.isArray(d.entries)?d.entries.slice():[];
      renderArpTable();
      setErr('');
    }).catch(function(e){ setErr(String(e)); }).finally(function(){
      if(btn) btn.disabled=false;
      if(btn2) btn2.disabled=false;
    });
  }
  function adminSetStatus(msg){
    var el=document.getElementById('admin-status');
    if(el) el.textContent=msg||'—';
  }
  function runCheck(){
    adminSetStatus('Validating…');
    fetch('/admin/check',{headers:authHeaders()}).then(function(r){
      return r.json().then(function(j){ return {ok:r.ok, j:j, status:r.status}; });
    }).then(function(x){
      if(x.status===401){ setErr('Unauthorized — set API token in the sidebar.'); adminSetStatus('Unauthorized'); return; }
      var j=x.j||{};
      if(j.ok) adminSetStatus('OK: config valid · subnet '+ (j.subnet_cidr||'')+' · reservations '+ (j.reservations_n|0));
      else adminSetStatus('INVALID ('+(j.stage||'?')+'): '+(j.error||'unknown error'));
    }).catch(function(e){ adminSetStatus(String(e)); });
  }
  function runReload(){
    if(!confirm('Reload dhcplane config now?')) return;
    adminSetStatus('Signaling reload…');
    fetch('/admin/reload',{method:'POST',headers:authHeaders()}).then(function(r){
      return r.json().then(function(j){ return {status:r.status, j:j}; });
    }).then(function(x){
      if(x.status===401){ setErr('Unauthorized — set API token in the sidebar.'); adminSetStatus('Unauthorized'); return; }
      if(x.status===501){ adminSetStatus('Reload not available in this process'); return; }
      if(x.j && x.j.ok) adminSetStatus('Reload signaled — watch console/logs for apply result');
      else adminSetStatus((x.j&&x.j.error)||('HTTP '+x.status));
      setTimeout(load, 800);
    }).catch(function(e){ adminSetStatus(String(e)); });
  }
  function runResAdd(){
    var mac=gid('admin-res-mac'), ip=gid('admin-res-ip'), note=gid('admin-res-note');
    adminSetStatus('Saving reservation…');
    fetch('/dhcp/reservations',{method:'POST',headers:Object.assign({'Content-Type':'application/json'}, authHeaders()), body:JSON.stringify({mac:mac,ip:ip,note:note})}).then(function(r){
      return r.json().then(function(j){ return {status:r.status, j:j}; });
    }).then(function(x){
      if(x.status===401){ setErr('Unauthorized — set API token in the sidebar.'); adminSetStatus('Unauthorized'); return; }
      if(x.j && x.j.ok){
        var w=(x.j.warnings&&x.j.warnings.length)?' · warnings: '+x.j.warnings.join('; '):'';
        adminSetStatus((x.j.created?'Added':'Updated')+' '+x.j.mac+' → '+x.j.ip+w);
        load();
      } else adminSetStatus((x.j&&x.j.error)||('HTTP '+x.status));
    }).catch(function(e){ adminSetStatus(String(e)); });
  }
  function runResDel(){
    var mac=gid('admin-res-del-mac');
    if(!mac){ adminSetStatus('Enter a MAC to remove'); return; }
    if(!confirm('Remove reservation for '+mac+'?')) return;
    adminSetStatus('Removing…');
    fetch('/dhcp/reservations/'+encodeURIComponent(mac),{method:'DELETE',headers:authHeaders()}).then(function(r){
      return r.json().then(function(j){ return {status:r.status, j:j}; });
    }).then(function(x){
      if(x.status===401){ setErr('Unauthorized — set API token in the sidebar.'); adminSetStatus('Unauthorized'); return; }
      if(x.j && x.j.ok){ adminSetStatus(x.j.removed?('Removed '+x.j.mac):('No reservation for '+x.j.mac)); load(); }
      else adminSetStatus((x.j&&x.j.error)||('HTTP '+x.status));
    }).catch(function(e){ adminSetStatus(String(e)); });
  }
  ['subnet-in-type','subnet-in-ip','subnet-in-mac','subnet-in-any'].forEach(function(id){
    var el=document.getElementById(id); if(el) el.addEventListener('input', function(){ renderSubnetTable(); });
  });
  var alertsIn=document.getElementById('alerts-in-any'); if(alertsIn) alertsIn.addEventListener('input', function(){ renderAlertsTable(); });
  var arpIn=document.getElementById('arp-in-any'); if(arpIn) arpIn.addEventListener('input', function(){ renderArpTable(); });
  var searchBtn=document.getElementById('search-run'); if(searchBtn) searchBtn.onclick=runSearch;
  var searchIp=document.getElementById('search-ip'); if(searchIp) searchIp.addEventListener('keydown', function(e){ if(e.key==='Enter') runSearch(); });
  var arpBtn=document.getElementById('arp-scan-btn'); if(arpBtn) arpBtn.onclick=function(){ runArpScan(false); };
  var arpAllBtn=document.getElementById('arp-scan-all-btn'); if(arpAllBtn) arpAllBtn.onclick=function(){ runArpScan(true); };
  var checkBtn=document.getElementById('admin-check-btn'); if(checkBtn) checkBtn.onclick=runCheck;
  var reloadBtn=document.getElementById('admin-reload-btn'); if(reloadBtn) reloadBtn.onclick=runReload;
  var resAddBtn=document.getElementById('admin-res-add'); if(resAddBtn) resAddBtn.onclick=runResAdd;
  var resDelBtn=document.getElementById('admin-res-del'); if(resDelBtn) resDelBtn.onclick=runResDel;
  var logChipsHost=document.getElementById('log-chips');
  if(logChipsHost) logChipsHost.addEventListener('click', function(e){
    var btn=e.target.closest('button[data-log-chip-idx]');
    if(!btn) return;
    var idx=parseInt(btn.getAttribute('data-log-chip-idx'),10);
    if(isNaN(idx)) return;
    logState.chips.splice(idx,1);
    logRenderChips();
    renderLeaseLogFiltered();
  });
  var logBody=document.getElementById('lease-log-body');
  if(logBody) logBody.addEventListener('click', function(e){
    var td=e.target.closest('td.res-cell-filter');
    if(!td) return;
    var kind=td.getAttribute('data-log-kind');
    var val=td.getAttribute('data-log-val');
    if(!kind) return;
    logAddChip(kind, val);
  });
  function applyStatus(st){
    var sk=JSON.stringify({
      ready:!!st.ready, dhcp:!!st.dhcp_up, api:!!st.api_up,
      ls:st.listeners||{}, feats:st.features||[]
    });
    if(sk===lastStatusKey) return;
    lastStatusKey=sk;
    function pill(el, ok, okText, badText){
      el.textContent=ok?okText:badText;
      el.className='status-pill '+(ok?'ok':'fail');
    }
    pill(document.getElementById('st-ready'), st.ready, 'Yes', 'No');
    pill(document.getElementById('st-api'), st.api_up, 'Up', 'Down');
    pill(document.getElementById('st-dhcp'), st.dhcp_up, 'Up', 'Down');
    document.getElementById('st-console').className='status-pill neutral';
    document.getElementById('st-console').textContent='—';
    var ls=st.listeners||{};
    function setMono(id, v){
      var el=document.getElementById(id);
      var s=v!=null&&v!==''?String(v):'—';
      el.textContent=s;
      el.className='status-pill neutral mono';
    }
    setMono('st-dhcp-port', ls.dhcp_port);
    setMono('st-api-port', ls.api_address!=null&&ls.api_address!==''?ls.api_address:(ls.api_port||'—'));
    var en=document.getElementById('st-api-en');
    if(ls.api_enabled){
      en.textContent='Yes';
      en.className='status-pill ok';
    } else {
      en.textContent='No';
      en.className='status-pill neutral';
    }
    setMono('st-sock', ls.client_socket);
    setMono('st-tcp', ls.client_tcp);
    function featPillClass(v){
      if(v==='ok') return 'status-pill ok';
      if(v==='bad') return 'status-pill fail';
      if(v==='warn') return 'status-pill warn';
      return 'status-pill neutral';
    }
    var fj=JSON.stringify(st.features||[]);
    if(fj!==lastFeaturesJSON){
      lastFeaturesJSON=fj;
      var fg=document.getElementById('status-features-grid');
      var feats=st.features||[];
      var fh='';
      for(var fi=0;fi<feats.length;fi++){
        var f=feats[fi];
        var lab=f.label!=null?String(f.label):'';
        var val=f.value!=null?String(f.value):'—';
        var vc=featPillClass(f.variant);
        fh+='<div class="card status-cell"><h3>'+esc(lab)+'</h3><div class="'+vc+'">'+esc(val)+'</div></div>';
      }
      fg.innerHTML=fh;
    }
  }
  function metricsKey(c){
    c=c||{};
    return [c.allocations_last_1m|0,c.allocations_last_1h|0,c.allocations_last_24h|0,c.allocations_last_7d|0,c.allocations_last_30d|0,
      c.leases_current|0,c.leases_expiring|0,c.leases_expired|0].join('|');
  }
  function setText(id, v){
    var el=document.getElementById(id);
    if(el) el.textContent=v==null?'':String(v);
  }
  function renderMetrics(d){
    var c=d.counters||{}, mk=metricsKey(c);
    if(mk===lastMetricsKey) return;
    lastMetricsKey=mk;
    setText('m-al-1m', c.allocations_last_1m|0);
    setText('m-al-1h', c.allocations_last_1h|0);
    setText('m-al-24h', c.allocations_last_24h|0);
    setText('m-al-7d', c.allocations_last_7d|0);
    setText('m-al-30d', c.allocations_last_30d|0);
    setText('m-lc', c.leases_current|0);
    setText('m-le', c.leases_expiring|0);
    setText('m-lx', c.leases_expired|0);
  }
  function renderServerMeta(d){
    var dh=d.dhcp||{}, b=d.build||{};
    setText('m-iface', dh.interface===''?'(any)':String(dh.interface||'—'));
    setText('m-subnet', String(dh.subnet_cidr||'—'));
    setText('m-srvip', String(dh.server_ip||'—'));
    var ver=(b.version||'')+'';
    if(b.go_version) ver+=' · '+b.go_version;
    setText('m-ver', ver||'—');
    var tb=document.getElementById('subnet-kv-body');
    if(!tb) return;
    var rows=[
      ['Gateway', dh.gateway||'—'],
      ['Reservations', String(dh.reservations_n|0)],
      ['Banned MACs', String(dh.banned_macs_n|0)],
      ['Lease DB', dh.lease_db_path||'—'],
      ['Lease TTL (s)', String(dh.lease_seconds|0)],
      ['Authoritative', dh.authoritative?'yes':'no']
    ];
    var h='';
    for(var i=0;i<rows.length;i++){
      h+='<tr><td class="mono" style="color:var(--muted)">'+esc(rows[i][0])+'</td><td class="mono">'+esc(rows[i][1])+'</td></tr>';
    }
    tb.innerHTML=h;
  }
  function renderLeases(d){
    var rows=d.leases_preview||[];
    configMACData=Array.isArray(d.config_macs)?d.config_macs.slice():[];
    leasesAllData=Array.isArray(d.leases_all)?d.leases_all.slice():[];
    subnetData=Array.isArray(d.subnet_details)?d.subnet_details.slice():[];
    subnetGrid=Array.isArray(d.subnet_grid)?d.subnet_grid.slice():[];
    findingsData=Array.isArray(d.findings)?d.findings.slice():[];
    consoleLines=Array.isArray(d.console_lines)?d.console_lines.slice():[];
    var js=JSON.stringify(rows);
    if(js!==lastPreviewJSON){
      lastPreviewJSON=js;
      leasePreviewData=rows.slice();
      var topb=document.getElementById('lease-top-body');
      if(topb){
        topb.innerHTML='';
        var n=Math.min(10, rows.length);
        for(var i=0;i<n;i++){
          var r=rows[i];
          var tr=document.createElement('tr');
          tr.innerHTML='<td class="mono">'+esc(r.ip)+'</td><td class="mono">'+esc(r.mac)+'</td><td>'+esc(r.hostname)+'</td>';
          topb.appendChild(tr);
        }
      }
      var feed=document.getElementById('lease-feed');
      if(feed){
        var fh='';
        for(var j=0;j<rows.length;j++){
          var e=rows[j];
          fh+='<div class="log-item"><div class="top"><span class="dot ok"></span><div style="flex:1;min-width:0">';
          fh+='<div><strong class="mono">'+esc(e.ip)+'</strong> <span style="color:var(--muted)">'+esc(e.hostname||'')+'</span></div>';
          fh+='<div style="color:var(--muted);font-size:0.78rem;margin-top:0.2rem" class="mono">'+esc(e.mac)+' · until '+esc(e.expiry||'')+'</div>';
          fh+='</div></div></div>';
        }
        if(!fh) fh='<div class="log-item" style="color:var(--muted)">No preview rows.</div>';
        feed.innerHTML=fh;
      }
    }
    renderLeaseLogFiltered();
    renderDevicesTable();
    renderAllLeasesTable();
    renderSubnetGrid(d.subnet_counts||{});
    renderSubnetTable();
    renderAlertsTable();
    renderConsole();
  }
  function render(d){
    setErr('');
    if(d.status) applyStatus(d.status);
    var b=d.build||{}, bk=(b.version||'')+' '+String(b.go_version||'')+' '+String(b.os||'')+'/'+String(b.arch||'');
    if(bk!==lastBuildKey){ lastBuildKey=bk; }
    renderMetrics(d);
    renderServerMeta(d);
    pushTrendSamplesFromDashboard(d);
    updateAllocHourChart(d);
    renderLeases(d);
  }
  function load(){
    fetch('/stats/dashboard/data',{headers:authHeaders()}).then(function(r){
      if(r.status===401){ setErr('Unauthorized — set API token in the sidebar.'); return null; }
      if(!r.ok){ setErr('HTTP '+r.status); return null; }
      return r.json();
    }).then(function(d){ if(d){ setWsStatus('Updates: HTTP'); render(d); } }).catch(function(e){ setErr(String(e)); });
  }
  function wsUrl(){
    var u=new URL('/stats/dashboard/ws', location.href);
    u.protocol=u.protocol==='https:'?'wss:':'ws:';
    var t=tok();
    if(t) u.searchParams.set('access_token', t);
    return u.toString();
  }
  function startWs(){
    if(!window.WebSocket) return;
    try{ if(ws) ws.close(); }catch(e){}
    ws=new WebSocket(wsUrl());
    ws.onopen=function(){
      setWsStatus('Updates: live (WebSocket)');
      try{ ws.send(JSON.stringify({op:'sub',stats:true})); }catch(e){}
    };
    ws.onmessage=function(ev){
      try{
        var o=JSON.parse(ev.data);
        if(o.dashboard){ setWsStatus('Updates: live (WebSocket)'); render(o.dashboard); }
      }catch(e){}
    };
    ws.onclose=function(){ ws=null; setWsStatus('Updates: HTTP (WS closed)'); };
    ws.onerror=function(){ try{ ws.close(); }catch(e2){} };
  }
  initTrendCharts();
  load();
  startWs();
  setInterval(load, 30000);
})();
</script>
</body>
</html>
`

// buildDHCPDashboardHTML returns the full dashboard document served at GET /stats/dashboard.
func buildDHCPDashboardHTML(showTokenPanel bool) string {
	tokenPanel := ""
	if showTokenPanel {
		tokenPanel = dhcpDashboardTokenPanel
	}
	return dhcpDashboardHTMLPart1 + tokenPanel + dhcpDashboardHTMLPart2 + dhcpDashboardHTMLPart3
}
