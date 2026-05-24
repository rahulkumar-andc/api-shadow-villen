"""Web dashboard for visualizing Shadow API Mapper results."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

report_data: Dict[str, Any] = {}

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Shadow API Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { background-color: #0d1117; color: #c9d1d9; font-family: -apple-system, sans-serif; }
        .card { background-color: #161b22; border: 1px solid #30363d; border-radius: 8px; }
        .table-row:hover { background-color: #21262d; }
        .badge { display:inline-block; padding:2px 10px; border-radius:999px; font-size:0.75rem; font-weight:600; }
        .badge-shadow   { background:#7c3aed; color:#fff; }
        .badge-zombie   { background:#d97706; color:#fff; }
        .badge-verified { background:#059669; color:#fff; }
        .badge-protected{ background:#2563eb; color:#fff; }
        .badge-dead     { background:#4b5563; color:#fff; }
        .badge-discovered{background:#0891b2; color:#fff; }
        .method-GET    { color:#34d399; font-weight:700; }
        .method-POST   { color:#60a5fa; font-weight:700; }
        .method-PUT    { color:#fbbf24; font-weight:700; }
        .method-DELETE { color:#f87171; font-weight:700; }
        .method-PATCH  { color:#a78bfa; font-weight:700; }
        #search { background:#21262d; border:1px solid #30363d; color:#c9d1d9;
                  padding:8px 14px; border-radius:6px; width:300px; }
        .filter-btn { padding:6px 14px; border-radius:6px; font-size:0.8rem;
                      cursor:pointer; border:1px solid #30363d;
                      background:#161b22; color:#c9d1d9; transition:all 0.2s; }
        .filter-btn:hover { background:#21262d; }
        .filter-btn.active { background:#7c3aed; border-color:#7c3aed; color:#fff; }
        .risk-CRITICAL { color:#f87171; font-weight:700; }
        .risk-HIGH     { color:#fb923c; font-weight:700; }
        .risk-MEDIUM   { color:#fbbf24; }
        .risk-LOW      { color:#34d399; }
        .risk-INFO     { color:#94a3b8; }
        .tab { padding:8px 20px; cursor:pointer; border-bottom:2px solid transparent;
               color:#94a3b8; font-size:0.9rem; }
        .tab.active { border-bottom-color:#7c3aed; color:#c9d1d9; }
        .section { display:none; }
        .section.active { display:block; }
        th { cursor:pointer; user-select:none; }
        th:hover { color:#a78bfa; }
    </style>
</head>
<body class="min-h-screen p-6">
<div style="max-width:1400px;margin:0 auto;">

    <!-- Header -->
    <div class="card p-6 mb-6 flex justify-between items-start">
        <div>
            <h1 style="font-size:1.8rem;font-weight:700;color:#fff;">
                🕵️ Shadow API Dashboard
            </h1>
            <p style="color:#8b949e;margin-top:4px;">
                Scan ID: <span style="color:#60a5fa;font-family:monospace;">{{SCAN_ID}}</span>
                &nbsp;|&nbsp; Target: <span style="color:#34d399;">{{TARGET}}</span>
                &nbsp;|&nbsp; Duration: <span style="color:#fbbf24;">{{DURATION}}s</span>
            </p>
        </div>
        <div style="text-align:right;">
            <p style="color:#8b949e;font-size:0.8rem;">Generated</p>
            <p style="color:#c9d1d9;font-size:0.85rem;">{{GENERATED_AT}}</p>
        </div>
    </div>

    <!-- Stats -->
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:24px;">
        <div class="card p-4 text-center">
            <div style="font-size:2.2rem;font-weight:700;color:#60a5fa;">{{TOTAL_ENDPOINTS}}</div>
            <div style="color:#8b949e;font-size:0.85rem;">Total Endpoints</div>
        </div>
        <div class="card p-4 text-center">
            <div style="font-size:2.2rem;font-weight:700;color:#7c3aed;">{{SHADOW_COUNT}}</div>
            <div style="color:#8b949e;font-size:0.85rem;">Shadow APIs</div>
        </div>
        <div class="card p-4 text-center">
            <div style="font-size:2.2rem;font-weight:700;color:#d97706;">{{ZOMBIE_COUNT}}</div>
            <div style="color:#8b949e;font-size:0.85rem;">Zombie APIs</div>
        </div>
        <div class="card p-4 text-center">
            <div style="font-size:2.2rem;font-weight:700;color:#f87171;">{{SECRETS_COUNT}}</div>
            <div style="color:#8b949e;font-size:0.85rem;">Secrets Found</div>
        </div>
        <div class="card p-4 text-center">
            <div style="font-size:2.2rem;font-weight:700;color:#34d399;">{{FILES_SCANNED}}</div>
            <div style="color:#8b949e;font-size:0.85rem;">Files Scanned</div>
        </div>
        <div class="card p-4 text-center">
            <div style="font-size:2.2rem;font-weight:700;color:#059669;">{{VERIFIED_COUNT}}</div>
            <div style="color:#8b949e;font-size:0.85rem;">Verified Active</div>
        </div>
    </div>

    <!-- Tabs -->
    <div style="display:flex;border-bottom:1px solid #30363d;margin-bottom:20px;">
        <div class="tab active" onclick="switchTab('endpoints', this)">📡 Endpoints</div>
        <div class="tab" onclick="switchTab('secrets', this)">🔐 Secrets</div>
        <div class="tab" onclick="switchTab('errors', this)">⚠️ Errors</div>
    </div>

    <!-- Endpoints Tab -->
    <div id="tab-endpoints" class="section active">

        <!-- Controls -->
        <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px;align-items:center;">
            <input type="text" id="search" placeholder="🔍 Search URL..."
                   oninput="applyFilters()">
            <button class="filter-btn active" onclick="setFilter('all', this)">All ({{TOTAL_ENDPOINTS}})</button>
            <button class="filter-btn" onclick="setFilter('shadow', this)">⚠ Shadow ({{SHADOW_COUNT}})</button>
            <button class="filter-btn" onclick="setFilter('zombie', this)">☠ Zombie ({{ZOMBIE_COUNT}})</button>
            <button class="filter-btn" onclick="setFilter('verified', this)">✓ Verified</button>
            <button class="filter-btn" onclick="setFilter('protected', this)">🔒 Protected</button>
            <button class="filter-btn" onclick="setFilter('dead', this)">💀 Dead</button>
            <button class="filter-btn" style="margin-left:auto;" onclick="exportCSV()">
                ⬇ Export CSV
            </button>
        </div>

        <!-- Table -->
        <div class="card" style="overflow:auto;">
            <table style="width:100%;border-collapse:collapse;">
                <thead>
                    <tr style="background:#21262d;">
                        <th style="padding:12px 16px;text-align:left;color:#8b949e;font-size:0.8rem;"
                            onclick="sortTable('method')">METHOD ↕</th>
                        <th style="padding:12px 16px;text-align:left;color:#8b949e;font-size:0.8rem;"
                            onclick="sortTable('url')">URL ↕</th>
                        <th style="padding:12px 16px;text-align:left;color:#8b949e;font-size:0.8rem;"
                            onclick="sortTable('status')">STATUS ↕</th>
                        <th style="padding:12px 16px;text-align:left;color:#8b949e;font-size:0.8rem;"
                            onclick="sortTable('risk')">RISK ↕</th>
                        <th style="padding:12px 16px;text-align:left;color:#8b949e;font-size:0.8rem;">HTTP</th>
                        <th style="padding:12px 16px;text-align:left;color:#8b949e;font-size:0.8rem;">SOURCE</th>
                    </tr>
                </thead>
                <tbody id="endpoints-table">
                    {{ENDPOINTS_ROWS}}
                </tbody>
            </table>
        </div>
        <div id="no-results" style="display:none;text-align:center;padding:40px;color:#8b949e;">
            No endpoints match your filter.
        </div>
    </div>

    <!-- Secrets Tab -->
    <div id="tab-secrets" class="section">
        {{SECRETS_TABLE}}
    </div>

    <!-- Errors Tab -->
    <div id="tab-errors" class="section">
        {{ERRORS_TABLE}}
    </div>

</div>

<script>
const RISK_MAP = {
    shadow: 'HIGH', zombie: 'CRITICAL', unprotected: 'CRITICAL',
    vulnerable: 'CRITICAL', verified: 'LOW', protected: 'LOW',
    dead: 'INFO', discovered: 'INFO', documented: 'INFO',
};

let currentFilter = 'all';
let sortCol = '';
let sortDir = 1;

function getRisk(status) {
    return RISK_MAP[status] || 'MEDIUM';
}

function switchTab(name, el) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    el.classList.add('active');
    document.getElementById('tab-' + name).classList.add('active');
}

function setFilter(f, btn) {
    currentFilter = f;
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    applyFilters();
}

function applyFilters() {
    const query = document.getElementById('search').value.toLowerCase();
    const rows = document.querySelectorAll('#endpoints-table tr');
    let visible = 0;
    rows.forEach(row => {
        const url    = (row.dataset.url    || '').toLowerCase();
        const status = (row.dataset.status || '').toLowerCase();
        const matchFilter = currentFilter === 'all' || status === currentFilter;
        const matchSearch = url.includes(query);
        if (matchFilter && matchSearch) {
            row.style.display = '';
            visible++;
        } else {
            row.style.display = 'none';
        }
    });
    document.getElementById('no-results').style.display = visible === 0 ? '' : 'none';
}

function sortTable(col) {
    if (sortCol === col) sortDir *= -1;
    else { sortCol = col; sortDir = 1; }
    const tbody = document.getElementById('endpoints-table');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    rows.sort((a, b) => {
        const va = (a.dataset[col] || '').toLowerCase();
        const vb = (b.dataset[col] || '').toLowerCase();
        return va < vb ? -sortDir : va > vb ? sortDir : 0;
    });
    rows.forEach(r => tbody.appendChild(r));
}

function exportCSV() {
    const rows = document.querySelectorAll('#endpoints-table tr');
    let csv = 'Method,URL,Status,Risk,HTTP Code,Source\\n';
    rows.forEach(row => {
        if (row.style.display === 'none') return;
        const cells = row.querySelectorAll('td');
        if (cells.length === 0) return;
        const method = cells[0].innerText.trim();
        const url    = cells[1].innerText.trim();
        const status = cells[2].innerText.trim();
        const risk   = cells[3].innerText.trim();
        const http   = cells[4].innerText.trim();
        const src    = cells[5].innerText.trim();
        csv += `"${method}","${url}","${status}","${risk}","${http}","${src}"\\n`;
    });
    const blob = new Blob([csv], {type:'text/csv'});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'shadow-api-report.csv';
    a.click();
}
</script>
</body>
</html>
"""


def _risk_level(status: str) -> str:
    risk_map = {
        "shadow": "HIGH", "zombie": "CRITICAL", "unprotected": "CRITICAL",
        "vulnerable": "CRITICAL", "verified": "LOW", "protected": "LOW",
        "dead": "INFO", "discovered": "INFO", "documented": "INFO",
    }
    return risk_map.get(str(status).lower(), "MEDIUM")


def _build_endpoints_rows(endpoints: list) -> str:
    rows = []
    for ep in endpoints:
        method = ep.get("method", "GET")
        url    = ep.get("url", "")
        status = ep.get("status", "discovered")
        http   = ep.get("http_status") or "-"
        source = ep.get("source") or {}
        if isinstance(source, dict):
            src_str = f"{source.get('file','')}"
            line    = source.get('line', '')
            if line:
                src_str += f":{line}"
        else:
            src_str = str(source)

        risk = _risk_level(status)

        rows.append(
            f'<tr class="table-row" '
            f'data-url="{url}" data-status="{status}" '
            f'data-method="{method}" data-risk="{risk}">'
            f'<td style="padding:10px 16px;">'
            f'<span class="method-{method}">{method}</span></td>'
            f'<td style="padding:10px 16px;font-family:monospace;font-size:0.85rem;">{url}</td>'
            f'<td style="padding:10px 16px;">'
            f'<span class="badge badge-{status}">{status}</span></td>'
            f'<td style="padding:10px 16px;" class="risk-{risk}">{risk}</td>'
            f'<td style="padding:10px 16px;color:#94a3b8;">{http}</td>'
            f'<td style="padding:10px 16px;color:#8b949e;font-size:0.8rem;">{src_str}</td>'
            f'</tr>'
        )
    return "\n".join(rows) if rows else (
        '<tr><td colspan="6" style="padding:40px;text-align:center;color:#8b949e;">'
        'No endpoints discovered</td></tr>'
    )


def _build_secrets_table(secrets: list) -> str:
    if not secrets:
        return '<div style="text-align:center;padding:40px;color:#8b949e;">No secrets detected ✅</div>'

    rows = []
    for s in secrets:
        stype    = s.get("type", "unknown")
        severity = s.get("severity", "medium")
        value    = s.get("value", "")
        # Redact for display
        if len(value) > 8:
            value_display = value[:4] + "****" + value[-4:]
        else:
            value_display = "****"
        source = s.get("source") or {}
        if isinstance(source, dict):
            loc = f"{source.get('file','')}:{source.get('line','')}"
        else:
            loc = str(source)

        rows.append(
            f'<tr class="table-row">'
            f'<td style="padding:10px 16px;">{stype}</td>'
            f'<td style="padding:10px 16px;font-family:monospace;color:#f87171;">{value_display}</td>'
            f'<td style="padding:10px 16px;" class="risk-{severity.upper()}">{severity.upper()}</td>'
            f'<td style="padding:10px 16px;color:#8b949e;font-size:0.8rem;">{loc}</td>'
            f'</tr>'
        )

    return (
        '<div class="card" style="overflow:auto;">'
        '<table style="width:100%;border-collapse:collapse;">'
        '<thead><tr style="background:#21262d;">'
        '<th style="padding:12px 16px;text-align:left;color:#8b949e;font-size:0.8rem;">TYPE</th>'
        '<th style="padding:12px 16px;text-align:left;color:#8b949e;font-size:0.8rem;">VALUE (REDACTED)</th>'
        '<th style="padding:12px 16px;text-align:left;color:#8b949e;font-size:0.8rem;">SEVERITY</th>'
        '<th style="padding:12px 16px;text-align:left;color:#8b949e;font-size:0.8rem;">LOCATION</th>'
        '</tr></thead>'
        '<tbody>' + "\n".join(rows) + '</tbody>'
        '</table></div>'
    )


def _build_errors_table(errors: list) -> str:
    if not errors:
        return '<div style="text-align:center;padding:40px;color:#8b949e;">No errors ✅</div>'
    items = "".join(
        f'<div style="padding:10px 16px;border-bottom:1px solid #30363d;'
        f'font-family:monospace;font-size:0.85rem;color:#f87171;">{e}</div>'
        for e in errors
    )
    return f'<div class="card">{items}</div>'


def render_dashboard(data: dict) -> str:
    """Render dashboard HTML from report data."""
    from datetime import datetime

    endpoints = data.get("endpoints", [])
    secrets   = data.get("secrets", [])
    errors    = data.get("errors", [])

    shadow_count  = sum(1 for e in endpoints if e.get("status") == "shadow")
    zombie_count  = sum(1 for e in endpoints if e.get("status") == "zombie")
    verified_count = sum(1 for e in endpoints if e.get("status") == "verified")

    html = DASHBOARD_HTML
    html = html.replace("{{SCAN_ID}}", str(data.get("scan_id", "N/A")))
    html = html.replace("{{TARGET}}", str(data.get("target", "N/A")))
    html = html.replace("{{DURATION}}", f"{data.get('duration_seconds', 0):.2f}")
    html = html.replace("{{GENERATED_AT}}", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"))
    html = html.replace("{{TOTAL_ENDPOINTS}}", str(len(endpoints)))
    html = html.replace("{{SHADOW_COUNT}}", str(shadow_count))
    html = html.replace("{{ZOMBIE_COUNT}}", str(zombie_count))
    html = html.replace("{{SECRETS_COUNT}}", str(len(secrets)))
    html = html.replace("{{FILES_SCANNED}}", str(data.get("total_files_scanned", 0)))
    html = html.replace("{{VERIFIED_COUNT}}", str(verified_count))
    html = html.replace("{{ENDPOINTS_ROWS}}", _build_endpoints_rows(endpoints))
    html = html.replace("{{SECRETS_TABLE}}", _build_secrets_table(secrets))
    html = html.replace("{{ERRORS_TABLE}}", _build_errors_table(errors))
    return html


def start_dashboard(report_path: Path, port: int = 8000) -> None:
    """Load report and start the dashboard server."""
    try:
        import uvicorn
        from fastapi import FastAPI
        from fastapi.responses import HTMLResponse
    except ImportError:
        # Fallback: save as HTML file if uvicorn/fastapi not installed
        if not report_path.exists():
            print(f"Error: Report file {report_path} not found.")
            return
        data = json.loads(report_path.read_text())
        html = render_dashboard(data)
        out = report_path.parent / "dashboard.html"
        out.write_text(html)
        print(f"Dashboard saved to: {out}")
        print("Open this file in your browser.")
        return

    if not report_path.exists():
        print(f"Error: Report file {report_path} not found.")
        return

    data = json.loads(report_path.read_text())

    fastapi_app = FastAPI(title="Shadow API Dashboard")

    @fastapi_app.get("/", response_class=HTMLResponse)
    async def index():
        return render_dashboard(data)

    @fastapi_app.get("/api/data")
    async def api_data():
        return data

    print(f"🚀 Dashboard running at http://localhost:{port}")
    uvicorn.run(fastapi_app, host="127.0.0.1", port=port, log_level="error")
