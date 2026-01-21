"""HTML report generator for Shadow API Mapper.

Generates visual HTML reports with scan summaries, endpoint tables,
and security findings.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from shadow_mapper.core.models import ScanReport


HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Shadow API Mapper - Scan Report</title>
    <style>
        :root {{
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --border-color: #30363d;
            --accent-green: #238636;
            --accent-red: #da3633;
            --accent-yellow: #d29922;
            --accent-blue: #58a6ff;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
        header {{
            background: linear-gradient(135deg, var(--bg-secondary), var(--bg-tertiary));
            padding: 2rem;
            border-radius: 12px;
            margin-bottom: 2rem;
            border: 1px solid var(--border-color);
        }}
        h1 {{ color: var(--accent-blue); font-size: 2rem; margin-bottom: 0.5rem; }}
        h2 {{ color: var(--text-primary); font-size: 1.5rem; margin: 1.5rem 0 1rem; }}
        .meta {{ color: var(--text-secondary); font-size: 0.9rem; }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin: 1.5rem 0;
        }}
        .stat-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1.5rem;
            text-align: center;
        }}
        .stat-value {{ font-size: 2rem; font-weight: bold; color: var(--accent-blue); }}
        .stat-label {{ color: var(--text-secondary); font-size: 0.9rem; }}
        .stat-card.danger .stat-value {{ color: var(--accent-red); }}
        .stat-card.warning .stat-value {{ color: var(--accent-yellow); }}
        .stat-card.success .stat-value {{ color: var(--accent-green); }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-secondary);
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid var(--border-color);
            margin: 1rem 0;
        }}
        th, td {{ padding: 1rem; text-align: left; border-bottom: 1px solid var(--border-color); }}
        th {{ background: var(--bg-tertiary); color: var(--text-primary); font-weight: 600; }}
        tr:hover {{ background: var(--bg-tertiary); }}
        .badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .badge-shadow {{ background: var(--accent-red); color: white; }}
        .badge-verified {{ background: var(--accent-green); color: white; }}
        .badge-discovered {{ background: var(--accent-blue); color: white; }}
        .badge-zombie {{ background: var(--accent-yellow); color: black; }}
        .method {{ font-family: monospace; font-weight: bold; }}
        .method-get {{ color: var(--accent-green); }}
        .method-post {{ color: var(--accent-blue); }}
        .method-put {{ color: var(--accent-yellow); }}
        .method-delete {{ color: var(--accent-red); }}
        .url {{ font-family: monospace; color: var(--text-primary); }}
        footer {{
            margin-top: 3rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--border-color);
            text-align: center;
            color: var(--text-secondary);
            font-size: 0.85rem;
        }}
        .empty-state {{
            text-align: center;
            padding: 3rem;
            color: var(--text-secondary);
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🕵️ Shadow API Mapper Report</h1>
            <p class="meta">
                <strong>Scan ID:</strong> {scan_id} |
                <strong>Target:</strong> {target} |
                <strong>Duration:</strong> {duration:.2f}s
            </p>
        </header>
        
        <section class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{files_scanned}</div>
                <div class="stat-label">Files Scanned</div>
            </div>
            <div class="stat-card success">
                <div class="stat-value">{endpoints_discovered}</div>
                <div class="stat-label">Endpoints Discovered</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{endpoints_verified}</div>
                <div class="stat-label">Endpoints Verified</div>
            </div>
            <div class="stat-card danger">
                <div class="stat-value">{secrets_found}</div>
                <div class="stat-label">Secrets Found</div>
            </div>
        </section>
        
        <h2>📡 Discovered Endpoints</h2>
        {endpoints_table}
        
        <h2>🔐 Detected Secrets</h2>
        {secrets_table}
        
        <footer>
            <p>Generated by Shadow API Mapper on {generated_at}</p>
        </footer>
    </div>
</body>
</html>
'''


def generate_html_report(report: "ScanReport") -> str:
    """Generate an HTML report from scan results.
    
    Args:
        report: Completed scan report
        
    Returns:
        HTML string
    """
    # Generate endpoints table
    if report.endpoints:
        rows = []
        for ep in report.endpoints:
            method = ep.method.value if hasattr(ep.method, 'value') else ep.method
            status = ep.status.value if hasattr(ep.status, 'value') else ep.status
            method_class = f"method-{method.lower()}"
            badge_class = f"badge-{status.lower()}"
            
            rows.append(f'''
                <tr>
                    <td><span class="method {method_class}">{method}</span></td>
                    <td><span class="url">{ep.url}</span></td>
                    <td><span class="badge {badge_class}">{status}</span></td>
                    <td>{ep.http_status or '-'}</td>
                </tr>
            ''')
        
        endpoints_table = f'''
            <table>
                <thead>
                    <tr>
                        <th>Method</th>
                        <th>URL</th>
                        <th>Status</th>
                        <th>HTTP Code</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows)}
                </tbody>
            </table>
        '''
    else:
        endpoints_table = '<div class="empty-state">No endpoints discovered</div>'
    
    # Generate secrets table
    if report.secrets:
        rows = []
        for secret in report.secrets:
            redacted = secret.redact()
            severity = secret.severity.value if hasattr(secret.severity, 'value') else secret.severity
            
            rows.append(f'''
                <tr>
                    <td>{secret.type}</td>
                    <td><code>{redacted.value}</code></td>
                    <td>{severity}</td>
                    <td>{secret.source.file.name}:{secret.source.line}</td>
                </tr>
            ''')
        
        secrets_table = f'''
            <table>
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Value (Redacted)</th>
                        <th>Severity</th>
                        <th>Location</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows)}
                </tbody>
            </table>
        '''
    else:
        secrets_table = '<div class="empty-state">No secrets detected</div>'
    
    return HTML_TEMPLATE.format(
        scan_id=report.scan_id,
        target=report.target,
        duration=report.duration_seconds,
        files_scanned=report.total_files_scanned,
        endpoints_discovered=report.total_endpoints_discovered,
        endpoints_verified=report.total_endpoints_verified,
        secrets_found=len(report.secrets),
        endpoints_table=endpoints_table,
        secrets_table=secrets_table,
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    )


def save_html_report(report: "ScanReport", output_path: Path) -> Path:
    """Save HTML report to file.
    
    Args:
        report: Scan report
        output_path: Directory or file path
        
    Returns:
        Path to saved file
    """
    if output_path.is_dir():
        file_path = output_path / f"report-{report.scan_id}.html"
    else:
        file_path = output_path
    
    html = generate_html_report(report)
    file_path.write_text(html)
    
    return file_path
