"""Web dashboard for visualizing Shadow API Mapper results.

Uses FastAPI and Jinja2 to render an interactive report viewer.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

app = FastAPI(title="Shadow API Dashboard")

# Global state to hold report data
report_data: Dict[str, Any] = {}

# HTML Template (embedded for simplicity)
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Shadow API Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        dark: '#0d1117',
                        secondary: '#161b22',
                        accent: '#238636',
                    }
                }
            }
        }
    </script>
    <style>
        body { background-color: #0d1117; color: #c9d1d9; }
        .card { background-color: #161b22; border: 1px solid #30363d; border-radius: 6px; }
        .table-row:hover { background-color: #21262d; }
    </style>
</head>
<body class="min-h-screen p-6">
    <div class="max-w-7xl mx-auto">
        <header class="mb-8 flex justify-between items-center">
            <div>
                <h1 class="text-3xl font-bold text-white mb-2">🕵️ Shadow API Dashboard</h1>
                <p class="text-gray-400">Scan ID: <span class="text-blue-400 font-mono">{{ scan_id }}</span></p>
            </div>
            <div class="text-right">
                <p class="text-sm text-gray-400">Target</p>
                <p class="text-lg font-mono text-green-400">{{ target }}</p>
            </div>
        </header>

        <!-- Stats Grid -->
        <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
            <div class="card p-4">
                <p class="text-gray-400 text-sm">Endpoints</p>
                <p class="text-3xl font-bold text-white">{{ stats.endpoints }}</p>
            </div>
            <div class="card p-4">
                <p class="text-gray-400 text-sm">Secrets</p>
                <p class="text-3xl font-bold text-red-400">{{ stats.secrets }}</p>
            </div>
            <div class="card p-4">
                <p class="text-gray-400 text-sm">Files Scanned</p>
                <p class="text-3xl font-bold text-blue-400">{{ stats.files }}</p>
            </div>
            <div class="card p-4">
                <p class="text-gray-400 text-sm">Duration</p>
                <p class="text-3xl font-bold text-yellow-400">{{ stats.duration }}s</p>
            </div>
        </div>

        <!-- content tabs -->
        <div class="mb-6 border-b border-gray-700">
            <nav class="-mb-px flex space-x-8">
                <a href="#" class="border-green-500 text-green-500 whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm">Endpoints</a>
                <a href="#secrets" class="border-transparent text-gray-400 hover:text-gray-300 hover:border-gray-300 whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm">Secrets</a>
            </nav>
        </div>

        <!-- Endpoints Table -->
        <div class="card overflow-hidden mb-8">
            <table class="min-w-full divide-y divide-gray-700">
                <thead class="bg-gray-800">
                    <tr>
                        <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Method</th>
                        <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">URL</th>
                        <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Status</th>
                        <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Source</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-gray-700">
                    {% for ep in endpoints %}
                    <tr class="table-row transition-colors">
                        <td class="px-6 py-4 whitespace-nowrap">
                            <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full 
                                {% if ep.method == 'GET' %}bg-blue-900 text-blue-200
                                {% elif ep.method == 'POST' %}bg-green-900 text-green-200
                                {% elif ep.method == 'DELETE' %}bg-red-900 text-red-200
                                {% else %}bg-gray-700 text-gray-200{% endif %}">
                                {{ ep.method }}
                            </span>
                        </td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-300 font-mono">{{ ep.url }}</td>
                        <td class="px-6 py-4 whitespace-nowrap">
                            <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full 
                                {% if ep.status == 'verified' %}bg-green-900 text-green-200
                                {% elif ep.status == 'shadow' %}bg-purple-900 text-purple-200
                                {% elif ep.status == 'zombie' %}bg-yellow-900 text-yellow-200
                                {% else %}bg-gray-700 text-gray-200{% endif %}">
                                {{ ep.status }}
                            </span>
                        </td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                            {% if ep.source %}
                                {{ ep.source.file }}:{{ ep.source.line }}
                            {% else %}
                                -
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        {% if secrets %}
        <h2 class="text-2xl font-bold text-white mb-4" id="secrets">Secrets Discovered</h2>
        <div class="card overflow-hidden">
            <table class="min-w-full divide-y divide-gray-700">
                <thead class="bg-gray-800">
                    <tr>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Type</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Value</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Severity</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Location</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-gray-700">
                    {% for secret in secrets %}
                    <tr class="table-row">
                        <td class="px-6 py-4 text-sm font-medium text-gray-200">{{ secret.type }}</td>
                        <td class="px-6 py-4 text-sm font-mono text-red-300">{{ secret.value[:4] }}...{{ secret.value[-4:] }}</td>
                        <td class="px-6 py-4">
                             <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-900 text-red-200">
                                {{ secret.severity }}
                            </span>
                        </td>
                        <td class="px-6 py-4 text-sm text-gray-500">
                            {{ secret.source.file }}:{{ secret.source.line }}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

    </div>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Render the dashboard."""
    templates = Jinja2Templates(directory=".")
    # Hack: Create template from string since we don't want to manage extra files
    # Actually Jinja2 requires files by default. Let's use string substitution or write a temp file.
    # For robust production use, we'd package the HTML. 
    # Here we'll just write to a temp file or use Template directly.
    from jinja2 import Template
    t = Template(DASHBOARD_HTML)
    
    return t.render(
        scan_id=report_data.get("scan_id", "Unknown"),
        target=report_data.get("target", "Unknown"),
        stats={
            "endpoints": report_data.get("total_endpoints_discovered", 0),
            "secrets": len(report_data.get("secrets", [])),
            "files": report_data.get("total_files_scanned", 0),
            "duration": f"{report_data.get('duration_seconds', 0):.2f}"
        },
        endpoints=report_data.get("endpoints", []),
        secrets=report_data.get("secrets", [])
    )

def start_dashboard(report_path: Path, port: int = 8000):
    """Load report and start the dashboard server."""
    import uvicorn
    
    global report_data
    if not report_path.exists():
        print(f"Error: Report file {report_path} not found.")
        return

    text = report_path.read_text()
    report_data = json.loads(text)
    
    print(f"Starting dashboard on http://localhost:{port}")
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="error")
