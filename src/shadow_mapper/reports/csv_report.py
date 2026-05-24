"""CSV report generator for Shadow API Mapper.

Generates Excel-compatible CSV reports with risk scoring.
"""

from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from shadow_mapper.core.models import ScanReport


# Risk level mapping
RISK_LEVELS = {
    "shadow": "HIGH",
    "zombie": "CRITICAL",
    "unprotected": "CRITICAL",
    "vulnerable": "CRITICAL",
    "discovered": "INFO",
    "verified": "LOW",
    "protected": "LOW",
    "dead": "INFO",
    "documented": "INFO",
}


def _get_risk_level(status: str) -> str:
    """Get risk level string for an endpoint status."""
    return RISK_LEVELS.get(str(status).lower(), "MEDIUM")


def generate_csv_report(report: "ScanReport") -> str:
    """
    Generate CSV report as string.

    Args:
        report: Completed scan report

    Returns:
        CSV content as string
    """
    import io

    output = io.StringIO()

    # --- Summary section ---
    output.write("# Shadow API Mapper - Scan Report\n")
    output.write(f"# Scan ID: {report.scan_id}\n")
    output.write(f"# Target: {report.target}\n")
    output.write(f"# Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
    output.write(f"# Duration: {report.duration_seconds:.2f}s\n")
    output.write(f"# Total Endpoints: {report.total_endpoints_discovered}\n")
    output.write(f"# Secrets Found: {len(report.secrets)}\n")
    output.write("\n")

    # --- Endpoints section ---
    output.write("## ENDPOINTS\n")

    writer = csv.DictWriter(output, fieldnames=[
        "method", "url", "status", "risk_level",
        "http_code", "source_file", "line",
        "response_time_ms", "content_type",
        "has_deprecation", "notes",
    ])
    writer.writeheader()

    for ep in report.endpoints:
        method = ep.method.value if hasattr(ep.method, "value") else str(ep.method)
        status = ep.status.value if hasattr(ep.status, "value") else str(ep.status)
        risk = _get_risk_level(status)

        notes = []
        if status == "shadow":
            notes.append("Undocumented endpoint — not in OpenAPI spec")
        if status == "zombie":
            notes.append("Deprecated endpoint still responding")
        if status == "unprotected":
            notes.append("No authentication required")
        if ep.deprecation_date:
            notes.append(f"Deprecated since: {ep.deprecation_date}")

        writer.writerow({
            "method": method,
            "url": ep.url,
            "status": status,
            "risk_level": risk,
            "http_code": ep.http_status or "N/A",
            "source_file": str(ep.source.file) if ep.source else "",
            "line": ep.source.line if ep.source else "",
            "response_time_ms": f"{ep.response_time_ms:.1f}" if ep.response_time_ms else "",
            "content_type": ep.content_type or "",
            "has_deprecation": "YES" if ep.deprecation_date else "NO",
            "notes": " | ".join(notes),
        })

    output.write("\n")

    # --- Secrets section ---
    if report.secrets:
        output.write("## SECRETS\n")
        secret_writer = csv.DictWriter(output, fieldnames=[
            "type", "severity", "value_preview",
            "source_file", "line", "context",
        ])
        secret_writer.writeheader()

        for secret in report.secrets:
            redacted = secret.redact()
            severity = secret.severity.value if hasattr(secret.severity, "value") else str(secret.severity)

            secret_writer.writerow({
                "type": secret.type,
                "severity": severity,
                "value_preview": redacted.value,
                "source_file": str(secret.source.file) if secret.source else "",
                "line": secret.source.line if secret.source else "",
                "context": secret.source.context if secret.source else "",
            })

    return output.getvalue()


def save_csv_report(report: "ScanReport", output_path: Path) -> Path:
    """
    Save CSV report to file.

    Args:
        report: Scan report
        output_path: Directory or file path

    Returns:
        Path to saved file
    """
    if output_path.is_dir():
        file_path = output_path / f"report-{report.scan_id}.csv"
    else:
        file_path = output_path

    file_path.parent.mkdir(parents=True, exist_ok=True)
    csv_content = generate_csv_report(report)
    file_path.write_text(csv_content, encoding="utf-8")

    return file_path
