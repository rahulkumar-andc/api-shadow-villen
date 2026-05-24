"""Tests for CSV report generation."""

import pytest
from pathlib import Path
from datetime import datetime

from shadow_mapper.core.models import (
    Endpoint, HTTPMethod, EndpointStatus,
    Secret, Severity, SourceLocation, ScanReport,
)
from shadow_mapper.reports.csv_report import generate_csv_report, save_csv_report


def _make_report() -> ScanReport:
    return ScanReport(
        scan_id="test123",
        target="https://example.com",
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow(),
        duration_seconds=5.0,
        total_files_scanned=3,
        total_endpoints_discovered=4,
        total_endpoints_verified=3,
        endpoints=[
            Endpoint(url="/api/v1/users",   method=HTTPMethod.GET,    status=EndpointStatus.VERIFIED),
            Endpoint(url="/api/admin",       method=HTTPMethod.GET,    status=EndpointStatus.SHADOW),
            Endpoint(url="/api/v0/old",      method=HTTPMethod.POST,   status=EndpointStatus.ZOMBIE),
            Endpoint(url="/api/v1/products", method=HTTPMethod.DELETE, status=EndpointStatus.PROTECTED),
        ],
        secrets=[
            Secret(
                type="stripe_key",
                value="sk_live_abc123",
                severity=Severity.CRITICAL,
                source=SourceLocation(file=Path("app.js"), line=10),
            )
        ],
    )


class TestGenerateCsvReport:

    def test_returns_string(self):
        report = _make_report()
        csv    = generate_csv_report(report)
        assert isinstance(csv, str)
        assert len(csv) > 0

    def test_contains_headers(self):
        csv = generate_csv_report(_make_report())
        assert "method" in csv.lower()
        assert "url"    in csv.lower()
        assert "status" in csv.lower()
        assert "risk"   in csv.lower()

    def test_contains_endpoints(self):
        csv = generate_csv_report(_make_report())
        assert "/api/v1/users"   in csv
        assert "/api/admin"      in csv
        assert "/api/v0/old"     in csv

    def test_contains_risk_levels(self):
        csv = generate_csv_report(_make_report())
        assert "HIGH"     in csv     # shadow
        assert "CRITICAL" in csv     # zombie

    def test_contains_secrets_section(self):
        csv = generate_csv_report(_make_report())
        assert "SECRETS"     in csv.upper()
        assert "stripe_key"  in csv

    def test_secrets_redacted(self):
        csv = generate_csv_report(_make_report())
        # Full secret value should NOT appear
        assert "sk_live_abc123" not in csv

    def test_scan_metadata_in_header(self):
        csv = generate_csv_report(_make_report())
        assert "test123"         in csv   # scan_id
        assert "example.com"     in csv   # target


class TestSaveCsvReport:

    def test_saves_to_file(self, tmp_path: Path):
        report = _make_report()
        out    = tmp_path / "report.csv"
        result = save_csv_report(report, out)
        assert result.exists()
        assert result.stat().st_size > 0

    def test_saves_to_directory(self, tmp_path: Path):
        report = _make_report()
        result = save_csv_report(report, tmp_path)
        assert result.exists()
        assert result.name.endswith(".csv")

    def test_content_is_valid_csv(self, tmp_path: Path):
        import csv, io
        report = _make_report()
        out    = tmp_path / "test.csv"
        save_csv_report(report, out)
        content = out.read_text()
        # Strip comment lines and parse CSV
        data_lines = [l for l in content.splitlines() if not l.startswith("#")]
        # Should have at least headers + endpoints rows
        assert len(data_lines) >= 3
