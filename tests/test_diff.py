"""Tests for scan diff / comparison module."""

import pytest
from shadow_mapper.core.diff import (
    compare_scans,
    format_diff_summary,
    ScanDiff,
)


def _make_report(scan_id: str, target: str, endpoints: list, secrets: list = None):
    return {
        "scan_id": scan_id,
        "target":  target,
        "endpoints": endpoints,
        "secrets": secrets or [],
    }


def _ep(method: str, url: str, status: str = "verified"):
    return {"method": method, "url": url, "status": status}


class TestComparScans:

    def test_no_changes(self):
        ep = _ep("GET", "/api/v1/users")
        base    = _make_report("base", "https://ex.com", [ep])
        current = _make_report("curr", "https://ex.com", [ep])
        diff = compare_scans(base, current)
        assert len(diff.endpoints.added)   == 0
        assert len(diff.endpoints.removed) == 0
        assert len(diff.endpoints.unchanged) == 1

    def test_new_endpoint_detected(self):
        base    = _make_report("base", "https://ex.com", [_ep("GET", "/api/v1/users")])
        current = _make_report("curr", "https://ex.com", [
            _ep("GET", "/api/v1/users"),
            _ep("POST", "/api/v1/admin"),   # new shadow API
        ])
        diff = compare_scans(base, current)
        assert len(diff.endpoints.added) == 1
        assert diff.endpoints.added[0]["url"] == "/api/v1/admin"

    def test_removed_endpoint_detected(self):
        base = _make_report("base", "https://ex.com", [
            _ep("GET", "/api/v1/users"),
            _ep("GET", "/api/v1/old"),
        ])
        current = _make_report("curr", "https://ex.com", [
            _ep("GET", "/api/v1/users"),
        ])
        diff = compare_scans(base, current)
        assert len(diff.endpoints.removed) == 1
        assert diff.endpoints.removed[0]["url"] == "/api/v1/old"

    def test_status_change_detected(self):
        base = _make_report("base", "https://ex.com", [
            _ep("GET", "/api/v1/users", "verified"),
        ])
        current = _make_report("curr", "https://ex.com", [
            _ep("GET", "/api/v1/users", "zombie"),
        ])
        diff = compare_scans(base, current)
        assert len(diff.endpoints.changed) == 1

    def test_new_secrets_counted(self):
        base    = _make_report("base", "https://ex.com", [], secrets=[{"type": "key"}])
        current = _make_report("curr", "https://ex.com", [],
                               secrets=[{"type": "key"}, {"type": "token"}])
        diff = compare_scans(base, current)
        assert diff.secrets_added == 1

    def test_has_changes_property(self):
        base = _make_report("b", "https://ex.com", [])
        curr = _make_report("c", "https://ex.com", [_ep("GET", "/api/new")])
        diff = compare_scans(base, curr)
        assert diff.endpoints.has_changes is True

    def test_no_changes_property(self):
        ep   = _ep("GET", "/api/v1/users")
        base = _make_report("b", "https://ex.com", [ep])
        curr = _make_report("c", "https://ex.com", [ep])
        diff = compare_scans(base, curr)
        assert diff.endpoints.has_changes is False


class TestFormatDiffSummary:

    def test_format_contains_counts(self):
        base = _make_report("b", "https://ex.com", [])
        curr = _make_report("c", "https://ex.com", [_ep("GET", "/api/new")])
        diff = compare_scans(base, curr)
        summary = format_diff_summary(diff)
        assert "Added" in summary or "added" in summary.lower()
        assert "1" in summary

    def test_format_no_changes(self):
        ep   = _ep("GET", "/api/v1/users")
        base = _make_report("b", "https://ex.com", [ep])
        curr = _make_report("c", "https://ex.com", [ep])
        diff = compare_scans(base, curr)
        summary = format_diff_summary(diff)
        assert summary is not None
        assert len(summary) > 0


class TestScanDiffToDict:

    def test_to_dict_structure(self):
        base = _make_report("b", "https://ex.com", [_ep("GET", "/api/v1/users")])
        curr = _make_report("c", "https://ex.com", [
            _ep("GET", "/api/v1/users"),
            _ep("GET", "/api/v2/admin"),
        ])
        diff = compare_scans(base, curr)
        d = diff.to_dict()

        assert "baseline_scan_id" in d
        assert "current_scan_id"  in d
        assert "endpoints"        in d
        assert "summary"          in d
        assert d["endpoints"]["added"]
