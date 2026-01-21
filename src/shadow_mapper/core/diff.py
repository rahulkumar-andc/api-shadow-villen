"""Diff mode for comparing scan results.

Compare two scan results to identify new, removed, and changed endpoints.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class EndpointDiff:
    """Represents differences between two sets of endpoints."""
    
    # New endpoints (in current but not in baseline)
    added: list[dict[str, Any]] = field(default_factory=list)
    
    # Removed endpoints (in baseline but not in current)
    removed: list[dict[str, Any]] = field(default_factory=list)
    
    # Changed endpoints (same URL but different status/properties)
    changed: list[tuple[dict[str, Any], dict[str, Any]]] = field(default_factory=list)
    
    # Unchanged endpoints
    unchanged: list[dict[str, Any]] = field(default_factory=list)
    
    @property
    def has_changes(self) -> bool:
        """Check if there are any differences."""
        return bool(self.added or self.removed or self.changed)
    
    def summary(self) -> dict[str, int]:
        """Get summary counts."""
        return {
            "added": len(self.added),
            "removed": len(self.removed),
            "changed": len(self.changed),
            "unchanged": len(self.unchanged),
        }


@dataclass
class ScanDiff:
    """Complete diff between two scan reports."""
    
    baseline_scan_id: str
    current_scan_id: str
    baseline_target: str
    current_target: str
    
    endpoints: EndpointDiff = field(default_factory=EndpointDiff)
    secrets_added: int = 0
    secrets_removed: int = 0
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "baseline_scan_id": self.baseline_scan_id,
            "current_scan_id": self.current_scan_id,
            "baseline_target": self.baseline_target,
            "current_target": self.current_target,
            "endpoints": {
                "added": self.endpoints.added,
                "removed": self.endpoints.removed,
                "changed": [
                    {"before": b, "after": a}
                    for b, a in self.endpoints.changed
                ],
                "unchanged_count": len(self.endpoints.unchanged),
            },
            "secrets": {
                "added": self.secrets_added,
                "removed": self.secrets_removed,
            },
            "summary": self.endpoints.summary(),
        }


def _endpoint_signature(ep: dict[str, Any]) -> str:
    """Generate unique signature for an endpoint."""
    method = ep.get("method", "GET")
    url = ep.get("url", "")
    return f"{method}:{url}"


def compare_scans(
    baseline: dict[str, Any],
    current: dict[str, Any],
) -> ScanDiff:
    """Compare two scan results.
    
    Args:
        baseline: Baseline/previous scan report (as dict)
        current: Current scan report (as dict)
        
    Returns:
        ScanDiff with all differences
    """
    diff = ScanDiff(
        baseline_scan_id=baseline.get("scan_id", "unknown"),
        current_scan_id=current.get("scan_id", "unknown"),
        baseline_target=baseline.get("target", "unknown"),
        current_target=current.get("target", "unknown"),
    )
    
    # Build lookup maps
    baseline_endpoints = {
        _endpoint_signature(ep): ep
        for ep in baseline.get("endpoints", [])
    }
    current_endpoints = {
        _endpoint_signature(ep): ep
        for ep in current.get("endpoints", [])
    }
    
    baseline_sigs = set(baseline_endpoints.keys())
    current_sigs = set(current_endpoints.keys())
    
    # Find added endpoints
    for sig in current_sigs - baseline_sigs:
        diff.endpoints.added.append(current_endpoints[sig])
    
    # Find removed endpoints
    for sig in baseline_sigs - current_sigs:
        diff.endpoints.removed.append(baseline_endpoints[sig])
    
    # Find changed and unchanged
    for sig in baseline_sigs & current_sigs:
        baseline_ep = baseline_endpoints[sig]
        current_ep = current_endpoints[sig]
        
        # Check for property changes
        if _has_significant_changes(baseline_ep, current_ep):
            diff.endpoints.changed.append((baseline_ep, current_ep))
        else:
            diff.endpoints.unchanged.append(current_ep)
    
    # Compare secrets (just count changes)
    baseline_secrets = len(baseline.get("secrets", []))
    current_secrets = len(current.get("secrets", []))
    
    if current_secrets > baseline_secrets:
        diff.secrets_added = current_secrets - baseline_secrets
    elif baseline_secrets > current_secrets:
        diff.secrets_removed = baseline_secrets - current_secrets
    
    return diff


def _has_significant_changes(
    baseline: dict[str, Any],
    current: dict[str, Any],
) -> bool:
    """Check if endpoint has significant property changes."""
    # Properties to check for changes
    check_fields = ["status", "http_status", "deprecated"]
    
    for field in check_fields:
        if baseline.get(field) != current.get(field):
            return True
    
    return False


def load_scan_report(path: Path) -> dict[str, Any]:
    """Load a scan report from JSON file.
    
    Args:
        path: Path to report.json file
        
    Returns:
        Scan report as dictionary
    """
    return json.loads(path.read_text())


def compare_scan_files(
    baseline_path: Path,
    current_path: Path,
) -> ScanDiff:
    """Compare two scan report files.
    
    Args:
        baseline_path: Path to baseline report
        current_path: Path to current report
        
    Returns:
        ScanDiff with differences
    """
    baseline = load_scan_report(baseline_path)
    current = load_scan_report(current_path)
    return compare_scans(baseline, current)


def format_diff_summary(diff: ScanDiff) -> str:
    """Format diff as human-readable summary.
    
    Args:
        diff: ScanDiff to format
        
    Returns:
        Formatted string
    """
    lines = [
        f"Scan Comparison: {diff.baseline_scan_id} → {diff.current_scan_id}",
        f"Targets: {diff.baseline_target} → {diff.current_target}",
        "",
        "Endpoint Changes:",
        f"  + Added:     {len(diff.endpoints.added)}",
        f"  - Removed:   {len(diff.endpoints.removed)}",
        f"  ~ Changed:   {len(diff.endpoints.changed)}",
        f"  = Unchanged: {len(diff.endpoints.unchanged)}",
        "",
    ]
    
    if diff.endpoints.added:
        lines.append("New Endpoints:")
        for ep in diff.endpoints.added[:10]:  # Limit to 10
            lines.append(f"  + {ep.get('method', 'GET')} {ep.get('url', '')}")
        if len(diff.endpoints.added) > 10:
            lines.append(f"  ... and {len(diff.endpoints.added) - 10} more")
    
    if diff.endpoints.removed:
        lines.append("")
        lines.append("Removed Endpoints:")
        for ep in diff.endpoints.removed[:10]:
            lines.append(f"  - {ep.get('method', 'GET')} {ep.get('url', '')}")
        if len(diff.endpoints.removed) > 10:
            lines.append(f"  ... and {len(diff.endpoints.removed) - 10} more")
    
    if diff.secrets_added or diff.secrets_removed:
        lines.append("")
        lines.append(f"Secrets: +{diff.secrets_added} / -{diff.secrets_removed}")
    
    return "\n".join(lines)
