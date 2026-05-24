"""Bulk scanning orchestrator.

Handles processing of multiple targets with concurrency control,
result aggregation and master report generation.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

from rich.progress import Progress, TaskID

from shadow_mapper.core.config import Settings
from shadow_mapper.core.orchestrator import FullScanOrchestrator


@dataclass
class BulkResult:
    """Result for a single target in a bulk scan."""

    target: str
    status: str          # success | failed | skipped
    endpoints_found: int = 0
    secrets_found: int   = 0
    shadow_count: int    = 0
    zombie_count: int    = 0
    duration_seconds: float = 0.0
    error: Optional[str] = None
    report_path: Optional[Path] = None


class BulkScanOrchestrator:
    """Orchestrates scanning of multiple targets."""

    def __init__(
        self,
        settings: Settings,
        targets: List[str],
        concurrency: int = 3,
    ):
        self.settings   = settings
        self.targets    = targets
        self.concurrency = concurrency
        self.results: List[BulkResult] = []
        self._sem = asyncio.Semaphore(concurrency)

    async def run(self, progress: Progress) -> List[BulkResult]:
        """Run bulk scan across all targets."""
        overall = progress.add_task(
            f"[green]Scanning {len(self.targets)} targets...",
            total=len(self.targets),
        )
        tasks = [
            self._scan_target(t, progress, overall)
            for t in self.targets
        ]
        self.results = await asyncio.gather(*tasks)
        return self.results

    async def _scan_target(
        self,
        target: str,
        progress: Progress,
        overall_task: TaskID,
    ) -> BulkResult:
        """Scan a single target, protected by semaphore."""
        async with self._sem:
            target = self._normalize_url(target)
            start  = datetime.utcnow()

            # Per-target output directory
            domain = urlparse(target).netloc or target.replace("/", "_")
            target_output = Path(self.settings.output.output_dir) / domain
            target_output.mkdir(parents=True, exist_ok=True)

            try:
                target_settings = self.settings.model_copy(deep=True)
                target_settings.output.output_dir = target_output
                target_settings.target_url        = target
                target_settings.harvester.headless = True

                orchestrator = FullScanOrchestrator(target_settings)
                report = await orchestrator.run_pipeline()

                # Save per-target report
                report_file = target_output / "report.json"
                with open(report_file, "w") as f:
                    json.dump(report.model_dump(), f, indent=2, default=str)

                # Count shadow/zombie
                shadow = sum(
                    1 for e in report.endpoints
                    if (e.status.value if hasattr(e.status, "value") else e.status) == "shadow"
                )
                zombie = sum(
                    1 for e in report.endpoints
                    if (e.status.value if hasattr(e.status, "value") else e.status) == "zombie"
                )

                duration = (datetime.utcnow() - start).total_seconds()
                progress.advance(overall_task)

                return BulkResult(
                    target=target,
                    status="success",
                    endpoints_found=report.total_endpoints_discovered,
                    secrets_found=len(report.secrets),
                    shadow_count=shadow,
                    zombie_count=zombie,
                    duration_seconds=duration,
                    report_path=report_file,
                )

            except Exception as e:
                progress.console.print(f"[red]✗ Failed: {target} — {e}[/red]")
                progress.advance(overall_task)
                return BulkResult(
                    target=target,
                    status="failed",
                    error=str(e),
                    duration_seconds=(datetime.utcnow() - start).total_seconds(),
                )

    @staticmethod
    def _normalize_url(url: str) -> str:
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            return f"https://{url}"
        return url

    def generate_master_report(self) -> Dict[str, Any]:
        """Generate aggregated report for all targets."""
        successful = [r for r in self.results if r.status == "success"]
        failed     = [r for r in self.results if r.status != "success"]

        return {
            "generated_at": datetime.utcnow().isoformat(),
            "summary": {
                "total_targets":    len(self.targets),
                "successful":       len(successful),
                "failed":           len(failed),
                "total_endpoints":  sum(r.endpoints_found for r in successful),
                "total_secrets":    sum(r.secrets_found   for r in successful),
                "total_shadow":     sum(r.shadow_count    for r in successful),
                "total_zombie":     sum(r.zombie_count    for r in successful),
                "total_duration_s": sum(r.duration_seconds for r in self.results),
            },
            "targets": [
                {
                    "url":         r.target,
                    "status":      r.status,
                    "endpoints":   r.endpoints_found,
                    "secrets":     r.secrets_found,
                    "shadow":      r.shadow_count,
                    "zombie":      r.zombie_count,
                    "duration_s":  round(r.duration_seconds, 2),
                    "error":       r.error,
                    "report_file": str(r.report_path) if r.report_path else None,
                }
                for r in self.results
            ],
            "failed_targets": [
                {"url": r.target, "error": r.error}
                for r in failed
            ],
        }
