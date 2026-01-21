"""Bulk scanning orchestrator.

Handles processing of multiple targets with concurrency control and
result aggregation.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
from urllib.parse import urlparse

from rich.progress import Progress, TaskID

from shadow_mapper.core.config import Settings
from shadow_mapper.core.orchestrator import FullScanOrchestrator


@dataclass
class BulkResult:
    """Summary result for a single target in bulk scan."""
    
    target: str
    status: str  # "success", "failed", "skipped"
    endpoints_found: int = 0
    secrets_found: int = 0
    duration_seconds: float = 0.0
    error: str | None = None
    report_path: Path | None = None


class BulkScanOrchestrator:
    """Orchestrates scanning of multiple targets."""
    
    def __init__(
        self,
        settings: Settings,
        targets: List[str],
        concurrency: int = 3,
    ):
        self.settings = settings
        self.targets = targets
        self.concurrency = concurrency
        self.results: List[BulkResult] = []
        self._sem = asyncio.Semaphore(concurrency)
        
    async def run(self, progress: Progress) -> List[BulkResult]:
        """Run bulk scan."""
        overall_task = progress.add_task(
            f"[green]Bulk Scan ({len(self.targets)} targets)...",
            total=len(self.targets)
        )
        
        # Create coroutines for all targets
        tasks = [
            self._scan_target(target, progress, overall_task)
            for target in self.targets
        ]
        
        # Run with concurrency handled by semaphore inside _scan_target
        # await asyncio.gather(*tasks) # gather might not report individual failures nicely?
        # Actually it's better to use as_completed or similar if we want streaming updates
        
        # We'll use gather for simplicity as _scan_target handles errors
        self.results = await asyncio.gather(*tasks)
        
        return self.results
    
    async def _scan_target(
        self,
        target: str,
        progress: Progress,
        overall_task: TaskID,
    ) -> BulkResult:
        """Scan a single target with semaphore protection."""
        async with self._sem:
            target = self._normalize_url(target)
            start_time = datetime.utcnow()
            
            # Create target-specific output directory
            domain_name = urlparse(target).netloc or target.replace("/", "_")
            target_output = self.settings.output.output_dir / domain_name
            target_output.mkdir(parents=True, exist_ok=True)
            
            # Create task for this target (hidden initially?)
            # For 300+ targets, showing 300 tasks is bad. 
            # We only show active ones or just update the main bar?
            # Let's just log to console and update main bar.
            
            try:
                # Clone settings for this target
                # We need a deep copy or new instance to avoid shared state issues (like output dir)
                # Settings is Pydantic, so copy() works but nested models might need care
                # safest is to create new orchestrator with modified settings
                
                target_settings = self.settings.model_copy(deep=True)
                target_settings.output.output_dir = target_output
                target_settings.target_url = target
                # disable browser GUI for bulk
                target_settings.harvester.headless = True 
                
                orchestrator = FullScanOrchestrator(target_settings)
                
                # Run scan (without its own progress bar if possible? 
                # Orchestrator uses passed progress or creates one.
                # We need to adapt Orchestrator to accept existing progress?
                # Currently FullScanOrchestrator creates its own Live display.
                # This conflicts with our Bulk progress.
                # We need to run it in "silent" mode or adapt it.
                # For now, let's capture its output or suppress it.
                
                # TODO: Refactor Orchestrator to accept progress or run silently.
                # For now, we will assume standard run and it might get messy with nested Live displays.
                # Hack: We can't change orchestrator easily right now without Refactor.
                # We will suppress orchestrator output by mocking console?
                
                # Let's modify Orchestrator.run() to take a `silent=True` flag in future refactor.
                # For this implementation, we'll accept the noise or try to capture it.
                
                # Actually, simplest is to just await the scan logic directly without the CLI wrapper visual.
                # Orchestrator.run() calls self.run_pipeline().
                
                report = await orchestrator.run_pipeline()
                
                duration = (datetime.utcnow() - start_time).total_seconds()
                
                progress.advance(overall_task)
                
                return BulkResult(
                    target=target,
                    status="success",
                    endpoints_found=report.total_endpoints_discovered,
                    secrets_found=len(report.secrets),
                    duration_seconds=duration,
                    report_path=target_output / "report.json"
                )
                
            except Exception as e:
                progress.console.print(f"[red]Failed to scan {target}: {str(e)}[/red]")
                progress.advance(overall_task)
                return BulkResult(
                    target=target,
                    status="failed",
                    error=str(e),
                    duration_seconds=(datetime.utcnow() - start_time).total_seconds()
                )

    def _normalize_url(self, url: str) -> str:
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            return f"https://{url}"
        return url

    def generate_master_report(self) -> Dict[str, Any]:
        """Generate aggregated report for all targets."""
        return {
            "summary": {
                "total_targets": len(self.targets),
                "successful": len([r for r in self.results if r.status == "success"]),
                "failed": len([r for r in self.results if r.status == "failed"]),
                "total_endpoints": sum(r.endpoints_found for r in self.results),
                "total_secrets": sum(r.secrets_found for r in self.results),
                "scan_date": datetime.utcnow().isoformat(),
            },
            "targets": [
                {
                    "url": r.target,
                    "status": r.status,
                    "endpoints": r.endpoints_found,
                    "secrets": r.secrets_found,
                    "duration": r.duration_seconds,
                    "error": r.error,
                    "report_file": str(r.report_path) if r.report_path else None
                }
                for r in self.results
            ]
        }
