"""Main orchestrator for full scan pipeline."""

from __future__ import annotations

import time
import traceback
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console

from shadow_mapper.core.checkpoint import (
    CheckpointManager,
    ScanCheckpoint,
    deserialize_endpoints,
    serialize_endpoints,
    serialize_secrets,
)
from shadow_mapper.core.config import Settings
from shadow_mapper.core.exceptions import (
    AuditError,
    HarvestError,
    ParserError,
    ProbeError,
    ShadowMapperError,
)
from shadow_mapper.core.models import (
    Endpoint,
    EndpointStatus,
    ScanReport,
    Secret,
)
from shadow_mapper.core.safety import ScopeEnforcer, ScopeViolationError

console = Console()


class FullScanOrchestrator:
    """Orchestrates the full scan pipeline: Harvest → Parse → Probe → Audit."""

    STEP_HARVEST = 1
    STEP_PARSE = 2
    STEP_PROBE = 3
    STEP_AUDIT = 4

    def __init__(self, settings: Settings):
        self.settings = settings
        self.scope_enforcer = ScopeEnforcer(settings.scope)

    async def run_pipeline(self) -> ScanReport:
        """
        Alias for bulk scanning — runs pipeline with settings.target_url.
        Called by BulkScanOrchestrator.
        """
        target = self.settings.target_url or ""
        if not target:
            raise ValueError("target_url must be set in settings for run_pipeline()")
        return await self.run(
            target=target,
            spec_path=None,
            include_wayback=False,
            run_nuclei=False,
            resume=False,
        )

    async def run(
        self,
        target: str,
        spec_path: Optional[Path] = None,
        include_wayback: bool = True,
        run_nuclei: bool = False,
        resume: bool = False,
    ) -> ScanReport:
        """Execute the full discovery pipeline."""
        from shadow_mapper.harvester import HarvesterOrchestrator
        from shadow_mapper.parser import ParserEngine
        from shadow_mapper.prober import ProberEngine
        from shadow_mapper.auditor import AuditEngine

        output_dir = self.settings.output.output_dir
        output_dir.mkdir(parents=True, exist_ok=True)
        cache_dir = output_dir / "cache"

        checkpoint_mgr = CheckpointManager(output_dir)

        scan_id = str(uuid.uuid4())[:8]
        started_at = datetime.utcnow()
        start_time = time.time()
        completed_steps: list[int] = []
        all_endpoints: list[Endpoint] = []
        all_secrets: list[Secret] = []
        errors: list[str] = []
        warnings: list[str] = []
        parse_results = []

        if resume and checkpoint_mgr.exists():
            try:
                checkpoint = checkpoint_mgr.load()
                if checkpoint and checkpoint.target == target:
                    console.print(f"[yellow]Resuming scan {checkpoint.scan_id}[/yellow]")
                    scan_id = checkpoint.scan_id
                    started_at = datetime.fromisoformat(checkpoint.started_at)
                    completed_steps = checkpoint.completed_steps
                    all_endpoints = deserialize_endpoints(checkpoint.endpoints)
                    errors = checkpoint.errors
                    warnings = checkpoint.warnings
                else:
                    console.print("[yellow]Checkpoint target mismatch, starting fresh[/yellow]")
            except Exception as e:
                console.print(f"[yellow]Could not load checkpoint: {e}[/yellow]")

        # Validate scope
        self.scope_enforcer.validate(target)

        checkpoint = ScanCheckpoint(
            scan_id=scan_id,
            target=target,
            started_at=started_at.isoformat(),
            current_step=0,
            completed_steps=completed_steps,
            harvest_cache_dir=str(cache_dir),
            endpoints=serialize_endpoints(all_endpoints),
            errors=errors,
            warnings=warnings,
        )

        verified_count = 0
        diff_result = None

        # Step 1: Harvest
        if self.STEP_HARVEST not in completed_steps:
            console.print("\n[bold cyan]Step 1/4: Harvesting assets...[/bold cyan]")
            try:
                harvester = HarvesterOrchestrator(self.settings)
                harvest_result = await harvester.harvest(
                    target=target,
                    output_dir=cache_dir,
                    include_wayback=include_wayback,
                    enumerate_subdomains=False,
                )
                console.print(f"  [green]✓ Harvested {harvest_result.file_count} files[/green]")
                checkpoint.current_step = self.STEP_HARVEST
                checkpoint.completed_steps.append(self.STEP_HARVEST)
                checkpoint.harvest_file_count = harvest_result.file_count
                checkpoint_mgr.save(checkpoint)
            except ScopeViolationError:
                raise
            except HarvestError as e:
                errors.append(f"Harvest error: {str(e)}")
                console.print(f"  [red]✗ Harvest failed: {e}[/red]")
            except Exception as e:
                console.print(f"  [red]✗ Unexpected harvest error: {e}[/red]")
                errors.append(f"Unexpected harvest error: {str(e)}")
        else:
            console.print("\n[bold cyan]Step 1/4: Harvesting...[/bold cyan] [green]✓ (resumed)[/green]")

        # Step 2: Parse
        if self.STEP_PARSE not in completed_steps:
            console.print("\n[bold cyan]Step 2/4: Parsing source files...[/bold cyan]")
            try:
                parser = ParserEngine(self.settings)
                parse_results = parser.parse_directory(cache_dir)
                for result in parse_results:
                    all_endpoints.extend(result.endpoints)
                    all_secrets.extend(result.secrets)
                    errors.extend(result.errors)
                console.print(
                    f"  [green]✓ Found {len(all_endpoints)} endpoints "
                    f"in {len(parse_results)} files[/green]"
                )
                if all_secrets:
                    console.print(f"  [yellow]⚠ Found {len(all_secrets)} secrets[/yellow]")
                checkpoint.current_step = self.STEP_PARSE
                checkpoint.completed_steps.append(self.STEP_PARSE)
                checkpoint.endpoints = serialize_endpoints(all_endpoints)
                checkpoint.secrets = serialize_secrets(all_secrets)
                checkpoint.errors = errors
                checkpoint_mgr.save(checkpoint)
            except ParserError as e:
                errors.append(f"Parse error: {str(e)}")
                console.print(f"  [red]✗ Parse failed: {e}[/red]")
            except Exception as e:
                console.print(f"  [red]✗ Unexpected parse error: {e}[/red]")
                errors.append(f"Unexpected parse error: {str(e)}")
        else:
            console.print("\n[bold cyan]Step 2/4: Parsing...[/bold cyan] [green]✓ (resumed)[/green]")

        # Step 3: Probe
        if self.STEP_PROBE not in completed_steps:
            console.print("\n[bold cyan]Step 3/4: Probing endpoints...[/bold cyan]")
            if all_endpoints and not self.settings.dry_run:
                try:
                    prober = ProberEngine(self.settings)
                    probe_results = await prober.probe_endpoints(
                        all_endpoints, run_nuclei=run_nuclei,
                    )
                    for probe_result in probe_results:
                        ep = probe_result.endpoint
                        if probe_result.success:
                            verified_count += 1
                            if probe_result.http_status:
                                ep.http_status = probe_result.http_status
                                if probe_result.http_status < 400:
                                    ep.status = EndpointStatus.VERIFIED
                                elif probe_result.http_status in [401, 403]:
                                    ep.status = EndpointStatus.PROTECTED
                            if probe_result.has_deprecation_header:
                                ep.status = EndpointStatus.ZOMBIE
                                ep.deprecation_date = probe_result.deprecation_date
                        else:
                            ep.status = EndpointStatus.DEAD
                    active = sum(
                        1 for r in probe_results
                        if r.success and r.http_status and r.http_status < 400
                    )
                    console.print(
                        f"  [green]✓ Verified {verified_count}, Active: {active}[/green]"
                    )
                    checkpoint.current_step = self.STEP_PROBE
                    checkpoint.completed_steps.append(self.STEP_PROBE)
                    checkpoint.endpoints = serialize_endpoints(all_endpoints)
                    checkpoint_mgr.save(checkpoint)
                except ProbeError as e:
                    errors.append(f"Probe error: {str(e)}")
                    console.print(f"  [red]✗ Probe failed: {e}[/red]")
                except Exception as e:
                    console.print(f"  [red]✗ Unexpected probe error: {e}[/red]")
                    errors.append(f"Unexpected probe error: {str(e)}")
            else:
                console.print("  [yellow]⚠ Skipped (no endpoints or dry run)[/yellow]")
        else:
            console.print("\n[bold cyan]Step 3/4: Probing...[/bold cyan] [green]✓ (resumed)[/green]")

        # Step 4: Audit
        if self.STEP_AUDIT not in completed_steps:
            console.print("\n[bold cyan]Step 4/4: Auditing against spec...[/bold cyan]")
            if spec_path and spec_path.exists():
                try:
                    auditor = AuditEngine(self.settings)
                    diff_result = auditor.compare(all_endpoints, spec_path)
                    shadow_sigs = {ep.signature() for ep in diff_result.shadow}
                    for ep in all_endpoints:
                        if ep.signature() in shadow_sigs:
                            ep.status = EndpointStatus.SHADOW
                    console.print(
                        f"  [green]✓ Documented: {len(diff_result.documented)}[/green]"
                    )
                    if diff_result.shadow:
                        console.print(f"  [red]⚠ Shadow APIs: {len(diff_result.shadow)}[/red]")
                    if diff_result.zombie:
                        console.print(f"  [red]⚠ Zombie APIs: {len(diff_result.zombie)}[/red]")
                    checkpoint.current_step = self.STEP_AUDIT
                    checkpoint.completed_steps.append(self.STEP_AUDIT)
                except AuditError as e:
                    errors.append(f"Audit error: {str(e)}")
                    console.print(f"  [red]✗ Audit failed: {e}[/red]")
                except Exception as e:
                    console.print(f"  [red]✗ Unexpected audit error: {e}[/red]")
                    errors.append(f"Unexpected audit error: {str(e)}")
            else:
                console.print("  [yellow]⚠ Skipped (no spec provided)[/yellow]")
        else:
            console.print("\n[bold cyan]Step 4/4: Auditing...[/bold cyan] [green]✓ (resumed)[/green]")

        checkpoint_mgr.cleanup()

        duration = time.time() - start_time
        return ScanReport(
            scan_id=scan_id,
            target=target,
            started_at=started_at,
            completed_at=datetime.utcnow(),
            duration_seconds=duration,
            dry_run=self.settings.dry_run,
            total_files_scanned=len(parse_results) if parse_results else 0,
            total_endpoints_discovered=len(all_endpoints),
            total_endpoints_verified=verified_count,
            endpoints=all_endpoints,
            secrets=all_secrets,
            diff=diff_result,
            errors=errors,
            warnings=warnings,
        )
