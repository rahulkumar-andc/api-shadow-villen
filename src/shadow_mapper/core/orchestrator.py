"""Main orchestrator for full scan pipeline."""

from __future__ import annotations

import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console

from shadow_mapper.core.config import Settings
from shadow_mapper.core.models import (
    Endpoint,
    EndpointStatus,
    ScanReport,
    Secret,
)
from shadow_mapper.core.safety import ScopeEnforcer

console = Console()


class FullScanOrchestrator:
    """Orchestrates the full scan pipeline: Harvest → Parse → Probe → Audit."""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.scope_enforcer = ScopeEnforcer(settings.scope)
    
    async def run(
        self,
        target: str,
        spec_path: Optional[Path] = None,
        include_wayback: bool = True,
        run_nuclei: bool = False,
    ) -> ScanReport:
        """Execute the full discovery pipeline."""
        from shadow_mapper.harvester import HarvesterOrchestrator
        from shadow_mapper.parser import ParserEngine
        from shadow_mapper.prober import ProberEngine
        from shadow_mapper.auditor import AuditEngine
        
        scan_id = str(uuid.uuid4())[:8]
        started_at = datetime.utcnow()
        start_time = time.time()
        
        # Validate scope
        self.scope_enforcer.validate(target)
        
        all_endpoints: list[Endpoint] = []
        all_secrets: list[Secret] = []
        errors: list[str] = []
        warnings: list[str] = []
        
        # Create output directory
        output_dir = self.settings.output.output_dir
        output_dir.mkdir(parents=True, exist_ok=True)
        cache_dir = output_dir / "cache"
        
        # Step 1: Harvest
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
        except Exception as e:
            errors.append(f"Harvest error: {str(e)}")
            console.print(f"  [red]✗ Harvest failed: {e}[/red]")
        
        # Step 2: Parse
        console.print("\n[bold cyan]Step 2/4: Parsing source files...[/bold cyan]")
        try:
            parser = ParserEngine(self.settings)
            parse_results = parser.parse_directory(cache_dir)
            
            for result in parse_results:
                all_endpoints.extend(result.endpoints)
                all_secrets.extend(result.secrets)
                errors.extend(result.errors)
            
            console.print(f"  [green]✓ Found {len(all_endpoints)} endpoints in {len(parse_results)} files[/green]")
            if all_secrets:
                console.print(f"  [yellow]⚠ Found {len(all_secrets)} secrets[/yellow]")
        except Exception as e:
            errors.append(f"Parse error: {str(e)}")
            console.print(f"  [red]✗ Parse failed: {e}[/red]")
        
        # Step 3: Probe
        console.print("\n[bold cyan]Step 3/4: Probing endpoints...[/bold cyan]")
        verified_count = 0
        if all_endpoints and not self.settings.dry_run:
            try:
                prober = ProberEngine(self.settings)
                probe_results = await prober.probe_endpoints(
                    all_endpoints,
                    run_nuclei=run_nuclei,
                )
                
                # Update endpoint statuses
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
                
                active = sum(1 for r in probe_results if r.success and r.http_status and r.http_status < 400)
                console.print(f"  [green]✓ Verified {verified_count}, Active: {active}[/green]")
            except Exception as e:
                errors.append(f"Probe error: {str(e)}")
                console.print(f"  [red]✗ Probe failed: {e}[/red]")
        else:
            console.print("  [yellow]⚠ Skipped (no endpoints or dry run)[/yellow]")
        
        # Step 4: Audit
        console.print("\n[bold cyan]Step 4/4: Auditing against spec...[/bold cyan]")
        diff_result = None
        if spec_path and spec_path.exists():
            try:
                auditor = AuditEngine(self.settings)
                diff_result = auditor.compare(all_endpoints, spec_path)
                
                # Update statuses based on diff
                shadow_sigs = {ep.signature() for ep in diff_result.shadow}
                for ep in all_endpoints:
                    if ep.signature() in shadow_sigs:
                        ep.status = EndpointStatus.SHADOW
                
                console.print(f"  [green]✓ Documented: {len(diff_result.documented)}[/green]")
                if diff_result.shadow:
                    console.print(f"  [red]⚠ Shadow APIs: {len(diff_result.shadow)}[/red]")
                if diff_result.zombie:
                    console.print(f"  [red]⚠ Zombie APIs: {len(diff_result.zombie)}[/red]")
            except Exception as e:
                errors.append(f"Audit error: {str(e)}")
                console.print(f"  [red]✗ Audit failed: {e}[/red]")
        else:
            console.print("  [yellow]⚠ Skipped (no spec provided)[/yellow]")
        
        # Build report
        duration = time.time() - start_time
        
        return ScanReport(
            scan_id=scan_id,
            target=target,
            started_at=started_at,
            completed_at=datetime.utcnow(),
            duration_seconds=duration,
            dry_run=self.settings.dry_run,
            total_files_scanned=len(parse_results) if 'parse_results' in locals() else 0,
            total_endpoints_discovered=len(all_endpoints),
            total_endpoints_verified=verified_count,
            endpoints=all_endpoints,
            secrets=all_secrets,
            diff=diff_result,
            errors=errors,
            warnings=warnings,
        )
