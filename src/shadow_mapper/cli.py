"""Shadow-API Mapper CLI - Main entry point."""

from __future__ import annotations

import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from shadow_mapper import __version__
from shadow_mapper.core.config import Settings
from shadow_mapper.core.safety import display_legal_disclaimer

app = typer.Typer(
    name="shadow-mapper",
    help="🕵️ Shadow-API Mapper - Discover hidden and deprecated API endpoints",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()


def version_callback(value: bool) -> None:
    """Display version and exit."""
    if value:
        console.print(f"Shadow-API Mapper v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit",
    ),
) -> None:
    """Shadow-API Mapper - Automated Shadow and Zombie API Discovery."""
    pass


@app.command()
def harvest(
    target: str = typer.Argument(..., help="Target URL to harvest assets from"),
    output: Path = typer.Option(Path("./cache"), help="Output directory for cached assets"),
    config: Optional[Path] = typer.Option(None, help="Path to configuration file"),
    source_maps: bool = typer.Option(True, "--source-maps/--no-source-maps", help="Extract source maps"),
    wayback: bool = typer.Option(True, "--wayback/--no-wayback", help="Include Wayback Machine archives"),
    subdomains: bool = typer.Option(False, "--subdomains/--no-subdomains", help="Enumerate subdomains"),
    dry_run: bool = typer.Option(False, "--dry-run/--no-dry-run", help="Show what would be done without executing"),
) -> None:
    """
    🕷️ Harvest JavaScript and assets from a target URL.
    
    Uses Playwright to render the page and intercept all JavaScript files,
    optionally downloading source maps and historical versions.
    """
    import asyncio
    from shadow_mapper.harvester import HarvesterOrchestrator
    
    settings = Settings.from_file_or_default(config)
    settings.dry_run = dry_run
    settings.harvester.extract_source_maps = source_maps
    
    display_legal_disclaimer()
    
    console.print(Panel.fit(
        f"[bold cyan]Target:[/bold cyan] {target}\n"
        f"[bold cyan]Output:[/bold cyan] {output}\n"
        f"[bold cyan]Source Maps:[/bold cyan] {source_maps}\n"
        f"[bold cyan]Wayback:[/bold cyan] {wayback}\n"
        f"[bold cyan]Subdomains:[/bold cyan] {subdomains}",
        title="🕷️ Harvester Configuration",
    ))
    
    if dry_run:
        console.print("[yellow]DRY RUN - No actual requests will be made[/yellow]")
        return
    
    async def run_harvest():
        harvester = HarvesterOrchestrator(settings)
        return await harvester.harvest(
            target=target,
            output_dir=output,
            include_wayback=wayback,
            enumerate_subdomains=subdomains,
        )
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task("Harvesting assets...", total=None)
        result = asyncio.run(run_harvest())
    
    console.print(f"\n[green]✓ Harvested {result.file_count} files to {output}[/green]")


@app.command()
def parse(
    source: Path = typer.Argument(..., help="Directory containing source files to parse"),
    output: Path = typer.Option(Path("./endpoints.json"), help="Output file for discovered endpoints"),
    config: Optional[Path] = typer.Option(None, help="Path to configuration file"),
    secrets: bool = typer.Option(True, "--secrets/--no-secrets", help="Detect hardcoded secrets"),
    resolve: bool = typer.Option(True, "--resolve/--no-resolve", help="Resolve variable values"),
) -> None:
    """
    🧠 Parse source files and extract API endpoints using AST analysis.
    
    Analyzes JavaScript, TypeScript, and Python files using Tree-sitter
    to identify HTTP client calls and API routes.
    """
    import json
    from shadow_mapper.parser import ParserEngine
    
    settings = Settings.from_file_or_default(config)
    settings.parser.detect_secrets = secrets
    settings.parser.resolve_variables = resolve
    
    if not source.exists():
        console.print(f"[red]Error: Source directory '{source}' does not exist[/red]")
        raise typer.Exit(1)
    
    console.print(Panel.fit(
        f"[bold cyan]Source:[/bold cyan] {source}\n"
        f"[bold cyan]Output:[/bold cyan] {output}\n"
        f"[bold cyan]Secret Detection:[/bold cyan] {secrets}\n"
        f"[bold cyan]Variable Resolution:[/bold cyan] {resolve}",
        title="🧠 Parser Configuration",
    ))
    
    parser = ParserEngine(settings)
    results = parser.parse_directory(source)
    
    # Aggregate endpoints
    all_endpoints = []
    all_secrets = []
    
    for result in results:
        all_endpoints.extend([ep.model_dump() for ep in result.endpoints])
        all_secrets.extend([s.model_dump() for s in result.secrets])
    
    # Write output
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w") as f:
        json.dump({
            "endpoints": all_endpoints,
            "secrets": all_secrets,
            "files_parsed": len(results),
        }, f, indent=2, default=str)
    
    console.print(f"\n[green]✓ Found {len(all_endpoints)} endpoints in {len(results)} files[/green]")
    if all_secrets:
        console.print(f"[yellow]⚠ Found {len(all_secrets)} potential secrets[/yellow]")
    console.print(f"[green]✓ Results written to {output}[/green]")


@app.command()
def dashboard(
    report: Path = typer.Argument(..., help="Path to JSON scan report"),
    port: int = typer.Option(8000, help="Port to run dashboard on"),
):
    """📊 Launch the interactive web dashboard."""
    from shadow_mapper.reports.dashboard import start_dashboard
    start_dashboard(report, port=port)


@app.command()
def dashboard(
    report: Path = typer.Argument(..., help="Path to JSON scan report"),
    port: int = typer.Option(8000, help="Port to run dashboard on"),
):
    """📊 Launch the interactive web dashboard."""
    from shadow_mapper.reports.dashboard import start_dashboard
    start_dashboard(report, port=port)


@app.command()
def probe(
    endpoints: Path = typer.Argument(..., help="JSON file containing endpoints to probe"),
    output: Path = typer.Option(Path("./probe-results.json"), help="Output file for probe results"),
    config: Optional[Path] = typer.Option(None, help="Path to configuration file"),
    concurrency: int = typer.Option(10, help="Number of concurrent requests"),
    dry_run: bool = typer.Option(False, "--dry-run/--no-dry-run", help="Show what would be probed without executing"),
    nuclei: bool = typer.Option(False, "--nuclei/--no-nuclei", help="Run Nuclei vulnerability scan"),
) -> None:
    """
    🎯 Probe discovered endpoints to verify they are active.
    
    Tests each endpoint with the configured HTTP methods and
    classifies responses based on status codes and headers.
    """
    import asyncio
    import json
    from shadow_mapper.prober import ProberEngine
    from shadow_mapper.core.models import Endpoint
    
    settings = Settings.from_file_or_default(config)
    settings.dry_run = dry_run
    settings.rate_limit.requests_per_second = float(concurrency)
    
    display_legal_disclaimer()
    
    if not endpoints.exists():
        console.print(f"[red]Error: Endpoints file '{endpoints}' does not exist[/red]")
        raise typer.Exit(1)
    
    with open(endpoints) as f:
        data = json.load(f)
    
    endpoint_list = [Endpoint(**ep) for ep in data.get("endpoints", [])]
    
    console.print(Panel.fit(
        f"[bold cyan]Endpoints:[/bold cyan] {len(endpoint_list)}\n"
        f"[bold cyan]Concurrency:[/bold cyan] {concurrency} req/s\n"
        f"[bold cyan]Nuclei:[/bold cyan] {nuclei}",
        title="🎯 Prober Configuration",
    ))
    
    if dry_run:
        console.print("[yellow]DRY RUN - Endpoints that would be probed:[/yellow]")
        for ep in endpoint_list[:10]:
            console.print(f"  • {ep.method.value} {ep.url}")
        if len(endpoint_list) > 10:
            console.print(f"  ... and {len(endpoint_list) - 10} more")
        return
    
    async def run_probe():
        prober = ProberEngine(settings)
        return await prober.probe_endpoints(endpoint_list, run_nuclei=nuclei)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task("Probing endpoints...", total=None)
        results = asyncio.run(run_probe())
    
    # Write results
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w") as f:
        json.dump([r.model_dump() for r in results], f, indent=2, default=str)
    
    # Summary
    active = sum(1 for r in results if r.success and r.http_status and r.http_status < 400)
    protected = sum(1 for r in results if r.http_status in [401, 403])
    zombies = sum(1 for r in results if r.has_deprecation_header)
    
    console.print(f"\n[green]✓ Probed {len(results)} endpoints[/green]")
    console.print(f"  • Active: {active}")
    console.print(f"  • Protected (401/403): {protected}")
    console.print(f"  • Zombie candidates: {zombies}")


@app.command()
def audit(
    endpoints: Path = typer.Argument(..., help="JSON file containing discovered endpoints"),
    spec: Path = typer.Option(..., help="OpenAPI specification file"),
    output: Path = typer.Option(Path("./audit-report.json"), help="Output file for audit report"),
    config: Optional[Path] = typer.Option(None, help="Path to configuration file"),
    sarif: Optional[Path] = typer.Option(None, help="Also output in SARIF format"),
) -> None:
    """
    📊 Audit discovered endpoints against an OpenAPI specification.
    
    Compares findings to the official API spec and identifies
    Shadow (undocumented) and Ghost (missing) endpoints.
    """
    import json
    from shadow_mapper.auditor import AuditEngine
    from shadow_mapper.core.models import Endpoint
    
    settings = Settings.from_file_or_default(config)
    
    if not endpoints.exists():
        console.print(f"[red]Error: Endpoints file '{endpoints}' does not exist[/red]")
        raise typer.Exit(1)
    
    if not spec.exists():
        console.print(f"[red]Error: Spec file '{spec}' does not exist[/red]")
        raise typer.Exit(1)
    
    with open(endpoints) as f:
        data = json.load(f)
    
    endpoint_list = [Endpoint(**ep) for ep in data.get("endpoints", [])]
    
    console.print(Panel.fit(
        f"[bold cyan]Endpoints:[/bold cyan] {len(endpoint_list)}\n"
        f"[bold cyan]Spec:[/bold cyan] {spec}",
        title="📊 Auditor Configuration",
    ))
    
    auditor = AuditEngine(settings)
    diff_result = auditor.compare(endpoint_list, spec)
    
    # Write results
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w") as f:
        json.dump(diff_result.model_dump(), f, indent=2, default=str)
    
    if sarif:
        sarif_report = auditor.to_sarif(diff_result)
        with open(sarif, "w") as f:
            json.dump(sarif_report, f, indent=2)
        console.print(f"[green]✓ SARIF report written to {sarif}[/green]")
    
    # Summary table
    table = Table(title="Audit Summary")
    table.add_column("Category", style="cyan")
    table.add_column("Count", justify="right")
    table.add_column("Status", style="bold")
    
    table.add_row("Documented", str(len(diff_result.documented)), "[green]✓[/green]")
    table.add_row("Shadow APIs", str(len(diff_result.shadow)), 
                  "[red]⚠[/red]" if diff_result.shadow else "[green]✓[/green]")
    table.add_row("Ghost APIs", str(len(diff_result.ghost)),
                  "[yellow]?[/yellow]" if diff_result.ghost else "[green]✓[/green]")
    table.add_row("Zombie APIs", str(len(diff_result.zombie)),
                  "[red]☠[/red]" if diff_result.zombie else "[green]✓[/green]")
    
    console.print(table)



@app.command()
def bulk(
    domains_file: Path = typer.Argument(..., help="File containing list of domains (one per line)"),
    output_dir: Path = typer.Option(Path("./bulk-results"), "--output", "-o", help="Output directory"),
    concurrency: int = typer.Option(3, help="Number of concurrent scans"),
    config: Optional[Path] = typer.Option(None, help="Config file path"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Dry run mode (validates input)"),
):
    """📦 Run bulk scan on a list of domains from a file."""
    import asyncio
    import json
    from shadow_mapper.core.bulk import BulkScanOrchestrator
    
    if not domains_file.exists():
        console.print(f"[red]Error: Domain list '{domains_file}' not found[/red]")
        raise typer.Exit(1)
        
    # Read domains
    domains = [
        line.strip() 
        for line in domains_file.read_text().splitlines() 
        if line.strip() and not line.startswith("#")
    ]
    
    if not domains:
        console.print("[red]Error: usage: No valid domains found in file[/red]")
        raise typer.Exit(1)
        
    console.print(Panel.fit(
        f"[bold cyan]Input:[/bold cyan] {domains_file} ({len(domains)} domains)\n"
        f"[bold cyan]Output:[/bold cyan] {output_dir}\n"
        f"[bold cyan]Concurrency:[/bold cyan] {concurrency}",
        title="📦 Bulk Scan Configuration",
    ))
    
    if dry_run:
        console.print("[yellow]DRY RUN: Validated input file. Exiting.[/yellow]")
        return

    # Setup settings
    settings = Settings.from_file_or_default(config)
    settings.output.output_dir = output_dir
    
    async def run_bulk():
        orchestrator = BulkScanOrchestrator(settings, domains, concurrency=concurrency)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            results = await orchestrator.run(progress)
            
        # Generate master report
        report = orchestrator.generate_master_report()
        report_path = output_dir / "master-report.json"
        
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)
            
        # Summary
        success = report["summary"]["successful"]
        failed = report["summary"]["failed"]
        
        console.print(f"\n[green]✓ Bulk scan complete![/green]")
        console.print(f"  Successful: [green]{success}[/green]")
        console.print(f"  Failed:     [red]{failed}[/red]")
        console.print(f"  Report:     {report_path}")

    try:
        if asyncio.get_event_loop().is_running():
             # If we are already in an event loop (e.g. running from script)
             # this might fail with "This event loop is already running"
             # But cli is entry point, so usually fine.
             asyncio.run(run_bulk())
        else:
             asyncio.run(run_bulk())
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Fatal error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL to scan"),
    output: Path = typer.Option(Path("./scan-output"), help="Output directory for all results"),
    config: Optional[Path] = typer.Option(None, help="Path to configuration file"),
    spec: Optional[Path] = typer.Option(None, help="OpenAPI specification for comparison"),
    sarif: Optional[Path] = typer.Option(None, help="Output SARIF report"),
    dry_run: bool = typer.Option(False, "--dry-run/--no-dry-run", help="Dry run mode"),
    skip_wayback: bool = typer.Option(False, "--skip-wayback/--include-wayback", help="Skip Wayback Machine mining"),
    nuclei: bool = typer.Option(False, "--nuclei/--no-nuclei", help="Run Nuclei vulnerability scan"),
    resume: bool = typer.Option(False, "--resume/--no-resume", help="Resume from last checkpoint if available"),
    fuzz: bool = typer.Option(False, "--fuzz/--no-fuzz", help="Enable shadow parameter fuzzing"),
) -> None:
    """
    🔍 Execute full discovery pipeline (harvest → parse → probe → audit).
    
    This is the main command that runs all stages of the Shadow-API Mapper
    against a target and produces a comprehensive report.
    
    Use --resume to continue an interrupted scan from the last checkpoint.
    """
    import asyncio
    import json
    from shadow_mapper.core.orchestrator import FullScanOrchestrator
    from shadow_mapper.core.checkpoint import CheckpointManager
    
    settings = Settings.from_file_or_default(config)
    settings.dry_run = dry_run
    settings.output.output_dir = output
    
    display_legal_disclaimer()
    
    # Check for existing checkpoint if resume requested
    if resume:
        checkpoint_mgr = CheckpointManager(output)
        if checkpoint_mgr.exists():
            info = checkpoint_mgr.get_checkpoint_info()
            if info:
                console.print(Panel.fit(
                    f"[bold yellow]Resuming scan:[/bold yellow]\\n"
                    f"Scan ID: {info['scan_id']}\\n"
                    f"Target: {info['target']}\\n"
                    f"Last step: {info['last_completed_step']}\\n"
                    f"Endpoints found: {info['endpoints_found']}",
                    title="🔄 Resume Mode",
                ))
        else:
            console.print("[yellow]No checkpoint found, starting fresh scan[/yellow]")
    
    console.print(Panel.fit(
        f"[bold cyan]Target:[/bold cyan] {target}\\n"
        f"[bold cyan]Output:[/bold cyan] {output}\\n"
        f"[bold cyan]Spec:[/bold cyan] {spec or 'None'}\\n"
        f"[bold cyan]Nuclei:[/bold cyan] {nuclei}\\n"
        f"[bold cyan]Fuzzing:[/bold cyan] {fuzz}\\n"
        f"[bold cyan]Resume:[/bold cyan] {resume}",
        title="🔍 Full Scan Configuration",
    ))
    
    if dry_run:
        console.print("[yellow]DRY RUN - Pipeline preview:[/yellow]")
        console.print("  1. Harvest: Would fetch JS from target")
        console.print("  2. Parse: Would analyze with Tree-sitter")
        console.print("  3. Probe: Would verify discovered endpoints")
        if spec:
            console.print("  4. Audit: Would compare against spec")
        return
    
    async def run_full_scan():
        orchestrator = FullScanOrchestrator(settings)
        return await orchestrator.run(
            target=target,
            spec_path=spec,
            include_wayback=not skip_wayback,
            run_nuclei=nuclei,
            resume=resume,
        )
    
    scan_id = str(uuid.uuid4())[:8]
    started_at = datetime.utcnow()
    
    console.print(f"\n[cyan]Scan ID: {scan_id}[/cyan]")
    console.print(f"[cyan]Started: {started_at.isoformat()}[/cyan]\n")
    
    # Create progress display with multiple stats
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        refresh_per_second=4,
    ) as progress:
        # Add tasks for each pipeline step
        harvest_task = progress.add_task("[cyan]Harvesting assets...", total=100)
        parse_task = progress.add_task("[blue]Parsing files...", total=100, visible=False)
        probe_task = progress.add_task("[green]Probing endpoints...", total=100, visible=False)
        audit_task = progress.add_task("[yellow]Auditing spec...", total=100, visible=False)
        
        # Stats display
        stats = {"files": 0, "endpoints": 0, "secrets": 0, "verified": 0}
        
        async def run_with_progress():
            orchestrator = FullScanOrchestrator(settings)
            
            # Run the scan (orchestrator prints its own progress)
            report = await orchestrator.run(
                target=target,
                spec_path=spec,
                include_wayback=not skip_wayback,
                run_nuclei=nuclei,
                resume=resume,
            )
            
            # Update stats from report
            stats["files"] = report.total_files_scanned
            stats["endpoints"] = report.total_endpoints_discovered
            stats["secrets"] = len(report.secrets)
            stats["verified"] = report.total_endpoints_verified
            
            return report
        
        # Simulate progress updates for visual feedback
        progress.update(harvest_task, completed=30, description="[cyan]Harvesting assets...")
        report = asyncio.run(run_with_progress())
        
        # Mark all complete
        progress.update(harvest_task, completed=100)
        progress.update(parse_task, completed=100, visible=True,
                       description=f"[blue]Parsed {stats['files']} files")
        progress.update(probe_task, completed=100, visible=True,
                       description=f"[green]Probed {stats['verified']}/{stats['endpoints']} endpoints")
        if spec:
            progress.update(audit_task, completed=100, visible=True,
                           description="[yellow]Audit complete")
    
    # Save report
    output.mkdir(parents=True, exist_ok=True)
    report_path = output / "report.json"
    with open(report_path, "w") as f:
        json.dump(report.model_dump(), f, indent=2, default=str)
    
    if sarif:
        from shadow_mapper.auditor.sarif import generate_sarif
        sarif_report = generate_sarif(report)
        with open(sarif, "w") as f:
            json.dump(sarif_report, f, indent=2)
        console.print(f"[green]✓ SARIF report: {sarif}[/green]")
    
    # Final summary
    console.print("\n" + "=" * 60)
    console.print(Panel.fit(
        f"[bold green]Scan Complete![/bold green]\n\n"
        f"Files scanned: {report.total_files_scanned}\n"
        f"Endpoints discovered: {report.total_endpoints_discovered}\n"
        f"Endpoints verified: {report.total_endpoints_verified}\n"
        f"Secrets found: {len(report.secrets)}\n"
        f"Duration: {report.duration_seconds:.2f}s",
        title="📊 Summary",
    ))


if __name__ == "__main__":
    app()
