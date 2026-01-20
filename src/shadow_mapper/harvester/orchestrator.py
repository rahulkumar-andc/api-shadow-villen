"""Harvester orchestrator - coordinates all harvesting activities."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from rich.console import Console

from shadow_mapper.core.config import Settings
from shadow_mapper.core.safety import ScopeEnforcer
from shadow_mapper.harvester.browser import BrowserHarvester
from shadow_mapper.harvester.archive import WaybackHarvester
from shadow_mapper.harvester.subdomain import SubdomainEnumerator

console = Console()


@dataclass
class HarvestResult:
    """Combined result from all harvesting activities."""
    
    file_count: int = 0
    js_files: list[Path] = field(default_factory=list)
    source_maps: list[Path] = field(default_factory=list)
    wayback_files: list[Path] = field(default_factory=list)
    subdomains: set[str] = field(default_factory=set)
    errors: list[str] = field(default_factory=list)


class HarvesterOrchestrator:
    """Orchestrates all harvesting activities."""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.scope_enforcer = ScopeEnforcer(settings.scope)
    
    async def harvest(
        self,
        target: str,
        output_dir: Path,
        include_wayback: bool = True,
        enumerate_subdomains: bool = False,
    ) -> HarvestResult:
        """
        Execute full harvesting pipeline.
        
        Args:
            target: Target URL to harvest
            output_dir: Directory for harvested assets
            include_wayback: Include Wayback Machine mining
            enumerate_subdomains: Enumerate and harvest subdomains
            
        Returns:
            HarvestResult with all harvested data
        """
        result = HarvestResult()
        
        # Validate scope
        self.scope_enforcer.validate(target)
        
        # Ensure output directory exists
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Extract domain for subdomain enumeration
        parsed = urlparse(target)
        domain = parsed.netloc
        
        # Step 1: Browser harvesting
        console.print("[cyan]Harvesting with browser...[/cyan]")
        try:
            async with BrowserHarvester(self.settings) as browser:
                browser_result = await browser.harvest(target, output_dir)
                
                for asset in browser_result.assets:
                    if asset.is_source_map:
                        result.source_maps.append(asset.local_path)
                    else:
                        result.js_files.append(asset.local_path)
                
                result.errors.extend(browser_result.errors)
                
        except Exception as e:
            result.errors.append(f"Browser harvest error: {str(e)}")
            console.print(f"  [red]Browser harvest failed: {e}[/red]")
        
        # Step 2: Wayback Machine mining
        if include_wayback:
            console.print("[cyan]Mining Wayback Machine...[/cyan]")
            try:
                wayback = WaybackHarvester(self.settings)
                wayback_result = await wayback.harvest(target, output_dir)
                
                result.wayback_files.extend(wayback_result.downloaded_files)
                result.errors.extend(wayback_result.errors)
                
            except Exception as e:
                result.errors.append(f"Wayback harvest error: {str(e)}")
                console.print(f"  [yellow]Wayback mining failed: {e}[/yellow]")
        
        # Step 3: Subdomain enumeration
        if enumerate_subdomains:
            console.print("[cyan]Enumerating subdomains...[/cyan]")
            try:
                enumerator = SubdomainEnumerator(self.settings)
                subdomain_result = await enumerator.enumerate(domain)
                
                result.subdomains = subdomain_result.subdomains
                result.errors.extend(subdomain_result.errors)
                
                # Optionally harvest each subdomain
                # For now, just save the list
                subdomains_file = output_dir / "subdomains.txt"
                with open(subdomains_file, "w") as f:
                    for subdomain in sorted(result.subdomains):
                        f.write(f"{subdomain}\n")
                
            except Exception as e:
                result.errors.append(f"Subdomain enumeration error: {str(e)}")
                console.print(f"  [yellow]Subdomain enumeration failed: {e}[/yellow]")
        
        # Calculate totals
        result.file_count = (
            len(result.js_files) +
            len(result.source_maps) +
            len(result.wayback_files)
        )
        
        return result
