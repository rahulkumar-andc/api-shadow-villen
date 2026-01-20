"""Wayback Machine integration for historical asset mining."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import httpx
from rich.console import Console

from shadow_mapper.core.config import Settings
from shadow_mapper.core.safety import ScopeEnforcer

console = Console()


@dataclass
class WaybackSnapshot:
    """Represents a Wayback Machine snapshot."""
    
    url: str
    timestamp: str
    original_url: str
    mime_type: str
    status_code: int
    
    @property
    def datetime(self) -> datetime:
        """Parse timestamp to datetime."""
        return datetime.strptime(self.timestamp, "%Y%m%d%H%M%S")
    
    @property
    def archive_url(self) -> str:
        """Get the full Wayback Machine archive URL."""
        return f"https://web.archive.org/web/{self.timestamp}id_/{self.original_url}"


@dataclass
class WaybackHarvestResult:
    """Result of Wayback Machine harvesting."""
    
    snapshots: list[WaybackSnapshot] = field(default_factory=list)
    downloaded_files: list[Path] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class WaybackHarvester:
    """Harvests historical JavaScript files from the Wayback Machine."""
    
    CDX_API = "https://web.archive.org/cdx/search/cdx"
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.scope_enforcer = ScopeEnforcer(settings.scope)
    
    async def find_js_snapshots(
        self,
        domain: str,
        months_back: Optional[int] = None,
    ) -> list[WaybackSnapshot]:
        """
        Find JavaScript file snapshots in the Wayback Machine.
        
        Args:
            domain: Domain to search for
            months_back: How many months of history to search
            
        Returns:
            List of Wayback snapshots for JS files
        """
        months = months_back or self.settings.harvester.wayback_months
        
        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=months * 30)
        
        params = {
            "url": f"{domain}/*.js",
            "matchType": "prefix",
            "output": "json",
            "fl": "timestamp,original,mimetype,statuscode",
            "filter": "statuscode:200",
            "from": start_date.strftime("%Y%m%d"),
            "to": end_date.strftime("%Y%m%d"),
            "collapse": "urlkey",  # Deduplicate by URL
            "limit": 500,
        }
        
        snapshots = []
        
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                console.print(f"  [dim]Querying Wayback Machine for {domain}...[/dim]")
                
                resp = await client.get(self.CDX_API, params=params)
                
                if resp.status_code != 200:
                    return snapshots
                
                data = resp.json()
                
                # Skip header row
                for row in data[1:] if len(data) > 1 else []:
                    if len(row) >= 4:
                        snapshot = WaybackSnapshot(
                            url=f"https://web.archive.org/web/{row[0]}id_/{row[1]}",
                            timestamp=row[0],
                            original_url=row[1],
                            mime_type=row[2],
                            status_code=int(row[3]),
                        )
                        snapshots.append(snapshot)
                
                console.print(f"  [dim]Found {len(snapshots)} historical JS files[/dim]")
                
        except Exception as e:
            console.print(f"  [yellow]Wayback query error: {e}[/yellow]")
        
        return snapshots
    
    async def download_snapshots(
        self,
        snapshots: list[WaybackSnapshot],
        output_dir: Path,
        max_concurrent: int = 5,
    ) -> WaybackHarvestResult:
        """
        Download historical JavaScript files.
        
        Args:
            snapshots: List of snapshots to download
            output_dir: Directory to save files
            max_concurrent: Maximum concurrent downloads
            
        Returns:
            WaybackHarvestResult with downloaded files
        """
        result = WaybackHarvestResult(snapshots=snapshots)
        
        # Create wayback subdirectory
        wayback_dir = output_dir / "wayback"
        wayback_dir.mkdir(parents=True, exist_ok=True)
        
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def download_one(snapshot: WaybackSnapshot) -> Optional[Path]:
            async with semaphore:
                try:
                    # Check scope
                    if not self.scope_enforcer.is_allowed(snapshot.original_url):
                        return None
                    
                    async with httpx.AsyncClient(
                        timeout=30,
                        follow_redirects=True,
                    ) as client:
                        resp = await client.get(snapshot.archive_url)
                        
                        if resp.status_code != 200:
                            return None
                        
                        # Generate local path
                        parsed = urlparse(snapshot.original_url)
                        filename = Path(parsed.path).name or "index.js"
                        
                        # Add timestamp to filename
                        local_path = wayback_dir / f"{snapshot.timestamp}_{filename}"
                        
                        with open(local_path, "wb") as f:
                            f.write(resp.content)
                        
                        return local_path
                        
                except Exception as e:
                    result.errors.append(f"Download error for {snapshot.original_url}: {e}")
                    return None
        
        # Download all snapshots concurrently
        tasks = [download_one(s) for s in snapshots]
        results = await asyncio.gather(*tasks)
        
        result.downloaded_files = [r for r in results if r is not None]
        
        console.print(f"  [dim]Downloaded {len(result.downloaded_files)} historical files[/dim]")
        
        return result
    
    async def harvest(
        self,
        target_url: str,
        output_dir: Path,
    ) -> WaybackHarvestResult:
        """
        Full Wayback Machine harvest workflow.
        
        Args:
            target_url: Target URL to search history for
            output_dir: Output directory for downloaded files
            
        Returns:
            WaybackHarvestResult with all data
        """
        # Extract domain from URL
        parsed = urlparse(target_url)
        domain = parsed.netloc
        
        # Find snapshots
        snapshots = await self.find_js_snapshots(domain)
        
        if not snapshots:
            return WaybackHarvestResult()
        
        # Download snapshots
        return await self.download_snapshots(snapshots, output_dir)
