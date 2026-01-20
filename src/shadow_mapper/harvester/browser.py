"""Playwright-based browser harvester for JavaScript asset collection."""

from __future__ import annotations

import asyncio
import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse

from rich.console import Console

from shadow_mapper.core.config import Settings
from shadow_mapper.core.safety import ScopeEnforcer

console = Console()


@dataclass
class HarvestedAsset:
    """Represents a harvested asset file."""
    
    url: str
    local_path: Path
    content_type: str
    size_bytes: int
    is_source_map: bool = False
    original_url: Optional[str] = None  # For source maps, the parent JS file


@dataclass
class BrowserHarvestResult:
    """Result of browser-based harvesting."""
    
    assets: list[HarvestedAsset] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    page_title: str = ""
    final_url: str = ""
    
    @property
    def js_files(self) -> list[HarvestedAsset]:
        return [a for a in self.assets if not a.is_source_map]
    
    @property
    def source_maps(self) -> list[HarvestedAsset]:
        return [a for a in self.assets if a.is_source_map]


class BrowserHarvester:
    """Uses Playwright to harvest JavaScript assets from web pages."""
    
    # JavaScript content types
    JS_CONTENT_TYPES = {
        "application/javascript",
        "text/javascript",
        "application/x-javascript",
        "application/ecmascript",
        "text/ecmascript",
    }
    
    # Source map pattern in JS files
    SOURCE_MAP_PATTERN = re.compile(r'//[#@]\s*sourceMappingURL=(.+?)(?:\s|$)')
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.scope_enforcer = ScopeEnforcer(settings.scope)
        self._playwright = None
        self._browser = None
    
    async def __aenter__(self):
        """Async context manager entry."""
        from playwright.async_api import async_playwright
        
        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(
            headless=True,
            args=[
                "--disable-dev-shm-usage",
                "--no-sandbox",
                "--disable-setuid-sandbox",
            ],
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()
    
    async def harvest(
        self,
        url: str,
        output_dir: Path,
    ) -> BrowserHarvestResult:
        """
        Harvest JavaScript assets from a URL.
        
        Args:
            url: Target URL to harvest from
            output_dir: Directory to save harvested files
            
        Returns:
            BrowserHarvestResult with harvested assets and metadata
        """
        result = BrowserHarvestResult()
        
        # Validate scope
        self.scope_enforcer.validate(url)
        
        # Ensure output directory exists
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Track downloaded assets to avoid duplicates
        downloaded_urls: set[str] = set()
        
        if not self._browser:
            raise RuntimeError("BrowserHarvester must be used as async context manager")
        
        context = await self._browser.new_context(
            user_agent=self.settings.prober.user_agent,
            ignore_https_errors=not self.settings.prober.verify_ssl,
        )
        
        page = await context.new_page()
        
        # Set up response interception
        async def handle_response(response):
            try:
                content_type = response.headers.get("content-type", "")
                resp_url = response.url
                
                # Check if it's a JavaScript file
                is_js = any(ct in content_type.lower() for ct in self.JS_CONTENT_TYPES)
                is_js = is_js or resp_url.endswith(".js") or ".js?" in resp_url
                
                if not is_js:
                    return
                
                # Skip if already downloaded or out of scope
                if resp_url in downloaded_urls:
                    return
                
                if not self.scope_enforcer.is_allowed(resp_url):
                    return
                
                # Check size limit
                content_length = response.headers.get("content-length")
                if content_length:
                    size_mb = int(content_length) / (1024 * 1024)
                    if size_mb > self.settings.harvester.max_js_size_mb:
                        console.print(f"  [yellow]Skipping large file: {resp_url} ({size_mb:.1f}MB)[/yellow]")
                        return
                
                # Download the file
                try:
                    body = await response.body()
                except Exception:
                    return
                
                # Generate local path
                local_path = self._url_to_path(resp_url, output_dir)
                local_path.parent.mkdir(parents=True, exist_ok=True)
                
                # Save file
                with open(local_path, "wb") as f:
                    f.write(body)
                
                asset = HarvestedAsset(
                    url=resp_url,
                    local_path=local_path,
                    content_type=content_type,
                    size_bytes=len(body),
                )
                result.assets.append(asset)
                downloaded_urls.add(resp_url)
                
                console.print(f"  [dim]Downloaded: {resp_url}[/dim]")
                
                # Check for source map
                if self.settings.harvester.extract_source_maps:
                    await self._extract_source_map(
                        body.decode("utf-8", errors="ignore"),
                        resp_url,
                        output_dir,
                        result,
                        downloaded_urls,
                    )
                
            except Exception as e:
                result.errors.append(f"Error processing {response.url}: {str(e)}")
        
        page.on("response", handle_response)
        
        try:
            # Navigate to page
            console.print(f"  [cyan]Navigating to {url}...[/cyan]")
            
            response = await page.goto(
                url,
                wait_until="networkidle" if self.settings.harvester.wait_for_idle else "load",
                timeout=self.settings.harvester.browser_timeout,
            )
            
            if response:
                result.final_url = response.url
            
            result.page_title = await page.title()
            
            # Wait a bit more for any lazy-loaded scripts
            await asyncio.sleep(2)
            
            # Also extract inline scripts
            await self._extract_inline_scripts(page, output_dir, result)
            
        except Exception as e:
            result.errors.append(f"Navigation error: {str(e)}")
        
        finally:
            await context.close()
        
        return result
    
    async def _extract_source_map(
        self,
        js_content: str,
        js_url: str,
        output_dir: Path,
        result: BrowserHarvestResult,
        downloaded_urls: set[str],
    ) -> None:
        """Extract and download source map if present."""
        import httpx
        
        match = self.SOURCE_MAP_PATTERN.search(js_content)
        if not match:
            return
        
        map_ref = match.group(1).strip()
        
        # Handle data URLs
        if map_ref.startswith("data:"):
            return  # Skip inline source maps for now
        
        # Resolve relative URL
        map_url = urljoin(js_url, map_ref)
        
        if map_url in downloaded_urls:
            return
        
        if not self.scope_enforcer.is_allowed(map_url):
            return
        
        try:
            async with httpx.AsyncClient(verify=self.settings.prober.verify_ssl) as client:
                resp = await client.get(
                    map_url,
                    timeout=30,
                    headers={"User-Agent": self.settings.prober.user_agent},
                )
                
                if resp.status_code == 200:
                    local_path = self._url_to_path(map_url, output_dir)
                    local_path.parent.mkdir(parents=True, exist_ok=True)
                    
                    with open(local_path, "wb") as f:
                        f.write(resp.content)
                    
                    asset = HarvestedAsset(
                        url=map_url,
                        local_path=local_path,
                        content_type="application/json",
                        size_bytes=len(resp.content),
                        is_source_map=True,
                        original_url=js_url,
                    )
                    result.assets.append(asset)
                    downloaded_urls.add(map_url)
                    
                    console.print(f"  [dim]Downloaded source map: {map_url}[/dim]")
                    
        except Exception as e:
            result.errors.append(f"Source map download error: {str(e)}")
    
    async def _extract_inline_scripts(
        self,
        page,
        output_dir: Path,
        result: BrowserHarvestResult,
    ) -> None:
        """Extract inline script tags from the page."""
        try:
            scripts = await page.evaluate("""
                () => {
                    const scripts = document.querySelectorAll('script:not([src])');
                    return Array.from(scripts).map(s => s.textContent).filter(s => s && s.length > 100);
                }
            """)
            
            for i, script_content in enumerate(scripts):
                if not script_content:
                    continue
                
                # Generate a hash-based filename
                content_hash = hashlib.md5(script_content.encode()).hexdigest()[:8]
                local_path = output_dir / "inline" / f"inline_{i}_{content_hash}.js"
                local_path.parent.mkdir(parents=True, exist_ok=True)
                
                with open(local_path, "w") as f:
                    f.write(script_content)
                
                asset = HarvestedAsset(
                    url=f"inline://script_{i}",
                    local_path=local_path,
                    content_type="application/javascript",
                    size_bytes=len(script_content),
                )
                result.assets.append(asset)
                
        except Exception as e:
            result.errors.append(f"Inline script extraction error: {str(e)}")
    
    def _url_to_path(self, url: str, base_dir: Path) -> Path:
        """Convert a URL to a local file path."""
        parsed = urlparse(url)
        
        # Use domain as subdirectory
        domain = parsed.netloc.replace(":", "_")
        
        # Get path, defaulting to index.js if empty
        path = parsed.path.strip("/") or "index.js"
        
        # Handle query strings by hashing them
        if parsed.query:
            query_hash = hashlib.md5(parsed.query.encode()).hexdigest()[:8]
            path_parts = path.rsplit(".", 1)
            if len(path_parts) == 2:
                path = f"{path_parts[0]}_{query_hash}.{path_parts[1]}"
            else:
                path = f"{path}_{query_hash}"
        
        return base_dir / domain / path
