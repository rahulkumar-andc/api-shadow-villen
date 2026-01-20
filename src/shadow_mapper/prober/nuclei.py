"""Nuclei vulnerability scanner integration."""

from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from rich.console import Console

from shadow_mapper.core.config import Settings

console = Console()


@dataclass
class NucleiResult:
    """Result from a Nuclei scan."""
    
    template_id: str
    name: str
    severity: str
    host: str
    matched_at: str
    extracted_results: list[str] = field(default_factory=list)
    curl_command: str = ""
    description: str = ""


@dataclass
class NucleiScanResult:
    """Complete result from a Nuclei scan."""
    
    findings: list[NucleiResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scanned_count: int = 0


class NucleiScanner:
    """
    Wrapper for Nuclei vulnerability scanner.
    
    Nuclei must be installed separately: https://nuclei.projectdiscovery.io/
    """
    
    # Templates to use for API scanning
    API_TEMPLATES = [
        "exposures/",
        "misconfiguration/",
        "vulnerabilities/",
        "cves/",
        "default-logins/",
        "exposed-panels/",
        "technologies/",
    ]
    
    # API-specific template tags
    API_TAGS = [
        "api",
        "swagger",
        "graphql",
        "rest",
        "oauth",
        "jwt",
        "cors",
        "ssrf",
        "idor",
    ]
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self._nuclei_path: Optional[str] = None
    
    def is_available(self) -> bool:
        """Check if Nuclei is installed and available."""
        self._nuclei_path = shutil.which("nuclei")
        return self._nuclei_path is not None
    
    async def scan(
        self,
        urls: list[str],
        templates: Optional[list[str]] = None,
        tags: Optional[list[str]] = None,
        severity: str = "low,medium,high,critical",
    ) -> NucleiScanResult:
        """
        Run Nuclei scan on a list of URLs.
        
        Args:
            urls: List of URLs to scan
            templates: Specific template directories to use
            tags: Template tags to filter by
            severity: Severity levels to include
            
        Returns:
            NucleiScanResult with findings
        """
        result = NucleiScanResult(scanned_count=len(urls))
        
        if not self.is_available():
            result.errors.append("Nuclei is not installed. Install from https://nuclei.projectdiscovery.io/")
            console.print("  [yellow]Nuclei not found, skipping vulnerability scan[/yellow]")
            return result
        
        # Create temporary files for input and output
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as targets_file:
            for url in urls:
                targets_file.write(f"{url}\n")
            targets_path = targets_file.name
        
        output_path = tempfile.mktemp(suffix=".json")
        
        try:
            # Build command
            cmd = [
                self._nuclei_path,
                "-l", targets_path,
                "-json-export", output_path,
                "-silent",
                "-severity", severity,
                "-timeout", str(self.settings.prober.timeout),
                "-rate-limit", str(int(self.settings.rate_limit.requests_per_second)),
            ]
            
            # Add templates or tags
            if templates:
                for template in templates:
                    cmd.extend(["-t", template])
            elif tags:
                cmd.extend(["-tags", ",".join(tags)])
            else:
                # Use default API-focused tags
                cmd.extend(["-tags", ",".join(self.API_TAGS)])
            
            console.print(f"  [dim]Running: {' '.join(cmd[:5])}...[/dim]")
            
            # Run Nuclei
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=300,  # 5 minute timeout
            )
            
            if process.returncode != 0:
                error_msg = stderr.decode() if stderr else "Unknown error"
                result.errors.append(f"Nuclei error: {error_msg}")
            
            # Parse results
            if Path(output_path).exists():
                with open(output_path) as f:
                    for line in f:
                        try:
                            finding = json.loads(line.strip())
                            result.findings.append(NucleiResult(
                                template_id=finding.get("template-id", ""),
                                name=finding.get("info", {}).get("name", ""),
                                severity=finding.get("info", {}).get("severity", ""),
                                host=finding.get("host", ""),
                                matched_at=finding.get("matched-at", ""),
                                extracted_results=finding.get("extracted-results", []),
                                curl_command=finding.get("curl-command", ""),
                                description=finding.get("info", {}).get("description", ""),
                            ))
                        except json.JSONDecodeError:
                            continue
            
            if result.findings:
                console.print(f"  [yellow]⚠ Found {len(result.findings)} potential vulnerabilities[/yellow]")
            else:
                console.print(f"  [green]No vulnerabilities found[/green]")
                
        except asyncio.TimeoutError:
            result.errors.append("Nuclei scan timed out")
        except Exception as e:
            result.errors.append(f"Nuclei scan error: {str(e)}")
        finally:
            # Cleanup
            Path(targets_path).unlink(missing_ok=True)
            Path(output_path).unlink(missing_ok=True)
        
        return result
    
    async def update_templates(self) -> bool:
        """Update Nuclei templates to latest version."""
        if not self.is_available():
            return False
        
        try:
            process = await asyncio.create_subprocess_exec(
                self._nuclei_path,
                "-update-templates",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            await asyncio.wait_for(process.communicate(), timeout=120)
            return process.returncode == 0
            
        except Exception:
            return False
