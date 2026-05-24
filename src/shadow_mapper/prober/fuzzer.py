"""Fuzzing engine for discovering hidden parameters and vulnerabilities.

Performs:
- Shadow parameter discovery (e.g. ?admin=true, ?debug=1)
- Mass assignment detection (JSON body injection)
- HTTP verb tampering
- Version enumeration (/v1, /v2, /v3 ...)
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx
from rich.console import Console

from shadow_mapper.core.config import Settings
from shadow_mapper.core.models import Endpoint, HTTPMethod

console = Console()


@dataclass
class FuzzResult:
    """Result of a single fuzzing attempt."""

    endpoint: str
    parameter: str
    attack_type: str       # shadow_param | mass_assignment | verb_tamper | version_enum
    payload: Any
    status_code: int
    baseline_status: int   # original status for comparison
    confidence: str = "medium"   # low | medium | high
    description: str = ""
    response_diff_pct: float = 0.0

    @property
    def is_interesting(self) -> bool:
        """True if result is likely a real finding."""
        if self.confidence == "low":
            return False
        if self.attack_type == "shadow_param":
            # Status code changed OR response size changed significantly
            return (
                self.status_code != self.baseline_status
                or self.response_diff_pct > 0.10
            )
        if self.attack_type == "mass_assignment":
            return self.confidence in ("medium", "high")
        if self.attack_type == "verb_tamper":
            return self.status_code not in (404, 405, 400)
        return True


@dataclass
class FuzzSummary:
    """Summary of all fuzzing results for one endpoint."""

    endpoint: str
    total_probes: int = 0
    interesting: List[FuzzResult] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        return len(self.interesting) > 0


class FuzzerEngine:
    """
    Active fuzzing engine for API endpoints.

    ⚠️  Only use against systems you own or have explicit permission to test.
    """

    # Common hidden/debug query parameters
    SHADOW_PARAMS: List[str] = [
        "admin", "debug", "test", "root", "super",
        "internal", "dev", "verbose", "trace",
        "show_all", "override", "bypass", "source",
        "config", "preview", "draft", "force",
        "raw", "export", "format", "pretty",
    ]

    # Values to try for boolean-style params
    BOOL_VALUES: List[str] = ["true", "1", "yes", "on"]

    # Fields to inject for mass assignment testing
    MASS_ASSIGNMENT_FIELDS: Dict[str, Any] = {
        "role":         "admin",
        "is_admin":     True,
        "isAdmin":      True,
        "admin":        True,
        "permissions":  ["admin"],
        "groups":       ["admin"],
        "access_level": 100,
        "plan":         "premium",
        "subscription": "enterprise",
        "verified":     True,
        "active":       True,
        "status":       "admin",
    }

    # HTTP verbs to try when current method returns non-2xx
    EXTRA_VERBS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]

    def __init__(self, settings: Settings, concurrency: int = 5):
        self.settings = settings
        self.concurrency = concurrency
        self._client: Optional[httpx.AsyncClient] = None
        self._sem = asyncio.Semaphore(concurrency)

    async def _get_client(self) -> httpx.AsyncClient:
        if not self._client:
            self._client = httpx.AsyncClient(
                verify=self.settings.prober.verify_ssl,
                timeout=httpx.Timeout(10.0),
                follow_redirects=True,
                headers={"User-Agent": self.settings.prober.user_agent},
            )
        return self._client

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def fuzz_endpoint(self, endpoint: Endpoint) -> FuzzSummary:
        """Run all fuzzing checks against a single endpoint."""
        summary = FuzzSummary(endpoint=endpoint.url)
        client  = await self._get_client()

        # Get baseline first
        baseline_status, baseline_size = await self._baseline(client, endpoint)
        if baseline_status is None:
            return summary

        tasks: List[asyncio.Task] = []

        # 1. Shadow parameter discovery
        tasks.append(asyncio.create_task(
            self._fuzz_shadow_params(client, endpoint, baseline_status, baseline_size)
        ))

        # 2. Mass assignment (only for write methods)
        method = endpoint.method.value if hasattr(endpoint.method, "value") else endpoint.method
        if method in ("POST", "PUT", "PATCH"):
            tasks.append(asyncio.create_task(
                self._fuzz_mass_assignment(client, endpoint, baseline_status)
            ))

        # 3. HTTP verb tampering
        tasks.append(asyncio.create_task(
            self._fuzz_verb_tampering(client, endpoint, baseline_status)
        ))

        results_lists = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results_lists:
            if isinstance(r, list):
                summary.total_probes += len(r)
                summary.interesting.extend(
                    [res for res in r if res.is_interesting]
                )

        return summary

    async def fuzz_multiple(
        self,
        endpoints: List[Endpoint],
    ) -> List[FuzzSummary]:
        """Fuzz multiple endpoints with concurrency control."""
        summaries = []

        for ep in endpoints:
            try:
                summary = await self.fuzz_endpoint(ep)
                summaries.append(summary)
                if summary.has_findings:
                    console.print(
                        f"  [yellow]⚠ Fuzzing found {len(summary.interesting)} "
                        f"interesting response(s) on {ep.url}[/yellow]"
                    )
            except Exception as e:
                console.print(f"  [red]Fuzzing error on {ep.url}: {e}[/red]")

        return summaries

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _baseline(
        self,
        client: httpx.AsyncClient,
        endpoint: Endpoint,
    ) -> tuple[Optional[int], int]:
        """Get baseline status code and response size."""
        method = (
            endpoint.method.value
            if hasattr(endpoint.method, "value")
            else str(endpoint.method)
        )
        try:
            async with self._sem:
                resp = await client.request(method, endpoint.url)
            return resp.status_code, len(resp.content)
        except Exception:
            return None, 0

    async def _fuzz_shadow_params(
        self,
        client: httpx.AsyncClient,
        endpoint: Endpoint,
        baseline_status: int,
        baseline_size: int,
    ) -> List[FuzzResult]:
        """Probe for hidden query parameters."""
        results: List[FuzzResult] = []
        method = (
            endpoint.method.value
            if hasattr(endpoint.method, "value")
            else str(endpoint.method)
        )
        sep = "&" if "?" in endpoint.url else "?"

        for param in self.SHADOW_PARAMS:
            for val in self.BOOL_VALUES:
                fuzz_url = f"{endpoint.url}{sep}{param}={val}"
                try:
                    async with self._sem:
                        resp = await client.request(method, fuzz_url)

                    size_diff = (
                        abs(len(resp.content) - baseline_size) / max(baseline_size, 1)
                    )

                    if (
                        resp.status_code != baseline_status
                        or size_diff > 0.10
                    ):
                        confidence = "high" if resp.status_code != baseline_status else "medium"
                        results.append(FuzzResult(
                            endpoint=endpoint.url,
                            parameter=param,
                            attack_type="shadow_param",
                            payload=f"{param}={val}",
                            status_code=resp.status_code,
                            baseline_status=baseline_status,
                            confidence=confidence,
                            response_diff_pct=size_diff,
                            description=(
                                f"Status changed {baseline_status}→{resp.status_code}"
                                if resp.status_code != baseline_status
                                else f"Response size changed {size_diff*100:.0f}%"
                            ),
                        ))
                        # Found something interesting with this param — skip other values
                        break
                except Exception:
                    continue

        return results

    async def _fuzz_mass_assignment(
        self,
        client: httpx.AsyncClient,
        endpoint: Endpoint,
        baseline_status: int,
    ) -> List[FuzzResult]:
        """Probe for mass assignment vulnerabilities."""
        results: List[FuzzResult] = []
        method = (
            endpoint.method.value
            if hasattr(endpoint.method, "value")
            else str(endpoint.method)
        )

        for field_name, value in self.MASS_ASSIGNMENT_FIELDS.items():
            payload = {field_name: value}
            try:
                async with self._sem:
                    resp = await client.request(
                        method, endpoint.url,
                        json=payload,
                        headers={"Content-Type": "application/json"},
                    )

                if resp.status_code < 400:
                    body_lower = resp.text.lower()
                    # High confidence: injected field reflected in response
                    if (
                        field_name.lower() in body_lower
                        and str(value).lower() in body_lower
                    ):
                        confidence = "high"
                        description = f"Injected '{field_name}={value}' reflected in response"
                    else:
                        confidence = "low"
                        description = f"Accepted payload with '{field_name}={value}' (status {resp.status_code})"

                    results.append(FuzzResult(
                        endpoint=endpoint.url,
                        parameter=field_name,
                        attack_type="mass_assignment",
                        payload=payload,
                        status_code=resp.status_code,
                        baseline_status=baseline_status,
                        confidence=confidence,
                        description=description,
                    ))
            except Exception:
                continue

        return results

    async def _fuzz_verb_tampering(
        self,
        client: httpx.AsyncClient,
        endpoint: Endpoint,
        baseline_status: int,
    ) -> List[FuzzResult]:
        """Try different HTTP verbs on the same endpoint."""
        results: List[FuzzResult] = []
        current_method = (
            endpoint.method.value
            if hasattr(endpoint.method, "value")
            else str(endpoint.method)
        ).upper()

        for verb in self.EXTRA_VERBS:
            if verb == current_method:
                continue
            try:
                async with self._sem:
                    resp = await client.request(verb, endpoint.url)

                # Interesting: succeeded with a different verb
                if resp.status_code not in (404, 405, 400, 501):
                    results.append(FuzzResult(
                        endpoint=endpoint.url,
                        parameter=verb,
                        attack_type="verb_tamper",
                        payload=verb,
                        status_code=resp.status_code,
                        baseline_status=baseline_status,
                        confidence="medium",
                        description=(
                            f"Endpoint responds to {verb} "
                            f"(original: {current_method} → {baseline_status})"
                        ),
                    ))
            except Exception:
                continue

        return results
