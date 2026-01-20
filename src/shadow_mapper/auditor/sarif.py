"""SARIF report generation for CI/CD integration."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from shadow_mapper.core.models import (
    DiffResult,
    Endpoint,
    EndpointStatus,
    ScanReport,
    Secret,
    Severity,
)


class SARIFGenerator:
    """
    Generates SARIF (Static Analysis Results Interchange Format) reports.
    
    SARIF is the standard format for static analysis tools and is supported
    by GitHub Advanced Security, Azure DevOps, and other CI/CD platforms.
    """
    
    # SARIF schema version
    SCHEMA_VERSION = "2.1.0"
    SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    
    # Rule definitions
    RULES = {
        "SHADOW-API-001": {
            "id": "SHADOW-API-001",
            "name": "UndocumentedEndpoint",
            "shortDescription": {"text": "Undocumented API endpoint discovered"},
            "fullDescription": {
                "text": "An API endpoint was discovered that is not present in the official API documentation or OpenAPI specification. This may indicate a Shadow API that should be documented and secured."
            },
            "helpUri": "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
            "defaultConfiguration": {"level": "warning"},
            "properties": {"tags": ["security", "api", "shadow"]},
        },
        "SHADOW-API-002": {
            "id": "SHADOW-API-002",
            "name": "ZombieEndpoint",
            "shortDescription": {"text": "Deprecated API endpoint still active"},
            "fullDescription": {
                "text": "An API endpoint marked as deprecated is still responding. Zombie APIs often lack security updates and should be decommissioned."
            },
            "helpUri": "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
            "defaultConfiguration": {"level": "error"},
            "properties": {"tags": ["security", "api", "zombie", "deprecated"]},
        },
        "SHADOW-API-003": {
            "id": "SHADOW-API-003",
            "name": "UnprotectedEndpoint",
            "shortDescription": {"text": "API endpoint accessible without authentication"},
            "fullDescription": {
                "text": "An API endpoint was found to be accessible without any authentication. This may expose sensitive data or functionality."
            },
            "helpUri": "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
            "defaultConfiguration": {"level": "error"},
            "properties": {"tags": ["security", "api", "authentication"]},
        },
        "SHADOW-API-004": {
            "id": "SHADOW-API-004",
            "name": "HardcodedSecret",
            "shortDescription": {"text": "Hardcoded secret detected in source code"},
            "fullDescription": {
                "text": "A potential secret (API key, token, password) was found hardcoded in the source code. Secrets should be stored securely and not committed to version control."
            },
            "helpUri": "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
            "defaultConfiguration": {"level": "error"},
            "properties": {"tags": ["security", "secrets", "credentials"]},
        },
        "SHADOW-API-005": {
            "id": "SHADOW-API-005",
            "name": "GhostEndpoint",
            "shortDescription": {"text": "Documented endpoint not responding"},
            "fullDescription": {
                "text": "An endpoint documented in the API specification is not responding. This may indicate incomplete deployment or configuration issues."
            },
            "helpUri": "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
            "defaultConfiguration": {"level": "note"},
            "properties": {"tags": ["api", "documentation"]},
        },
    }
    
    def generate(self, report: ScanReport) -> dict[str, Any]:
        """
        Generate SARIF report from a ScanReport.
        
        Args:
            report: Complete scan report
            
        Returns:
            SARIF report as dictionary
        """
        sarif = {
            "$schema": self.SCHEMA_URI,
            "version": self.SCHEMA_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Shadow-API Mapper",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/villen/shadow-api-mapper",
                            "rules": list(self.RULES.values()),
                        },
                    },
                    "results": [],
                    "invocations": [
                        {
                            "executionSuccessful": len(report.errors) == 0,
                            "startTimeUtc": report.started_at.isoformat() + "Z",
                            "endTimeUtc": (report.completed_at or datetime.utcnow()).isoformat() + "Z",
                        },
                    ],
                },
            ],
        }
        
        results = sarif["runs"][0]["results"]
        
        # Add endpoint findings
        for endpoint in report.endpoints:
            result = self._endpoint_to_result(endpoint)
            if result:
                results.append(result)
        
        # Add secret findings
        for secret in report.secrets:
            result = self._secret_to_result(secret)
            results.append(result)
        
        # Add diff results if available
        if report.diff:
            for ghost in report.diff.ghost:
                results.append({
                    "ruleId": "SHADOW-API-005",
                    "level": "note",
                    "message": {
                        "text": f"Documented endpoint not responding: {ghost.method.value} {ghost.path}",
                    },
                    "locations": [],
                })
        
        return sarif
    
    def generate_from_diff(self, diff: DiffResult) -> dict[str, Any]:
        """Generate SARIF report from a DiffResult."""
        sarif = {
            "$schema": self.SCHEMA_URI,
            "version": self.SCHEMA_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Shadow-API Mapper",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/villen/shadow-api-mapper",
                            "rules": list(self.RULES.values()),
                        },
                    },
                    "results": [],
                },
            ],
        }
        
        results = sarif["runs"][0]["results"]
        
        # Shadow APIs
        for ep in diff.shadow:
            results.append(self._endpoint_to_result(ep, force_rule="SHADOW-API-001"))
        
        # Zombie APIs
        for ep in diff.zombie:
            results.append(self._endpoint_to_result(ep, force_rule="SHADOW-API-002"))
        
        # Ghost APIs
        for spec_ep in diff.ghost:
            results.append({
                "ruleId": "SHADOW-API-005",
                "level": "note",
                "message": {
                    "text": f"Documented endpoint not responding: {spec_ep.method.value} {spec_ep.path}",
                },
                "locations": [],
            })
        
        return sarif
    
    def _endpoint_to_result(
        self,
        endpoint: Endpoint,
        force_rule: str | None = None,
    ) -> dict[str, Any] | None:
        """Convert an Endpoint to a SARIF result."""
        # Determine rule based on status
        if force_rule:
            rule_id = force_rule
        elif endpoint.status == EndpointStatus.SHADOW:
            rule_id = "SHADOW-API-001"
        elif endpoint.status == EndpointStatus.ZOMBIE:
            rule_id = "SHADOW-API-002"
        elif endpoint.status == EndpointStatus.UNPROTECTED:
            rule_id = "SHADOW-API-003"
        else:
            return None  # Don't report documented/compliant endpoints
        
        # Determine level
        level = "warning"
        if endpoint.status in [EndpointStatus.ZOMBIE, EndpointStatus.UNPROTECTED]:
            level = "error"
        
        method = endpoint.method.value if hasattr(endpoint.method, 'value') else endpoint.method
        
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": f"Discovered {endpoint.status.value if hasattr(endpoint.status, 'value') else endpoint.status} endpoint: {method} {endpoint.url}",
            },
            "locations": [],
        }
        
        # Add source location if available
        if endpoint.source:
            result["locations"].append({
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": str(endpoint.source.file),
                    },
                    "region": {
                        "startLine": endpoint.source.line,
                        "startColumn": endpoint.source.column,
                    },
                },
            })
        
        # Add properties
        result["properties"] = {
            "url": endpoint.url,
            "method": method,
            "httpStatus": endpoint.http_status,
        }
        
        return result
    
    def _secret_to_result(self, secret: Secret) -> dict[str, Any]:
        """Convert a Secret to a SARIF result."""
        level = "error"
        if secret.severity == Severity.LOW:
            level = "note"
        elif secret.severity == Severity.MEDIUM:
            level = "warning"
        
        result: dict[str, Any] = {
            "ruleId": "SHADOW-API-004",
            "level": level,
            "message": {
                "text": f"Hardcoded {secret.type} detected",
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": str(secret.source.file),
                        },
                        "region": {
                            "startLine": secret.source.line,
                            "startColumn": secret.source.column,
                        },
                    },
                },
            ],
            "properties": {
                "secretType": secret.type,
                "severity": secret.severity.value if hasattr(secret.severity, 'value') else secret.severity,
            },
        }
        
        return result


def generate_sarif(report: ScanReport) -> dict[str, Any]:
    """Convenience function to generate SARIF from a ScanReport."""
    generator = SARIFGenerator()
    return generator.generate(report)
