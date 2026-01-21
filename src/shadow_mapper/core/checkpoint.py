"""Checkpoint system for resumable scans.

Allows saving and loading scan state to resume interrupted scans.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from shadow_mapper.core.exceptions import CheckpointError
from shadow_mapper.core.models import Endpoint, ScanResult, Secret


@dataclass
class ScanCheckpoint:
    """Represents the state of a scan at a checkpoint.
    
    Attributes:
        scan_id: Unique identifier for the scan
        target: Target URL being scanned
        started_at: When the scan started
        current_step: Current pipeline step (1=Harvest, 2=Parse, 3=Probe, 4=Audit)
        completed_steps: List of completed step numbers
        harvest_files: Paths to harvested files
        endpoints: Discovered endpoints (serialized)
        secrets: Discovered secrets (serialized)
        errors: Accumulated errors
        warnings: Accumulated warnings
        timestamp: When checkpoint was created
    """
    
    scan_id: str
    target: str
    started_at: str
    current_step: int = 0
    completed_steps: list[int] = field(default_factory=list)
    harvest_cache_dir: Optional[str] = None
    harvest_file_count: int = 0
    endpoints: list[dict[str, Any]] = field(default_factory=list)
    secrets: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def to_dict(self) -> dict[str, Any]:
        """Convert checkpoint to a serializable dictionary."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanCheckpoint":
        """Create checkpoint from a dictionary."""
        return cls(**data)


class CheckpointManager:
    """Manages checkpoint persistence for resumable scans.
    
    Checkpoints are stored as JSON files in the output directory.
    """
    
    CHECKPOINT_FILENAME = ".scan_checkpoint.json"
    
    def __init__(self, output_dir: Path):
        """Initialize checkpoint manager.
        
        Args:
            output_dir: Directory to store checkpoint files
        """
        self.output_dir = output_dir
        self.checkpoint_path = output_dir / self.CHECKPOINT_FILENAME
    
    def save(self, checkpoint: ScanCheckpoint) -> None:
        """Save checkpoint to disk.
        
        Args:
            checkpoint: Checkpoint state to save
            
        Raises:
            CheckpointError: If save fails
        """
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            checkpoint.timestamp = datetime.utcnow().isoformat()
            
            with open(self.checkpoint_path, "w") as f:
                json.dump(checkpoint.to_dict(), f, indent=2)
                
        except (OSError, IOError, TypeError) as e:
            raise CheckpointError(f"Failed to save checkpoint: {e}") from e
    
    def load(self) -> Optional[ScanCheckpoint]:
        """Load checkpoint from disk if it exists.
        
        Returns:
            ScanCheckpoint if exists, None otherwise
            
        Raises:
            CheckpointError: If load fails (corrupted file, etc.)
        """
        if not self.exists():
            return None
            
        try:
            with open(self.checkpoint_path, "r") as f:
                data = json.load(f)
            return ScanCheckpoint.from_dict(data)
            
        except (OSError, IOError, json.JSONDecodeError, TypeError, KeyError) as e:
            raise CheckpointError(f"Failed to load checkpoint: {e}") from e
    
    def exists(self) -> bool:
        """Check if a checkpoint exists.
        
        Returns:
            True if checkpoint file exists
        """
        return self.checkpoint_path.exists()
    
    def cleanup(self) -> None:
        """Remove checkpoint file after successful scan completion."""
        if self.checkpoint_path.exists():
            try:
                self.checkpoint_path.unlink()
            except OSError:
                pass  # Ignore cleanup failures
    
    def get_checkpoint_info(self) -> Optional[dict[str, Any]]:
        """Get summary info about existing checkpoint.
        
        Returns:
            Dictionary with checkpoint summary or None
        """
        checkpoint = self.load()
        if checkpoint is None:
            return None
            
        step_names = {
            1: "Harvest",
            2: "Parse", 
            3: "Probe",
            4: "Audit",
        }
        
        return {
            "scan_id": checkpoint.scan_id,
            "target": checkpoint.target,
            "started_at": checkpoint.started_at,
            "last_completed_step": step_names.get(checkpoint.current_step, "Unknown"),
            "endpoints_found": len(checkpoint.endpoints),
            "errors": len(checkpoint.errors),
            "timestamp": checkpoint.timestamp,
        }


def serialize_endpoints(endpoints: list[Endpoint]) -> list[dict[str, Any]]:
    """Serialize endpoints for checkpoint storage."""
    result = []
    for ep in endpoints:
        result.append({
            "url": ep.url,
            "method": ep.method.value if hasattr(ep.method, 'value') else ep.method,
            "source_file": str(ep.source.file) if ep.source else None,
            "source_line": ep.source.line if ep.source else None,
            "status": ep.status.value if hasattr(ep.status, 'value') else ep.status,
            "http_status": ep.http_status,
            "headers": ep.headers,
            "path_params": ep.path_params,
            "query_params": ep.query_params,
        })
    return result


def deserialize_endpoints(data: list[dict[str, Any]]) -> list[Endpoint]:
    """Deserialize endpoints from checkpoint storage."""
    from shadow_mapper.core.models import (
        Endpoint,
        EndpointStatus,
        HTTPMethod,
        SourceLocation,
    )
    
    result = []
    for item in data:
        source = None
        if item.get("source_file"):
            source = SourceLocation(
                file=Path(item["source_file"]),
                line=item.get("source_line", 0),
            )
        
        ep = Endpoint(
            url=item["url"],
            method=HTTPMethod(item["method"]) if item.get("method") else HTTPMethod.GET,
            source=source,
            status=EndpointStatus(item["status"]) if item.get("status") else EndpointStatus.DISCOVERED,
            http_status=item.get("http_status"),
            headers=item.get("headers", {}),
            path_params=item.get("path_params", []),
            query_params=item.get("query_params", []),
        )
        result.append(ep)
    return result


def serialize_secrets(secrets: list[Secret]) -> list[dict[str, Any]]:
    """Serialize secrets for checkpoint storage."""
    result = []
    for secret in secrets:
        result.append({
            "type": secret.type,
            "value": secret.value,
            "source_file": str(secret.source.file) if secret.source else None,
            "source_line": secret.source.line if secret.source else None,
        })
    return result
