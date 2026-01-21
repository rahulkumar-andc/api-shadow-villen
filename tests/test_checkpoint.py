"""Tests for checkpoint module."""

import json
import pytest
from pathlib import Path
from datetime import datetime

from shadow_mapper.core.checkpoint import (
    CheckpointManager,
    ScanCheckpoint,
    serialize_endpoints,
    deserialize_endpoints,
    serialize_secrets,
)
from shadow_mapper.core.exceptions import CheckpointError
from shadow_mapper.core.models import Endpoint, HTTPMethod, SourceLocation, EndpointStatus


@pytest.fixture
def temp_checkpoint_dir(tmp_path: Path) -> Path:
    """Create a temporary directory for checkpoints."""
    return tmp_path / "checkpoints"


@pytest.fixture
def sample_checkpoint() -> ScanCheckpoint:
    """Create a sample checkpoint for testing."""
    return ScanCheckpoint(
        scan_id="abc12345",
        target="https://example.com",
        started_at=datetime.utcnow().isoformat(),
        current_step=2,
        completed_steps=[1, 2],
        harvest_cache_dir="/tmp/cache",
        harvest_file_count=10,
        endpoints=[
            {
                "url": "/api/v1/users",
                "method": "GET",
                "source_file": "/tmp/app.js",
                "source_line": 42,
                "status": "unknown",
                "http_status": None,
                "headers": {},
                "params": {},
            }
        ],
        secrets=[],
        errors=["Some non-fatal error"],
        warnings=[],
    )


class TestScanCheckpoint:
    """Tests for ScanCheckpoint dataclass."""
    
    def test_to_dict(self, sample_checkpoint: ScanCheckpoint):
        """Test converting checkpoint to dictionary."""
        data = sample_checkpoint.to_dict()
        
        assert data["scan_id"] == "abc12345"
        assert data["target"] == "https://example.com"
        assert data["current_step"] == 2
        assert data["completed_steps"] == [1, 2]
        assert len(data["endpoints"]) == 1
    
    def test_from_dict(self, sample_checkpoint: ScanCheckpoint):
        """Test creating checkpoint from dictionary."""
        data = sample_checkpoint.to_dict()
        restored = ScanCheckpoint.from_dict(data)
        
        assert restored.scan_id == sample_checkpoint.scan_id
        assert restored.target == sample_checkpoint.target
        assert restored.current_step == sample_checkpoint.current_step
        assert restored.completed_steps == sample_checkpoint.completed_steps
    
    def test_default_timestamp(self):
        """Test that timestamp is set by default."""
        checkpoint = ScanCheckpoint(
            scan_id="test",
            target="https://example.com",
            started_at="2024-01-01T00:00:00",
        )
        assert checkpoint.timestamp is not None
        # Should be a valid ISO format timestamp
        datetime.fromisoformat(checkpoint.timestamp)


class TestCheckpointManager:
    """Tests for CheckpointManager class."""
    
    def test_save_creates_file(
        self,
        temp_checkpoint_dir: Path,
        sample_checkpoint: ScanCheckpoint,
    ):
        """Test that save creates checkpoint file."""
        manager = CheckpointManager(temp_checkpoint_dir)
        manager.save(sample_checkpoint)
        
        assert manager.checkpoint_path.exists()
    
    def test_save_creates_valid_json(
        self,
        temp_checkpoint_dir: Path,
        sample_checkpoint: ScanCheckpoint,
    ):
        """Test that saved checkpoint is valid JSON."""
        manager = CheckpointManager(temp_checkpoint_dir)
        manager.save(sample_checkpoint)
        
        with open(manager.checkpoint_path) as f:
            data = json.load(f)
        
        assert data["scan_id"] == sample_checkpoint.scan_id
    
    def test_load_returns_checkpoint(
        self,
        temp_checkpoint_dir: Path,
        sample_checkpoint: ScanCheckpoint,
    ):
        """Test loading a saved checkpoint."""
        manager = CheckpointManager(temp_checkpoint_dir)
        manager.save(sample_checkpoint)
        
        loaded = manager.load()
        
        assert loaded is not None
        assert loaded.scan_id == sample_checkpoint.scan_id
        assert loaded.target == sample_checkpoint.target
    
    def test_load_returns_none_if_not_exists(self, temp_checkpoint_dir: Path):
        """Test that load returns None when no checkpoint exists."""
        manager = CheckpointManager(temp_checkpoint_dir)
        
        assert manager.load() is None
    
    def test_exists_returns_true_when_checkpoint_exists(
        self,
        temp_checkpoint_dir: Path,
        sample_checkpoint: ScanCheckpoint,
    ):
        """Test exists method when checkpoint exists."""
        manager = CheckpointManager(temp_checkpoint_dir)
        manager.save(sample_checkpoint)
        
        assert manager.exists() is True
    
    def test_exists_returns_false_when_no_checkpoint(
        self,
        temp_checkpoint_dir: Path,
    ):
        """Test exists method when no checkpoint."""
        manager = CheckpointManager(temp_checkpoint_dir)
        
        assert manager.exists() is False
    
    def test_cleanup_removes_checkpoint(
        self,
        temp_checkpoint_dir: Path,
        sample_checkpoint: ScanCheckpoint,
    ):
        """Test that cleanup removes the checkpoint file."""
        manager = CheckpointManager(temp_checkpoint_dir)
        manager.save(sample_checkpoint)
        
        assert manager.exists() is True
        
        manager.cleanup()
        
        assert manager.exists() is False
    
    def test_get_checkpoint_info(
        self,
        temp_checkpoint_dir: Path,
        sample_checkpoint: ScanCheckpoint,
    ):
        """Test getting checkpoint summary info."""
        manager = CheckpointManager(temp_checkpoint_dir)
        manager.save(sample_checkpoint)
        
        info = manager.get_checkpoint_info()
        
        assert info is not None
        assert info["scan_id"] == sample_checkpoint.scan_id
        assert info["target"] == sample_checkpoint.target
        assert info["last_completed_step"] == "Parse"
        assert info["endpoints_found"] == 1
    
    def test_get_checkpoint_info_returns_none(self, temp_checkpoint_dir: Path):
        """Test get_checkpoint_info when no checkpoint exists."""
        manager = CheckpointManager(temp_checkpoint_dir)
        
        assert manager.get_checkpoint_info() is None


class TestEndpointSerialization:
    """Tests for endpoint serialization/deserialization."""
    
    def test_serialize_endpoints(self):
        """Test serializing endpoints to dictionaries."""
        endpoints = [
            Endpoint(
                url="/api/v1/users",
                method=HTTPMethod.GET,
                source=SourceLocation(file=Path("/tmp/app.js"), line=42),
                status=EndpointStatus.VERIFIED,
                http_status=200,
            ),
            Endpoint(
                url="/api/v1/products",
                method=HTTPMethod.POST,
                source=SourceLocation(file=Path("/tmp/app.js"), line=100),
            ),
        ]
        
        serialized = serialize_endpoints(endpoints)
        
        assert len(serialized) == 2
        assert serialized[0]["url"] == "/api/v1/users"
        assert serialized[0]["method"] == "GET"
        assert serialized[0]["http_status"] == 200
        assert serialized[1]["url"] == "/api/v1/products"
        assert serialized[1]["method"] == "POST"
    
    def test_deserialize_endpoints(self):
        """Test deserializing endpoints from dictionaries."""
        data = [
            {
                "url": "/api/v1/users",
                "method": "GET",
                "source_file": "/tmp/app.js",
                "source_line": 42,
                "status": "verified",
                "http_status": 200,
                "headers": {},
                "path_params": [],
                "query_params": [],
            }
        ]
        
        endpoints = deserialize_endpoints(data)
        
        assert len(endpoints) == 1
        assert endpoints[0].url == "/api/v1/users"
        assert endpoints[0].method == HTTPMethod.GET
        assert endpoints[0].http_status == 200
    
    def test_round_trip_serialization(self):
        """Test that serialization and deserialization preserve data."""
        original = [
            Endpoint(
                url="/api/v1/users",
                method=HTTPMethod.GET,
                source=SourceLocation(file=Path("/tmp/app.js"), line=42),
                status=EndpointStatus.VERIFIED,
                http_status=200,
            ),
        ]
        
        serialized = serialize_endpoints(original)
        restored = deserialize_endpoints(serialized)
        
        assert len(restored) == len(original)
        assert restored[0].url == original[0].url
        assert restored[0].method == original[0].method
        assert restored[0].http_status == original[0].http_status
