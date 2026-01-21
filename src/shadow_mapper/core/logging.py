"""Structured logging configuration for Shadow API Mapper.

Uses structlog for JSON-formatted, structured logging suitable for
SIEM integration and log aggregation systems.
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone
from typing import Any

try:
    import structlog
    STRUCTLOG_AVAILABLE = True
except ImportError:
    STRUCTLOG_AVAILABLE = False


def get_utc_timestamp() -> str:
    """Get current UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).isoformat()


def add_timestamp(
    logger: Any,
    method_name: str,
    event_dict: dict[str, Any],
) -> dict[str, Any]:
    """Add UTC timestamp to log events."""
    event_dict["timestamp"] = get_utc_timestamp()
    return event_dict


def add_context(
    logger: Any,
    method_name: str,
    event_dict: dict[str, Any],
) -> dict[str, Any]:
    """Add default context fields to log events."""
    event_dict.setdefault("service", "shadow-api-mapper")
    return event_dict


def configure_logging(
    level: str = "INFO",
    json_format: bool = False,
    log_file: str | None = None,
) -> logging.Logger:
    """Configure structured logging.
    
    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR)
        json_format: If True, output JSON logs for machine parsing
        log_file: Optional file path for logging
        
    Returns:
        Configured logger instance
    """
    if not STRUCTLOG_AVAILABLE:
        # Fallback to standard logging
        logging.basicConfig(
            level=getattr(logging, level.upper()),
            format="%(asctime)s [%(levelname)s] %(message)s",
        )
        return logging.getLogger("shadow_mapper")
    
    # Configure structlog processors
    processors = [
        structlog.stdlib.filter_by_level,
        add_timestamp,
        add_context,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    
    if json_format:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(
            structlog.dev.ConsoleRenderer(colors=True)
        )
    
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper()))
    
    # Add console handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(getattr(logging, level.upper()))
    root_logger.addHandler(handler)
    
    # Add file handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(getattr(logging, level.upper()))
        root_logger.addHandler(file_handler)
    
    return structlog.get_logger("shadow_mapper")


def get_logger(name: str = "shadow_mapper") -> Any:
    """Get a logger instance.
    
    Args:
        name: Logger name
        
    Returns:
        Logger instance (structlog if available, else stdlib)
    """
    if STRUCTLOG_AVAILABLE:
        return structlog.get_logger(name)
    return logging.getLogger(name)


# Convenience function for scan-related logging
def log_scan_event(
    event: str,
    scan_id: str,
    target: str = None,
    **kwargs: Any,
) -> None:
    """Log a scan-related event with standard fields.
    
    Args:
        event: Event name (e.g., "scan_started", "endpoint_found")
        scan_id: Unique scan identifier
        target: Target URL (optional)
        **kwargs: Additional event data
    """
    logger = get_logger("shadow_mapper.scan")
    
    event_data = {
        "scan_id": scan_id,
        **kwargs,
    }
    if target:
        event_data["target"] = target
    
    logger.info(event, **event_data)
