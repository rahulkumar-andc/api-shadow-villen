"""Shadow-API Mapper - Automated Shadow and Zombie API Discovery Tool."""

__version__ = "1.0.0"
__author__ = "VILLEN Security"

from shadow_mapper.core.config import Settings
from shadow_mapper.core.models import Endpoint, ScanResult, ScanReport

__all__ = [
    "Settings",
    "Endpoint",
    "ScanResult",
    "ScanReport",
]
