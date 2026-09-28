"""Log Ingestion module for Autonomous IT Incident Responder.
Supports dual-mode ingestion: synthetic demo logs and multi-format real logs.
"""

from .log_parser import LogParser, LogEvent
from .redis_client import RedisClient, default_redis_client
from .file_watcher import LogFileWatcher
from .windows_event_reader import WindowsEventReader
from .log_normalizer import LogNormalizer
from .real_log_ingestor import RealLogIngestor, default_real_log_ingestor
from .api import router as ingestion_router

__all__ = [
    "LogParser",
    "LogEvent",
    "RedisClient",
    "default_redis_client",
    "LogFileWatcher",
    "WindowsEventReader",
    "LogNormalizer",
    "RealLogIngestor",
    "default_real_log_ingestor",
    "ingestion_router",
]
