"""Real Log Ingestor coordinator for Autonomous IT Incident Responder.

Coordinates ingestion from:
1. Files on disk (.log, .txt, .json, .csv, .xml)
2. Raw paste text from dashboard UI
3. Windows Event Viewer (Application, System, Security)
4. Monitored folder watcher (watched_logs/)

Publishes all normalized LogEvent records to Redis 'raw-logs' channel.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .file_watcher import LogFileWatcher
from .log_normalizer import LogNormalizer
from .log_parser import LogEvent, LogParser
from .redis_client import RedisClient, default_redis_client
from .windows_event_reader import WindowsEventReader

logger = logging.getLogger(__name__)


class RealLogIngestor:
    """Main coordinator for all real log ingestion sources."""

    def __init__(
        self,
        watch_folder: str = "./watched_logs",
        redis_client: Optional[RedisClient] = None,
        log_parser: Optional[LogParser] = None,
    ):
        self.redis_client = redis_client or default_redis_client
        self.parser = log_parser or LogParser()
        self.windows_reader = WindowsEventReader(redis_client=self.redis_client, log_parser=self.parser)
        self.file_watcher = LogFileWatcher(
            watch_folder=watch_folder,
            redis_client=self.redis_client,
            log_parser=self.parser,
        )
        self.total_events_today = 0
        self.mode = "real"  # "real", "demo", or "both"

    def ingest_file(
        self,
        file_path: str,
        service_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Ingest and parse an entire log file from disk, publishing events to Redis."""
        norm_path = os.path.abspath(file_path)
        if not os.path.exists(norm_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        events = self.parser.parse_file(
            norm_path,
            source_type="file",
            default_service=service_name,
        )

        published_count = 0
        errors_skipped = 0

        for evt in events:
            try:
                norm_dict = LogNormalizer.normalize_dict(evt.to_dict())
                self.redis_client.publish_event(norm_dict)
                published_count += 1
                self.total_events_today += 1
            except Exception as e:
                logger.error("Failed to publish event: %s", e)
                errors_skipped += 1

        return {
            "lines_parsed": len(events),
            "events_published": published_count,
            "errors_skipped": errors_skipped,
        }

    def ingest_paste(
        self,
        raw_text: str,
        service_name: Optional[str] = None,
        format_hint: Optional[str] = "auto",
    ) -> Dict[str, Any]:
        """Ingest raw pasted text, parse into normalized events, and publish to Redis."""
        if not raw_text or not raw_text.strip():
            return {"lines_parsed": 0, "events_published": 0, "errors_skipped": 0}

        events = self.parser.parse_text(
            raw_text=raw_text,
            source_type="paste",
            source_path="paste",
            default_service=service_name,
            format_hint=format_hint,
        )

        published_count = 0
        errors_skipped = 0

        for evt in events:
            try:
                norm_dict = LogNormalizer.normalize_dict(evt.to_dict())
                self.redis_client.publish_event(norm_dict)
                published_count += 1
                self.total_events_today += 1
            except Exception as e:
                logger.error("Failed to publish paste event: %s", e)
                errors_skipped += 1

        return {
            "lines_parsed": len(events),
            "events_published": published_count,
            "errors_skipped": errors_skipped,
        }

    def ingest_windows_events(
        self,
        channel: str = "Application",
        last_n_events: int = 100,
        min_level: str = "Error",
    ) -> Dict[str, Any]:
        """Read real Windows Event Viewer logs and publish to Redis."""
        res = self.windows_reader.ingest_and_publish(
            channel=channel,
            last_n_events=last_n_events,
            min_level=min_level,
        )
        self.total_events_today += res["events_published"]
        return res

    def get_status(self) -> Dict[str, Any]:
        """Return real-log ingestion status for GET /api/ingest/status."""
        watcher_status = self.file_watcher.get_status()
        return {
            "file_watcher_active": watcher_status["file_watcher_active"],
            "watch_folder": watcher_status["watch_folder"],
            "files_being_watched": watcher_status["files_being_watched"],
            "total_events_ingested_today": self.total_events_today + watcher_status["total_events_ingested_today"],
            "mode": self.mode,
        }


# Global coordinator instance
default_real_log_ingestor = RealLogIngestor()
