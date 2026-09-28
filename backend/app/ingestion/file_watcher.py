"""File watcher for Autonomous IT Incident Responder.

Monitors a directory for log files using watchdog, parsing new or modified
lines and publishing normalized LogEvent objects to Redis channel 'raw-logs'.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any, Callable, Dict, List, Optional, Set

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from .log_parser import LogEvent, LogParser
from .redis_client import RedisClient, default_redis_client

logger = logging.getLogger(__name__)

SUPPORTED_EXTENSIONS: Set[str] = {".log", ".txt", ".json", ".csv", ".xml"}
IGNORED_EXTENSIONS: Set[str] = {".py", ".docx", ".pdf", ".png", ".tmp", ".swp"}


class LogFileWatcherHandler(FileSystemEventHandler):
    """Handles watchdog file creation and modification events."""

    def __init__(self, watcher: "LogFileWatcher"):
        super().__init__()
        self.watcher = watcher

    def on_created(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        self.watcher.handle_file_event(event.src_path, is_new=True)

    def on_modified(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        self.watcher.handle_file_event(event.src_path, is_new=False)


class LogFileWatcher:
    """Watches a designated folder for log files and publishes parsed events."""

    def __init__(
        self,
        watch_folder: str = "./watched_logs",
        redis_client: Optional[RedisClient] = None,
        log_parser: Optional[LogParser] = None,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.watch_folder = os.path.abspath(watch_folder)
        self.redis_client = redis_client or default_redis_client
        self.parser = log_parser or LogParser()
        self.event_callback = event_callback

        self.file_positions: Dict[str, int] = {}
        self.is_running = False
        self._observer: Optional[Observer] = None
        self.total_events_ingested = 0

        # Ensure watch folder exists
        os.makedirs(self.watch_folder, exist_ok=True)

    def is_eligible_file(self, file_path: str) -> bool:
        """Check if file should be processed based on extension and naming."""
        filename = os.path.basename(file_path)
        if filename.startswith("~$") or filename.startswith("."):
            return False

        _, ext = os.path.splitext(filename.lower())
        if ext in IGNORED_EXTENSIONS:
            return False

        return ext in SUPPORTED_EXTENSIONS

    def ingest_file(self, file_path: str, is_new: bool = False) -> List[LogEvent]:
        """Read newly appended content from file and publish parsed LogEvents."""
        norm_path = os.path.abspath(file_path)
        if not os.path.exists(norm_path) or not self.is_eligible_file(norm_path):
            return []

        # If file was recreated or shrank, reset byte offset
        last_pos = self.file_positions.get(norm_path, 0)
        try:
            curr_size = os.path.getsize(norm_path)
            if curr_size < last_pos:
                last_pos = 0
        except OSError:
            return []

        try:
            with open(norm_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(last_pos)
                new_text = f.read()
                new_pos = f.tell()
                self.file_positions[norm_path] = new_pos
        except Exception as e:
            logger.error("Error reading file %s: %s", norm_path, e)
            return []

        if not new_text.strip():
            return []

        # Determine format hint from extension
        _, ext = os.path.splitext(norm_path.lower())
        format_hint = "auto"
        if ext == ".json":
            format_hint = "json"
        elif ext == ".csv":
            format_hint = "csv"
        elif ext == ".xml":
            format_hint = "windows"

        events = self.parser.parse_text(
            raw_text=new_text,
            source_type="folder",
            source_path=norm_path,
            format_hint=format_hint,
        )

        for evt in events:
            evt_dict = evt.to_dict()
            self.redis_client.publish_event(evt_dict)
            self.total_events_ingested += 1
            if self.event_callback:
                try:
                    self.event_callback(evt_dict)
                except Exception as cb_err:
                    logger.error("Callback error: %s", cb_err)

        logger.info(
            "Ingested %d events from %s (new_bytes=%d)",
            len(events),
            norm_path,
            new_pos - last_pos,
        )
        return events

    def handle_file_event(self, file_path: str, is_new: bool = False) -> None:
        """Handle incoming file system event with a slight settle delay if needed."""
        if not self.is_eligible_file(file_path):
            return

        # Give disk write 50ms to settle if new
        if is_new:
            time.sleep(0.05)

        self.ingest_file(file_path, is_new=is_new)

    def scan_initial_files(self) -> int:
        """Ingest all pre-existing supported files in the watched folder."""
        count = 0
        if not os.path.exists(self.watch_folder):
            return 0

        for entry in os.listdir(self.watch_folder):
            full_path = os.path.join(self.watch_folder, entry)
            if os.path.isfile(full_path) and self.is_eligible_file(full_path):
                events = self.ingest_file(full_path, is_new=True)
                count += len(events)
        return count

    def start_sync(self) -> None:
        """Synchronously start the watchdog observer."""
        if self.is_running:
            return

        self.scan_initial_files()
        self._observer = Observer()
        handler = LogFileWatcherHandler(self)
        self._observer.schedule(handler, path=self.watch_folder, recursive=False)
        self._observer.start()
        self.is_running = True
        logger.info("LogFileWatcher started on %s", self.watch_folder)

    def stop_sync(self) -> None:
        """Synchronously stop the watchdog observer."""
        if not self.is_running:
            return
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=3.0)
            self._observer = None
        self.is_running = False
        logger.info("LogFileWatcher stopped.")

    async def start_watching(self) -> None:
        """Background asyncio task runner for FastAPI integration."""
        self.start_sync()
        try:
            while self.is_running:
                await asyncio.sleep(0.5)
        except asyncio.CancelledError:
            self.stop_sync()

    def get_status(self) -> Dict[str, Any]:
        """Return status information for GET /api/ingest/status."""
        files = []
        if os.path.exists(self.watch_folder):
            files = [
                f
                for f in os.listdir(self.watch_folder)
                if os.path.isfile(os.path.join(self.watch_folder, f))
                and self.is_eligible_file(os.path.join(self.watch_folder, f))
            ]

        return {
            "file_watcher_active": self.is_running,
            "watch_folder": self.watch_folder,
            "files_being_watched": files,
            "total_events_ingested_today": self.total_events_ingested,
            "mode": "both" if self.is_running else "real",
        }
