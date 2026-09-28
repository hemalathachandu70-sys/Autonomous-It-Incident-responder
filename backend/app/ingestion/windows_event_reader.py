"""Windows Event Log reader for Autonomous IT Incident Responder.

Reads real Windows Event Viewer logs (Application, System, Security channels)
using pywin32, maps them to normalized LogEvent schemas, and publishes
them to the Redis 'raw-logs' channel.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .log_parser import LogEvent, LogParser
from .redis_client import RedisClient, default_redis_client

logger = logging.getLogger(__name__)

# Check pywin32 availability gracefully
try:
    import win32evtlog
    import win32evtlogutil
    PYWIN32_AVAILABLE = True
except ImportError:
    PYWIN32_AVAILABLE = False
    logger.warning("pywin32 is not available. Real-time Windows Event Viewer reading disabled.")


class WindowsEventReader:
    """Reads Windows Event Viewer logs and converts them into normalized LogEvents."""

    # EventID to specific level and message description
    KNOWN_EVENT_IDS = {
        1000: ("ERROR", "Application crash"),
        1001: ("ERROR", "Windows Error Reporting"),
        7034: ("ERROR", "Service crashed unexpectedly"),
        7036: ("WARN", "Service state change"),
        41: ("CRITICAL", "Kernel power failure"),
        4625: ("WARN", "Failed logon attempt"),
    }

    def __init__(
        self,
        redis_client: Optional[RedisClient] = None,
        log_parser: Optional[LogParser] = None,
    ):
        self.redis_client = redis_client or default_redis_client
        self.parser = log_parser or LogParser()

    @property
    def is_available(self) -> bool:
        return PYWIN32_AVAILABLE

    def _map_event(self, event_record, channel: str) -> Optional[LogEvent]:
        """Convert a win32evtlog record to a normalized LogEvent."""
        event_id = event_record.EventID & 0xFFFF
        event_type = event_record.EventType
        source_name = str(event_record.SourceName or channel).strip()

        # Determine level
        if event_id in self.KNOWN_EVENT_IDS:
            level, _ = self.KNOWN_EVENT_IDS[event_id]
        elif event_type == win32evtlog.EVENTLOG_ERROR_TYPE:
            level = "ERROR"
        elif event_type == win32evtlog.EVENTLOG_WARNING_TYPE or event_type == win32evtlog.EVENTLOG_AUDIT_FAILURE:
            level = "WARN"
        elif event_type == win32evtlog.EVENTLOG_INFORMATION_TYPE or event_type == win32evtlog.EVENTLOG_AUDIT_SUCCESS:
            level = "INFO"
        else:
            level = "INFO"

        # Format message
        message = ""
        try:
            msg_formatted = win32evtlogutil.SafeFormatMessage(event_record, channel)
            if msg_formatted and msg_formatted.strip():
                message = msg_formatted.strip()
        except Exception:
            pass

        if not message and event_record.StringInserts:
            inserts = [str(s) for s in event_record.StringInserts if s]
            message = " | ".join(inserts)

        if not message:
            known_desc = self.KNOWN_EVENT_IDS.get(event_id, (None, f"Windows Event {event_id}"))[1]
            message = f"{known_desc} ({source_name})"

        # Service name extraction
        service = source_name
        # If string inserts mention an application (.exe)
        if event_record.StringInserts:
            for s in event_record.StringInserts:
                if s and (".exe" in str(s).lower() or ".dll" in str(s).lower()):
                    cand = str(s).replace(".exe", "").replace(".dll", "").strip()
                    if cand and len(cand.split()) == 1:
                        service = cand
                        break

        # Timestamp conversion to ISO 8601 UTC
        time_gen = event_record.TimeGenerated
        if hasattr(time_gen, "astimezone"):
            dt_utc = time_gen.astimezone(timezone.utc)
            ts_str = dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        else:
            ts_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Extract any metrics in message if present
        cpu, mem, err = self.parser.extract_metrics(message)

        raw_line = f"EventID={event_id} Source={source_name} Level={level}: {message}"

        return LogEvent(
            timestamp=ts_str,
            service=service,
            level=level,
            message=message,
            cpu_percent=cpu,
            memory_percent=mem,
            error_rate=err,
            source_type="windows_event",
            source_path=f"event_viewer/{channel}",
            raw_line=raw_line,
        )

    def read_events(
        self,
        channel: str = "Application",
        last_n_events: int = 100,
        min_level: str = "Error",
        server: Optional[str] = None,
    ) -> List[LogEvent]:
        """Read real Windows Event Viewer logs from a given channel."""
        if not PYWIN32_AVAILABLE:
            logger.warning("pywin32 is not installed. Returning empty list.")
            return []

        allowed_levels = {"CRITICAL", "ERROR"}
        if min_level.lower() in ("warn", "warning"):
            allowed_levels.update(["WARN"])
        elif min_level.lower() in ("all", "info", "debug"):
            allowed_levels.update(["WARN", "INFO", "DEBUG"])

        events_collected: List[LogEvent] = []

        try:
            handle = win32evtlog.OpenEventLog(server, channel)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

            while len(events_collected) < last_n_events:
                records = win32evtlog.ReadEventLog(handle, flags, 0)
                if not records:
                    break

                for rec in records:
                    evt = self._map_event(rec, channel)
                    if evt and evt.level in allowed_levels:
                        events_collected.append(evt)
                        if len(events_collected) >= last_n_events:
                            break

            win32evtlog.CloseEventLog(handle)
        except Exception as e:
            logger.error("Failed to read Windows Event channel %s: %s", channel, e)

        return events_collected

    def ingest_and_publish(
        self,
        channel: str = "Application",
        last_n_events: int = 50,
        min_level: str = "Error",
    ) -> Dict[str, int]:
        """Read events and publish normalized LogEvents to Redis."""
        events = self.read_events(channel=channel, last_n_events=last_n_events, min_level=min_level)
        published_count = 0

        for evt in events:
            self.redis_client.publish_event(evt.to_dict())
            published_count += 1

        return {
            "events_read": len(events),
            "events_published": published_count,
        }
