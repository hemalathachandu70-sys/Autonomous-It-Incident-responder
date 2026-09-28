"""Log Normalizer for Autonomous IT Incident Responder.

Ensures every parsed log event strictly adheres to the standard schema:
{
  "timestamp": "ISO 8601 UTC string",
  "service": "extracted service name or 'unknown-service'",
  "level": "ERROR | WARN | INFO | DEBUG | CRITICAL",
  "message": "the log message text",
  "cpu_percent": float or null,
  "memory_percent": float or null,
  "error_rate": float or null,
  "source_type": "file | windows_event | paste | demo | folder",
  "source_path": "path to file or 'paste' or 'demo'",
  "raw_line": "original unparsed log line for reference"
}
"""

from __future__ import annotations

from typing import Any, Dict, Optional
from datetime import datetime, timezone
from .log_parser import LogEvent


class LogNormalizer:
    """Normalizes raw dictionaries or LogEvents into the strict incident responder schema."""

    VALID_LEVELS = {"CRITICAL", "ERROR", "WARN", "INFO", "DEBUG"}
    VALID_SOURCES = {"file", "windows_event", "paste", "demo", "folder"}

    @classmethod
    def normalize_dict(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and normalize a dictionary to the LogEvent schema."""
        # Timestamp
        ts = data.get("timestamp")
        if not ts:
            ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        elif isinstance(ts, datetime):
            ts = ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        else:
            ts = str(ts)

        # Service
        service = str(data.get("service") or "unknown-service").strip()
        if not service:
            service = "unknown-service"

        # Level
        raw_level = str(data.get("level") or "INFO").strip().upper()
        if raw_level not in cls.VALID_LEVELS:
            if "ERR" in raw_level:
                raw_level = "ERROR"
            elif "WARN" in raw_level:
                raw_level = "WARN"
            elif "CRIT" in raw_level or "FATAL" in raw_level:
                raw_level = "CRITICAL"
            elif "DBG" in raw_level or "TRACE" in raw_level:
                raw_level = "DEBUG"
            else:
                raw_level = "INFO"

        # Message
        message = str(data.get("message") or "")

        # Numeric metrics (must be float or None)
        def to_float(val: Any) -> Optional[float]:
            if val is None or val == "":
                return None
            try:
                return float(val)
            except (ValueError, TypeError):
                return None

        cpu = to_float(data.get("cpu_percent") if "cpu_percent" in data else data.get("cpu"))
        mem = to_float(data.get("memory_percent") if "memory_percent" in data else data.get("memory"))
        err = to_float(data.get("error_rate") if "error_rate" in data else data.get("err_rate"))

        # Source type & path
        src_type = str(data.get("source_type") or "file").lower()
        if src_type not in cls.VALID_SOURCES:
            src_type = "file"

        src_path = str(data.get("source_path") or "unknown")
        raw_line = str(data.get("raw_line") or message)

        return {
            "timestamp": ts,
            "service": service,
            "level": raw_level,
            "message": message,
            "cpu_percent": cpu,
            "memory_percent": mem,
            "error_rate": err,
            "source_type": src_type,
            "source_path": src_path,
            "raw_line": raw_line,
        }

    @classmethod
    def to_log_event(cls, data: Dict[str, Any]) -> LogEvent:
        norm = cls.normalize_dict(data)
        return LogEvent(
            timestamp=norm["timestamp"],
            service=norm["service"],
            level=norm["level"],
            message=norm["message"],
            cpu_percent=norm["cpu_percent"],
            memory_percent=norm["memory_percent"],
            error_rate=norm["error_rate"],
            source_type=norm["source_type"],
            source_path=norm["source_path"],
            raw_line=norm["raw_line"],
        )
