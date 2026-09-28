"""Incident Simulator for Mode 1 (Demo Mode).

Generates synthetic logs with controlled escalation pattern for presentations,
demos, and testing. Publishes events to Redis channel 'raw-logs'.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..ingestion.redis_client import RedisClient, default_redis_client

logger = logging.getLogger(__name__)


class IncidentSimulator:
    """Simulates controlled escalation synthetic logs."""

    def __init__(self, redis_client: Optional[RedisClient] = None):
        self.redis_client = redis_client or default_redis_client

    def run_simulation(self, service: str = "payment-service") -> List[Dict[str, Any]]:
        """Run standard 5-step escalation sequence."""
        events: List[Dict[str, Any]] = []
        now = datetime.now(timezone.utc)

        sequence = [
            ("INFO", f"Request processed OK - HTTP 200 (latency=45ms)", 25.0, 48.0, 0.1),
            ("INFO", f"Worker pool healthy - 12 active workers", 30.5, 52.0, 0.2),
            ("WARN", f"Latency spike detected - HTTP 200 (latency=1450ms)", 65.2, 75.0, 2.5),
            ("WARN", f"Memory usage warning sustained above 85%", 82.0, 88.5, 8.4),
            ("ERROR", f"Connection pool exhausted - database queries timing out", 94.5, 96.0, 35.8),
            ("ERROR", f"OOMKilled - container exceeded memory limit 512Mi", 98.2, 99.1, 62.4),
        ]

        for level, msg, cpu, mem, err in sequence:
            ts_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            evt = {
                "timestamp": ts_str,
                "service": service,
                "level": level,
                "message": msg,
                "cpu_percent": cpu,
                "memory_percent": mem,
                "error_rate": err,
                "source_type": "demo",
                "source_path": "demo",
                "raw_line": f"{ts_str} {level} {service}: {msg} cpu={cpu}% mem={mem}% err={err}%",
            }
            self.redis_client.publish_event(evt)
            events.append(evt)

        logger.info("Demo simulation executed with %d events.", len(events))
        return events


default_simulator = IncidentSimulator()
