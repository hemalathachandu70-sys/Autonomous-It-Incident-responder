"""Anomaly Detector for Autonomous IT Incident Responder.

Implements real-log upgrades:
1. Keyword-based instant P1 escalation
2. Null metric handling with dynamic z-score thresholds (1.5 for partial metrics)
3. 60-second time-window burst detection (5+ ERRORs from same service)
4. Repeated connection failure detection (3+ 'connection refused' in 60s)
5. Source-aware context
"""

from __future__ import annotations

import collections
import logging
import math
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..core.models import Incident, incident_store

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """Detects anomalies from synthetic and real-world logs."""

    # Keywords that trigger immediate P1 incident regardless of z-score
    INSTANT_P1_KEYWORDS = [
        "oomkilled",
        "out of memory",
        "kill process",
        "killed process",
        "segmentation fault",
        "core dumped",
        "kernel panic",
        "critical",
        "fatal",
        "panic",
        "crashed",
        "crash",
        "fatal error",
        "database connection pool exhausted",
        "connection pool exhausted",
        "circuit breaker open",
    ]

    def __init__(
        self,
        on_incident_created: Optional[Callable[[Incident], None]] = None,
        burst_threshold: int = 5,
        burst_window_seconds: float = 60.0,
        z_score_threshold_full: float = 2.0,
        z_score_threshold_partial: float = 1.5,
    ):
        self.on_incident_created = on_incident_created
        self.burst_threshold = burst_threshold
        self.burst_window_seconds = burst_window_seconds
        self.z_threshold_full = z_score_threshold_full
        self.z_threshold_partial = z_score_threshold_partial

        # Service-based rolling error timestamps: service -> deque([timestamps])
        self.service_error_history: Dict[str, collections.deque] = collections.defaultdict(collections.deque)
        # Service-based 'connection refused' timestamps: service -> deque([timestamps])
        self.service_conn_refused: Dict[str, collections.deque] = collections.defaultdict(collections.deque)
        # Recent raw logs for context
        self.service_recent_logs: Dict[str, collections.deque] = collections.defaultdict(
            lambda: collections.deque(maxlen=20)
        )

        # Baseline metrics history for z-score: service -> metric_name -> list of floats
        self.metrics_history: Dict[str, Dict[str, List[float]]] = collections.defaultdict(
            lambda: {"cpu_percent": [], "memory_percent": [], "error_rate": []}
        )

    def _check_instant_keywords(self, message: str) -> Optional[str]:
        msg_lower = message.lower()
        for kw in self.INSTANT_P1_KEYWORDS:
            if kw in msg_lower:
                return f"Instant P1 Keyword match: '{kw}'"
        return None

    def _compute_z_scores(
        self, service: str, event: Dict[str, Any]
    ) -> Tuple[Dict[str, float], float, int]:
        """Compute z-scores for non-null metrics."""
        z_scores: Dict[str, float] = {}
        available_count = 0

        for metric in ["cpu_percent", "memory_percent", "error_rate"]:
            val = event.get(metric)
            if val is not None:
                available_count += 1
                history = self.metrics_history[service][metric]
                # Maintain up to 100 historical readings
                if len(history) >= 5:
                    mean = sum(history) / len(history)
                    variance = sum((x - mean) ** 2 for x in history) / len(history)
                    std_dev = math.sqrt(variance) if variance > 0 else 1.0
                    z = (val - mean) / (std_dev if std_dev > 0.001 else 1.0)
                    z_scores[metric] = round(z, 2)
                else:
                    # Initial heuristic baseline
                    default_means = {"cpu_percent": 30.0, "memory_percent": 50.0, "error_rate": 1.0}
                    default_stds = {"cpu_percent": 15.0, "memory_percent": 15.0, "error_rate": 5.0}
                    mean = default_means.get(metric, 50.0)
                    std_dev = default_stds.get(metric, 10.0)
                    z_scores[metric] = round((val - mean) / std_dev, 2)

                history.append(float(val))
                if len(history) > 100:
                    history.pop(0)

        max_z = max(z_scores.values()) if z_scores else 0.0
        return z_scores, max_z, available_count

    def process_event(self, event: Dict[str, Any]) -> Optional[Incident]:
        """Evaluate an incoming LogEvent for anomalies and create an incident if triggered."""
        now = time.time()
        service = event.get("service", "unknown-service")
        level = event.get("level", "INFO").upper()
        message = event.get("message", "")
        source_type = event.get("source_type", "file")
        source_path = event.get("source_path", "unknown")
        raw_line = event.get("raw_line") or message

        # Save to recent logs for raw preview
        self.service_recent_logs[service].append(raw_line)

        # -------------------------------------------------------------
        # 1. Keyword-based instant P1 escalation
        # -------------------------------------------------------------
        kw_reason = self._check_instant_keywords(message)
        if kw_reason:
            logger.warning("ANOMALY DETECTED (%s): %s", service, kw_reason)
            return self._trigger_incident(
                service=service,
                severity="P1",
                trigger_reason=kw_reason,
                source_type=source_type,
                source_path=source_path,
                event=event,
            )

        # -------------------------------------------------------------
        # 2. Connection Refused Burst (3+ in 60 seconds)
        # -------------------------------------------------------------
        if "connection refused" in message.lower():
            dq_conn = self.service_conn_refused[service]
            dq_conn.append(now)
            while dq_conn and dq_conn[0] < now - self.burst_window_seconds:
                dq_conn.popleft()
            if len(dq_conn) >= 3:
                reason = "Burst: 3+ connection refused errors within 60s"
                dq_conn.clear()
                return self._trigger_incident(
                    service=service,
                    severity="P1",
                    trigger_reason=reason,
                    source_type=source_type,
                    source_path=source_path,
                    event=event,
                )

        # -------------------------------------------------------------
        # 3. Time-window burst detection (5+ ERRORs in 60 seconds)
        # -------------------------------------------------------------
        if level in ("ERROR", "CRITICAL"):
            dq_err = self.service_error_history[service]
            dq_err.append(now)
            while dq_err and dq_err[0] < now - self.burst_window_seconds:
                dq_err.popleft()

            if len(dq_err) >= self.burst_threshold:
                reason = f"Cascading Burst: {len(dq_err)} ERRORs detected within 60s"
                dq_err.clear()
                return self._trigger_incident(
                    service=service,
                    severity="P1",
                    trigger_reason=reason,
                    source_type=source_type,
                    source_path=source_path,
                    event=event,
                )

        # -------------------------------------------------------------
        # 4. Metric z-score with null-metric handling
        # -------------------------------------------------------------
        z_scores, max_z, available_metrics = self._compute_z_scores(service, event)
        if available_metrics > 0:
            threshold = self.z_threshold_partial if available_metrics < 3 else self.z_threshold_full
            if max_z >= threshold:
                sev = "P1" if max_z >= 3.0 else "P2"
                reason = f"Metric Spike: z-score={max_z} exceeded threshold={threshold} (metrics={z_scores})"
                return self._trigger_incident(
                    service=service,
                    severity=sev,
                    trigger_reason=reason,
                    source_type=source_type,
                    source_path=source_path,
                    event=event,
                )

        return None

    def _trigger_incident(
        self,
        service: str,
        severity: str,
        trigger_reason: str,
        source_type: str,
        source_path: str,
        event: Dict[str, Any],
    ) -> Incident:
        raw_logs = list(self.service_recent_logs[service])
        metrics_summary = {
            "cpu_percent": event.get("cpu_percent"),
            "memory_percent": event.get("memory_percent"),
            "error_rate": event.get("error_rate"),
        }
        inc = incident_store.create(
            service=service,
            severity=severity,
            source_type=source_type,
            source_path=source_path,
            trigger_reason=trigger_reason,
            raw_logs=raw_logs,
            metrics_summary=metrics_summary,
        )
        if self.on_incident_created:
            try:
                self.on_incident_created(inc)
            except Exception as e:
                logger.error("Error in on_incident_created callback: %s", e)
        return inc


default_anomaly_detector = AnomalyDetector()
