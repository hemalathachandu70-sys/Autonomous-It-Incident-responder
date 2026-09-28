"""Core models for Autonomous IT Incident Responder."""

from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class Incident:
    id: str
    service: str
    severity: str  # P1, P2, P3
    status: str  # DETECTED, TRIAGED, RCA_IN_PROGRESS, MITIGATED, RESOLVED
    source_type: str  # demo, file, windows_event, paste, folder
    source_path: str
    trigger_reason: str
    created_at: str
    raw_logs: List[str] = field(default_factory=list)
    metrics_summary: Dict[str, Optional[float]] = field(default_factory=dict)
    rca: Optional[Dict[str, Any]] = None
    mitigation: Optional[Dict[str, Any]] = None
    post_mortem: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class IncidentStore:
    """In-memory thread-safe store for incidents."""

    def __init__(self):
        self._incidents: Dict[str, Incident] = {}
        self._counter = 1

    def create(
        self,
        service: str,
        severity: str,
        source_type: str,
        source_path: str,
        trigger_reason: str,
        raw_logs: List[str],
        metrics_summary: Optional[Dict[str, Optional[float]]] = None,
    ) -> Incident:
        inc_id = f"INC-{datetime.now().year}-{self._counter:03d}"
        self._counter += 1
        created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        inc = Incident(
            id=inc_id,
            service=service,
            severity=severity,
            status="DETECTED",
            source_type=source_type,
            source_path=source_path,
            trigger_reason=trigger_reason,
            created_at=created_at,
            raw_logs=raw_logs[:20],
            metrics_summary=metrics_summary or {},
        )
        self._incidents[inc_id] = inc
        return inc

    def get(self, incident_id: str) -> Optional[Incident]:
        return self._incidents.get(incident_id)

    def list_all(self) -> List[Incident]:
        return list(self._incidents.values())

    def update(self, inc: Incident) -> None:
        self._incidents[inc.id] = inc


incident_store = IncidentStore()
