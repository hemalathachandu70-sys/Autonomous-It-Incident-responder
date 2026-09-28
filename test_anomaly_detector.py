"""Test script for Phase 21: Anomaly Detector Upgrades.

Verifies:
1. Keyword instant escalation (OOMKilled, core dumped, panic, etc.) -> Immediate P1
2. Null metric handling (z-scores skipped for null, lower threshold 1.5)
3. Time-window burst detection (5+ ERRORs from same service in 60s)
4. Repeated connection failure detection (3+ 'connection refused' in 60s)
"""

import os
import sys

sys.path.insert(0, os.path.abspath("."))

from backend.app.core.models import incident_store
from backend.app.detection.anomaly_detector import AnomalyDetector


def test_anomaly_detection():
    print("=" * 80)
    print("PHASE 21 TEST SUITE: ANOMALY DETECTOR UPGRADES")
    print("=" * 80)

    created_incidents = []
    detector = AnomalyDetector(on_incident_created=lambda inc: created_incidents.append(inc))

    # ---------------------------------------------------------------------
    # TEST 1: Keyword Instant P1 Escalation (OOMKilled)
    # ---------------------------------------------------------------------
    print("\n--> TEST 1: Testing instant P1 keyword escalation (OOMKilled)...")
    event_oom = {
        "timestamp": "2024-01-15T03:42:13Z",
        "service": "payment-service",
        "level": "ERROR",
        "message": "OOMKilled - container exceeded memory limit 512Mi",
        "cpu_percent": None,
        "memory_percent": None,
        "error_rate": None,
        "source_type": "file",
        "source_path": "test_logs/java_oom_crash.log",
        "raw_line": "2024-01-15 03:42:13 ERROR payment-service: OOMKilled - container exceeded memory limit",
    }
    inc_oom = detector.process_event(event_oom)
    assert inc_oom is not None, "OOM event failed to trigger an incident!"
    assert inc_oom.severity == "P1", f"Expected severity P1, got {inc_oom.severity}"
    assert "Instant P1 Keyword" in inc_oom.trigger_reason
    print(f"    Verified P1 incident created: {inc_oom.id} ({inc_oom.trigger_reason})")

    # ---------------------------------------------------------------------
    # TEST 2: Null Metric Handling (No metrics provided, no crash, baseline)
    # ---------------------------------------------------------------------
    print("\n--> TEST 2: Testing null metric handling...")
    event_null = {
        "timestamp": "2024-01-15T03:40:00Z",
        "service": "auth-service",
        "level": "INFO",
        "message": "Normal request handled",
        "cpu_percent": None,
        "memory_percent": None,
        "error_rate": None,
    }
    # Should not crash or trigger false positive
    inc_null = detector.process_event(event_null)
    assert inc_null is None, "Normal INFO with null metrics should not trigger incident"
    print("    Null metrics handled gracefully with zero errors.")

    # ---------------------------------------------------------------------
    # TEST 3: Partial Metric Z-Score Detection
    # ---------------------------------------------------------------------
    print("\n--> TEST 3: Testing partial metric threshold (1.5 for single metric spike)...")
    event_spike = {
        "timestamp": "2024-01-15T03:40:05Z",
        "service": "auth-service",
        "level": "WARN",
        "message": "Elevated CPU detected",
        "cpu_percent": 99.0,  # Far above default mean 30, std 15 -> z = 4.6
        "memory_percent": None,
        "error_rate": None,
        "source_type": "file",
        "source_path": "auth.log",
    }
    inc_spike = detector.process_event(event_spike)
    assert inc_spike is not None, "High partial metric spike failed to trigger incident!"
    print(f"    Verified partial metric spike incident: {inc_spike.id} ({inc_spike.trigger_reason})")

    # ---------------------------------------------------------------------
    # TEST 4: Time-Window Burst Detection (5+ ERRORs in 60s)
    # ---------------------------------------------------------------------
    print("\n--> TEST 4: Testing cascading burst detection (5+ ERRORs in 60s)...")
    service_name = "order-service"
    inc_burst = None
    for i in range(5):
        evt_err = {
            "timestamp": f"2024-01-15T03:42:0{i}Z",
            "service": service_name,
            "level": "ERROR",
            "message": f"Internal database error attempt #{i+1}",
            "cpu_percent": 40.0,
            "memory_percent": 50.0,
            "error_rate": 5.0,
            "source_type": "file",
            "source_path": "order.log",
        }
        res = detector.process_event(evt_err)
        if res:
            inc_burst = res

    assert inc_burst is not None, "5 cascading ERRORs failed to trigger burst incident!"
    assert inc_burst.severity == "P1"
    assert "Cascading Burst" in inc_burst.trigger_reason
    print(f"    Verified burst detection incident: {inc_burst.id} ({inc_burst.trigger_reason})")

    # ---------------------------------------------------------------------
    # TEST 5: Repeated 'Connection Refused' (3 in 60s)
    # ---------------------------------------------------------------------
    print("\n--> TEST 5: Testing repeated 'connection refused' detection (3x in 60s)...")
    conn_service = "inventory-service"
    inc_conn = None
    for i in range(3):
        evt_conn = {
            "timestamp": f"2024-01-15T03:45:0{i}Z",
            "service": conn_service,
            "level": "WARN",
            "message": f"Postgres connection refused on port 5432 attempt {i}",
            "cpu_percent": None,
            "memory_percent": None,
            "error_rate": None,
            "source_type": "file",
            "source_path": "inventory.log",
        }
        res = detector.process_event(evt_conn)
        if res:
            inc_conn = res

    assert inc_conn is not None, "3 repeated connection refused failed to trigger incident!"
    assert "connection refused" in inc_conn.trigger_reason.lower()
    print(f"    Verified connection refused incident: {inc_conn.id} ({inc_conn.trigger_reason})")

    print("\n" + "=" * 80)
    print("ALL PHASE 21 TESTS PASSED SUCCESSFULLY!")
    print("=" * 80)


if __name__ == "__main__":
    test_anomaly_detection()
