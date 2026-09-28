"""Test script for Phase 22: RCA Agent Upgrades.

Verifies:
1. Raw log lines evidence included in RCA
2. Stack trace extraction (top 5 frames)
3. Log volume analysis (error count, trend, most frequent message)
4. Past incident knowledge base match (similarity score & confidence >= 0.85)
"""

import os
import sys

sys.path.insert(0, os.path.abspath("."))

from backend.app.core.models import Incident
from backend.app.rca.rca_agent import RCAAgent, EXPANDED_PAST_INCIDENTS


def test_rca_upgrades():
    print("=" * 80)
    print("PHASE 22 TEST SUITE: RCA AGENT UPGRADES")
    print("=" * 80)

    rca = RCAAgent()

    # Verify 10 past incident seeds exist
    print(f"\n--> Checking expanded knowledge base: {len(EXPANDED_PAST_INCIDENTS)} incidents loaded.")
    assert len(EXPANDED_PAST_INCIDENTS) >= 10

    # ---------------------------------------------------------------------
    # TEST 1: Java OOM Crash with Stack Trace
    # ---------------------------------------------------------------------
    print("\n--> TEST 1: Testing RCA on Java OOM Crash...")
    raw_logs = [
        "2024-01-15 03:41:30 WARN  payment-service: Memory usage at 89%",
        "2024-01-15 03:42:00 ERROR payment-service: GC overhead limit exceeded",
        "2024-01-15 03:42:11 ERROR payment-service: java.lang.OutOfMemoryError: Java heap space",
        "    at com.payment.service.TransactionManager.allocateBuffer(TransactionManager.java:214)",
        "    at com.payment.service.PaymentPipeline.processTransaction(PaymentPipeline.java:89)",
        "    at com.payment.service.WorkerThread.run(WorkerThread.java:45)",
        "2024-01-15 03:42:12 ERROR payment-service: Killed process 1234 (java) total-vm:2048000kB",
        "2024-01-15 03:42:13 ERROR payment-service: OOMKilled - container exceeded memory limit",
    ]

    inc = Incident(
        id="INC-TEST-001",
        service="payment-service",
        severity="P1",
        status="DETECTED",
        source_type="file",
        source_path="test_logs/java_oom_crash.log",
        trigger_reason="Instant P1 Keyword match: 'OOMKilled'",
        created_at="2024-01-15T03:42:13Z",
        raw_logs=raw_logs,
    )

    res = rca.analyze_incident(inc)
    print(f"    Root Cause: {res['root_cause']}")
    print(f"    Confidence: {res['confidence']}")
    print(f"    Remediation: {res['recommended_remediation']}")
    print(f"    Stack Trace Frames Detected: {len(res['stack_trace_frames'])}")
    print(f"    Volume Trend: {res['log_volume_analysis']['trend']}, Total Errors: {res['log_volume_analysis']['total_errors']}")

    assert res["confidence"] >= 0.85, f"Expected confidence >= 0.85, got {res['confidence']}"
    assert len(res["stack_trace_frames"]) == 3, f"Expected 3 stack frames, got {len(res['stack_trace_frames'])}"
    assert "heap" in res["root_cause"].lower() or "memory" in res["root_cause"].lower()
    assert res["log_volume_analysis"]["total_errors"] >= 4

    # ---------------------------------------------------------------------
    # TEST 2: Nginx 500/503 Cascading Failure
    # ---------------------------------------------------------------------
    print("\n--> TEST 2: Testing RCA on Nginx 500/503 Cascading Failure...")
    nginx_logs = [
        '127.0.0.1 - - [15/Jan/2024:03:42:01 +0000] "POST /api/pay HTTP/1.1" 500 567',
        '127.0.0.1 - - [15/Jan/2024:03:42:01 +0000] "POST /api/pay HTTP/1.1" 500 567',
        '127.0.0.1 - - [15/Jan/2024:03:42:02 +0000] "POST /api/pay HTTP/1.1" 500 567',
        '127.0.0.1 - - [15/Jan/2024:03:42:03 +0000] "GET /health HTTP/1.1" 503 89',
        '127.0.0.1 - - [15/Jan/2024:03:42:04 +0000] "POST /api/pay HTTP/1.1" 500 567',
    ]
    inc_nginx = Incident(
        id="INC-TEST-002",
        service="payment-service",
        severity="P1",
        status="DETECTED",
        source_type="file",
        source_path="test_logs/nginx_500_errors.log",
        trigger_reason="Cascading Burst: 5 ERRORs detected within 60s",
        created_at="2024-01-15T03:42:05Z",
        raw_logs=nginx_logs,
    )

    res_nginx = rca.analyze_incident(inc_nginx)
    print(f"    Root Cause: {res_nginx['root_cause']}")
    print(f"    Confidence: {res_nginx['confidence']}")
    assert res_nginx["confidence"] >= 0.85
    assert len(res_nginx["evidence_lines"]) == 5

    print("\n" + "=" * 80)
    print("ALL PHASE 22 TESTS PASSED SUCCESSFULLY!")
    print("=" * 80)


if __name__ == "__main__":
    test_rca_upgrades()
