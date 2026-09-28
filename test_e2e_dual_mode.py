"""End-to-End Test Suite for Dual-Mode Incident Responder (Phase 20 & 23).

Tests:
Test 1: Run demo simulator -> confirm incident flow & FSM pipeline resolution
Test 2: Drop java_oom_crash.log into watched_logs/ -> confirm auto-ingestion -> P1 incident created
Test 3: Paste nginx_500_errors.log via API -> confirm paste ingestion -> cascading burst incident
Test 4: Read Windows Events -> confirm real events read, normalized, and published
"""

import os
import shutil
import sys
import time

sys.path.insert(0, os.path.abspath("."))

from fastapi import FastAPI
from starlette.testclient import TestClient

from backend.app.core.models import incident_store
from backend.app.main import app


def run_e2e_tests():
    print("=" * 80)
    print("PHASE 23: END-TO-END DUAL-MODE TEST SUITE")
    print("=" * 80)

    client = TestClient(app)

    # -------------------------------------------------------------------------
    # TEST 1: Demo Mode Ingestion -> Incident Creation -> Pipeline Execution
    # -------------------------------------------------------------------------
    print("\n--> TEST 1: Running Demo Simulator...")
    resp_demo = client.post("/api/ingest/demo")
    assert resp_demo.status_code == 200
    print(f"    Demo response: {resp_demo.json()}")

    # Check incidents list
    resp_inc = client.get("/api/incidents")
    assert resp_inc.status_code == 200
    incidents = resp_inc.json()
    print(f"    Total incidents after demo: {len(incidents)}")
    assert len(incidents) > 0

    demo_inc = next((i for i in incidents if i["source_type"] == "demo" and i["severity"] == "P1"), None)
    if demo_inc is None:
        demo_inc = next((i for i in incidents if i["source_type"] == "demo"), None)
    assert demo_inc is not None, "Demo incident was not created!"
    print(f"    Found Demo Incident: {demo_inc['id']} ({demo_inc['service']}, Severity={demo_inc['severity']}, Status={demo_inc['status']})")
    assert demo_inc["severity"] in ("P1", "P2")

    # Run FSM pipeline on this incident
    print(f"    Running autonomous pipeline on {demo_inc['id']}...")
    resp_pipe = client.post(f"/api/pipeline/run/{demo_inc['id']}")
    assert resp_pipe.status_code == 200
    pipe_res = resp_pipe.json()
    assert pipe_res["status"] == "RESOLVED"
    assert pipe_res["rca"] is not None
    assert pipe_res["post_mortem"] is not None
    print(f"    Pipeline completed! Incident status: {pipe_res['status']}, RCA Confidence: {pipe_res['rca']['confidence']}")

    print("\n--> TEST 2: File Watcher Ingestion (Dropping java_oom_crash.log)...")
    watch_folder = os.path.abspath("./watched_logs")
    os.makedirs(watch_folder, exist_ok=True)
    dest_path = os.path.join(watch_folder, "test_java_oom.log")

    from backend.app.ingestion.real_log_ingestor import default_real_log_ingestor
    default_real_log_ingestor.file_watcher.start_sync()
    time.sleep(0.2)

    shutil.copy("test_logs/java_oom_crash.log", dest_path)

    # Allow up to 2 seconds for watchdog detection & anomaly detector
    time.sleep(0.6)
    resp_inc = client.get("/api/incidents")
    incidents = resp_inc.json()
    folder_inc = next((i for i in incidents if i["source_type"] == "folder"), None)
    assert folder_inc is not None, "Folder watcher did not trigger an incident for java_oom_crash.log!"
    print(f"    Found Folder Incident: {folder_inc['id']} ({folder_inc['service']}, Trigger={folder_inc['trigger_reason']})")
    assert folder_inc["severity"] == "P1"

    # Clean up test file
    if os.path.exists(dest_path):
        os.remove(dest_path)

    # -------------------------------------------------------------------------
    # TEST 3: Paste Ingestion via API (nginx_500_errors.log)
    # -------------------------------------------------------------------------
    print("\n--> TEST 3: Paste Ingestion (Pasting nginx 500 errors)...")
    with open("test_logs/nginx_500_errors.log", "r") as f:
        nginx_content = f.read()

    resp_paste = client.post(
        "/api/ingest/paste",
        json={"raw_text": nginx_content, "service_name": "payment-service", "format_hint": "apache"},
    )
    assert resp_paste.status_code == 200
    print(f"    Paste response: {resp_paste.json()}")

    # Verify incident created from paste
    resp_inc = client.get("/api/incidents")
    incidents = resp_inc.json()
    paste_inc = next((i for i in incidents if i["source_type"] == "paste"), None)
    assert paste_inc is not None, "Paste ingestion did not trigger an incident!"
    print(f"    Found Paste Incident: {paste_inc['id']} (Source={paste_inc['source_type']}, Trigger={paste_inc['trigger_reason']})")

    # -------------------------------------------------------------------------
    # TEST 4: Read Windows Events via API
    # -------------------------------------------------------------------------
    print("\n--> TEST 4: Read Windows Events via API...")
    resp_win = client.post(
        "/api/ingest/windows-events",
        json={"channel": "Application", "last_n_events": 20, "min_level": "All"},
    )
    assert resp_win.status_code == 200
    print(f"    Windows Events response: {resp_win.json()}")
    assert resp_win.json()["events_published"] > 0

    # -------------------------------------------------------------------------
    # TEST 5: Verify Dashboard UI endpoint
    # -------------------------------------------------------------------------
    print("\n--> TEST 5: Verifying Dashboard UI endpoint (GET /)...")
    resp_ui = client.get("/")
    assert resp_ui.status_code == 200
    assert "AUTONOMOUS IT INCIDENT RESPONDER" in resp_ui.text
    assert "LOG INGESTION" in resp_ui.text
    assert "DEMO MODE" in resp_ui.text
    assert "REAL LOG MODE" in resp_ui.text
    print("    Dashboard UI loaded successfully with all dual-mode controls.")

    default_real_log_ingestor.file_watcher.stop_sync()
    print("\n" + "=" * 80)
    print("ALL END-TO-END DUAL-MODE TESTS (PHASE 23) PASSED SUCCESSFULLY!")
    print("=" * 80)


if __name__ == "__main__":
    run_e2e_tests()
