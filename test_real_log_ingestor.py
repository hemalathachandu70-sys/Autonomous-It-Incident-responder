"""Test script for Phase 19: real_log_ingestor.py and API endpoints.
Validates wiring of all sources and tests POST /api/ingest/paste across all formats.
"""

import json
import os
import sys

sys.path.insert(0, os.path.abspath("."))

from fastapi import FastAPI
from starlette.testclient import TestClient

from backend.app.ingestion.api import router as ingestion_router
from backend.app.ingestion.real_log_ingestor import default_real_log_ingestor


def test_real_log_ingestion():
    print("=" * 80)
    print("PHASE 19 TEST SUITE: REAL LOG INGESTOR & API ENDPOINTS")
    print("=" * 80)

    # Setup test FastAPI app
    app = FastAPI()
    app.include_router(ingestion_router)
    client = TestClient(app)

    # ---------------------------------------------------------------------
    # TEST 1: Direct ingest_file
    # ---------------------------------------------------------------------
    print("\n--> TEST 1: Testing direct file ingestion (java_oom_crash.log)...")
    res_file = default_real_log_ingestor.ingest_file("test_logs/java_oom_crash.log")
    print(f"    File ingestion result: {res_file}")
    assert res_file["lines_parsed"] > 0
    assert res_file["events_published"] > 0
    assert res_file["errors_skipped"] == 0

    # ---------------------------------------------------------------------
    # TEST 2: Testing POST /api/ingest/paste for each format
    # ---------------------------------------------------------------------
    paste_samples = [
        (
            "Plain Text Log",
            "2024-01-15 03:42:11 ERROR payment-service: OOMKilled container exceeded memory limit 512Mi\n"
            "2024-01-15 03:42:13 WARN  payment-service: CPU usage 97.4% sustained for 180 seconds\n",
            "auto",
        ),
        (
            "JSON Structured Log",
            '{"timestamp":"2024-01-15T03:42:11Z","level":"ERROR","service":"payment-service","message":"Connection refused","cpu":97.4,"memory":98.1,"error_rate":43.2}\n',
            "json",
        ),
        (
            "Apache / Nginx Access Log",
            '127.0.0.1 - - [15/Jan/2024:03:42:11 +0000] "POST /api/pay HTTP/1.1" 500 1234 "-" "curl/7.68"\n',
            "apache",
        ),
        (
            "Windows Event XML Log",
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n'
            '  <System><EventID>1000</EventID><Level>2</Level><TimeCreated SystemTime="2024-01-15T03:42:11Z"/></System>\n'
            '  <EventData><Data>Application crashed: payment-service.exe</Data></EventData>\n'
            '</Event>\n',
            "windows",
        ),
        (
            "CSV Log Export",
            "timestamp,level,service,message,cpu,memory,error_rate\n"
            "2024-01-15 03:42:11,ERROR,payment-service,OOMKilled,97.4,98.1,43\n",
            "csv",
        ),
        (
            "Syslog RFC 3164",
            "Jan 15 03:42:11 server01 kernel: Out of memory: Kill process 1234 (java) score 900 or sacrifice child\n",
            "syslog",
        ),
        (
            "Raw Unstructured Trace",
            "Worker thread panic: fatal memory corruption detected pid=9988\n",
            "auto",
        ),
    ]

    print("\n--> TEST 2: Testing POST /api/ingest/paste for all 7 formats...")
    for label, raw_text, format_hint in paste_samples:
        response = client.post(
            "/api/ingest/paste",
            json={
                "raw_text": raw_text,
                "service_name": "test-paste-service",
                "format_hint": format_hint,
            },
        )
        print(f"    Testing {label} -> Status: {response.status_code}, Body: {response.json()}")
        assert response.status_code == 200
        body = response.json()
        assert body["lines_parsed"] > 0
        assert body["events_published"] > 0
        assert body["errors_skipped"] == 0

    # ---------------------------------------------------------------------
    # TEST 3: Testing POST /api/ingest/file via HTTP API
    # ---------------------------------------------------------------------
    print("\n--> TEST 3: Testing POST /api/ingest/file via HTTP...")
    resp_f = client.post(
        "/api/ingest/file",
        json={"file_path": os.path.abspath("test_logs/structured_json.log")},
    )
    print(f"    File API result: {resp_f.status_code}, {resp_f.json()}")
    assert resp_f.status_code == 200
    assert resp_f.json()["lines_parsed"] == 4

    # ---------------------------------------------------------------------
    # TEST 4: Testing POST /api/ingest/windows-events via HTTP
    # ---------------------------------------------------------------------
    print("\n--> TEST 4: Testing POST /api/ingest/windows-events via HTTP...")
    resp_w = client.post(
        "/api/ingest/windows-events",
        json={"channel": "Application", "last_n_events": 10, "min_level": "All"},
    )
    print(f"    Windows events API result: {resp_w.status_code}, {resp_w.json()}")
    assert resp_w.status_code == 200
    assert resp_w.json()["events_published"] > 0

    # ---------------------------------------------------------------------
    # TEST 5: Testing GET /api/ingest/status
    # ---------------------------------------------------------------------
    print("\n--> TEST 5: Testing GET /api/ingest/status...")
    resp_s = client.get("/api/ingest/status")
    print(f"    Status API result: {resp_s.status_code}, {resp_s.json()}")
    assert resp_s.status_code == 200
    status_body = resp_s.json()
    assert "file_watcher_active" in status_body
    assert "watch_folder" in status_body
    assert status_body["total_events_ingested_today"] > 0

    # ---------------------------------------------------------------------
    # TEST 6: Testing POST /api/ingest/demo
    # ---------------------------------------------------------------------
    print("\n--> TEST 6: Testing POST /api/ingest/demo...")
    resp_d = client.post("/api/ingest/demo")
    assert resp_d.status_code == 200
    assert resp_d.json()["message"] == "Demo simulation started"

    print("\n" + "=" * 80)
    print("ALL PHASE 19 TESTS PASSED SUCCESSFULLY!")
    print("=" * 80)


if __name__ == "__main__":
    test_real_log_ingestion()
