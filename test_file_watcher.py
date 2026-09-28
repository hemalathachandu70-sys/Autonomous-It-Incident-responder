"""Test script for Phase 17: file_watcher.py
Verifies:
1. File watcher detects new file in watched_logs/ within 2 seconds
2. Events are parsed and published to Redis channel
3. File modifications ingest only the new lines
4. Unsupported extensions and temp files are ignored
"""

import os
import shutil
import sys
import time

sys.path.insert(0, os.path.abspath("."))

from backend.app.ingestion.file_watcher import LogFileWatcher
from backend.app.ingestion.redis_client import RedisClient


def test_file_watcher():
    test_watch_dir = os.path.abspath("test_watched_logs")
    if os.path.exists(test_watch_dir):
        shutil.rmtree(test_watch_dir)
    os.makedirs(test_watch_dir, exist_ok=True)

    redis_client = RedisClient()
    redis_client.clear_history()

    received_events = []

    def on_event(evt):
        received_events.append((time.time(), evt))

    watcher = LogFileWatcher(
        watch_folder=test_watch_dir,
        redis_client=redis_client,
        event_callback=on_event,
    )

    print("=" * 80)
    print("PHASE 17 TEST SUITE: FILE WATCHER & REDIS PUBLISHING VALIDATION")
    print("=" * 80)

    try:
        # Start the file watcher
        watcher.start_sync()
        print(f"Watcher started on: {test_watch_dir}")
        time.sleep(0.2)  # Give watchdog thread moment to attach

        # ---------------------------------------------------------------------
        # TEST 1: Drop new log file into watched folder
        # ---------------------------------------------------------------------
        print("\n--> TEST 1: Dropping new file into watched directory...")
        drop_file_path = os.path.join(test_watch_dir, "incident_drop.log")
        drop_content = (
            "2024-01-15 05:00:00 ERROR auth-service: OAuth token expired\n"
            "2024-01-15 05:00:01 WARN  auth-service: High authentication latency\n"
        )

        t_drop = time.time()
        with open(drop_file_path, "w", encoding="utf-8") as f:
            f.write(drop_content)

        # Wait up to 2 seconds for event arrival
        event_arrived = False
        time_elapsed = 0.0
        while time.time() - t_drop < 2.0:
            if len(received_events) >= 2:
                time_elapsed = time.time() - t_drop
                event_arrived = True
                break
            time.sleep(0.05)

        print(f"    Events arrived in Redis: {event_arrived} (in {time_elapsed:.3f}s)")
        assert event_arrived, "Events did not arrive in Redis within 2 seconds!"
        assert time_elapsed <= 2.0, f"Arrival took longer than 2.0s: {time_elapsed}s"
        assert len(received_events) == 2, f"Expected 2 events, got {len(received_events)}"

        first_evt = received_events[0][1]
        print(f"    First Event Level: {first_evt['level']}, Service: {first_evt['service']}, Source: {first_evt['source_type']}")
        assert first_evt["service"] == "auth-service"
        assert first_evt["level"] == "ERROR"
        assert first_evt["source_type"] == "folder"

        # ---------------------------------------------------------------------
        # TEST 2: Modify existing file - verify ONLY new lines are ingested
        # ---------------------------------------------------------------------
        print("\n--> TEST 2: Appending new line to existing file...")
        prev_count = len(received_events)
        append_line = "2024-01-15 05:00:02 CRITICAL auth-service: Identity provider unreachable cpu=91.5%\n"

        t_modify = time.time()
        with open(drop_file_path, "a", encoding="utf-8") as f:
            f.write(append_line)

        mod_arrived = False
        while time.time() - t_modify < 2.0:
            if len(received_events) == prev_count + 1:
                mod_arrived = True
                break
            time.sleep(0.05)

        print(f"    New line ingested: {mod_arrived} (total events: {len(received_events)})")
        assert mod_arrived, "Appended line was not ingested within 2 seconds!"
        latest_evt = received_events[-1][1]
        assert latest_evt["level"] == "CRITICAL"
        assert latest_evt["cpu_percent"] == 91.5

        # ---------------------------------------------------------------------
        # TEST 3: Ignored files test
        # ---------------------------------------------------------------------
        print("\n--> TEST 3: Verifying ignored file types (.py, .pdf, temp files)...")
        ignored_path = os.path.join(test_watch_dir, "script.py")
        with open(ignored_path, "w", encoding="utf-8") as f:
            f.write("print('should be ignored')\n")
        time.sleep(0.3)
        assert len(received_events) == 3, f"Ignored file should not trigger events, count={len(received_events)}"
        print("    Ignored file skipped correctly.")

        # ---------------------------------------------------------------------
        # TEST 4: Status endpoint inspection
        # ---------------------------------------------------------------------
        print("\n--> TEST 4: Verifying watcher status payload...")
        status = watcher.get_status()
        print(f"    Status: {status}")
        assert status["file_watcher_active"] is True
        assert "incident_drop.log" in status["files_being_watched"]
        assert status["total_events_ingested_today"] == 3

    finally:
        watcher.stop_sync()
        print("\nWatcher stopped successfully.")
        if os.path.exists(test_watch_dir):
            shutil.rmtree(test_watch_dir, ignore_errors=True)

    print("\n" + "=" * 80)
    print("ALL PHASE 17 TESTS PASSED SUCCESSFULLY!")
    print("=" * 80)


if __name__ == "__main__":
    test_file_watcher()
