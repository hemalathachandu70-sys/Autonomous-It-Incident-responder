"""Test script for Phase 18: windows_event_reader.py
Tests reading real Windows Event Viewer logs and publishing to Redis.
"""

import json
import os
import sys

sys.path.insert(0, os.path.abspath("."))

from backend.app.ingestion.windows_event_reader import WindowsEventReader
from backend.app.ingestion.redis_client import RedisClient


def test_windows_events():
    print("=" * 80)
    print("PHASE 18 TEST SUITE: WINDOWS EVENT VIEWER INGESTION")
    print("=" * 80)

    redis_client = RedisClient()
    redis_client.clear_history()

    reader = WindowsEventReader(redis_client=redis_client)
    assert reader.is_available, "pywin32 is not available on this Windows host"

    print("\n--> TEST 1: Reading last 50 Application events (All levels)...")
    events = reader.read_events(channel="Application", last_n_events=50, min_level="All")
    print(f"    Successfully read {len(events)} events from Application channel.")
    assert len(events) > 0, "No Application events could be read from Event Viewer"

    # Validate schema for all events
    for evt in events:
        d = evt.to_dict()
        assert d["source_type"] == "windows_event"
        assert d["source_path"] == "event_viewer/Application"
        assert d["level"] in ("CRITICAL", "ERROR", "WARN", "INFO", "DEBUG")
        assert len(d["timestamp"]) > 0
        assert len(d["service"]) > 0

    print("    Sample Event 0:")
    print("    " + json.dumps(events[0].to_dict(), indent=2).replace("\n", "\n    "))

    # Test ingest_and_publish
    print("\n--> TEST 2: Ingest and publish last 25 Application events...")
    redis_client.clear_history()
    result = reader.ingest_and_publish(channel="Application", last_n_events=25, min_level="All")
    print(f"    Result: {result}")
    assert result["events_read"] == len(redis_client.get_history())
    assert result["events_published"] == result["events_read"]
    print(f"    Verified {result['events_published']} events published to Redis.")

    # Test System channel
    print("\n--> TEST 3: Reading System channel...")
    sys_events = reader.read_events(channel="System", last_n_events=10, min_level="All")
    print(f"    Successfully read {len(sys_events)} events from System channel.")
    assert len(sys_events) > 0

    print("\n" + "=" * 80)
    print("ALL PHASE 18 TESTS PASSED SUCCESSFULLY!")
    print("=" * 80)


if __name__ == "__main__":
    test_windows_events()
