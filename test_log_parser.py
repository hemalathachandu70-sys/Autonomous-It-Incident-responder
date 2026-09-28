"""Test script for Phase 16: log_parser.py
Validates parsing across all 7 supported log formats.
"""

import json
import os
import sys

# Ensure backend package can be imported
sys.path.insert(0, os.path.abspath("."))

from backend.app.ingestion.log_parser import LogParser, LogEvent

REQUIRED_KEYS = {
    "timestamp",
    "service",
    "level",
    "message",
    "cpu_percent",
    "memory_percent",
    "error_rate",
    "source_type",
    "source_path",
    "raw_line",
}

VALID_LEVELS = {"CRITICAL", "ERROR", "WARN", "INFO", "DEBUG"}


def validate_event(event: LogEvent, format_name: str) -> None:
    d = event.to_dict()
    missing = REQUIRED_KEYS - set(d.keys())
    assert not missing, f"[{format_name}] Event dictionary missing keys: {missing}"
    assert d["level"] in VALID_LEVELS, f"[{format_name}] Invalid level: {d['level']}"
    assert isinstance(d["timestamp"], str) and len(d["timestamp"]) > 0, f"[{format_name}] Invalid timestamp"
    assert isinstance(d["service"], str) and len(d["service"]) > 0, f"[{format_name}] Invalid service"
    assert isinstance(d["message"], str), f"[{format_name}] Invalid message"
    for metric_key in ("cpu_percent", "memory_percent", "error_rate"):
        val = d[metric_key]
        assert val is None or isinstance(val, (int, float)), f"[{format_name}] {metric_key} must be float or None, got {val}"


def run_tests():
    parser = LogParser(default_service="test-service")
    test_dir = "test_logs"

    files_to_test = [
        ("Format 1: Plain Text (Java OOM Crash)", os.path.join(test_dir, "java_oom_crash.log")),
        ("Format 2: Structured JSON", os.path.join(test_dir, "structured_json.log")),
        ("Format 3: Nginx Access Logs", os.path.join(test_dir, "nginx_500_errors.log")),
        ("Format 4: Windows Event XML", os.path.join(test_dir, "sample_windows_event.xml")),
        ("Format 5: CSV Log Export", os.path.join(test_dir, "sample_export.csv")),
        ("Format 6: Syslog RFC 3164", os.path.join(test_dir, "syslog_sample.log")),
        ("Mixed Format Log", os.path.join(test_dir, "mixed_format.log")),
    ]

    total_events = 0
    print("=" * 80)
    print("PHASE 16 TEST SUITE: LOG PARSER VALIDATION")
    print("=" * 80)

    for desc, file_path in files_to_test:
        print(f"\n--> Testing {desc}: {file_path}")
        assert os.path.exists(file_path), f"File not found: {file_path}"
        events = parser.parse_file(file_path)
        print(f"    Parsed {len(events)} events successfully.")
        assert len(events) > 0, f"No events parsed from {file_path}"

        for idx, evt in enumerate(events):
            validate_event(evt, desc)
            total_events += 1

        # Display first parsed event sample
        sample_dict = events[0].to_dict()
        print("    Sample Event 0:")
        print("    " + json.dumps(sample_dict, indent=2).replace("\n", "\n    "))

    # Test Format 7: Raw Paste
    print("\n--> Testing Format 7: Raw Paste Ingestion")
    raw_paste = (
        "2024-01-15 04:00:00 ERROR billing: database lock timeout\n"
        "Unstructured trace: critical failure in worker pool cpu_percent=88.5 mem=92.1\n"
    )
    paste_events = parser.parse_text(raw_paste, source_type="paste", source_path="paste")
    print(f"    Parsed {len(paste_events)} paste events successfully.")
    assert len(paste_events) == 2, f"Expected 2 paste events, got {len(paste_events)}"
    for evt in paste_events:
        validate_event(evt, "Format 7: Raw Paste")
        total_events += 1

    print("\n" + "=" * 80)
    print(f"ALL TESTS PASSED! Total validated LogEvent records: {total_events}")
    print("=" * 80)


if __name__ == "__main__":
    run_tests()
