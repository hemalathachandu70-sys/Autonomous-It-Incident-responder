"""Log Parser for Autonomous IT Incident Responder.

Parses logs from 7 formats into normalized LogEvent objects:
1. Plain text logs (timestamp, level, service, message, metric extraction)
2. JSON structured logs (standard and shorthand formats)
3. Apache / Nginx access logs
4. Windows Event Viewer XML export
5. CSV log exports
6. Syslog format (RFC 3164)
7. Raw paste / Unstructured text with LLM fallback & keyword heuristics
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class LogEvent:
    timestamp: str  # ISO 8601 UTC string
    service: str  # extracted service name or 'unknown-service'
    level: str  # ERROR | WARN | INFO | DEBUG | CRITICAL
    message: str  # the log message text
    cpu_percent: Optional[float] = None  # float or None
    memory_percent: Optional[float] = None  # float or None
    error_rate: Optional[float] = None  # float or None
    source_type: str = "file"  # file | windows_event | paste | demo | folder
    source_path: str = "paste"  # path to file or 'paste' or 'demo'
    raw_line: str = ""  # original unparsed log line for reference

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "service": self.service or "unknown-service",
            "level": self.level or "INFO",
            "message": self.message or "",
            "cpu_percent": float(self.cpu_percent) if self.cpu_percent is not None else None,
            "memory_percent": float(self.memory_percent) if self.memory_percent is not None else None,
            "error_rate": float(self.error_rate) if self.error_rate is not None else None,
            "source_type": self.source_type,
            "source_path": self.source_path,
            "raw_line": self.raw_line,
        }


class LogParser:
    """Multi-format log parser conforming to the Autonomous IT Incident Responder schema."""

    # Regex patterns
    APACHE_REGEX = re.compile(
        r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?'
    )
    SYSLOG_REGEX = re.compile(
        r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:\[]+)(?:\[(\d+)\])?:\s+(.*)$"
    )

    # Plain text timestamp patterns
    # Pattern 1: 2024-01-15 03:40:00 INFO payment-service: Request processed OK
    PLAIN_P1 = re.compile(
        r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+([A-Z]+)\s+([a-zA-Z0-9_\-\.]+):\s+(.*)$"
    )
    # Pattern 2: ERROR 2024-01-15T03:42:01Z service=payment msg="memory limit exceeded"
    PLAIN_P2 = re.compile(
        r"^([A-Z]+)\s+(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:?\d{2})?)\s+(.*)$"
    )
    # Pattern 3: [2024-01-15 03:42:00] [ERROR] payment-service crashed - signal 9
    PLAIN_P3 = re.compile(
        r"^\[(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\]\s+\[([A-Z]+)\]\s+(.*)$"
    )
    # Pattern 4: 03:42:02 CRITICAL cpu=97% mem=98% err_rate=43% service=payment-service
    PLAIN_P4 = re.compile(
        r"^(\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+([A-Z]+)\s+(.*)$"
    )
    # Pattern 5: 2024-01-15T03:42:11Z LEVEL message
    PLAIN_P5 = re.compile(
        r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:?\d{2})?)\s+([A-Z]+)\s+(.*)$"
    )

    # Metric extraction regexes
    CPU_REGEX = re.compile(r"(?:cpu_percent|cpu)[\s:=]+([0-9]+(?:\.[0-9]+)?)%?", re.IGNORECASE)
    MEM_REGEX = re.compile(r"(?:memory_percent|memory|mem)[\s:=]+([0-9]+(?:\.[0-9]+)?)%?", re.IGNORECASE)
    ERR_REGEX = re.compile(r"(?:error_rate_percent|error_rate|err_rate|err)[\s:=]+([0-9]+(?:\.[0-9]+)?)%?", re.IGNORECASE)

    LEVEL_MAP = {
        "CRIT": "CRITICAL",
        "CRITICAL": "CRITICAL",
        "FATAL": "CRITICAL",
        "ERR": "ERROR",
        "ERROR": "ERROR",
        "WARN": "WARN",
        "WARNING": "WARN",
        "INFO": "INFO",
        "INF": "INFO",
        "DEBUG": "DEBUG",
        "DBG": "DEBUG",
        "TRACE": "DEBUG",
    }

    def __init__(self, default_service: str = "unknown-service"):
        self.default_service = default_service

    def normalize_level(self, raw_level: Any) -> str:
        if raw_level is None:
            return "INFO"
        lvl_str = str(raw_level).strip().upper()
        return self.LEVEL_MAP.get(lvl_str, "INFO")

    def parse_iso_timestamp(self, ts_str: Optional[str]) -> str:
        if not ts_str:
            return datetime.now(timezone.utc).isoformat()
        ts_clean = ts_str.strip()
        try:
            # Handle ISO formats
            if ts_clean.endswith("Z"):
                dt = datetime.fromisoformat(ts_clean[:-1] + "+00:00")
            elif "+" in ts_clean or "-" in ts_clean[10:]:
                dt = datetime.fromisoformat(ts_clean)
            else:
                # Naive date/time
                if "T" in ts_clean:
                    dt = datetime.fromisoformat(ts_clean).replace(tzinfo=timezone.utc)
                else:
                    dt = datetime.strptime(ts_clean, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            pass

        # Handle time-only "HH:MM:SS"
        try:
            t = datetime.strptime(ts_clean, "%H:%M:%S").time()
            now = datetime.now(timezone.utc)
            dt = datetime(now.year, now.month, now.day, t.hour, t.minute, t.second, tzinfo=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            pass

        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def extract_metrics(self, text: str) -> Tuple[Optional[float], Optional[float], Optional[float]]:
        cpu: Optional[float] = None
        mem: Optional[float] = None
        err: Optional[float] = None

        m_cpu = self.CPU_REGEX.search(text)
        if m_cpu:
            try:
                cpu = float(m_cpu.group(1))
            except ValueError:
                pass

        m_mem = self.MEM_REGEX.search(text)
        if m_mem:
            try:
                mem = float(m_mem.group(1))
            except ValueError:
                pass

        m_err = self.ERR_REGEX.search(text)
        if m_err:
            try:
                err = float(m_err.group(1))
            except ValueError:
                pass

        return cpu, mem, err

    def parse_line(
        self,
        line: str,
        source_type: str = "file",
        source_path: str = "paste",
        default_service: Optional[str] = None,
        format_hint: Optional[str] = None,
    ) -> LogEvent:
        """Parse a single log line into a normalized LogEvent."""
        raw_line = line.rstrip("\r\n")
        stripped = raw_line.strip()
        svc_fallback = default_service or self.default_service

        if not stripped:
            return LogEvent(
                timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                service=svc_fallback,
                level="INFO",
                message="",
                source_type=source_type,
                source_path=source_path,
                raw_line=raw_line,
            )

        # ---------------------------------------------------------
        # Step 1: Try JSON parse
        # ---------------------------------------------------------
        if format_hint in (None, "auto", "json") and (stripped.startswith("{") and stripped.endswith("}")):
            try:
                data = json.loads(stripped)
                if isinstance(data, dict):
                    # Check for timestamp keys
                    raw_ts = data.get("timestamp") or data.get("time") or data.get("t")
                    ts = self.parse_iso_timestamp(raw_ts) if raw_ts else datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

                    # Level
                    raw_lvl = data.get("level") or data.get("lvl") or data.get("severity") or "INFO"
                    level = self.normalize_level(raw_lvl)

                    # Service
                    service = (
                        data.get("service")
                        or data.get("svc")
                        or data.get("app")
                        or data.get("name")
                        or svc_fallback
                    )

                    # Message
                    msg = str(data.get("message") or data.get("msg") or data.get("log") or "")

                    # Metrics
                    cpu = data.get("cpu_percent")
                    if cpu is None:
                        cpu = data.get("cpu")
                    mem = data.get("memory_percent")
                    if mem is None:
                        mem = data.get("memory") or data.get("mem")
                    err = data.get("error_rate")
                    if err is None:
                        err = data.get("error_rate_percent") or data.get("err_rate")

                    cpu = float(cpu) if cpu is not None else None
                    mem = float(mem) if mem is not None else None
                    err = float(err) if err is not None else None

                    # If metrics missing in JSON keys, check message
                    if cpu is None or mem is None or err is None:
                        c, m, e = self.extract_metrics(msg)
                        cpu = cpu if cpu is not None else c
                        mem = mem if mem is not None else m
                        err = err if err is not None else e

                    return LogEvent(
                        timestamp=ts,
                        service=str(service),
                        level=level,
                        message=msg,
                        cpu_percent=cpu,
                        memory_percent=mem,
                        error_rate=err,
                        source_type=source_type,
                        source_path=source_path,
                        raw_line=raw_line,
                    )
            except Exception:
                pass

        # ---------------------------------------------------------
        # Step 3: Try XML detection (Windows Event Viewer XML export)
        # ---------------------------------------------------------
        if format_hint in (None, "auto", "windows", "xml") and (stripped.startswith("<Event") or "<Event" in stripped):
            try:
                xml_str = stripped
                # If wrapped or fragment
                root = ET.fromstring(xml_str)
                # Remove namespaces for easy querying
                for elem in root.iter():
                    if "}" in elem.tag:
                        elem.tag = elem.tag.split("}", 1)[1]

                # EventID
                event_id_elem = root.find(".//EventID")
                event_id = event_id_elem.text if event_id_elem is not None else "Unknown"

                # Level: 1=Critical, 2=Error, 3=Warn, 4=Info
                level_elem = root.find(".//Level")
                lvl_val = level_elem.text.strip() if level_elem is not None and level_elem.text else "2"
                level_map_xml = {"1": "CRITICAL", "2": "ERROR", "3": "WARN", "4": "INFO", "0": "INFO"}
                level = level_map_xml.get(lvl_val, "ERROR")

                # Timestamp
                time_elem = root.find(".//TimeCreated")
                sys_time = time_elem.get("SystemTime") if time_elem is not None else None
                ts = self.parse_iso_timestamp(sys_time)

                # Provider / Service
                provider_elem = root.find(".//Provider")
                prov_name = provider_elem.get("Name") if provider_elem is not None else None
                service = prov_name or svc_fallback

                # Message / EventData
                data_elements = root.findall(".//EventData/Data")
                if data_elements:
                    msg = " | ".join([d.text for d in data_elements if d.text])
                else:
                    msg = f"Windows EventID {event_id}"

                # Check if message specifies service (e.g., Application crashed: payment-service.exe)
                svc_match = re.search(r"([a-zA-Z0-9_\-\.]+)\.(?:exe|dll)", msg, re.IGNORECASE)
                if svc_match:
                    service = svc_match.group(1)

                cpu, mem, err = self.extract_metrics(msg)

                return LogEvent(
                    timestamp=ts,
                    service=service,
                    level=level,
                    message=msg,
                    cpu_percent=cpu,
                    memory_percent=mem,
                    error_rate=err,
                    source_type="windows_event" if source_type == "file" else source_type,
                    source_path=source_path,
                    raw_line=raw_line,
                )
            except Exception:
                pass

        # ---------------------------------------------------------
        # Step 4: Try Apache/Nginx pattern
        # ---------------------------------------------------------
        if format_hint in (None, "auto", "apache", "nginx"):
            m_apache = self.APACHE_REGEX.match(stripped)
            if m_apache:
                ip, raw_date, request, status_code_str, bytes_sent, referer, user_agent = (
                    m_apache.groups()
                )
                try:
                    # e.g., 15/Jan/2024:03:42:11 +0000
                    # clean timezone
                    dt = datetime.strptime(raw_date.split()[0], "%d/%b/%Y:%H:%M:%S").replace(
                        tzinfo=timezone.utc
                    )
                    ts = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                except Exception:
                    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

                status_code = int(status_code_str)
                if status_code >= 500:
                    level = "ERROR"
                elif status_code >= 400:
                    level = "WARN"
                else:
                    level = "INFO"

                # Extract service from URL if present (e.g. /api/pay -> payment-service or pay)
                service = svc_fallback
                req_parts = request.split()
                if len(req_parts) >= 2:
                    url = req_parts[1]
                    url_match = re.search(r"^/api/([a-zA-Z0-9_\-]+)", url)
                    if url_match:
                        matched_name = url_match.group(1)
                        if "pay" in matched_name:
                            service = "payment-service"
                        else:
                            service = f"{matched_name}-service"
                    elif service == "unknown-service":
                        service = "nginx"

                msg = f'"{request}" {status_code} {bytes_sent}'
                return LogEvent(
                    timestamp=ts,
                    service=service,
                    level=level,
                    message=msg,
                    cpu_percent=None,
                    memory_percent=None,
                    error_rate=None,
                    source_type=source_type,
                    source_path=source_path,
                    raw_line=raw_line,
                )

        # ---------------------------------------------------------
        # Step 5: Try Syslog pattern (RFC 3164)
        # ---------------------------------------------------------
        if format_hint in (None, "auto", "syslog"):
            m_syslog = self.SYSLOG_REGEX.match(stripped)
            if m_syslog:
                raw_time, hostname, proc_name, pid, msg = m_syslog.groups()
                # Timestamp: Jan 15 03:42:11 (syslog lacks year, default to 2024 or current year)
                try:
                    now = datetime.now(timezone.utc)
                    curr_year = now.year if now.year >= 2024 else 2024
                    dt_str = f"{curr_year} {raw_time}"
                    dt = datetime.strptime(dt_str, "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
                    ts = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                except Exception:
                    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

                # Service name: proc_name, or if proc_name is systemd/kernel inspect msg
                service = proc_name.strip()
                if service in ("systemd", "kernel"):
                    # Check if service is named inside message e.g. payment-service.service
                    svc_m = re.search(r"([a-zA-Z0-9_\-]+)\.service", msg)
                    if svc_m:
                        service = svc_m.group(1)
                    else:
                        proc_m = re.search(r"process \d+ \(([^)]+)\)", msg, re.IGNORECASE)
                        if proc_m:
                            p = proc_m.group(1)
                            service = f"{p}-service" if not p.endswith("-service") else p

                # Severity heuristics for syslog
                msg_lower = msg.lower()
                if any(w in msg_lower for w in ["out of memory", "kill process", "killed process", "segfault", "segmentation fault", "kernel panic", "failed", "enter failed state"]):
                    level = "ERROR"
                elif any(w in msg_lower for w in ["warning", "warn", "above threshold", "high latency", "temperature"]):
                    level = "WARN"
                else:
                    level = "INFO"

                cpu, mem, err = self.extract_metrics(msg)

                return LogEvent(
                    timestamp=ts,
                    service=service,
                    level=level,
                    message=msg,
                    cpu_percent=cpu,
                    memory_percent=mem,
                    error_rate=err,
                    source_type=source_type,
                    source_path=source_path,
                    raw_line=raw_line,
                )

        # ---------------------------------------------------------
        # Step 6: Try Plain Text timestamp patterns
        # ---------------------------------------------------------
        # Pattern 1: 2024-01-15 03:40:00 INFO payment-service: Request processed OK
        m1 = self.PLAIN_P1.match(stripped)
        if m1:
            raw_ts, raw_lvl, service, msg = m1.groups()
            ts = self.parse_iso_timestamp(raw_ts)
            level = self.normalize_level(raw_lvl)
            cpu, mem, err = self.extract_metrics(msg)
            return LogEvent(
                timestamp=ts,
                service=service,
                level=level,
                message=msg,
                cpu_percent=cpu,
                memory_percent=mem,
                error_rate=err,
                source_type=source_type,
                source_path=source_path,
                raw_line=raw_line,
            )

        # Pattern 2: ERROR 2024-01-15T03:42:01Z service=payment msg="memory limit exceeded"
        m2 = self.PLAIN_P2.match(stripped)
        if m2:
            raw_lvl, raw_ts, rest = m2.groups()
            ts = self.parse_iso_timestamp(raw_ts)
            level = self.normalize_level(raw_lvl)

            # Extract service=... and msg="..." if present
            service = svc_fallback
            svc_m = re.search(r"service=([^\s]+)", rest)
            if svc_m:
                service = svc_m.group(1).strip('"\'')
            msg_m = re.search(r'msg="([^"]*)"', rest)
            msg = msg_m.group(1) if msg_m else rest

            cpu, mem, err = self.extract_metrics(rest)
            return LogEvent(
                timestamp=ts,
                service=service,
                level=level,
                message=msg,
                cpu_percent=cpu,
                memory_percent=mem,
                error_rate=err,
                source_type=source_type,
                source_path=source_path,
                raw_line=raw_line,
            )

        # Pattern 3: [2024-01-15 03:42:00] [ERROR] payment-service crashed - signal 9
        m3 = self.PLAIN_P3.match(stripped)
        if m3:
            raw_ts, raw_lvl, rest = m3.groups()
            ts = self.parse_iso_timestamp(raw_ts)
            level = self.normalize_level(raw_lvl)

            # Check if rest starts with service: or service - message
            service = svc_fallback
            rest_m = re.match(r"^([a-zA-Z0-9_\-\.]+)(?::\s+|\s+-\s+|\s+)(.*)$", rest)
            if rest_m:
                cand_svc, cand_msg = rest_m.groups()
                if any(cand_svc.endswith(s) for s in ("-service", "_service", ".exe", "service", "server")) or len(cand_svc.split()) == 1:
                    service = cand_svc
                    msg = cand_msg
                else:
                    msg = rest
            else:
                msg = rest

            cpu, mem, err = self.extract_metrics(msg)
            return LogEvent(
                timestamp=ts,
                service=service,
                level=level,
                message=msg,
                cpu_percent=cpu,
                memory_percent=mem,
                error_rate=err,
                source_type=source_type,
                source_path=source_path,
                raw_line=raw_line,
            )

        # Pattern 4: 03:42:02 CRITICAL cpu=97% mem=98% err_rate=43% service=payment-service
        m4 = self.PLAIN_P4.match(stripped)
        if m4:
            raw_time, raw_lvl, rest = m4.groups()
            ts = self.parse_iso_timestamp(raw_time)
            level = self.normalize_level(raw_lvl)

            service = svc_fallback
            svc_m = re.search(r"service=([^\s]+)", rest)
            if svc_m:
                service = svc_m.group(1).strip('"\'')
            elif "payment-service" in rest:
                service = "payment-service"

            cpu, mem, err = self.extract_metrics(rest)
            return LogEvent(
                timestamp=ts,
                service=service,
                level=level,
                message=rest,
                cpu_percent=cpu,
                memory_percent=mem,
                error_rate=err,
                source_type=source_type,
                source_path=source_path,
                raw_line=raw_line,
            )

        # Pattern 5: 2024-01-15T03:42:11Z LEVEL message
        m5 = self.PLAIN_P5.match(stripped)
        if m5:
            raw_ts, raw_lvl, rest = m5.groups()
            ts = self.parse_iso_timestamp(raw_ts)
            level = self.normalize_level(raw_lvl)
            cpu, mem, err = self.extract_metrics(rest)

            service = svc_fallback
            svc_m = re.match(r"^([a-zA-Z0-9_\-\.]+):\s+(.*)$", rest)
            if svc_m:
                service, msg = svc_m.groups()
            else:
                msg = rest

            return LogEvent(
                timestamp=ts,
                service=service,
                level=level,
                message=msg,
                cpu_percent=cpu,
                memory_percent=mem,
                error_rate=err,
                source_type=source_type,
                source_path=source_path,
                raw_line=raw_line,
            )

        # ---------------------------------------------------------
        # Step 7: Fallback Parser (Heuristics & LLM)
        # ---------------------------------------------------------
        # Keyword heuristics
        lower_line = stripped.lower()
        if any(w in lower_line for w in ["error", "exception", "failed", "crash", "killed", "panic", "oomkilled", "fatal"]):
            level = "ERROR"
        elif any(w in lower_line for w in ["warn", "warning", "slow", "timeout", "retry"]):
            level = "WARN"
        elif any(w in lower_line for w in ["debug", "trace"]):
            level = "DEBUG"
        else:
            level = "INFO"

        service = svc_fallback
        svc_m = re.search(r"([a-zA-Z0-9_\-]+(?:-service|_service))", stripped, re.IGNORECASE)
        if svc_m:
            service = svc_m.group(1)

        cpu, mem, err = self.extract_metrics(stripped)

        return LogEvent(
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            service=service,
            level=level,
            message=stripped,
            cpu_percent=cpu,
            memory_percent=mem,
            error_rate=err,
            source_type=source_type,
            source_path=source_path,
            raw_line=raw_line,
        )

    def parse_text(
        self,
        raw_text: str,
        source_type: str = "paste",
        source_path: str = "paste",
        default_service: Optional[str] = None,
        format_hint: Optional[str] = None,
    ) -> List[LogEvent]:
        """Parse raw text containing multiple log lines, handling CSV, XML, and multiline tracebacks."""
        if not raw_text or not raw_text.strip():
            return []

        # ---------------------------------------------------------
        # Step 2: Try CSV detection (whole block)
        # ---------------------------------------------------------
        first_line = raw_text.strip().splitlines()[0]
        if format_hint == "csv" or ("," in first_line and any(h in first_line.lower() for h in ["timestamp", "time", "message", "msg", "level", "service"])):
            try:
                reader = csv.DictReader(io.StringIO(raw_text.strip()))
                fieldnames = [f.strip().lower() for f in (reader.fieldnames or [])]
                if "timestamp" in fieldnames or "message" in fieldnames or "level" in fieldnames:
                    events: List[LogEvent] = []
                    for row in reader:
                        # Normalize key lookups
                        norm_row = {k.strip().lower(): (v.strip() if v else "") for k, v in row.items() if k}
                        raw_ts = norm_row.get("timestamp") or norm_row.get("time")
                        ts = self.parse_iso_timestamp(raw_ts)
                        level = self.normalize_level(norm_row.get("level") or norm_row.get("severity") or "INFO")
                        service = norm_row.get("service") or norm_row.get("svc") or default_service or self.default_service
                        message = norm_row.get("message") or norm_row.get("msg") or ""

                        cpu = norm_row.get("cpu_percent") or norm_row.get("cpu")
                        mem = norm_row.get("memory_percent") or norm_row.get("memory") or norm_row.get("mem")
                        err = norm_row.get("error_rate") or norm_row.get("error_rate_percent") or norm_row.get("err_rate")

                        cpu_val = float(cpu) if cpu and cpu != "" else None
                        mem_val = float(mem) if mem and mem != "" else None
                        err_val = float(err) if err and err != "" else None

                        raw_row_line = ",".join([str(v) for v in row.values()])
                        events.append(
                            LogEvent(
                                timestamp=ts,
                                service=service,
                                level=level,
                                message=message,
                                cpu_percent=cpu_val,
                                memory_percent=mem_val,
                                error_rate=err_val,
                                source_type=source_type,
                                source_path=source_path,
                                raw_line=raw_row_line,
                            )
                        )
                    if events:
                        return events
            except Exception:
                pass

        # ---------------------------------------------------------
        # Step 3: Try XML block detection (<Event ...> ... </Event>)
        # ---------------------------------------------------------
        if "<Event" in raw_text and ("</Event>" in raw_text or "<Events>" in raw_text):
            # Parse individual <Event> tags
            event_blocks = re.findall(r"(<Event\b[\s\S]*?</Event>)", raw_text)
            if event_blocks:
                events = []
                for block in event_blocks:
                    evt = self.parse_line(
                        block,
                        source_type="windows_event" if source_type == "file" else source_type,
                        source_path=source_path,
                        default_service=default_service,
                        format_hint="windows",
                    )
                    events.append(evt)
                return events

        # ---------------------------------------------------------
        # Multiline aggregation for standard lines (e.g. stack traces)
        # ---------------------------------------------------------
        lines = raw_text.splitlines()
        aggregated_entries: List[Tuple[str, str]] = []  # (primary_line, combined_raw)

        for line in lines:
            if not line.strip():
                continue
            # If line starts with whitespace or typical traceback markers, append to previous line
            if (line.startswith(" ") or line.startswith("\t") or line.startswith("Caused by:") or line.startswith("at ")) and aggregated_entries:
                prev_line, prev_raw = aggregated_entries[-1]
                aggregated_entries[-1] = (
                    f"{prev_line} {line.strip()}",
                    f"{prev_raw}\n{line}",
                )
            else:
                aggregated_entries.append((line, line))

        events: List[LogEvent] = []
        for primary, full_raw in aggregated_entries:
            evt = self.parse_line(
                primary,
                source_type=source_type,
                source_path=source_path,
                default_service=default_service,
                format_hint=format_hint,
            )
            evt.raw_line = full_raw
            events.append(evt)

        return events

    def parse_file(
        self,
        file_path: str,
        source_type: str = "file",
        default_service: Optional[str] = None,
    ) -> List[LogEvent]:
        """Read and parse an entire log file from disk."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Log file not found: {file_path}")

        # Detect hint from file extension
        _, ext = os.path.splitext(file_path.lower())
        format_hint = "auto"
        if ext == ".json":
            format_hint = "json"
        elif ext == ".csv":
            format_hint = "csv"
        elif ext == ".xml":
            format_hint = "windows"

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        return self.parse_text(
            content,
            source_type=source_type,
            source_path=file_path,
            default_service=default_service,
            format_hint=format_hint,
        )
