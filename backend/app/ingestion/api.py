"""FastAPI Router for Real Log Mode Ingestion.

Exposes:
- POST /api/ingest/file
- POST /api/ingest/paste
- POST /api/ingest/windows-events
- GET /api/ingest/status
- POST /api/ingest/demo
"""

from __future__ import annotations

from typing import Any, Dict, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from .real_log_ingestor import default_real_log_ingestor

router = APIRouter(prefix="/api/ingest", tags=["Ingestion"])


class IngestFileRequest(BaseModel):
    file_path: str = Field(..., description="Absolute or relative path to log file on disk")
    service_name: Optional[str] = Field(None, description="Optional service name override")


class IngestPasteRequest(BaseModel):
    raw_text: str = Field(..., description="Raw log text to parse and ingest")
    service_name: Optional[str] = Field(None, description="Optional default service name")
    format_hint: Optional[str] = Field("auto", description="auto | json | syslog | windows | apache | csv")


class IngestWindowsEventsRequest(BaseModel):
    channel: str = Field("Application", description="Windows Event channel (Application, System, Security)")
    last_n_events: int = Field(100, description="Maximum number of events to read")
    min_level: str = Field("Error", description="Minimum severity: Error | Warning | All")


@router.post("/file")
async def ingest_file_endpoint(req: IngestFileRequest) -> Dict[str, Any]:
    try:
        res = default_real_log_ingestor.ingest_file(
            file_path=req.file_path,
            service_name=req.service_name,
        )
        return res
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/paste")
async def ingest_paste_endpoint(req: IngestPasteRequest) -> Dict[str, Any]:
    try:
        res = default_real_log_ingestor.ingest_paste(
            raw_text=req.raw_text,
            service_name=req.service_name,
            format_hint=req.format_hint,
        )
        return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/windows-events")
async def ingest_windows_events_endpoint(req: IngestWindowsEventsRequest) -> Dict[str, Any]:
    try:
        res = default_real_log_ingestor.ingest_windows_events(
            channel=req.channel,
            last_n_events=req.last_n_events,
            min_level=req.min_level,
        )
        return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status")
async def get_ingest_status_endpoint() -> Dict[str, Any]:
    return default_real_log_ingestor.get_status()


@router.post("/demo")
async def trigger_demo_endpoint() -> Dict[str, Any]:
    from ..simulator.incident_simulator import default_simulator
    default_real_log_ingestor.mode = "both" if default_real_log_ingestor.file_watcher.is_running else "demo"
    events = default_simulator.run_simulation()
    return {"message": "Demo simulation started", "events_generated": len(events)}
