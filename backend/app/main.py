"""Main FastAPI application for Autonomous IT Incident Responder.

Serves:
1. Dual-mode Ingestion API (/api/ingest/*)
2. Incident management API (/api/incidents)
3. Pipeline execution API (/api/pipeline/run/{incident_id})
4. Full interactive 3-panel Dashboard UI at /
5. Background asyncio task for LogFileWatcher
"""

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from .core.models import Incident, incident_store
from .detection.anomaly_detector import default_anomaly_detector
from .ingestion.api import router as ingestion_router
from .ingestion.file_watcher import LogFileWatcher
from .ingestion.real_log_ingestor import default_real_log_ingestor
from .ingestion.redis_client import default_redis_client
from .pipeline.fsm import default_pipeline_fsm
from .simulator.incident_simulator import default_simulator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Connect AnomalyDetector to Redis events
default_redis_client.subscribe_memory(default_anomaly_detector.process_event)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Start file watcher as background asyncio task
    logger.info("Starting Autonomous IT Incident Responder...")
    default_redis_client.connect()
    watcher_task = asyncio.create_task(default_real_log_ingestor.file_watcher.start_watching())
    yield
    # Shutdown: Stop file watcher
    logger.info("Shutting down file watcher...")
    default_real_log_ingestor.file_watcher.stop_sync()
    watcher_task.cancel()


app = FastAPI(title="Autonomous IT Incident Responder", lifespan=lifespan)

# Include ingestion API
app.include_router(ingestion_router)

# Mount static folder
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return HTMLResponse("<h1>Autonomous IT Incident Responder</h1><p>UI loading...</p>")


@app.get("/api/incidents")
async def list_incidents() -> List[Dict[str, Any]]:
    incidents = incident_store.list_all()
    # Sort descending by creation time
    return [inc.to_dict() for inc in sorted(incidents, key=lambda x: x.created_at, reverse=True)]


@app.get("/api/incidents/{incident_id}")
async def get_incident(incident_id: str) -> Dict[str, Any]:
    inc = incident_store.get(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc.to_dict()


@app.post("/api/pipeline/run/{incident_id}")
async def run_pipeline_endpoint(incident_id: str) -> Dict[str, Any]:
    inc = incident_store.get(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    resolved_inc = default_pipeline_fsm.run_pipeline(inc)
    return resolved_inc.to_dict()

