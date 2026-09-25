from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from database import load_events, load_baseline
from correlation import correlate_events
from realtime_monitor import (
    start_monitor,
    stop_monitor,
    get_monitor_status,
    start_automatic_monitoring,
    stop_automatic_monitoring,
    verify_integrity_once,
)

app = FastAPI(title="3301 File Integrity Tool", version="2.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {"status": "online", "tool": "3301 File Integrity Tool"}

@app.get("/api/health")
def health():
    return {"status": "healthy", **get_monitor_status()}

@app.post("/api/start")
def start():
    try:
        status = start_monitor()
        return {"message": "Baseline created and monitoring started", **status}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@app.post("/api/stop")
def stop():
    stop_monitor()
    return {"message": "Monitoring stopped", **get_monitor_status()}

@app.post("/api/automatic/start")
def automatic_start():
    try:
        return {"message": "Automatic integrity monitoring enabled", **start_automatic_monitoring()}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))

@app.post("/api/automatic/stop")
def automatic_stop():
    stop_automatic_monitoring()
    return {"message": "Automatic integrity monitoring disabled", **get_monitor_status()}

@app.post("/api/automatic/check")
def automatic_check():
    try:
        result = verify_integrity_once()
        return {**result, **get_monitor_status()}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@app.get("/api/status")
def status():
    baseline = load_baseline()
    return {**get_monitor_status(), "baseline_file_count": len(baseline)}

@app.get("/api/activity")
def activity():
    events = load_events()
    correlation = correlate_events(events[:100], window_seconds=30)
    latest = events[0] if events else None
    return {
        "timestamp": latest.get("timestamp") if latest else None,
        "latest_event": latest,
        "changes": events[:10],
        "correlation": correlation,
    }

@app.get("/api/history")
def history():
    events = load_events()
    return {"events": events, "count": len(events)}
