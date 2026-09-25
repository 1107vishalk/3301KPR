import os
import time
import threading
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from hashing import calculate_sha256
from database import init_database, save_event, create_baseline, load_baseline, clear_event_data
from correlation import generate_incident_id, correlate_events, classify_risk
from severity import calculate_severity

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MONITORED_DIR = os.path.join(BASE_DIR, "monitored")
IGNORED_FILES = {".DS_Store"}
IGNORED_DIRECTORIES = {".git", "node_modules", "venv", "__pycache__"}
DEBOUNCE_SECONDS = 0.35

current_state = {}
last_event_time = {}
state_lock = threading.Lock()
observer = None
monitor_started_at = None
baseline_created_at = None

# Periodic full-integrity verification
AUTO_INTERVAL_SECONDS = 300
_auto_thread = None
_auto_stop = threading.Event()
auto_monitoring_enabled = False
last_auto_check_at = None
next_auto_check_at = None
auto_last_deviations = set()
auto_last_risk_score = 0
auto_last_new_changes = 0
auto_lock = threading.Lock()


def now_iso():
    return datetime.now().isoformat(timespec="seconds")


def relative_path(path):
    return os.path.relpath(path, MONITORED_DIR).replace("\\", "/")


def should_ignore(path):
    if os.path.basename(path) in IGNORED_FILES:
        return True
    try:
        relative = os.path.relpath(os.path.abspath(path), MONITORED_DIR).replace("\\", "/")
        return any(part in IGNORED_DIRECTORIES for part in relative.split("/"))
    except ValueError:
        return True


def get_file_hash(path):
    try:
        if not os.path.isfile(path) or should_ignore(path):
            return None
        return calculate_sha256(path)
    except (FileNotFoundError, PermissionError, OSError):
        return None


def is_debounced(path, event_type):
    key = (os.path.abspath(path), event_type)
    current_time = time.time()
    with state_lock:
        previous = last_event_time.get(key)
        if previous is not None and current_time - previous < DEBOUNCE_SECONDS:
            return True
        last_event_time[key] = current_time
    return False


def calculate_event_risk(change_type, file_path):
    score = {"DELETED": 45, "RENAMED": 35, "MODIFIED": 25, "COPIED": 20, "ADDED": 15}.get(change_type, 10)
    lower = file_path.lower()
    if any(k in lower for k in ("config", "security", "password", "credential", "auth", "secret", ".env", "token", "key")):
        score += 30
    return min(score, 100)


def record_event(activity_type, file_path, old_hash=None, new_hash=None, old_file=None, source_file=None):
    if should_ignore(file_path):
        return
    relative = relative_path(file_path)
    change = {"file": relative, "type": activity_type, "old_hash": old_hash, "new_hash": new_hash}
    if old_file:
        change["old_file"] = relative_path(old_file)
    if source_file:
        change["source_file"] = relative_path(source_file)

    incident = {"changes": [change]}
    severity = calculate_severity(incident)
    risk_score = calculate_event_risk(activity_type, relative)
    classification = classify_risk(risk_score)
    activity = {"CRITICAL": "HIGHLY_SUSPICIOUS", "HIGH_RISK": "SUSPICIOUS", "SUSPICIOUS": "WARNING", "NORMAL": "NORMAL"}[classification]

    event = {
        "timestamp": now_iso(),
        "incident_id": generate_incident_id(),
        "severity": severity,
        "file": relative,
        "type": activity_type,
        "old_hash": old_hash,
        "new_hash": new_hash,
        "risk_score": risk_score,
        "activity": activity,
        "classification": classification,
    }
    save_event(event)
    print(f"[{event['timestamp']}] {activity_type:<8} {relative} | severity={severity} risk={risk_score} class={classification}")



def _set_auto_times(check_time=None):
    global last_auto_check_at, next_auto_check_at
    check_time = check_time or datetime.now()
    last_auto_check_at = check_time.isoformat(timespec="seconds")
    next_auto_check_at = (check_time.timestamp() + AUTO_INTERVAL_SECONDS)
    next_auto_check_at = datetime.fromtimestamp(next_auto_check_at).isoformat(timespec="seconds")


def verify_integrity_once():
    """Perform a full SHA-256 comparison against the trusted baseline.

    Returns a compact result used by the API/dashboard. Events are recorded only
    when a new deviation appears, preventing the same unchanged violation from
    being logged every five minutes.
    """
    global auto_last_deviations, auto_last_risk_score, auto_last_new_changes
    baseline = load_baseline()
    if not baseline:
        _set_auto_times()
        return {"files_checked": 0, "changes_found": 0, "risk_score": 0, "classification": "NORMAL"}

    current = {}
    for root, dirs, files in os.walk(MONITORED_DIR):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRECTORIES]
        for filename in files:
            path = os.path.join(root, filename)
            if should_ignore(path):
                continue
            file_hash = get_file_hash(path)
            if file_hash:
                current[relative_path(path)] = file_hash

    deviations = []
    for rel, old_hash in baseline.items():
        if rel not in current:
            deviations.append(("DELETED", rel, old_hash, None))
        elif current[rel] != old_hash:
            deviations.append(("MODIFIED", rel, old_hash, current[rel]))
    for rel, new_hash in current.items():
        if rel not in baseline:
            deviations.append(("ADDED", rel, None, new_hash))

    deviation_keys = {(kind, rel, old_hash, new_hash) for kind, rel, old_hash, new_hash in deviations}
    new_deviations = deviation_keys - auto_last_deviations
    auto_last_deviations = deviation_keys

    max_risk = 0
    for kind, rel, old_hash, new_hash in deviations:
        max_risk = max(max_risk, calculate_event_risk(kind, rel))

    if new_deviations:
        for kind, rel, old_hash, new_hash in new_deviations:
            record_event(kind, os.path.join(MONITORED_DIR, rel), old_hash, new_hash)

    classification = classify_risk(max_risk)
    auto_last_risk_score = max_risk
    auto_last_new_changes = len(new_deviations)
    _set_auto_times()
    return {
        "files_checked": len(current),
        "changes_found": len(deviations),
        "new_changes_found": len(new_deviations),
        "risk_score": max_risk,
        "classification": classification,
        "verified_at": last_auto_check_at,
    }


def _automatic_integrity_loop():
    while not _auto_stop.wait(AUTO_INTERVAL_SECONDS):
        try:
            result = verify_integrity_once()
            print(f"[AUTO] Integrity verification complete: {result}")
        except Exception as exc:
            print(f"[AUTO] Integrity verification failed: {exc}")


def start_automatic_monitoring():
    global _auto_thread, auto_monitoring_enabled
    if auto_monitoring_enabled and _auto_thread is not None and _auto_thread.is_alive():
        return get_monitor_status()
    if not (observer is not None and observer.is_alive()):
        raise RuntimeError("Start the main file monitor before enabling automatic integrity monitoring.")
    _auto_stop.clear()
    auto_monitoring_enabled = True
    auto_last_deviations.clear()
    # Run an immediate verification, then continue every five minutes.
    verify_integrity_once()
    _auto_thread = threading.Thread(target=_automatic_integrity_loop, name="fim-auto-integrity", daemon=True)
    _auto_thread.start()
    return get_monitor_status()


def stop_automatic_monitoring():
    global _auto_thread, auto_monitoring_enabled, next_auto_check_at
    _auto_stop.set()
    if _auto_thread is not None and _auto_thread.is_alive():
        _auto_thread.join(timeout=2)
    _auto_thread = None
    auto_monitoring_enabled = False
    next_auto_check_at = None


def find_copy_source(new_file, new_hash):
    if not new_hash:
        return None
    target = os.path.abspath(new_file)
    for root, dirs, files in os.walk(MONITORED_DIR):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRECTORIES]
        for filename in files:
            path = os.path.join(root, filename)
            if should_ignore(path) or os.path.abspath(path) == target:
                continue
            if get_file_hash(path) == new_hash:
                return path
    return None


class FileIntegrityHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory or should_ignore(event.src_path) or is_debounced(event.src_path, "ADDED"):
            return
        time.sleep(0.08)
        new_hash = get_file_hash(event.src_path)
        if not new_hash:
            return
        rel = relative_path(event.src_path)
        with state_lock:
            old_hash = current_state.get(rel)
            current_state[rel] = new_hash
        if old_hash and old_hash != new_hash:
            record_event("MODIFIED", event.src_path, old_hash, new_hash)
        elif old_hash == new_hash:
            return
        else:
            source = find_copy_source(event.src_path, new_hash)
            record_event("COPIED" if source else "ADDED", event.src_path, new_hash=new_hash, source_file=source)

    def on_modified(self, event):
        if event.is_directory or should_ignore(event.src_path) or is_debounced(event.src_path, "MODIFIED"):
            return
        new_hash = get_file_hash(event.src_path)
        if not new_hash:
            return
        rel = relative_path(event.src_path)
        with state_lock:
            old_hash = current_state.get(rel)
            if old_hash is None:
                current_state[rel] = new_hash
                return
            if old_hash == new_hash:
                return
            current_state[rel] = new_hash
        record_event("MODIFIED", event.src_path, old_hash, new_hash)

    def on_deleted(self, event):
        if event.is_directory or should_ignore(event.src_path) or is_debounced(event.src_path, "DELETED"):
            return
        rel = relative_path(event.src_path)
        with state_lock:
            old_hash = current_state.pop(rel, None)
        if old_hash is not None:
            record_event("DELETED", event.src_path, old_hash=old_hash)

    def on_moved(self, event):
        if event.is_directory or should_ignore(event.src_path) or should_ignore(event.dest_path) or is_debounced(event.dest_path, "RENAMED"):
            return
        old_rel = relative_path(event.src_path)
        new_hash = get_file_hash(event.dest_path)
        with state_lock:
            old_hash = current_state.pop(old_rel, None)
            if new_hash:
                current_state[relative_path(event.dest_path)] = new_hash
        if new_hash:
            record_event("RENAMED", event.dest_path, old_hash, new_hash, old_file=event.src_path)


def start_monitor():
    global observer, current_state, monitor_started_at, baseline_created_at
    if observer is not None and observer.is_alive():
        return get_monitor_status()
    if not os.path.exists(MONITORED_DIR):
        raise FileNotFoundError(f"Monitored directory not found: {MONITORED_DIR}")

    stop_automatic_monitoring()
    global last_auto_check_at, next_auto_check_at, auto_last_risk_score, auto_last_new_changes
    last_auto_check_at = None
    next_auto_check_at = None
    auto_last_risk_score = 0
    auto_last_new_changes = 0
    clear_event_data()
    baseline = create_baseline()
    current_state = dict(baseline)
    last_event_time.clear()
    baseline_created_at = now_iso()
    monitor_started_at = now_iso()

    handler = FileIntegrityHandler()
    observer = Observer()
    observer.schedule(handler, MONITORED_DIR, recursive=True)
    observer.start()
    print(f"[OK] Baseline created: {len(baseline)} files")
    print(f"[OK] Real-time monitoring active: {MONITORED_DIR}")
    return get_monitor_status()


def stop_monitor():
    global observer
    stop_automatic_monitoring()
    if observer is not None:
        observer.stop()
        observer.join(timeout=3)
        observer = None


def get_monitor_status():
    return {
        "running": bool(observer is not None and observer.is_alive()),
        "monitored_directory": MONITORED_DIR,
        "baseline_file_count": len(current_state),
        "baseline_created_at": baseline_created_at,
        "monitor_started_at": monitor_started_at,
        "automatic_monitoring": auto_monitoring_enabled,
        "automatic_interval_seconds": AUTO_INTERVAL_SECONDS,
        "last_auto_check_at": last_auto_check_at,
        "next_auto_check_at": next_auto_check_at,
        "last_auto_risk_score": auto_last_risk_score,
        "last_auto_new_changes": auto_last_new_changes,
    }


def start_realtime_monitor():
    start_monitor()
    try:
        while observer is not None and observer.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        stop_monitor()


if __name__ == "__main__":
    start_realtime_monitor()
