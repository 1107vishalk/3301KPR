import os
import json
import sqlite3
from hashing import calculate_sha256

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MONITORED_DIR = os.path.join(BASE_DIR, "monitored")
DATA_DIR = os.path.join(BASE_DIR, "data")
BASELINE_FILE = os.path.join(DATA_DIR, "baseline.json")
DATABASE_FILE = os.path.join(DATA_DIR, "integrity.db")


def create_baseline():
    baseline = {}
    for root, dirs, files in os.walk(MONITORED_DIR):
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "venv", "__pycache__"}]
        for filename in files:
            if filename == ".DS_Store":
                continue
            file_path = os.path.join(root, filename)
            try:
                relative = os.path.relpath(file_path, MONITORED_DIR).replace("\\", "/")
                file_hash = calculate_sha256(file_path)
                baseline[relative] = file_hash
            except (OSError, PermissionError):
                continue
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(BASELINE_FILE, "w", encoding="utf-8") as file:
        json.dump(baseline, file, indent=2)
    return baseline


def load_baseline():
    if not os.path.exists(BASELINE_FILE):
        return {}
    try:
        with open(BASELINE_FILE, "r", encoding="utf-8") as file:
            return json.load(file)
    except (json.JSONDecodeError, OSError):
        return {}


def init_database():
    os.makedirs(DATA_DIR, exist_ok=True)
    connection = sqlite3.connect(DATABASE_FILE)
    cursor = connection.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            incident_id TEXT,
            severity TEXT,
            file TEXT,
            type TEXT,
            old_hash TEXT,
            new_hash TEXT,
            risk_score INTEGER,
            activity TEXT,
            classification TEXT DEFAULT 'NORMAL'
        )
    """)
    columns = {row[1] for row in cursor.execute("PRAGMA table_info(events)").fetchall()}
    if "classification" not in columns:
        cursor.execute("ALTER TABLE events ADD COLUMN classification TEXT DEFAULT 'NORMAL'")
    connection.commit()
    connection.close()


def save_event(event):
    init_database()
    connection = sqlite3.connect(DATABASE_FILE)
    cursor = connection.cursor()
    cursor.execute("""
        INSERT INTO events (timestamp, incident_id, severity, file, type, old_hash, new_hash, risk_score, activity, classification)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event.get("timestamp"), event.get("incident_id"), event.get("severity"), event.get("file"),
        event.get("type"), event.get("old_hash"), event.get("new_hash"), event.get("risk_score", 0),
        event.get("activity", "NORMAL"), event.get("classification", "NORMAL")
    ))
    connection.commit()
    connection.close()


def load_events(limit=None):
    init_database()
    connection = sqlite3.connect(DATABASE_FILE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    query = "SELECT * FROM events ORDER BY id DESC"
    params = ()
    if limit:
        query += " LIMIT ?"
        params = (limit,)
    cursor.execute(query, params)
    rows = cursor.fetchall()
    connection.close()
    return [dict(row) for row in rows]


def clear_event_data():
    os.makedirs(DATA_DIR, exist_ok=True)
    for filename in ("integrity.db", "events.db", "audit.json", "audit_chain.json", "incidents.json", "activity_history.json"):
        path = os.path.join(DATA_DIR, filename)
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass
    init_database()
