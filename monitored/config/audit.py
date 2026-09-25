import os
import json
from datetime import datetime


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATA_DIR = os.path.join(BASE_DIR, "data")

AUDIT_FILE = os.path.join(
    DATA_DIR,
    "audit.json"
)


def load_audit_logs():

    if not os.path.exists(AUDIT_FILE):
        return []

    with open(AUDIT_FILE, "r") as file:
        return json.load(file)


def write_audit_logs(incident):

    os.makedirs(DATA_DIR, exist_ok=True)

    logs = load_audit_logs()

    for change in incident["changes"]:

        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "incident_id": incident["incident_id"],
            "severity": incident["severity"],
            "file": change["file"],
            "type": change["type"],
            "old_hash": change["old_hash"],
            "new_hash": change["new_hash"]
        }

        logs.append(log_entry)

    with open(AUDIT_FILE, "w") as file:
        json.dump(
            logs,
            file,
            indent=4
        )

    return logs

