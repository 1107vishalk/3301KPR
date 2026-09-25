# backend/monitor.py

import os
import time
import threading
from datetime import datetime

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Support both:
#   python monitor.py
# and:
#   python -m backend.monitor
try:
    from .hashing import calculate_sha256
    from .database import (
        init_database,
        load_baseline,
        create_baseline,
        save_event,
    )
    from .correlation import create_incident
    from .severity import calculate_severity
    from .audit import write_audit_logs
    from .tamper import create_hash_chain
except ImportError:
    from hashing import calculate_sha256
    from database import (
        init_database,
        load_baseline,
        create_baseline,
        save_event,
    )
    from correlation import create_incident
    from severity import calculate_severity
    from audit import write_audit_logs
    from tamper import create_hash_chain


# ============================================================
# PATH CONFIGURATION
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

MONITORED_DIR = os.path.join(
    BASE_DIR,
    "monitored"
)


# ============================================================
# MONITOR CONFIGURATION
# ============================================================

# Files/folders that should not generate security events.
IGNORED_FILES = {
    ".DS_Store",
}

IGNORED_DIRECTORIES = {
    "__pycache__",
    ".git",
    "node_modules",
    "venv",
    ".venv",
}


# Watchdog can generate multiple MODIFIED events for one save.
# This prevents duplicate processing.
DEBOUNCE_SECONDS = 0.75


# Current state of files observed by the monitor.
#
# Example:
#
# {
#     "config/app.conf": "abc123..."
# }
#
# This is different from the baseline.
# The baseline represents the original trusted state.
current_state = {}


# Last event time for debounce.
last_event_time = {}


# Thread lock because watchdog events can arrive quickly.
state_lock = threading.Lock()


# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def now_iso():
    """
    Return current timestamp in ISO format.
    """
    return datetime.now().isoformat(timespec="seconds")


def relative_path(file_path):
    """
    Convert absolute path into path relative to monitored directory.
    """
    return os.path.relpath(
        file_path,
        MONITORED_DIR
    ).replace("\\", "/")


def should_ignore(path):
    """
    Determine whether a file should be ignored.
    """

    filename = os.path.basename(path)

    if filename in IGNORED_FILES:
        return True

    normalized = os.path.abspath(path)

    try:
        relative = os.path.relpath(
            normalized,
            MONITORED_DIR
        )

        parts = relative.replace("\\", "/").split("/")

        for part in parts:
            if part in IGNORED_DIRECTORIES:
                return True

    except ValueError:
        return True

    return False


def get_file_hash(path):
    """
    Safely calculate SHA-256 hash.
    """

    try:

        if not os.path.isfile(path):
            return None

        return calculate_sha256(path)

    except (
        FileNotFoundError,
        PermissionError,
        OSError
    ):
        return None


def is_debounced(path, event_type):
    """
    Prevent duplicate watchdog events.
    """

    key = (
        os.path.abspath(path),
        event_type
    )

    current_time = time.time()

    with state_lock:

        previous_time = last_event_time.get(key)

        if (
            previous_time is not None
            and current_time - previous_time < DEBOUNCE_SECONDS
        ):
            return True

        last_event_time[key] = current_time

    return False


# ============================================================
# RISK CALCULATION
# ============================================================

def calculate_risk_score(changes):
    """
    Calculate a simple explainable risk score.

    Maximum score is capped at 100.
    """

    score = 0

    sensitive_keywords = [
        "config",
        "security",
        "password",
        "credential",
        "auth",
        "secret",
        ".env",
        "key",
        "token",
    ]

    for change in changes:

        change_type = change.get("type", "")
        file_path = change.get("file", "").lower()

        # Event type contribution
        if change_type == "DELETED":
            score += 30

        elif change_type == "MODIFIED":
            score += 20

        elif change_type == "RENAMED":
            score += 20

        elif change_type == "COPIED":
            score += 15

        elif change_type == "ADDED":
            score += 10

        # Sensitive file contribution
        if any(
            keyword in file_path
            for keyword in sensitive_keywords
        ):
            score += 20

    # Multiple changes
    if len(changes) >= 5:
        score += 25

    elif len(changes) >= 3:
        score += 15

    elif len(changes) >= 2:
        score += 10

    return min(score, 100)


def activity_from_severity(severity):
    """
    Convert severity into a readable activity status.
    """

    mapping = {
        "CRITICAL": "HIGHLY_SUSPICIOUS",
        "HIGH": "SUSPICIOUS",
        "MEDIUM": "WARNING",
        "LOW": "NORMAL",
    }

    return mapping.get(
        severity,
        "NORMAL"
    )


# ============================================================
# INCIDENT PROCESSING
# ============================================================

def process_change(
    change_type,
    file_path,
    old_hash=None,
    new_hash=None,
    old_file=None,
    source_file=None
):
    """
    Central pipeline for every filesystem event.

    Flow:

        Watchdog
           ↓
        Change
           ↓
        SHA-256
           ↓
        Incident
           ↓
        Severity
           ↓
        Risk score
           ↓
        SQLite
           ↓
        Audit
           ↓
        Hash chain
    """

    if should_ignore(file_path):
        return

    file_relative = relative_path(file_path)

    change = {
        "type": change_type,
        "file": file_relative,
        "old_hash": old_hash,
        "new_hash": new_hash,
    }

    if old_file:
        change["old_file"] = relative_path(old_file)

    if source_file:
        change["source_file"] = relative_path(source_file)

    # --------------------------------------------------------
    # Create incident
    # --------------------------------------------------------

    incident = create_incident(
        [change]
    )

    if not incident:
        return

    # --------------------------------------------------------
    # Calculate severity
    # --------------------------------------------------------

    severity = calculate_severity(
        incident
    )

    # --------------------------------------------------------
    # Calculate risk
    # --------------------------------------------------------

    risk_score = calculate_risk_score(
        [change]
    )

    activity = activity_from_severity(
        severity
    )

    incident["severity"] = severity
    incident["risk_score"] = risk_score
    incident["activity"] = activity

    # --------------------------------------------------------
    # Save event to SQLite
    # --------------------------------------------------------

    event = {
        "timestamp": now_iso(),

        "incident_id": incident[
            "incident_id"
        ],

        "severity": severity,

        "file": file_relative,

        "type": change_type,

        "old_hash": old_hash,

        "new_hash": new_hash,

        "risk_score": risk_score,

        "activity": activity,
    }

    try:

        save_event(event)

    except Exception as error:

        print(
            f"[DATABASE ERROR] {error}"
        )

    # --------------------------------------------------------
    # Audit log
    # --------------------------------------------------------

    try:

        write_audit_logs(
            incident
        )

    except Exception as error:

        print(
            f"[AUDIT ERROR] {error}"
        )

    # --------------------------------------------------------
    # Rebuild tamper-evident hash chain
    # --------------------------------------------------------

    try:

        create_hash_chain()

    except Exception as error:

        print(
            f"[HASH CHAIN ERROR] {error}"
        )

    # --------------------------------------------------------
    # Display
    # --------------------------------------------------------

    display_activity(
        change_type=change_type,
        file_path=file_path,
        old_hash=old_hash,
        new_hash=new_hash,
        old_file=old_file,
        source_file=source_file,
        severity=severity,
        risk_score=risk_score,
        incident_id=incident[
            "incident_id"
        ],
    )


# ============================================================
# DISPLAY ACTIVITY
# ============================================================

def display_activity(
    change_type,
    file_path,
    old_hash=None,
    new_hash=None,
    old_file=None,
    source_file=None,
    severity="LOW",
    risk_score=0,
    incident_id=None,
):
    """
    Display detected activity in terminal.
    """

    print()
    print("=" * 75)

    if change_type == "COPIED":

        print("📋 FILE COPY DETECTED")

    elif change_type == "RENAMED":

        print("🔄 FILE RENAME DETECTED")

    elif change_type == "DELETED":

        print("🗑️ FILE DELETION DETECTED")

    elif change_type == "MODIFIED":

        print("⚠️ FILE MODIFICATION DETECTED")

    elif change_type == "ADDED":

        print("➕ NEW FILE DETECTED")

    else:

        print("⚡ FILE ACTIVITY DETECTED")

    print("=" * 75)

    print(
        "Time        :",
        datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    )

    print(
        "Incident ID :",
        incident_id
    )

    print(
        "Type        :",
        change_type
    )

    print(
        "File        :",
        relative_path(file_path)
    )

    print(
        "Severity    :",
        severity
    )

    print(
        "Risk Score  :",
        f"{risk_score}/100"
    )

    if old_file:

        print(
            "Old File    :",
            relative_path(old_file)
        )

    if source_file:

        print(
            "Source File :",
            relative_path(source_file)
        )

    if old_hash:

        print(
            "Old Hash    :",
            old_hash
        )

    if new_hash:

        print(
            "New Hash    :",
            new_hash
        )

    print("=" * 75)


# ============================================================
# COPY DETECTION
# ============================================================

def find_copy_source(
    new_file,
    new_hash
):
    """
    Find another file with the same SHA-256 hash.

    Used only for identifying possible copies.
    """

    if not new_hash:
        return None

    new_file_abs = os.path.abspath(
        new_file
    )

    for root, dirs, files in os.walk(
        MONITORED_DIR
    ):

        # Prevent scanning ignored directories.
        dirs[:] = [
            directory
            for directory in dirs
            if directory not in IGNORED_DIRECTORIES
        ]

        for filename in files:

            file_path = os.path.join(
                root,
                filename
            )

            if should_ignore(file_path):
                continue

            if (
                os.path.abspath(file_path)
                == new_file_abs
            ):
                continue

            existing_hash = get_file_hash(
                file_path
            )

            if (
                existing_hash is not None
                and existing_hash == new_hash
            ):
                return file_path

    return None


# ============================================================
# BASELINE INITIALIZATION
# ============================================================

def initialize_state():
    """
    Load baseline and build current in-memory state.
    """

    global current_state

    baseline = load_baseline()

    # If baseline does not exist, create it.
    if not baseline:

        print()
        print(
            "[INFO] No baseline found."
        )

        print(
            "[INFO] Creating trusted baseline..."
        )

        try:

            baseline = create_baseline()

            print(
                f"[OK] Baseline created with "
                f"{len(baseline)} files."
            )

        except Exception as error:

            print(
                "[ERROR] Baseline creation failed:"
            )

            print(error)

            return False

    current_state = dict(
        baseline
    )

    return True


# ============================================================
# FILE INTEGRITY EVENT HANDLER
# ============================================================

class FileIntegrityHandler(
    FileSystemEventHandler
):

    # --------------------------------------------------------
    # FILE CREATED
    # --------------------------------------------------------

    def on_created(self, event):

        if event.is_directory:
            return

        path = event.src_path

        if should_ignore(path):
            return

        if is_debounced(
            path,
            "ADDED"
        ):
            return

        # Small delay because some applications create
        # the file first and write its content immediately.
        time.sleep(0.10)

        new_hash = get_file_hash(
            path
        )

        if new_hash is None:
            return

        relative = relative_path(
            path
        )

        with state_lock:

            old_hash = current_state.get(
                relative
            )

            current_state[relative] = new_hash

        # If a file already existed in the observed state,
        # treat this as a modification rather than a new file.
        if old_hash:

            if old_hash == new_hash:
                return

            process_change(
                change_type="MODIFIED",
                file_path=path,
                old_hash=old_hash,
                new_hash=new_hash,
            )

            return

        # Check for possible copy.
        source_file = find_copy_source(
            path,
            new_hash
        )

        if source_file:

            process_change(
                change_type="COPIED",
                file_path=path,
                new_hash=new_hash,
                source_file=source_file,
            )

        else:

            process_change(
                change_type="ADDED",
                file_path=path,
                new_hash=new_hash,
            )

    # --------------------------------------------------------
    # FILE MODIFIED
    # --------------------------------------------------------

    def on_modified(self, event):

        if event.is_directory:
            return

        path = event.src_path

        if should_ignore(path):
            return

        if is_debounced(
            path,
            "MODIFIED"
        ):
            return

        new_hash = get_file_hash(
            path
        )

        if new_hash is None:
            return

        relative = relative_path(
            path
        )

        with state_lock:

            old_hash = current_state.get(
                relative
            )

            # First observation of this file.
            if old_hash is None:

                current_state[
                    relative
                ] = new_hash

                return

            # Content did not actually change.
            if old_hash == new_hash:
                return

            current_state[
                relative
            ] = new_hash

        process_change(
            change_type="MODIFIED",
            file_path=path,
            old_hash=old_hash,
            new_hash=new_hash,
        )

    # --------------------------------------------------------
    # FILE DELETED
    # --------------------------------------------------------

    def on_deleted(self, event):

        if event.is_directory:
            return

        path = event.src_path

        if should_ignore(path):
            return

        if is_debounced(
            path,
            "DELETED"
        ):
            return

        relative = relative_path(
            path
        )

        with state_lock:

            old_hash = current_state.pop(
                relative,
                None
            )

        # If the file wasn't previously observed,
        # there is no integrity information to report.
        if old_hash is None:
            return

        process_change(
            change_type="DELETED",
            file_path=path,
            old_hash=old_hash,
            new_hash=None,
        )

    # --------------------------------------------------------
    # FILE MOVED / RENAMED
    # --------------------------------------------------------

    def on_moved(self, event):

        if event.is_directory:
            return

        old_path = event.src_path
        new_path = event.dest_path

        if should_ignore(old_path):
            return

        if should_ignore(new_path):
            return

        if is_debounced(
            new_path,
            "RENAMED"
        ):
            return

        old_relative = relative_path(
            old_path
        )

        new_relative = relative_path(
            new_path
        )

        with state_lock:

            old_hash = current_state.pop(
                old_relative,
                None
            )

        new_hash = get_file_hash(
            new_path
        )

        if new_hash is None:
            return

        with state_lock:

            current_state[
                new_relative
            ] = new_hash

        process_change(
            change_type="RENAMED",
            file_path=new_path,
            old_hash=old_hash,
            new_hash=new_hash,
            old_file=old_path,
        )


# ============================================================
# START MONITOR
# ============================================================

def start_realtime_monitor():
    """
    Start the real-time file integrity monitor.
    """

    print()
    print("=" * 75)
    print(
        "      TAMPER-EVIDENT FILE INTEGRITY MONITOR"
    )
    print("=" * 75)

    print(
        "Monitored Directory :",
        MONITORED_DIR
    )

    # --------------------------------------------------------
    # Check monitored directory
    # --------------------------------------------------------

    if not os.path.exists(
        MONITORED_DIR
    ):

        print()
        print(
            "[ERROR] Monitored directory does not exist."
        )

        print(
            MONITORED_DIR
        )

        return

    # --------------------------------------------------------
    # Initialize database
    # --------------------------------------------------------

    try:

        init_database()

        print(
            "[OK] Database initialized."
        )

    except Exception as error:

        print(
            "[ERROR] Database initialization failed:"
        )

        print(error)

        return

    # --------------------------------------------------------
    # Initialize baseline/current state
    # --------------------------------------------------------

    if not initialize_state():

        print(
            "[ERROR] State initialization failed."
        )

        return

    print(
        f"[OK] Baseline/state loaded: "
        f"{len(current_state)} files."
    )

    # --------------------------------------------------------
    # Create watchdog handler
    # --------------------------------------------------------

    event_handler = FileIntegrityHandler()

    observer = Observer()

    observer.schedule(
        event_handler,
        MONITORED_DIR,
        recursive=True
    )

    # --------------------------------------------------------
    # Start watchdog
    # --------------------------------------------------------

    try:

        observer.start()

    except Exception as error:

        print()
        print(
            "[ERROR] Unable to start watchdog:"
        )

        print(error)

        return

    print()
    print(
        "[OK] REAL-TIME MONITORING ACTIVE"
    )

    print(
        "[OK] SHA-256 integrity checking active"
    )

    print(
        "[OK] Incident correlation active"
    )

    print(
        "[OK] Severity/risk analysis active"
    )

    print(
        "[OK] SQLite event storage active"
    )

    print(
        "[OK] Audit logging active"
    )

    print(
        "[OK] Tamper-evident hash chain active"
    )

    print()
    print(
        "Press CTRL+C to stop monitoring."
    )

    print("=" * 75)

    # --------------------------------------------------------
    # Keep monitor alive
    # --------------------------------------------------------

    try:

        while observer.is_alive():

            time.sleep(1)

    except KeyboardInterrupt:

        print()
        print(
            "[INFO] Stopping monitor..."
        )

        observer.stop()

    observer.join()

    print(
        "[OK] Monitor stopped."
    )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    start_realtime_monitor()