from datetime import datetime, timedelta
from collections import Counter


def generate_incident_id():
    return "INC-" + datetime.now().strftime("%Y%m%d%H%M%S%f")[:-3]


def _parse_timestamp(value):
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def classify_risk(score):
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH_RISK"
    if score >= 25:
        return "SUSPICIOUS"
    return "NORMAL"


def correlate_events(events, window_seconds=30):
    """Temporal + behavioural correlation of recent file events.

    Correlation signals:
    1. Temporal burst: multiple events in a short window.
    2. Event diversity: different event types in the same window.
    3. Sensitive-path activity.
    4. Destructive/identity-changing events such as DELETE/RENAME.
    5. Multiple distinct files affected.
    """
    if not events:
        return {
            "risk_score": 0,
            "classification": "NORMAL",
            "activity": "NO_ACTIVITY",
            "reason": "No file activity detected.",
            "correlation_method": "Temporal + behavioural correlation",
            "window_seconds": window_seconds,
            "event_count": 0,
            "distinct_files": 0,
            "types": [],
            "correlation_group": None,
        }

    parsed = [(e, _parse_timestamp(e.get("timestamp"))) for e in events]
    parsed = [(e, t) for e, t in parsed if t is not None]
    if not parsed:
        return {
            "risk_score": 0,
            "classification": "NORMAL",
            "activity": "NO_ACTIVITY",
            "reason": "No valid event timestamps available.",
            "correlation_method": "Temporal + behavioural correlation",
            "window_seconds": window_seconds,
            "event_count": 0,
            "distinct_files": 0,
            "types": [],
            "correlation_group": None,
        }

    latest_time = max(t for _, t in parsed)
    recent = [(e, t) for e, t in parsed if latest_time - t <= timedelta(seconds=window_seconds)]
    recent_events = [e for e, _ in recent]

    score = 0
    reasons = []
    types = Counter(e.get("type", "UNKNOWN") for e in recent_events)
    files = {e.get("file") for e in recent_events if e.get("file")}

    count = len(recent_events)
    if count >= 6:
        score += 30
        reasons.append(f"{count} events occurred within {window_seconds}s")
    elif count >= 3:
        score += 20
        reasons.append(f"{count} events occurred within {window_seconds}s")
    elif count == 2:
        score += 10
        reasons.append("Two events occurred in the same correlation window")

    if len(types) >= 3:
        score += 15
        reasons.append("Multiple event types were correlated")
    elif len(types) == 2:
        score += 8
        reasons.append("Two different event types were correlated")

    destructive = sum(types.get(t, 0) for t in ("DELETED", "RENAMED"))
    if destructive:
        score += min(25, destructive * 12)
        reasons.append("Deletion/rename activity detected")

    modified = types.get("MODIFIED", 0)
    if modified:
        score += min(15, modified * 5)

    sensitive_keywords = ("config", "security", "password", "credential", "auth", "secret", ".env", "token", "key")
    sensitive_files = [e.get("file", "").lower() for e in recent_events if any(k in e.get("file", "").lower() for k in sensitive_keywords)]
    if sensitive_files:
        score += min(25, len(sensitive_files) * 12)
        reasons.append("Sensitive-path activity detected")

    if len(files) >= 5:
        score += 15
        reasons.append("Five or more distinct files were affected")
    elif len(files) >= 3:
        score += 8
        reasons.append("Multiple distinct files were affected")

    # Include the strongest event risk without simply averaging it away.
    strongest = max((int(e.get("risk_score") or 0) for e in recent_events), default=0)
    score = min(100, max(score, strongest))
    classification = classify_risk(score)

    if classification == "CRITICAL":
        activity = "HIGHLY_SUSPICIOUS"
    elif classification == "HIGH_RISK":
        activity = "SUSPICIOUS"
    elif classification == "SUSPICIOUS":
        activity = "WARNING"
    else:
        activity = "NORMAL"

    if not reasons:
        reasons.append("No correlated risk indicators in the current window")

    first = min((t for _, t in recent), default=latest_time)
    group_id = "CORR-" + first.strftime("%Y%m%d%H%M%S%f")[:-3]

    return {
        "risk_score": score,
        "classification": classification,
        "activity": activity,
        "reason": "; ".join(reasons),
        "correlation_method": "Temporal + behavioural correlation",
        "window_seconds": window_seconds,
        "event_count": count,
        "distinct_files": len(files),
        "types": sorted(types.keys()),
        "correlation_group": group_id,
    }


def create_incident(changes):
    if not changes:
        return None
    return {
        "incident_id": generate_incident_id(),
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "changes": changes,
        "change_count": len(changes),
        "files": [c.get("file") for c in changes],
        "types": sorted({c.get("type") for c in changes}),
    }
