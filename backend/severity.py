
def calculate_severity(incident):
    if not incident:
        return "LOW"

    changes = incident.get("changes", [])
    score = 0

    if len(changes) >= 5:
        score += 4
    elif len(changes) >= 3:
        score += 3
    elif len(changes) == 2:
        score += 2
    else:
        score += 1

    for change in changes:
        change_type = change.get("type")
        if change_type == "DELETED":
            score += 3
        elif change_type in ("MODIFIED", "RENAMED"):
            score += 2
        elif change_type in ("ADDED", "COPIED"):
            score += 1

        path = change.get("file", "").lower()
        if any(k in path for k in ("config", "security", "password", "credential", "auth", "secret", ".env", "token", "key")):
            score += 2

    if score >= 9:
        return "CRITICAL"
    if score >= 6:
        return "HIGH"
    if score >= 3:
        return "MEDIUM"
    return "LOW"
