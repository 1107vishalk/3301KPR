import os
import json


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATA_DIR = os.path.join(BASE_DIR, "data")

INCIDENTS_FILE = os.path.join(
    DATA_DIR,
    "incidents.json"
)


def load_incidents():

    if not os.path.exists(INCIDENTS_FILE):
        return []

    with open(INCIDENTS_FILE, "r") as file:
        return json.load(file)


def save_incident(incident):

    os.makedirs(DATA_DIR, exist_ok=True)

    incidents = load_incidents()

    incidents.append(incident)

    with open(INCIDENTS_FILE, "w") as file:
        json.dump(
            incidents,
            file,
            indent=4
        )

    return incident
