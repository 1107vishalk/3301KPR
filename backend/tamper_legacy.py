import os
import json
import hashlib


BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

DATA_DIR = os.path.join(BASE_DIR, "data")

AUDIT_FILE = os.path.join(
    DATA_DIR,
    "audit.json"
)

CHAIN_FILE = os.path.join(
    DATA_DIR,
    "audit_chain.json"
)


def calculate_entry_hash(entry, previous_hash):

    data = {
        "entry": entry,
        "previous_hash": previous_hash
    }

    serialized = json.dumps(
        data,
        sort_keys=True
    ).encode()

    return hashlib.sha256(
        serialized
    ).hexdigest()


def create_hash_chain():

    if not os.path.exists(AUDIT_FILE):
        return []

    with open(AUDIT_FILE, "r") as file:
        audit_logs = json.load(file)

    chain = []

    previous_hash = "GENESIS"

    for entry in audit_logs:

        current_hash = calculate_entry_hash(
            entry,
            previous_hash
        )

        chain_entry = {
            "entry": entry,
            "previous_hash": previous_hash,
            "entry_hash": current_hash
        }

        chain.append(chain_entry)

        previous_hash = current_hash

    with open(CHAIN_FILE, "w") as file:

        json.dump(
            chain,
            file,
            indent=4
        )

    return chain


def verify_hash_chain():

    if not os.path.exists(CHAIN_FILE):
        return False

    with open(CHAIN_FILE, "r") as file:
        chain = json.load(file)

    previous_hash = "GENESIS"

    for item in chain:

        expected_hash = calculate_entry_hash(
            item["entry"],
            previous_hash
        )

        if item["previous_hash"] != previous_hash:
            return False

        if item["entry_hash"] != expected_hash:
            return False

        previous_hash = item["entry_hash"]

    return True
