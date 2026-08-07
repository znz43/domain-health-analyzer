from datetime import datetime


def unix_to_iso(timestamp):

    if not timestamp:
        return None

    return datetime.utcfromtimestamp(
        timestamp
    ).isoformat()