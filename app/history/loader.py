import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent.parent

REPORT_PATH = BASE_DIR / "data" / "reports"


def get_domain_snapshots(domain: str):

    files = list(
        REPORT_PATH.glob(
            f"{domain}_*.json"
        )
    )

    files.sort(
        key=lambda x: x.name
    )

    return files



def load_snapshot(path: Path):

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)



def get_previous_current(domain: str):

    snapshots = get_domain_snapshots(domain)

    if len(snapshots) < 2:
        return None, None

    previous = load_snapshot(
        snapshots[-2]
    )

    current = load_snapshot(
        snapshots[-1]
    )

    return previous, current