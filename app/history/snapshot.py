import json
from pathlib import Path
from datetime import datetime


REPORT_PATH = Path("data/reports")


def save_snapshot(snapshot):

    REPORT_PATH.mkdir(
        parents=True,
        exist_ok=True
    )


    filename = (
        f"{snapshot.domain}_"
        f"{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    )


    path = REPORT_PATH / filename


    print("Saving snapshot:")
    print(path.absolute())


    if hasattr(snapshot, "model_dump"):
        data = snapshot.model_dump()
    else:
        data = snapshot.to_dict()


    with open(
        path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            data,
            file,
            indent=4,
            default=str
        )


    return path