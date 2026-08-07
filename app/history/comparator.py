from urllib3 import _base_connection
from typing import Dict, Any


def get_change_reason(section, delta):

    if delta == 0:
        return "No change"

    if delta > 0:
        return f"{section} score improved"

    return f"{section} score decreased"

def compare_scores(
    previous: Dict[str, Any],
    current: Dict[str, Any]
):

    result = {}

    previous_overall = previous.get(
        "overall_score"
    )

    current_overall = current.get(
        "overall_score"
    )


    if previous_overall is not None and current_overall is not None:

        result["overall"] = {
            "previous": previous_overall,
            "current": current_overall,
            "delta": round(
                current_overall - previous_overall,
                2
            )
        }

    sections = [
        "smtp",
        "identity",
        "infrastructure",
        "malware",
        "human"
    ]

    for section in sections:

        previous_score = previous.get(section, {}).get("score")
        current_score = current.get(section, {}).get("score")

        if previous_score is None or current_score is None:
            continue

        delta = round(
    current_score - previous_score,
    2
)


        delta = round(
            current_score - previous_score,
            2
        )


        result[section] = {
            "previous": previous_score,
            "current": current_score,
            "delta": delta,
            "changed": delta != 0
        }

    return result