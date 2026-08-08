from utils.time import unix_to_iso


def normalize_records(
    records,
    field
):

    if not records:
        return []


    return [

        {
            field: item.get(field),

            "last_seen": unix_to_iso(
                item.get("last-seen")
            ),

            "score": item.get("score"),

            "counter": item.get("counter")
        }

        for item in records

    ]