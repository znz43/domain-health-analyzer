from utils.time import unix_to_iso


def normalize_timeline(
    listing,
    contexts
):

    zrd_date = None

    for item in contexts:

        if item.get("context") == "zrd":
            zrd_date = item.get("last_seen")


    return {

        "listed": listing.get(
            "is-listed"
        ),

        "listed_until": unix_to_iso(
            listing.get("listed-until")
        ),

        "listed_since": unix_to_iso(
            listing.get("ts")
        ),

        "zrd_detected": zrd_date

    }