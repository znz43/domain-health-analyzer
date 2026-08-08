from utils.time import unix_to_iso


def normalize_timeline(
    listing,
    contexts
):

    zrd_date = None

    for item in contexts:

        if item.get("context") == "zrd":

            zrd_date = item.get(
                "last_seen"
            )

    is_listed = listing.get(
        "is-listed"
    )

    ts = listing.get(
        "ts"
    )

    listed_until = listing.get(
        "listed-until"
    )

    listed_date = None
    last_seen = None

    if is_listed:

        listed_date = unix_to_iso(
            ts
        )

        last_seen = unix_to_iso(
            ts
        )

    else:

        last_seen = unix_to_iso(
            ts
        )

    return {

        "is_listed": is_listed,

        "listed_date": listed_date,

        "listed_until": unix_to_iso(
            listed_until
        ),

        "last_seen": last_seen,

        "zrd_detected": zrd_date

    }