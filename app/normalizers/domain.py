from utils.time import unix_to_iso


def normalize_domain(raw_domain):

    return {

        "domain": raw_domain.get(
            "domain"
        ),

        "score": raw_domain.get(
            "score"
        ),

        "tags": raw_domain.get(
            "tags",
            []
        ),

        "last_seen": unix_to_iso(
            raw_domain.get(
                "last-seen"
            )
        ),

        "clusters": raw_domain.get(
            "clusters",
            {}
        )

    }