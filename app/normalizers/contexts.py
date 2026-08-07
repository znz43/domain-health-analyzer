from utils.time import unix_to_iso



def normalize_contexts(
    raw_contexts,
    context_catalog=None
):


    if not raw_contexts:
        return []


    context_catalog = context_catalog or []


    context_map = {

        item.get("context"):
        item.get("description")

        for item in context_catalog

    }


    normalized = []

    seen = set()


    for item in raw_contexts:


        context = item.get(
            "context"
        )


        if not context:
            continue


        if context in seen:
            continue


        seen.add(
            context
        )


        normalized.append({

            "context": context,

            "description":
                item.get("description")
                or context_map.get(context),

            "last_seen":
                unix_to_iso(
                    item.get(
                        "last-seen"
                    )
                )

        })


    return normalized