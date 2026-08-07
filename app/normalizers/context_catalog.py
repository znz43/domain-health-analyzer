def build_context_map(raw):

    if not raw:
        return {}

    return {

        item["context"]: item["description"]

        for item in raw

    }