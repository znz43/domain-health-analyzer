DIMENSIONS = [
    "smtp",
    "identity",
    "infra",
    "malware",
    "human"
]


def normalize_dimensions(raw_dimensions):

    if not raw_dimensions:
        return {
            dimension: None
            for dimension in DIMENSIONS
        }


    return {
        dimension: raw_dimensions.get(dimension)
        for dimension in DIMENSIONS
    }