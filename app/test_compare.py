from history.loader import get_previous_current
from history.comparator import compare_scores


domain = "optitidepages.org"


previous, current = get_previous_current(
    domain
)


if previous and current:

    result = compare_scores(
        previous,
        current
    )

    print(result)

else:

    print(
        "Not enough snapshots"
    )