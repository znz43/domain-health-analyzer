from collectors.dns import (
    get_spf,
    get_dmarc,
    get_dkim
)


IDENTITY_CONTEXTS = [

    "tlscert",
    "dkim",
    "dkim-header"

]


def collect_identity(
    domain,
    contexts
):


    context_data = []


    for item in contexts:


        if item.get("context") in IDENTITY_CONTEXTS:

            context_data.append(
                item
            )


    return {

        "contexts": context_data,

        "spf": get_spf(
            domain
        ),

        "dmarc": get_dmarc(
            domain
        ),

        "dkim": get_dkim(
            domain
        )

    }