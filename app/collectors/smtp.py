SMTP_CONTEXTS = {

    "helo",
    "ehlo",
    "mailfrom",
    "envelope-sender",
    "rdns",
    "mailsample"

}


def collect_smtp(
    repo,
    domain,
    contexts
):

    smtp_contexts = [

        context

        for context in contexts

        if context.get("context") in SMTP_CONTEXTS

    ]


    senders = repo.get_senders(
        domain
    )

from utils.time import unix_to_iso


def collect_smtp(
    repo,
    domain,
    contexts
):

    smtp_contexts = [

        context

        for context in contexts

        if context.get("context") in [
            "envelope-sender",
            "mailsample",
            "helo",
            "rdns"
        ]

    ]


    raw_senders = repo.get_senders(
        domain
    )


    senders = []


    for sender in raw_senders:

        senders.append({

            "ip": sender.get(
                "ip"
            ),

            "helo": sender.get(
                "helo"
            ),

            "last_seen": unix_to_iso(
                sender.get(
                    "last-seen"
                )
            ),

            "score": sender.get(
                "score"
            )

        })


    return {

        "contexts": smtp_contexts,

        "senders": senders

    }