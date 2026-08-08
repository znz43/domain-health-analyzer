from utils.time import unix_to_iso


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

        for context in (contexts or [])

        if context.get("context") in SMTP_CONTEXTS

    ]


    raw_senders = repo.get_senders(
        domain
    )


    senders = []


    for sender in raw_senders or []:

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