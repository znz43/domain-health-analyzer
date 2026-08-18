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

    senders = repo.get_senders(
        domain
    )

    if senders is None:
        senders = []

    return {

        "senders": senders

    }