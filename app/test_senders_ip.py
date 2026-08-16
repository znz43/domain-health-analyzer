import requests

from datetime import datetime, timezone

from api.spamhaus_client import SpamhausClient


DOMAIN = "experience.biz"


def format_unix(value):

    if not value:
        return ""

    try:
        return datetime.fromtimestamp(
            value,
            tz=timezone.utc
        ).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )

    except (
        TypeError,
        ValueError,
        OSError
    ):
        return str(value)


def get_ip_history(
    client,
    ip
):

    endpoint = (
        f"/api/intel/v1/byobject/cidr/"
        f"ALL/listings/history/{ip}"
    )

    url = (
        client.BASE_URL
        + endpoint
    )

    print()
    print("=" * 60)

    print(
        "IP:",
        ip
    )

    print(
        "MODE: history"
    )

    print(
        "ENDPOINT:",
        endpoint
    )

    print("=" * 60)

    response = requests.get(
        url,
        headers={
            "Authorization": (
                f"Bearer {client.token}"
            ),
            "Accept": "application/json"
        },
        timeout=30
    )

    print()
    print(
        "STATUS:",
        response.status_code
    )

    if response.status_code != 200:

        print(
            "RESPONSE:",
            response.text
        )

        return []

    try:

        data = response.json()

    except ValueError:

        print(
            "INVALID JSON:"
        )

        print(
            response.text
        )

        return []

    return data.get(
        "results",
        []
    )


def get_latest_by_dataset(
    records
):

    latest = {}

    for item in records:

        dataset = item.get(
            "dataset"
        )

        if not dataset:
            continue

        seen = item.get(
            "seen"
        )

        if not seen:
            continue

        if (
            dataset not in latest
            or seen > latest[dataset].get(
                "seen",
                0
            )
        ):

            latest[dataset] = item

    return latest


def print_listing(
    item
):

    print()

    print(
        "IP:          ",
        item.get(
            "ipaddress"
        )
    )

    print(
        "HELO:        ",
        item.get(
            "helo"
        )
    )

    print(
        "DATASET:     ",
        item.get(
            "dataset"
        )
    )

    print(
        "LISTED:      ",
        format_unix(
            item.get(
                "listed"
            )
        )
    )

    print(
        "VALID UNTIL: ",
        format_unix(
            item.get(
                "valid_until"
            )
        )
    )

    print(
        "SEEN:        ",
        format_unix(
            item.get(
                "seen"
            )
        )
    )

    print(
        "RULE:        ",
        item.get(
            "rule"
        )
    )

    print(
        "HEURISTIC:   ",
        item.get(
            "heuristic"
        )
    )

    print(
        "PROTOCOL:    ",
        item.get(
            "protocol"
        )
    )

    print(
        "DOMAIN:      ",
        item.get(
            "domain"
        )
    )

    print(
        "ASN:         ",
        item.get(
            "asn"
        )
    )

    print(
        "CC:          ",
        item.get(
            "cc"
        )
    )

    print(
        "LAT/LON:     ",
        f"{item.get('lat')}, "
        f"{item.get('lon')}"
    )

    print(
        "-" * 60
    )


def main():

    client = SpamhausClient()

    client.login()

    # ==========================================================
    # GET SENDERS
    # ==========================================================

    senders = client.get_domain_senders(
        DOMAIN
    )

    if not senders:

        print(
            "No sender IPs found."
        )

        return

    print()
    print("=" * 60)

    print(
        "DOMAIN:",
        DOMAIN
    )

    print("=" * 60)

    for sender in senders:

        print(
            f"IP: {sender.get('ip')} | "
            f"HELO: {sender.get('helo')} | "
            f"SCORE: {sender.get('score')}"
        )

    # ==========================================================
    # IP HISTORY
    # ==========================================================

    for sender in senders:

        ip = sender.get(
            "ip"
        )

        if not ip:
            continue

        # IPv6 поки пропускаємо
        if ":" in ip:

            print()
            print(
                "SKIP IPv6:",
                ip
            )

            continue

        try:

            records = get_ip_history(
                client,
                ip
            )

            if not records:

                print()
                print(
                    "NO IP HISTORY"
                )

                continue

            # ==================================================
            # LATEST RECORD PER DATASET
            # ==================================================

            latest = get_latest_by_dataset(
                records
            )

            print()
            print(
                "LATEST RECORDS BY DATASET:"
            )

            print(
                f"Found {len(latest)} dataset(s)"
            )

            # Сортуємо для стабільного виводу
            for dataset in sorted(
                latest.keys()
            ):

                print_listing(
                    latest[dataset]
                )

        except Exception as e:

            print()
            print(
                "IP ERROR:",
                ip,
                "->",
                e
            )


if __name__ == "__main__":

    main()