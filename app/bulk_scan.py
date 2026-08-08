from api.spamhaus_client import SpamhausClient
from repositories.spamhaus_repository import SpamhausRepository

from services.domain_scanner import scan_domain
from history.snapshot import save_snapshot


INPUT_FILE = "data/domains.txt"


def load_domains():

    with open(
        INPUT_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        return [
            line.strip()
            for line in file
            if line.strip()
        ]


def main():

    client = SpamhausClient()

    repo = SpamhausRepository(
        client
    )


    for domain in load_domains():

        try:

            report = scan_domain(
                repo,
                domain
            )


            save_snapshot(
                report
            )


        except Exception as e:

            print(
                f"FAILED: {domain} -> {e}"
            )


if __name__ == "__main__":
    main()