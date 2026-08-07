from api.spamhaus_client import SpamhausClient
from repositories.spamhaus_repository import SpamhausRepository

from collectors.infrastructure import collect_infrastructure
from collectors.identity import collect_identity
from collectors.malware import collect_malware
from collectors.timeline import collect_timeline
from collectors.smtp import collect_smtp

from normalizers.domain import normalize_domain
from normalizers.dimensions import normalize_dimensions
from normalizers.contexts import normalize_contexts
from normalizers.malware import normalize_malware

from models.domain_report import DomainReport
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


def scan_domain(
    repo,
    domain
):

    print()
    print("=" * 60)
    print(f"Scanning: {domain}")
    print("=" * 60)

    #
    # RAW DOMAIN
    #

    raw_domain = repo.get_domain(domain)

    print("\nRAW WHOIS")
    print(raw_domain.get("whois"))

    #
    # Domain
    #

    domain_data = normalize_domain(raw_domain)

    print("\nNORMALIZED WHOIS")
    print(domain_data.get("whois"))

    import json

    print("\nRAW DOMAIN DATA")
    print(json.dumps(domain_data, indent=2))


    #
    # Dimensions
    #

    dimensions = normalize_dimensions(

        repo.get_dimensions(domain)

    )

    #
    # Contexts
    #

    context_catalog = repo.get_context_catalog()

    contexts = normalize_contexts(

        repo.get_contexts(domain),

        context_catalog

    )

    #
    # SMTP
    #

    smtp_data = collect_smtp(

        repo,

        domain,

        contexts

    )

    #
    # Identity
    #

    identity_data = collect_identity(

        domain,

        contexts

    )

    #
    # Timeline
    #

    timeline = collect_timeline(

        repo,

        domain,

        contexts,

        domain_data

    )

    #
    # Infrastructure
    #

    infrastructure_data = collect_infrastructure(

        repo,

        domain

    )

    #
    # Malware
    #

    malware_data = normalize_malware(

        collect_malware(

            repo,

            domain

        )

    )

    #
    # Report
    #

    report = DomainReport(

        domain=domain,

        score=domain_data.get("score"),

        timeline=timeline,

        dimensions={

            "smtp": {
                "score": dimensions.get("smtp"),
                "data": smtp_data
            },

            "identity": {
                "score": dimensions.get("identity"),
                "data": identity_data
            },

            "infrastructure": {
                "score": dimensions.get("infra"),
                "data": infrastructure_data
            },

            "malware": {
                "score": dimensions.get("malware"),
                "data": malware_data
            },

            "human": {
                "score": dimensions.get("human")
            }

        },

        contexts=contexts,

        tags=domain_data.get(
            "tags",
            []
        ),

       clusters=domain_data.get("clusters", {}),
    )

    save_snapshot(report)

    print(f"DONE: {domain}")

    return report


def main():

    client = SpamhausClient()

    repo = SpamhausRepository(client)

    domains = load_domains()

    for domain in domains:

        try:

            scan_domain(

                repo,

                domain

            )

        except Exception as e:

            import traceback

            traceback.print_exc()

            print(

                f"FAILED: {domain} -> {e}"

            )


if __name__ == "__main__":

    main()