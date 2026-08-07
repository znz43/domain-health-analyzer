from api.spamhaus_client import SpamhausClient

from normalizers.domain import normalize_domain
from normalizers.dimensions import normalize_dimensions
from normalizers.contexts import normalize_contexts
from normalizers.malware import normalize_malware

from collectors.identity import collect_identity
from collectors.infrastructure import collect_infrastructure
from collectors.malware import collect_malware
from collectors.timeline import collect_timeline

from history.snapshot import save_snapshot

from models.domain_report import DomainReport

from reporters.console import print_console_report


def main():

    client = SpamhausClient()

    domain = "sagebrushyard.org"

    #
    # Spamhaus
    #
    domain_data = normalize_domain(
        client.get_domain(domain)
    )

    dimensions = normalize_dimensions(
        client.get_domain_dimensions(domain)
    )

    context_catalog = client.get_context_catalog()

    contexts = normalize_contexts(
        client.get_domain_contexts(domain),
        context_catalog
    )

    #
    # Collectors
    #
    identity_data = collect_identity(
        domain,
        contexts
    )

    infrastructure_data = collect_infrastructure(
        client,
        domain
    )

    malware_data = normalize_malware(
        collect_malware(
            client,
            domain
        )
    )

    timeline = collect_timeline(
        client,
        domain,
        contexts,
        domain_data
    )

    report = DomainReport(

        domain=domain,

        timeline=timeline,

        overall_score=sum(
            value or 0
            for value in dimensions.values()
        ),

        dimensions={

            "smtp": {
                "score": dimensions.get("smtp")
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

        contexts=contexts

    )

    save_snapshot(report)

    print_console_report(report)


if __name__ == "__main__":
    main()