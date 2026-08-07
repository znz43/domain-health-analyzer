from collectors.infrastructure import collect_infrastructure
from collectors.identity import collect_identity
from collectors.malware import collect_malware
from collectors.timeline import collect_timeline
from collectors.smtp import collect_smtp

from normalizers.contexts import normalize_contexts
from normalizers.dimensions import normalize_dimensions
from normalizers.domain import normalize_domain
from normalizers.malware import normalize_malware

from models.domain_report import DomainReport


def scan_domain(
    repo,
    domain
):

    print()
    print("=" * 60)
    print(f"Scanning: {domain}")
    print("=" * 60)


    #
    # Domain
    #

    domain_data = normalize_domain(
        repo.get_domain(domain)
    )


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
    # Collectors
    #

    smtp_data = collect_smtp(
        repo,
        domain,
        contexts
    )


    identity_data = collect_identity(
        domain,
        contexts
    )


    timeline = collect_timeline(
        repo,
        domain,
        contexts,
        domain_data
    )


    infrastructure_data = collect_infrastructure(
        repo,
        domain
    )


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

        timeline=timeline,

        score=domain_data.get(
            "score"
        ),

        tags=domain_data.get(
            "tags",
            []
        ),

        abused=domain_data.get(
            "abused"
        ),

        whois=domain_data.get(
            "whois"
        ),

        clusters=domain_data.get(
            "clusters"
        ),


        dimensions={

            "smtp": {
                "score": dimensions.get("smtp"),
                "data": smtp_data
            },


            "identity": {
                "score": dimensions.get("identity"),
                "data": identity_data
            },


            "infra": {
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


    print(
        f"DONE: {domain}"
    )


    return report