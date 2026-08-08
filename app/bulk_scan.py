import json
import os

from api.spamhaus_client import SpamhausClient
from repositories.spamhaus_repository import SpamhausRepository

from models.domain_report import DomainReport

from collectors.timeline import collect_timeline
from collectors.infrastructure import collect_infrastructure
from collectors.identity import collect_identity
from collectors.smtp import collect_smtp
from collectors.malware import collect_malware

from normalizers.domain import normalize_domain
from normalizers.dimensions import normalize_dimensions
from normalizers.contexts import normalize_contexts
from normalizers.malware import normalize_malware


INPUT_FILE = "data/domains.txt"
OUTPUT_DIR = "data/reports"


def load_domains():

    with open(
        INPUT_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        return [
            x.strip()
            for x in file
            if x.strip()
        ]


def save_report(
    report,
    domain
):

    os.makedirs(
        OUTPUT_DIR,
        exist_ok=True
    )

    output_file = os.path.join(
        OUTPUT_DIR,
        f"{domain}.json"
    )

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report.model_dump(
                mode="json"
            ),
            file,
            indent=2,
            ensure_ascii=False
        )

    print(
        "REPORT:",
        output_file
    )


def build_report(
    repo,
    domain
):

    domain_data = normalize_domain(
        repo.get_domain(
            domain
        )
    )

    dimensions = normalize_dimensions(
        repo.get_dimensions(
            domain
        )
    )

    catalog = repo.get_context_catalog()

    contexts = normalize_contexts(
        repo.get_contexts(
            domain
        ),
        catalog
    )

    smtp = collect_smtp(
        repo,
        domain,
        contexts
    )

    identity = collect_identity(
        domain,
        contexts
    )

    timeline = collect_timeline(
        repo,
        domain,
        contexts,
        domain_data
    )

    infrastructure = collect_infrastructure(
        repo,
        domain
    )

    malware = normalize_malware(
        collect_malware(
            repo,
            domain
        )
    )

    return DomainReport(

        domain=domain,

        score=domain_data.get(
            "score"
        ),

        timeline=timeline,

        dimensions={

            "smtp": {
                "score": dimensions.get(
                    "smtp"
                ),
                "data": smtp
            },

            "identity": {
                "score": dimensions.get(
                    "identity"
                ),
                "data": identity
            },

            "infrastructure": {
                "score": dimensions.get(
                    "infra"
                ),
                "data": infrastructure
            },

            "malware": {
                "score": dimensions.get(
                    "malware"
                ),
                "data": malware
            },

            "human": {
                "score": dimensions.get(
                    "human"
                )
            }

        },

        contexts=contexts,

        tags=domain_data.get(
            "tags",
            []
        ),

        clusters=domain_data.get(
            "clusters",
            {}
        )

    )


def main():

    client = SpamhausClient()

    repo = SpamhausRepository(
        client
    )

    domains = load_domains()

    for domain in domains:

        try:

            print()
            print(
                "=" * 60
            )

            print(
                f"Scanning: {domain}"
            )

            print(
                "=" * 60
            )

            report = build_report(
                repo,
                domain
            )

            save_report(
                report,
                domain
            )

            print(
                "DONE:",
                domain
            )

        except Exception as e:

            print(
                "FAILED:",
                domain,
                "->",
                e
            )


if __name__ == "__main__":
    main()