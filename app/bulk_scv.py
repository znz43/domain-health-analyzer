import csv
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
OUTPUT_FILE = "data/export/spamhaus_domains.csv"


FIELDS = [

    "domain",
    "score",
    "tags",

    "is_listed",
    "listed_date",
    "listed_until",
    "last_seen",

    "contexts",

    "smtp_score",
    "identity_score",
    "infra_score",
    "malware_score",
    "human_score",

    "spf",
    "dmarc",
    "dkim",

    "mx",
    "dns_a",
    "dns_aaaa",
    "nameservers",
    "spamhaus_dqs",

    "malware",

    "clusters"
]


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


def join_values(values):

    if not values:
        return ""

    return " | ".join(
        str(x)
        for x in values
    )


def format_contexts(contexts):

    if not contexts:
        return ""

    return " | ".join(

        f"{x.get('context')}:{x.get('last_seen')}"

        for x in contexts

    )


def format_objects(data, key):

    result = []

    for item in data or []:

        if isinstance(item, dict):

            value = item.get(key)

            if value:
                result.append(
                    str(value)
                )

        else:

            result.append(
                str(item)
            )

    return " | ".join(result)


def format_dkim(data):

    result = []

    for item in data or []:

        if isinstance(item, dict):

            selector = item.get(
                "selector"
            )

            value = item.get(
                "value"
            )

            if selector:

                result.append(
                    selector
                    +
                    (
                        f":{value}"
                        if value
                        else ""
                    )
                )

        else:

            result.append(
                str(item)
            )

    return " | ".join(result)


def format_nameservers(data):

    result = []

    for item in data or []:

        if isinstance(item, dict):

            result.append(

                f"{item.get('ns')} "
                f"score={item.get('score')} "
                f"counter={item.get('counter')} "
                f"last_seen={item.get('last_seen')}"

            )

    return " | ".join(result)


def format_dqs(data):

    result = []

    for item in data or []:

        checks = []

        for name, value in item.get(
            "lists",
            {}
        ).items():

            checks.append(

                f"{name}="
                +
                (
                    "LISTED"
                    if value
                    else "CLEAN"
                )

            )

        result.append(

            f"{item.get('ip')}:"
            +
            ",".join(checks)

        )

    return " | ".join(result)


def format_dict(data):

    if not data:
        return ""

    if isinstance(data, list):

        return " | ".join(
            str(x)
            for x in data
        )

    if isinstance(data, dict):

        return " | ".join(

            f"{k}={v}"

            for k, v in data.items()

        )

    return str(data)


def build_report(repo, domain):

    domain_data = normalize_domain(

        repo.get_domain(domain)

    )


    dimensions = normalize_dimensions(

        repo.get_dimensions(domain)

    )


    catalog = repo.get_context_catalog()


    contexts = normalize_contexts(

        repo.get_contexts(domain),

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
                "score": dimensions.get("smtp"),
                "data": smtp
            },

            "identity": {
                "score": dimensions.get("identity"),
                "data": identity
            },

            "infrastructure": {
                "score": dimensions.get("infra"),
                "data": infrastructure
            },

            "malware": {
                "score": dimensions.get("malware"),
                "data": malware
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

        clusters=domain_data.get(
            "clusters",
            {}
        )

    )


def flatten_report(report):

    identity = report.dimensions["identity"]["data"]

    infra = report.dimensions["infrastructure"]["data"]


    return {

        "domain":
            report.domain,

        "score":
            report.score,

        "tags":
            join_values(
                report.tags
            ),


        "is_listed":
            report.timeline.get(
                "is_listed"
            ),

        "listed_date":
            report.timeline.get(
                "listed_date"
            ),

        "listed_until":
            report.timeline.get(
                "listed_until"
            ),

        "last_seen":
            report.timeline.get(
                "last_seen"
            ),


        "contexts":
            format_contexts(
                report.contexts
            ),


        "smtp_score":
            report.dimensions["smtp"]["score"],

        "identity_score":
            report.dimensions["identity"]["score"],

        "infra_score":
            report.dimensions["infrastructure"]["score"],

        "malware_score":
            report.dimensions["malware"]["score"],

        "human_score":
            report.dimensions["human"]["score"],


        "spf":
            join_values(
                identity.get("spf")
            ),

        "dmarc":
            join_values(
                identity.get("dmarc")
            ),

        "dkim":
            format_dkim(
                identity.get("dkim")
            ),


        "mx":
            format_objects(
                infra.get("mx_records"),
                "host"
            ),

        "dns_a":
            format_objects(
                infra.get("a_records"),
                "ip"
            ),

        "dns_aaaa":
            format_objects(
                infra.get("aaaa_records"),
                "ip"
            ),


        "nameservers":
            format_nameservers(
                infra.get("nameservers")
            ),

        "spamhaus_dqs":
            format_dqs(
                infra.get("spamhaus_dqs")
            ),


        "malware":
            format_dict(
                report.dimensions["malware"].get("data")
            ),


        "clusters":
            format_dict(
                report.clusters
            )

    }
def format_dkim(data):

    if not data:
        return ""


    result = []


    for item in data:

        if not isinstance(item, dict):
            continue


        selector = item.get(
            "selector"
        )

        value = item.get(
            "value"
        )


        if selector and value:

            result.append(
                f"{selector}:{value}"
            )

        elif selector:

            result.append(
                selector
            )


    return " | ".join(result)

def main():

    os.makedirs(
        "data/export",
        exist_ok=True
    )


    client = SpamhausClient()

    repo = SpamhausRepository(
        client
    )


    rows = []


    for domain in load_domains()[:50]:

        try:

            print()
            print("=" * 60)
            print(
                f"Scanning: {domain}"
            )
            print("=" * 60)


            report = build_report(
                repo,
                domain
            )


            rows.append(

                flatten_report(
                    report
                )

            )


            print(
                "DONE:",
                domain
            )


        except Exception as e:

            print(
                "FAILED:",
                domain,
                e
            )


    with open(
        OUTPUT_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:


        writer = csv.DictWriter(

            file,

            fieldnames=FIELDS

        )


        writer.writeheader()

        writer.writerows(rows)


    print()

    print(
        "EXPORT:",
        OUTPUT_FILE
    )


if __name__ == "__main__":

    main()