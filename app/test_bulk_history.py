import csv
import os
import requests

from datetime import datetime, timezone

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
OUTPUT_FILE = "data/export/spamhaus_history.csv"

DBL_BASE_URL = "https://apibl.spamhaus.net"


# ==========================================================
# CSV STRUCTURE
# ==========================================================

FIELDS = [

    "checked_at",

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

    "senders",
    "sender_ip_history",

    "mx",
    "dns_a",
    "dns_aaaa",
    "nameservers",

    "spamhaus_dqs",

    "dbl_api_code",
    "dbl_return_code",

    "malware",
    "clusters"

]


# ==========================================================
# INPUT
# ==========================================================

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


# ==========================================================
# FORMAT HELPERS
# ==========================================================

def join_values(values):

    if not values:
        return ""

    return " | ".join(
        str(value)
        for value in values
    )


def format_contexts(contexts):

    if not contexts:
        return ""

    return " | ".join(

        f"{item.get('context')}:{item.get('last_seen')}"

        for item in contexts

        if isinstance(item, dict)

    )


def format_objects(
    data,
    key
):

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


def format_senders(data):

    if not data:
        return ""

    result = []

    for item in data:

        if not isinstance(item, dict):
            continue

        result.append(

            f"ip={item.get('ip')} "
            f"helo={item.get('helo')} "
            f"score={item.get('score')} "
            f"last_seen={item.get('last_seen')}"

        )

    return " | ".join(result)


def format_nameservers(data):

    result = []

    for item in data or []:

        if not isinstance(item, dict):
            continue

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

        if not isinstance(item, dict):
            continue

        ip = item.get(
            "ip"
        )

        lists = item.get(
            "lists",
            {}
        )

        checks = []

        for name, value in lists.items():

            if value is True:

                status = "LISTED"

            elif value is False:

                status = "CLEAN"

            else:

                status = "UNKNOWN"

            checks.append(
                f"{name}={status}"
            )

        if ip:

            result.append(
                f"{ip}:"
                +
                ",".join(checks)
            )

    return " | ".join(result)


def format_dict(data):

    if not data:
        return ""

    if isinstance(data, list):

        return " | ".join(
            str(value)
            for value in data
        )

    if isinstance(data, dict):

        return " | ".join(

            f"{key}={value}"

            for key, value in data.items()

        )

    return str(data)


# ==========================================================
# SENDER IP HISTORY
# ==========================================================

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


def get_latest_by_dataset(records):

    latest = {}

    for item in records or []:

        if not isinstance(item, dict):
            continue

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


def format_sender_ip_history(
    client,
    senders
):

    if not senders:
        return ""

    result = []

    for sender in senders:

        if not isinstance(sender, dict):
            continue

        ip = sender.get(
            "ip"
        )

        if not ip:
            continue

        try:

            print()
            print(
                "=" * 60
            )

            print(
                "IP:",
                ip
            )

            print(
                "MODE: history"
            )

            print(
                "=" * 60
            )

            records = client.get_ip_history(
                ip
            )

            if not records:

                print(
                    "NO IP HISTORY"
                )

                continue

            latest = get_latest_by_dataset(
                records
            )

            print(
                f"Found {len(latest)} dataset(s)"
            )

            for dataset in sorted(
                latest.keys()
            ):

                item = latest[dataset]

                history = (

                    f"ip={item.get('ipaddress')} "
                    f"helo={item.get('helo')} "
                    f"dataset={item.get('dataset')} "
                    f"listed={format_unix(item.get('listed'))} "
                    f"valid_until={format_unix(item.get('valid_until'))} "
                    f"seen={format_unix(item.get('seen'))} "
                    f"rule={item.get('rule')} "
                    f"heuristic={item.get('heuristic')} "
                    f"protocol={item.get('protocol')} "
                    f"domain={item.get('domain')} "
                    f"asn={item.get('asn')} "
                    f"cc={item.get('cc')} "
                    f"lat={item.get('lat')} "
                    f"lon={item.get('lon')}"

                )

                result.append(
                    history
                )

        except Exception as error:

            print(
                "IP ERROR:",
                ip,
                "->",
                error
            )

    return " | ".join(result)


# ==========================================================
# DBL
# ==========================================================

def get_dbl_data(domain):

    api_key = os.getenv(
        "SPAMHAUS_DQS_KEY"
    )

    if not api_key:

        print(
            "DBL: SPAMHAUS_DQS_KEY not found"
        )

        return {
            "dbl_api_code": "",
            "dbl_return_code": ""
        }

    endpoint = (
        f"/lookup/v1/DBL/{domain}"
    )

    url = (
        DBL_BASE_URL
        + endpoint
    )

    print()
    print(
        "DBL:"
    )

    print(
        "ENDPOINT:",
        endpoint
    )

    try:

        response = requests.get(
            url,
            headers={
                "Authorization": api_key,
                "Accept": "application/json"
            },
            timeout=30
        )

        print(
            "STATUS:",
            response.status_code
        )

        if response.status_code != 200:

            print(
                "DBL ERROR:",
                response.text
            )

            return {
                "dbl_api_code": "",
                "dbl_return_code": ""
            }

        data = response.json()

        resp = data.get(
            "resp",
            []
        )

        dbl_api_code = ""

        if isinstance(resp, list) and resp:

            dbl_api_code = resp[0]

        dbl_return_code = ""

        if dbl_api_code:

            dbl_return_code = (
                f"127.0.1.{dbl_api_code - 2000}"
            )

        print(
            "DBL API CODE:",
            dbl_api_code
        )

        print(
            "DBL RETURN CODE:",
            dbl_return_code
        )

        return {

            "dbl_api_code":
                dbl_api_code,

            "dbl_return_code":
                dbl_return_code

        }

    except Exception as error:

        print(
            "DBL ERROR:",
            error
        )

        return {

            "dbl_api_code": "",

            "dbl_return_code": ""

        }


# ==========================================================
# BUILD REPORT
# ==========================================================

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


# ==========================================================
# FLATTEN REPORT
# ==========================================================

def flatten_report(
    client,
    report
):

    smtp = report.dimensions[
        "smtp"
    ][
        "data"
    ]

    identity = report.dimensions[
        "identity"
    ][
        "data"
    ]

    infra = report.dimensions[
        "infrastructure"
    ][
        "data"
    ]

    senders = smtp.get(
        "senders"
    ) or []

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
            report.dimensions[
                "smtp"
            ][
                "score"
            ],

        "identity_score":
            report.dimensions[
                "identity"
            ][
                "score"
            ],

        "infra_score":
            report.dimensions[
                "infrastructure"
            ][
                "score"
            ],

        "malware_score":
            report.dimensions[
                "malware"
            ][
                "score"
            ],

        "human_score":
            report.dimensions[
                "human"
            ][
                "score"
            ],

        "spf":
            join_values(
                identity.get(
                    "spf"
                )
            ),

        "dmarc":
            join_values(
                identity.get(
                    "dmarc"
                )
            ),

        "dkim":
            format_dkim(
                identity.get(
                    "dkim"
                )
            ),

        "senders":
            format_senders(
                senders
            ),

        "sender_ip_history":
            format_sender_ip_history(
                client,
                senders
            ),

        "mx":
            format_objects(
                infra.get(
                    "mx_records"
                ),
                "host"
            ),

        "dns_a":
            format_objects(
                infra.get(
                    "a_records"
                ),
                "ip"
            ),

        "dns_aaaa":
            format_objects(
                infra.get(
                    "aaaa_records"
                ),
                "ip"
            ),

        "nameservers":
            format_nameservers(
                infra.get(
                    "nameservers"
                )
            ),

        "spamhaus_dqs":
            format_dqs(
                infra.get(
                    "spamhaus_dqs"
                )
            ),

        "dbl_api_code":
            "",

        "dbl_return_code":
            "",

        "malware":
            format_dict(
                report.dimensions[
                    "malware"
                ].get(
                    "data"
                )
            ),

        "clusters":
            format_dict(
                report.clusters
            )

    }


# ==========================================================
# MAIN
# ==========================================================

def main():

    os.makedirs(
        "data/export",
        exist_ok=True
    )

    client = SpamhausClient()

    repo = SpamhausRepository(
        client
    )

    checked_at = datetime.now().isoformat(
        timespec="seconds"
    )

    rows = []

    domains = load_domains()

    print()
    print(
        "=" * 60
    )

    print(
        f"DOMAINS TO SCAN: {len(domains)}"
    )

    print(
        "=" * 60
    )

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

            row = flatten_report(
                client,
                report
            )

            dbl = get_dbl_data(
                domain
            )

            row["dbl_api_code"] = dbl.get(
                "dbl_api_code"
            )

            row["dbl_return_code"] = dbl.get(
                "dbl_return_code"
            )

            row["checked_at"] = checked_at

            rows.append(
                row
            )

            print(
                "DONE:",
                domain
            )

        except Exception as error:

            print(
                "FAILED:",
                domain,
                "->",
                error
            )

            continue

    file_exists = os.path.exists(
        OUTPUT_FILE
    )

    with open(
        OUTPUT_FILE,
        "a",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=FIELDS
        )

        if not file_exists:

            writer.writeheader()

        writer.writerows(
            rows
        )

    print()
    print(
        "=" * 60
    )

    print(
        "HISTORY APPEND:",
        OUTPUT_FILE
    )

    print(
        "ROWS ADDED:",
        len(rows)
    )

    print(
        "DOMAINS TOTAL:",
        len(domains)
    )

    print(
        "DOMAINS FAILED:",
        len(domains) - len(rows)
    )

    print(
        "=" * 60
    )


if __name__ == "__main__":
    main()