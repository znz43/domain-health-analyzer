import csv

from formatters.report_flattener import flatten_report



FIELDS = [

    "domain",

    "score",

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

    "clusters",

    "whois"

]



def export_reports(
    reports,
    filename
):

    with open(
        filename,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:


        writer = csv.DictWriter(
            file,
            fieldnames=FIELDS
        )


        writer.writeheader()



        for report in reports:

            writer.writerow(
                flatten_report(report)
            )