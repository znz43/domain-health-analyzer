from normalizers.infrastructure import normalize_records

from collectors.dns import (
    get_a,
    get_aaaa,
    get_mx,
    resolve_host
)

from collectors.spamhaus_dqs import check_dqs


def collect_infrastructure(
    repo,
    domain
):

    nameservers = normalize_records(
        repo.get_nameservers(domain),
        "ns"
    )

    a_records = [
        {
            "ip": ip
        }
        for ip in get_a(domain)
    ]

    aaaa_records = [
        {
            "ip": ip
        }
        for ip in get_aaaa(domain)
    ]

    mx_records = []
    mx_hosts = []

    for mx in get_mx(domain):

        parts = mx.split()

        if len(parts) < 2:
            continue

        host = parts[1].rstrip(".")

        mx_hosts.append(host)

        mx_records.append({
            "host": host
        })

    dqs_targets = {
        record["ip"]
        for record in a_records
    }

    for host in mx_hosts:

        dqs_targets.update(
            resolve_host(host)
        )

    spamhaus_dqs = []

    for ip in dqs_targets:

        result = check_dqs(ip)

        if result:

            spamhaus_dqs.append(
                result
            )

    return {

        "nameservers": nameservers,

        "a_records": a_records,

        "aaaa_records": aaaa_records,

        "mx_records": mx_records,

        "spamhaus_dqs": spamhaus_dqs

    }