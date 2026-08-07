import ipaddress

import dns.resolver

from utils.config import SPAMHAUS_DQS_KEY


LISTS = {
    "ZEN": "zen.dq.spamhaus.net",
    "SBL": "sbl.dq.spamhaus.net",
    "XBL": "xbl.dq.spamhaus.net",
    "PBL": "pbl.dq.spamhaus.net",
    "AUTHBL": "authbl.dq.spamhaus.net",
}


def reverse_ip(ip: str) -> str:
    return ".".join(reversed(ip.split(".")))


def check_dqs(ip: str):

    result = {
        "ip": ip,
        "lists": {}
    }

    #
    # DQS only supports IPv4
    #
    try:

        address = ipaddress.ip_address(ip)

        if address.version != 4:

            for name in LISTS:
                result["lists"][name] = None

            return result

    except ValueError:

        for name in LISTS:
            result["lists"][name] = None

        return result

    reversed_ip = reverse_ip(ip)

    for name, zone in LISTS.items():

        query = (
            f"{reversed_ip}."
            f"{SPAMHAUS_DQS_KEY}."
            f"{zone}"
        )

        try:

            dns.resolver.resolve(query, "A")

            result["lists"][name] = True

        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
        ):

            result["lists"][name] = False

        except Exception:

            result["lists"][name] = None

    return result