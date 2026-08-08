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


def reverse_ip(
    ip: str
) -> str:

    return ".".join(
        reversed(
            ip.split(".")
        )
    )


def empty_result(
    ip: str
):

    return {

        "ip": ip,

        "lists": {
            name: None
            for name in LISTS
        }

    }


def check_dqs(
    ip: str
):

    result = empty_result(ip)


    try:

        address = ipaddress.ip_address(ip)

        if address.version != 4:
            return result


    except ValueError:

        return result



    reversed_ip = reverse_ip(ip)


    for name, zone in LISTS.items():


        query = (
            f"{reversed_ip}."
            f"{SPAMHAUS_DQS_KEY}."
            f"{zone}"
        )


        try:

            dns.resolver.resolve(
                query,
                "A",
                lifetime=5
            )


            result["lists"][name] = True


        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer
        ):

            result["lists"][name] = False


        except Exception:

            result["lists"][name] = None


    return result