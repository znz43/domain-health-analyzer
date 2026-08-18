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


def reverse_ipv4(ip):
    """
    46.225.55.93
    ->
    93.55.225.46
    """

    return ".".join(
        reversed(
            ip.split(".")
        )
    )


def reverse_ipv6(ip):
    """
    IPv6 reverse nibble format.

    Example:

    2001:db8::1

    becomes:

    1.0.0.0.0.0.0.0.
    0.0.0.0.0.0.0.0.
    0.0.0.0.0.0.0.0.
    0.0.0.0.0.0.0.0.
    8.b.d.0.1.0.0.2

    with all 32 hexadecimal nibbles reversed.
    """

    address = ipaddress.IPv6Address(ip)

    exploded = address.exploded

    return ".".join(
        reversed(
            exploded.replace(":", "")
        )
    )


def reverse_ip(ip):
    """
    Build Spamhaus DNSBL reverse name
    for both IPv4 and IPv6.
    """

    address = ipaddress.ip_address(ip)

    if address.version == 4:

        return reverse_ipv4(ip)

    return reverse_ipv6(ip)


def empty_result(ip):
    return {

        "ip": ip,

        "lists": {
            name: None
            for name in LISTS
        }

    }


def check_dqs(ip):
    """
    Check an IP against Spamhaus DQS DNSBL zones.

    Returns:

    {
        "ip": "...",
        "lists": {
            "ZEN": True/False/None,
            "SBL": True/False/None,
            ...
        }
    }

    False = clean / NXDOMAIN
    True  = listed
    None  = DNS/query error
    """

    result = empty_result(ip)

    # ------------------------------------------------------
    # VALIDATE IP
    # ------------------------------------------------------

    try:

        address = ipaddress.ip_address(ip)

    except ValueError:

        return result

    # ------------------------------------------------------
    # REVERSE IP
    # ------------------------------------------------------

    try:

        reversed_ip = reverse_ip(ip)

    except Exception:

        return result

    # ------------------------------------------------------
    # QUERY DQS
    # ------------------------------------------------------

    for name, zone in LISTS.items():

        query = (
            f"{reversed_ip}."
            f"{SPAMHAUS_DQS_KEY}."
            f"{zone}"
        )

        try:

            answers = dns.resolver.resolve(
                query,
                "A",
                lifetime=5
            )

            # DNSBL returned an answer.
            # This means the IP is listed.

            result["lists"][name] = True

        except dns.resolver.NXDOMAIN:

            # No DNSBL record.
            # This means CLEAN.

            result["lists"][name] = False

        except dns.resolver.NoAnswer:

            # No answer also means no listing record.

            result["lists"][name] = False

        except dns.resolver.NoNameservers:

            # DNS infrastructure problem.

            result["lists"][name] = None

        except dns.resolver.Timeout:

            # DNS timeout.

            result["lists"][name] = None

        except Exception:

            # Unknown DNS error.

            result["lists"][name] = None

    return result