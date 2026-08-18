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
    return ".".join(
        reversed(ip.split("."))
    )


def reverse_ipv6(ip):
    address = ipaddress.IPv6Address(ip)

    exploded = address.exploded

    return ".".join(
        reversed(
            exploded.replace(":", "")
        )
    )


def reverse_ip(ip):
    address = ipaddress.ip_address(ip)

    if address.version == 4:
        return reverse_ipv4(ip)

    return reverse_ipv6(ip)


def test_ip(ip):

    print()
    print("=" * 70)
    print(f"IP: {ip}")
    print("=" * 70)

    try:
        address = ipaddress.ip_address(ip)

        print(
            "VERSION:",
            f"IPv{address.version}"
        )

        reversed_ip = reverse_ip(ip)

        print()
        print("REVERSED:")
        print(reversed_ip)

    except Exception as e:

        print(
            "IP ERROR:",
            e
        )

        return

    print()
    print("DQS QUERIES")
    print("-" * 70)

    for name, zone in LISTS.items():

        query = (
            f"{reversed_ip}."
            f"{SPAMHAUS_DQS_KEY}."
            f"{zone}"
        )

        print()
        print(f"{name}:")
        print(query)

        try:

            answers = dns.resolver.resolve(
                query,
                "A",
                lifetime=5
            )

            values = [
                answer.to_text()
                for answer in answers
            ]

            print(
                "RESULT:",
                "LISTED"
            )

            print(
                "A RECORDS:",
                values
            )

        except dns.resolver.NXDOMAIN:

            print(
                "RESULT:",
                "CLEAN"
            )

        except dns.resolver.NoAnswer:

            print(
                "RESULT:",
                "CLEAN / NO ANSWER"
            )

        except dns.resolver.Timeout:

            print(
                "RESULT:",
                "UNKNOWN / TIMEOUT"
            )

        except dns.resolver.NoNameservers:

            print(
                "RESULT:",
                "UNKNOWN / NO NAMESERVERS"
            )

        except Exception as e:

            print(
                "RESULT:",
                "UNKNOWN"
            )

            print(
                "ERROR:",
                repr(e)
            )


def main():

    print("=" * 70)
    print("SPAMHAUS DQS IPv4 / IPv6 DEBUG")
    print("=" * 70)

    print()
    print(
        "DQS KEY:",
        (
            f"{SPAMHAUS_DQS_KEY[:4]}..."
            if SPAMHAUS_DQS_KEY
            else "NOT FOUND"
        )
    )

    # IPv4
    test_ip(
        "46.225.55.93"
    )

    # IPv6
    test_ip(
        "2a01:4f8:1c19:7135::1"
    )


if __name__ == "__main__":
    main()