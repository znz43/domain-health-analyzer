import requests
from datetime import datetime


def _to_iso(value):

    if not value:
        return None

    try:

        return (
            datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )
            .replace(tzinfo=None)
            .isoformat()
        )

    except Exception:

        return value


def collect_whois(domain_data):

    #
    # Spamhaus already returned WHOIS
    #

    whois = domain_data.get("whois")

    if whois and whois.get("created"):

        return whois

    #
    # RDAP lookup
    #

    domain = domain_data.get("domain")

    try:

        response = requests.get(

            f"https://rdap.org/domain/{domain}",

            timeout=10

        )

        if response.status_code != 200:

            return {

                "created": None,
                "expires": None,
                "registrar": None

            }

        data = response.json()

        created = None
        expires = None

        for event in data.get("events", []):

            action = event.get("eventAction")

            if action == "registration":

                created = _to_iso(

                    event.get("eventDate")

                )

            elif action == "expiration":

                expires = _to_iso(

                    event.get("eventDate")

                )

        registrar = None

        for entity in data.get("entities", []):

            roles = entity.get("roles", [])

            if "registrar" in roles:

                registrar = entity.get("handle")

                vcard = entity.get("vcardArray")

                if vcard:

                    for row in vcard[1]:

                        if row[0] == "fn":

                            registrar = row[3]

                            break

                break

        return {

            "created": created,
            "expires": expires,
            "registrar": registrar

        }

    except Exception:

        return {

            "created": None,
            "expires": None,
            "registrar": None

        }