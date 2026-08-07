import requests


def get_rdap(domain: str) -> dict:

    try:

        url = f"https://rdap.org/domain/{domain}"

        r = requests.get(url, timeout=10)

        r.raise_for_status()

        data = r.json()

        created = None
        expires = None

        for event in data.get("events", []):

            action = event.get("eventAction")

            if action == "registration":
                created = event.get("eventDate")

            elif action == "expiration":
                expires = event.get("eventDate")

        registrar = None

        for entity in data.get("entities", []):

            roles = entity.get("roles", [])

            if "registrar" in roles:

                registrar = entity.get("handle")

                if entity.get("vcardArray"):

                    card = entity["vcardArray"][1]

                    for item in card:

                        if item[0] == "fn":

                            registrar = item[3]

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