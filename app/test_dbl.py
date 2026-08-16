import os
import requests

from dotenv import load_dotenv


load_dotenv()


DOMAIN = "completebenefitssolution.com"


def api_code_to_dbl_code(api_code):

    if not isinstance(api_code, int):
        return None

    if 2000 <= api_code <= 2199:
        return f"127.0.1.{api_code - 2000}"

    return None


def main():

    dqs_key = os.getenv(
        "SPAMHAUS_DQS_KEY"
    )

    if not dqs_key:

        print(
            "ERROR: SPAMHAUS_DQS_KEY is not set"
        )

        return

    endpoint = (
        f"/lookup/v1/DBL/{DOMAIN}"
    )

    url = (
        "https://apibl.spamhaus.net"
        + endpoint
    )

    response = requests.get(
        url,
        headers={
            "Authorization": dqs_key,
            "Accept": "application/json",
        },
        timeout=30
    )

    print()
    print("=" * 60)
    print(
        "DOMAIN:",
        DOMAIN
    )
    print("=" * 60)

    print(
        "STATUS:",
        response.status_code
    )

    if response.status_code != 200:

        print()
        print(
            "RESPONSE:"
        )

        print(
            response.text
        )

        return

    try:

        data = response.json()

    except ValueError:

        print(
            "Invalid JSON:"
        )

        print(
            response.text
        )

        return

    response_codes = data.get(
        "resp",
        []
    )

    print()

    if not response_codes:

        print(
            "DBL API CODE: None"
        )

        print(
            "DBL RETURN CODE: None"
        )

        return

    for api_code in response_codes:

        dbl_code = api_code_to_dbl_code(
            api_code
        )

        print(
            "DBL API CODE:",
            api_code
        )

        print(
            "DBL RETURN CODE:",
            dbl_code
        )


if __name__ == "__main__":
    main()