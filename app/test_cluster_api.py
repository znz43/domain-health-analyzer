import os
import requests

from pathlib import Path
from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parents[1]

load_dotenv(
    BASE_DIR / ".env"
)

BASE_URL = "https://api.spamhaus.org"

USERNAME = os.getenv("SPAMHAUS_USERNAME")
PASSWORD = os.getenv("SPAMHAUS_PASSWORD")

DOMAIN = "instapaychecks.com"


def login():

    response = requests.post(
        f"{BASE_URL}/api/v1/login",
        json={
            "username": USERNAME,
            "password": PASSWORD,
            "realm": "intel"
        },
        timeout=30
    )

    response.raise_for_status()

    return response.json()["token"]


def get_domain(
    domain,
    token
):

    response = requests.get(
        f"{BASE_URL}/api/intel/v2/byobject/domain/{domain}",
        headers={
            "Authorization": f"Bearer {token}"
        },
        timeout=30
    )

    response.raise_for_status()

    return response.json()


def get_cluster(
    cluster_type,
    cluster_hash,
    token
):

    response = requests.get(
        f"{BASE_URL}/api/intel/v2/byobject/hash/"
        f"{cluster_type}/{cluster_hash}",
        headers={
            "Authorization": f"Bearer {token}"
        },
        timeout=30
    )

    print(
        f"{cluster_type.upper()}:",
        response.status_code
    )

    if response.status_code == 200:
        return response.json()

    if response.status_code == 403:
        print("Extended Access required")
        return None

    if response.status_code == 404:
        print("Cluster not found")
        return None

    response.raise_for_status()


def main():

    token = login()

    domain_data = get_domain(
        DOMAIN,
        token
    )

    clusters = domain_data.get(
        "clusters",
        {}
    )

    print(
        "\nDOMAIN:",
        DOMAIN
    )

    print(
        "AUTH HASH:",
        clusters.get("auth")
    )

    print(
        "INFRA HASH:",
        clusters.get("infra")
    )

    for cluster_type in (
        "auth",
        "infra"
    ):

        cluster_hash = clusters.get(
            cluster_type
        )

        if not cluster_hash:
            continue

        data = get_cluster(
            cluster_type,
            cluster_hash,
            token
        )

        if data:
            print(
                data
            )


if __name__ == "__main__":
    main()