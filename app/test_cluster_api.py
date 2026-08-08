import os
import json
from pathlib import Path

import requests
from dotenv import load_dotenv


# =====================================================
# Configuration
# =====================================================

BASE_DIR = Path(__file__).resolve().parents[1]

load_dotenv(
    BASE_DIR / ".env"
)


BASE_URL = "https://api.spamhaus.org"

USERNAME = os.getenv(
    "SPAMHAUS_USERNAME"
)

PASSWORD = os.getenv(
    "SPAMHAUS_PASSWORD"
)


# =====================================================
# Helpers
# =====================================================

def save_json(filename, data):

    output_dir = BASE_DIR / "data"

    output_dir.mkdir(
        exist_ok=True
    )

    file_path = output_dir / filename


    with open(
        file_path,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            data,
            f,
            indent=2,
            ensure_ascii=False
        )


    print(
        f"\nSaved: {file_path}"
    )



def get_headers(token):

    return {
        "Authorization": f"Bearer {token}"
    }



def print_json(title, data):

    print(
        f"\n{title}:"
    )

    print(
        json.dumps(
            data,
            indent=2,
            ensure_ascii=False
        )
    )


# =====================================================
# Authentication
# =====================================================

def login():

    print(
        "USERNAME:",
        USERNAME
    )

    print(
        "PASSWORD LENGTH:",
        len(PASSWORD) if PASSWORD else None
    )


    response = requests.post(

        f"{BASE_URL}/api/v1/login",

        json={
            "username": USERNAME,
            "password": PASSWORD,
            "realm": "intel"
        },

        timeout=30
    )


    print(
        "\nLOGIN STATUS:",
        response.status_code
    )


    print(
        "LOGIN BODY:"
    )

    print(
        response.text
    )


    response.raise_for_status()


    data = response.json()


    return data.get(
        "token"
    )


# =====================================================
# Spamhaus API
# =====================================================

def get_domain(domain, token):

    response = requests.get(

        f"{BASE_URL}/api/intel/v2/byobject/domain/{domain}",

        headers=get_headers(token),

        timeout=30
    )


    print(
        "\nDOMAIN STATUS:",
        response.status_code
    )


    response.raise_for_status()


    return response.json()



def get_cluster(
        cluster_type,
        cluster_hash,
        token
):

    url = (

        f"{BASE_URL}/api/intel/v2/byobject/hash/"
        f"{cluster_type}/{cluster_hash}"

    )


    print(
        "\n" + "=" * 80
    )

    print(
        "CLUSTER REQUEST:"
    )

    print(
        url
    )


    response = requests.get(

        url,

        headers=get_headers(token),

        timeout=30
    )


    print(
        "STATUS:",
        response.status_code
    )


    print(
        "BODY:"
    )

    print(
        response.text
    )



    if response.status_code == 403:

        print(
            "Extended Access required"
        )

        return None



    if response.status_code == 404:

        print(
            "Cluster not found"
        )

        return None



    response.raise_for_status()


    return response.json()



# =====================================================
# Main
# =====================================================

def main():

    domain = "garnetgrid.org"


    token = login()


    if not token:

        raise Exception(
            "Token not received"
        )


    # ---------------------------------------------
    # Domain
    # ---------------------------------------------

    domain_data = get_domain(
        domain,
        token
    )


    save_json(
        f"{domain}_domain.json",
        domain_data
    )


    print_json(
        "DOMAIN DATA",
        domain_data
    )


    clusters = domain_data.get(
        "clusters",
        {}
    )


    print_json(
        "CLUSTERS",
        clusters
    )


    # ---------------------------------------------
    # Clusters
    # ---------------------------------------------

    for cluster_type, cluster_hash in clusters.items():


        print(
            f"\nCHECK {cluster_type.upper()} CLUSTER"
        )


        cluster_data = get_cluster(

            cluster_type,

            cluster_hash,

            token
        )


        if cluster_data:


            save_json(

                f"{domain}_{cluster_type}_{cluster_hash}.json",

                cluster_data
            )


            print_json(

                "CLUSTER DATA",

                cluster_data
            )



# =====================================================
# Entry point
# =====================================================

if __name__ == "__main__":

    main()