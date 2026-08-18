import os
import requests

from pathlib import Path
from dotenv import load_dotenv

from cache.cache_manager import CacheManager


BASE_DIR = Path(__file__).resolve().parents[2]

load_dotenv(
    BASE_DIR / ".env"
)


class SpamhausClient:

    BASE_URL = "https://api.spamhaus.org"

    def __init__(self):

        self.username = os.getenv(
            "SPAMHAUS_USERNAME"
        )

        self.password = os.getenv(
            "SPAMHAUS_PASSWORD"
        )

        self.token = None

        self.cache = CacheManager()

    # ==========================================================
    # AUTH
    # ==========================================================

    def login(self):

        cached = self.cache.get(
            "auth",
            "token"
        )

        if cached:

            self.token = cached

            return self.token

        response = requests.post(
            f"{self.BASE_URL}/api/v1/login",
            json={
                "username": self.username,
                "password": self.password,
                "realm": "intel"
            },
            headers={
                "Content-Type": "application/json"
            },
            timeout=30
        )

        response.raise_for_status()

        data = response.json()

        self.token = data["token"]

        self.cache.set(
            "auth",
            "token",
            self.token,
            24
        )

        return self.token

    # ==========================================================
    # GENERIC GET
    # ==========================================================

    def get(
        self,
        endpoint,
        cache_key=None,
        ttl=24
    ):

        namespace = None
        key = None

        if cache_key:

            namespace, key = cache_key.split(
                "/",
                1
            )

            cached = self.cache.get(
                namespace,
                key
            )

            if cached is not None:
                return cached

        if not self.token:
            self.login()

        response = requests.get(
            self.BASE_URL + endpoint,
            headers={
                "Authorization": f"Bearer {self.token}"
            },
            timeout=30
        )

        if response.status_code == 401:

            self.token = None

            self.login()

            response = requests.get(
                self.BASE_URL + endpoint,
                headers={
                    "Authorization": f"Bearer {self.token}"
                },
                timeout=30
            )

        if response.status_code == 404:

            return None

        response.raise_for_status()

        data = response.json()

        if cache_key and data is not None:

            self.cache.set(
                namespace,
                key,
                data,
                ttl
            )

        return data

    # ==========================================================
    # DOMAIN
    # ==========================================================

    def get_domain(
        self,
        domain
    ):

        return self.get(
            f"/api/intel/v2/byobject/domain/{domain}",
            f"domain/{domain}"
        )

    def get_domain_dimensions(
        self,
        domain
    ):

        return self.get(
            f"/api/intel/v2/byobject/domain/{domain}/dimensions",
            f"dimensions/{domain}"
        )

    def get_domain_contexts(
        self,
        domain
    ):

        return self.get(
            f"/api/intel/v2/byobject/domain/{domain}/contexts",
            f"contexts/{domain}"
        )

    def get_context_list(self):

        return self.get(
            "/api/intel/v2/context",
            "context_catalog/all",
            ttl=24 * 30
        )

    # ==========================================================
    # LISTING
    # ==========================================================

    def get_domain_listing(
        self,
        domain
    ):

        return self.get(
            f"/api/intel/v2/byobject/domain/{domain}/listing",
            f"listing/{domain}"
        )

    # ==========================================================
    # SENDERS
    # ==========================================================

    def get_domain_senders(
        self,
        domain
    ):

        return self.get(
            f"/api/intel/v2/byobject/domain/{domain}/senders",
            f"senders/{domain}"
        )

    def get_senders(
        self,
        domain
    ):

        return self.get_domain_senders(
            domain
        )

    # ==========================================================
    # SENDER IP HISTORY
    # ==========================================================

    def get_ip_history(
        self,
        ip
    ):

        data = self.get(
            f"/api/intel/v1/byobject/cidr/ALL/listings/history/{ip}",
            f"sender_ip_history/{ip}"
        )

        if isinstance(data, dict):

            return data.get(
                "results",
                []
            )

        if isinstance(data, list):

            return data

        return []

    # ==========================================================
    # NAMESERVERS
    # ==========================================================

    def get_domain_ns(
        self,
        domain
    ):

        return self.get(
            f"/api/intel/v2/byobject/domain/{domain}/ns",
            f"nameservers/{domain}"
        )

    def get_nameservers(
        self,
        domain
    ):

        return self.get_domain_ns(
            domain
        )

    def get_domain_nameservers(
        self,
        domain
    ):

        return self.get_nameservers(
            domain
        )

    # ==========================================================
    # TAGS
    # ==========================================================

    def get_domain_tags(
        self,
        domain
    ):

        return self.get(
            f"/api/intel/v2/byobject/domain/{domain}/tags",
            f"tags/{domain}"
        )

    def get_tags(
        self,
        domain
    ):

        return self.get_domain_tags(
            domain
        )

    # ==========================================================
    # MALWARE
    # ==========================================================

    def get_domain_malware(
        self,
        domain
    ):

        return self.get(
            f"/api/intel/v2/byobject/domain/{domain}/malware",
            f"malware/{domain}"
        )

    def get_malware(
        self,
        domain
    ):

        return self.get_domain_malware(
            domain
        )

    # ==========================================================
    # DNS / INFRA
    # ==========================================================

    def get_domain_a_records(
        self,
        domain
    ):

        return self.get(
            f"/api/intel/v2/byobject/domain/{domain}/a",
            f"a/{domain}"
        )

    # ==========================================================
    # CLUSTERS
    # ==========================================================

    def get_infra_cluster(
        self,
        infra_hash
    ):

        return self.get(
            f"/api/intel/v2/byobject/hash/infra/{infra_hash}",
            f"cluster_infra/{infra_hash}"
        )

    def get_auth_cluster(
        self,
        auth_hash
    ):

        return self.get(
            f"/api/intel/v2/byobject/hash/auth/{auth_hash}",
            f"cluster_auth/{auth_hash}"
        )