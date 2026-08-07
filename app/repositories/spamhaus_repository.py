from cache.cache_manager import CacheManager


class SpamhausRepository:


    def __init__(self, client):

        self.client = client
        self.cache = CacheManager()



    def _remember(
        self,
        namespace,
        key,
        loader,
        ttl_hours=24
    ):

        result = self.cache.remember(
            namespace=namespace,
            key=key,
            ttl_hours=ttl_hours,
            loader=loader
        )

        #
        # unwrap cache payload
        #
        if isinstance(result, dict) and "data" in result:

            return result["data"]

        return result



    def get_domain(self, domain):

        return self._remember(
            "domain",
            domain,
            lambda:
                self.client.get_domain(domain)
        )



    def get_dimensions(self, domain):

        return self._remember(
            "dimensions",
            domain,
            lambda:
                self.client.get_domain_dimensions(domain)
        )



    def get_contexts(self, domain):

        return self._remember(
            "contexts",
            domain,
            lambda:
                self.client.get_domain_contexts(domain)
        )



    def get_context_catalog(self):

        return self._remember(
            "context_catalog",
            "all",
            lambda:
                self.client.get_context_list(),
            ttl_hours=24 * 30
        )



    def get_tags(self):

        return self._remember(
            "tags",
            "all",
            lambda:
                self.client.get_tags(),
            ttl_hours=24 * 30
        )



    def get_listing(self, domain):

        return self._remember(
            "listing",
            domain,
            lambda:
                self.client.get_domain_listing(domain)
        )



    def get_senders(self, domain):

        return self._remember(
            "senders",
            domain,
            lambda:
                self.client.get_domain_senders(domain)
        )



    def get_nameservers(self, domain):

        return self._remember(
            "nameservers",
            domain,
            lambda:
                self.client.get_domain_nameservers(domain)
        )



    def get_a_records(self, domain):

        return self._remember(
            "a_records",
            domain,
            lambda:
                self.client.get_domain_a_records(domain)
        )



    def get_mx_records(self, domain):

        return self._remember(
            "mx_records",
            domain,
            lambda:
                self.client.get_domain_mx_records(domain)
        )



    def get_malware(self, domain):

        return self._remember(
            "malware",
            domain,
            lambda:
                self.client.get_domain_malware(domain)
        )