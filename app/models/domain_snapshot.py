class DomainSnapshot:

    def __init__(self, data):

        self.domain = data.get("domain")

        self.collected_at = datetime.utcnow().isoformat()

        # Spamhaus domain general
        self.score = data.get("score")

        self.tags = data.get(
            "tags",
            []
        )

        self.abused = data.get(
            "abused",
            False
        )

        self.whois = data.get(
            "whois",
            {}
        )

        self.clusters = data.get(
            "clusters",
            {}
        )


        # Spamhaus reputation dimensions
        self.dimensions = data.get(
            "dimensions",
            []
        )


        # Spamhaus contexts
        self.contexts = data.get(
            "contexts",
            []
        )