from datetime import datetime


class DomainSnapshot:

    def __init__(self, data: dict):

        self.domain = data.get("domain")

        self.collected_at = datetime.utcnow().isoformat()


        self.score = data.get("score")

        self.tags = data.get("tags", [])

        self.abused = data.get("abused", False)

        self.whois = data.get("whois", {})

        self.clusters = data.get("clusters", {})


        self.dimensions = data.get("dimensions", [])

        self.contexts = data.get("contexts", [])