from repositories.endpoint import Endpoint


ENDPOINTS = {
    Endpoint.DOMAIN: {
        "ttl": 24,
        "global": False,
        "loader": lambda c, d: c.get_domain(d),
    },

    Endpoint.DIMENSIONS: {
        "ttl": 24,
        "global": False,
        "loader": lambda c, d: c.get_domain_dimensions(d),
    },

    Endpoint.CONTEXTS: {
        "ttl": 24,
        "global": False,
        "loader": lambda c, d: c.get_domain_contexts(d),
    },

    Endpoint.CONTEXT_CATALOG: {
        "ttl": 24 * 30,
        "global": True,
        "loader": lambda c: c.get_context_list(),
    },

    Endpoint.TAGS: {
        "ttl": 24 * 30,
        "global": True,
        "loader": lambda c: c.get_tags(),
    },
}