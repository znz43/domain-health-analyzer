from enum import Enum


class Endpoint(str, Enum):
    DOMAIN = "domain"
    DIMENSIONS = "dimensions"
    CONTEXTS = "contexts"

    CONTEXT_CATALOG = "context_catalog"
    TAGS = "tags"

    NAMESERVERS = "nameservers"
    HOSTNAMES = "hostnames"

    MALWARE = "malware"

    MX = "mx"
    A = "a"
    AAAA = "aaaa"