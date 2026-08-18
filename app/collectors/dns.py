import dns.resolver


DEFAULT_DKIM_SELECTORS = [
    "default",
    "selector1",
    "selector2",
    "google",
    "dkim",
    "mail",
    "s1",
    "s2",
    "smtp",
    "email",
    "k1",
    "k2",
]


def resolve_record(
    domain: str,
    record_type: str
):

    try:

        answers = dns.resolver.resolve(
            domain,
            record_type,
            lifetime=5
        )

        return [
            str(record)
            .replace('"', "")
            .strip()
            for record in answers
        ]

    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout
    ):

        return []

    except Exception:

        return []


# ==========================================================
# A
# ==========================================================

def get_a(domain):

    return resolve_record(
        domain,
        "A"
    )


# ==========================================================
# AAAA
# ==========================================================

def get_aaaa(domain):

    return resolve_record(
        domain,
        "AAAA"
    )


# ==========================================================
# MX
# ==========================================================

def get_mx(domain):

    return resolve_record(
        domain,
        "MX"
    )


# ==========================================================
# TXT
# ==========================================================

def get_txt(domain):

    return resolve_record(
        domain,
        "TXT"
    )


# ==========================================================
# SPF
# ==========================================================

def get_spf(domain):

    records = get_txt(domain)

    return [
        record
        for record in records
        if record.lower().startswith("v=spf1")
    ]


# ==========================================================
# DMARC
# ==========================================================

def get_dmarc(domain):

    return resolve_record(
        f"_dmarc.{domain}",
        "TXT"
    )


# ==========================================================
# DKIM
# ==========================================================

def get_dkim(
    domain,
    selectors=None
):

    if selectors is None:

        selectors = DEFAULT_DKIM_SELECTORS

    results = []

    seen = set()

    for selector in selectors:

        selector = selector.strip().lower()

        if not selector:
            continue

        host = (
            f"{selector}._domainkey.{domain}"
        )

        records = resolve_record(
            host,
            "TXT"
        )

        if not records:
            continue

        value = "".join(
            record.strip()
            for record in records
        )

        value_lower = value.lower()

        if not (
            value_lower.startswith("v=dkim1")
            or "v=dkim1;" in value_lower
            or "v=dkim1 " in value_lower
        ):

            continue

        fingerprint = (
            selector,
            value
        )

        if fingerprint in seen:
            continue

        seen.add(
            fingerprint
        )

        results.append({

            "selector": selector,

            "value": value

        })

    return results


# ==========================================================
# HOST RESOLUTION
# ==========================================================

def resolve_host(host):

    result = []

    for record_type in (
        "A",
        "AAAA"
    ):

        result.extend(
            resolve_record(
                host,
                record_type
            )
        )

    return result