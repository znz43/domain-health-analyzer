import dns.resolver


DEFAULT_DKIM_SELECTORS = [
    "default",
    "selector1",
    "selector2",
    "google",
    "dkim",
    "mail",
    "s1",
    "s2"
]


def resolve_record(domain, record_type):

    try:

        print(
            f"DNS QUERY {record_type}: {domain}"
        )

        answers = dns.resolver.resolve(
            domain,
            record_type,
            lifetime=5
        )

        result = []

        for record in answers:

            result.append(
                str(record)
                .replace('"', '')
                .strip()
            )

        print(
            "DNS RESULT:",
            result
        )

        return result


    except Exception as e:

        print(
            f"DNS FAILED: {domain} {record_type} {e}"
        )

        return []



def get_a(domain):

    return resolve_record(
        domain,
        "A"
    )



def get_aaaa(domain):

    return resolve_record(
        domain,
        "AAAA"
    )



def get_mx(domain):

    return resolve_record(
        domain,
        "MX"
    )



def get_txt(domain):

    return resolve_record(
        domain,
        "TXT"
    )



def get_spf(domain):

    return [

        record

        for record in get_txt(domain)

        if record.lower().startswith(
            "v=spf1"
        )

    ]



def get_dmarc(domain):

    return resolve_record(
        f"_dmarc.{domain}",
        "TXT"
    )



def get_dkim(domain, selectors=None):

    if selectors is None:
        selectors = DEFAULT_DKIM_SELECTORS


    print(
        f"DKIM CHECK: {domain}"
    )


    results = []

    seen = set()


    for selector in selectors:


        host = (
            f"{selector}._domainkey.{domain}"
        )


        records = resolve_record(
            host,
            "TXT"
        )


        if not records:
            continue


        value = "".join(records)


        if "v=DKIM1" not in value:
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


    print(
        "DKIM FOUND:",
        results
    )


    return results



def resolve_host(host):

    result = []


    for record_type in [
        "A",
        "AAAA"
    ]:

        result.extend(

            resolve_record(
                host,
                record_type
            )

        )


    return result