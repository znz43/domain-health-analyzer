def join_list(values):

    if not values:
        return ""

    return " | ".join(
        str(v)
        for v in values
    )


def format_contexts(contexts):

    if not contexts:
        return ""

    return " | ".join(
        [
            f"{c.get('context')}:{c.get('last_seen')}"
            for c in contexts
        ]
    )


def format_dkim(records):

    if not records:
        return ""

    result = []

    for item in records:

        if isinstance(item, dict):

            result.append(
                f"{item.get('selector')}:{item.get('value')}"
            )

        else:

            result.append(
                str(item)
            )

    return " | ".join(result)



def format_mx(records):

    if not records:
        return ""

    result = []

    for item in records:

        if isinstance(item, dict):

            result.append(
                item.get("host", "")
            )

        else:

            result.append(
                str(item)
            )

    return " | ".join(result)



def format_ips(records):

    if not records:
        return ""

    result = []

    for item in records:

        if isinstance(item, dict):

            ip = item.get("ip")

            if ip:
                result.append(ip)

        else:

            result.append(
                str(item)
            )


    return " | ".join(result)



def format_nameservers(records):

    if not records:
        return ""

    result = []

    for item in records:

        result.append(
            "{} score={} counter={} last_seen={}".format(
                item.get("ns"),
                item.get("score"),
                item.get("counter"),
                item.get("last_seen")
            )
        )


    return " | ".join(result)



def format_dqs(records):

    if not records:
        return ""

    result = []


    for item in records:

        ip = item.get(
            "ip"
        )


        checks = []


        for name, value in item.get(
            "lists",
            {}
        ).items():

            status = (
                "LISTED"
                if value
                else "CLEAN"
            )


            checks.append(
                f"{name}={status}"
            )


        result.append(
            f"{ip}:{','.join(checks)}"
        )


    return " | ".join(result)



def format_clusters(clusters):

    if not clusters:
        return ""


    return " | ".join(
        [
            f"{k}={v}"
            for k,v in clusters.items()
        ]
    )



def format_whois(whois):

    if not whois:
        return ""


    return " | ".join(
        [
            f"{k}={v}"
            for k,v in whois.items()
        ]
    )