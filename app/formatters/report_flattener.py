def format_list(values):

    if not values:
        return ""

    return " | ".join(
        str(x)
        for x in values
    )



def format_dkim(records):

    if not records:
        return ""

    result = []

    for item in records:

        result.append(
            f"{item.get('selector')}:{item.get('value')}"
        )


    return " | ".join(result)



def format_mx(records):

    if not records:
        return ""

    result = []

    for item in records:

        result.append(
            item.get("host", "")
        )


    return " | ".join(result)



def format_ips(records):

    if not records:
        return ""

    result = []

    for item in records:

        ip = item.get(
            "ip"
        )

        if ip:
            result.append(
                ip
            )


    return " | ".join(result)



def format_nameservers(records):

    if not records:
        return ""

    result = []


    for item in records:

        result.append(

            f"{item.get('ns')} "
            f"score={item.get('score')} "
            f"counter={item.get('counter')} "
            f"last_seen={item.get('last_seen')}"

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


        lists = []


        for name, value in item.get(
            "lists",
            {}
        ).items():


            lists.append(

                f"{name}="
                +
                (
                    "LISTED"
                    if value
                    else
                    "CLEAN"
                )

            )


        result.append(

            f"{ip}:"
            +
            ",".join(lists)

        )


    return " | ".join(result)



def format_contexts(contexts):

    if not contexts:
        return ""


    return " | ".join(

        [

            f"{x.get('context')}:{x.get('last_seen')}"

            for x in contexts

        ]

    )



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





def flatten_report(report):


    dimensions = report.dimensions


    identity = dimensions.get(
        "identity",
        {}
    )


    infrastructure = dimensions.get(
        "infrastructure",
        {}
    )


    identity_data = identity.get(
        "data",
        {}
    )


    infra_data = infrastructure.get(
        "data",
        {}
    )



    return {


        "domain":
            report.domain,


        "score":
            report.score,



        "is_listed":
            report.timeline.get(
                "is_listed"
            ),


        "listed_date":
            report.timeline.get(
                "listed_date"
            ),


        "listed_until":
            report.timeline.get(
                "listed_until"
            ),


        "last_seen":
            report.timeline.get(
                "last_seen"
            ),



        "contexts":
            format_contexts(
                report.contexts
            ),



        "smtp_score":
            dimensions.get(
                "smtp",
                {}
            ).get(
                "score"
            ),



        "identity_score":
            identity.get(
                "score"
            ),



        "infra_score":
            infrastructure.get(
                "score"
            ),



        "malware_score":
            dimensions.get(
                "malware",
                {}
            ).get(
                "score"
            ),



        "human_score":
            dimensions.get(
                "human",
                {}
            ).get(
                "score"
            ),




        "spf":
            format_list(
                identity_data.get(
                    "spf"
                )
            ),



        "dmarc":
            format_list(
                identity_data.get(
                    "dmarc"
                )
            ),



        "dkim":
            format_dkim(
                identity_data.get(
                    "dkim"
                )
            ),




        "mx":
            format_mx(
                infra_data.get(
                    "mx_records"
                )
            ),



        "dns_a":
            format_ips(
                infra_data.get(
                    "a_records"
                )
            ),



        "dns_aaaa":
            format_ips(
                infra_data.get(
                    "aaaa_records"
                )
            ),



        "nameservers":
            format_nameservers(
                infra_data.get(
                    "nameservers"
                )
            ),



        "spamhaus_dqs":
            format_dqs(
                infra_data.get(
                    "spamhaus_dqs"
                )
            ),



        "clusters":
            "",



        "whois":
            ""

    }