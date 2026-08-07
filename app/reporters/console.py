def print_console_report(
    report,
    comparison=None,
    infrastructure=None,
    domain_data=None
):

    print("=" * 70)
    print()
    print("Current Domain Test")
    print()


    #
    # Basic
    #
    print(f"Domain: {report.domain}")
    print(f"Total Score: {report.overall_score}")



    #
    # Timeline
    #
    print()
    print("Timeline")
    print("-" * 70)


    for key, value in report.timeline.items():

        print(
            f"{key}: {value}"
        )



    #
    # Dimensions
    #
    print()
    print("Dimensions")
    print("-" * 70)


    for name, data in report.dimensions.items():

        print(
            f"{name:<15}: {data.get('score')}"
        )



    #
    # Identity DNS
    #
    identity = report.dimensions.get(
        "identity",
        {}
    )


    if identity.get("data"):


        dns = identity["data"].get(
            "dns",
            {}
        )


        print()
        print("Identity")
        print("-" * 70)



        if dns.get("mx"):

            print()
            print("MX")

            for item in dns["mx"]:

                print(
                    f"  {item}"
                )



        if dns.get("spf"):

            print()
            print("SPF")

            for item in dns["spf"]:

                print(
                    f"  {item}"
                )



        if dns.get("dkim"):

            print()
            print("DKIM")

            for item in dns["dkim"]:


                value = item.get(
                    "value",
                    ""
                )


                print(
                    f"  Selector : {item.get('selector')}"
                )


                print(
                    f"  Key      : {value[:80]}..."
                )



        if dns.get("dmarc"):

            print()
            print("DMARC")

            for item in dns["dmarc"]:

                print(
                    f"  {item}"
                )



    #
    # Contexts
    #
    print()
    print("Contexts")
    print("-" * 70)


    for context in report.contexts:


        print(
            f"{context.get('context')} "
            f"({context.get('last_seen')})"
        )


        if context.get("description"):

            print(
                f"  {context.get('description')}"
            )



    #
    # Infrastructure
    #
    print()
    print("Infrastructure")
    print("-" * 70)



    if infrastructure:


        #
        # Nameservers
        #
        print()
        print("Nameservers")


        nameservers = infrastructure.get(
            "nameservers",
            []
        )


        if nameservers:


            for ns in nameservers:

                print()

                print(
                    f"Host       : {ns.get('ns')}"
                )

                print(
                    f"Score      : {ns.get('score')}"
                )

                print(
                    f"Counter    : {ns.get('counter')}"
                )

                print(
                    f"Last Seen  : {ns.get('last_seen')}"
                )


        else:

            print("None")



        #
        # A Records
        #
        print()
        print("A Records")


        a_records = infrastructure.get(
            "a_records",
            []
        )


        if a_records:


            for record in a_records:

                print()

                print(
                    f"IP         : {record.get('ip')}"
                )


        else:

            print("None")



        #
        # AAAA Records
        #
        print()
        print("AAAA Records")


        aaaa_records = infrastructure.get(
            "aaaa_records",
            []
        )


        if aaaa_records:


            for record in aaaa_records:

                print()

                print(
                    f"IP         : {record.get('ip')}"
                )


        else:

            print("None")



        #
        # MX Records
        #
        print()
        print("MX Records")


        mx_records = infrastructure.get(
            "mx_records",
            []
        )


        if mx_records:


            for mx in mx_records:

                print()

                print(
                    f"Host       : {mx.get('host')}"
                )

                print(
                    f"IP         : {mx.get('ip')}"
                )


        else:

            print("None")



        #
        # Spamhaus DQS
        #
        print()
        print("Spamhaus DQS")
        print("-" * 70)


        dqs = infrastructure.get(
            "spamhaus_dqs",
            []
        )


        if dqs:


            for item in dqs:


                print()

                print(
                    f"IP: {item.get('ip')}"
                )


                for name, value in item.get(
                    "lists",
                    {}
                ).items():


                    if isinstance(value, dict):

                        listed = value.get(
                            "listed",
                            False
                        )

                    else:

                        listed = value



                    status = (
                        "LISTED"
                        if listed
                        else
                        "CLEAN"
                    )


                    print(
                        f"    {name:<8}: {status}"
                    )


        else:

            print("None")



    else:

        print("None")



    #
    # Domain Intelligence
    #
    print()
    print("Domain")
    print("-" * 70)


    if domain_data:


        print(
            f"Domain     : {domain_data.get('domain')}"
        )


        print(
            f"Score      : {domain_data.get('score')}"
        )


        tags = domain_data.get(
            "tags",
            []
        )


        print(
            f"Tags       : {', '.join(tags) if tags else 'None'}"
        )


        print(
            f"Abused     : {domain_data.get('abused')}"
        )


        print(
            f"Last Seen  : {domain_data.get('last_seen')}"
        )



        clusters = domain_data.get(
            "clusters",
            {}
        )


        if clusters:


            print()
            print("Clusters")


            for key, value in clusters.items():

                print(
                    f"  {key}: {value}"
                )



        whois = domain_data.get(
            "whois",
            {}
        )


        if whois:


            print()
            print("WHOIS")


            for key, value in whois.items():

                print(
                    f"  {key}: {value}"
                )


    else:

        print("None")



    print()
    print("=" * 70)