# ---------------------------------------------
# Clusters
# ---------------------------------------------

for cluster_type in ["auth", "infra"]:

    cluster_hash = clusters.get(
        cluster_type
    )

    print(
        "\n" + "=" * 80
    )

    print(
        f"CHECK {cluster_type.upper()} CLUSTER"
    )

    print(
        "HASH:",
        cluster_hash
    )

    if not cluster_hash:

        print(
            f"NO {cluster_type.upper()} HASH"
        )

        continue

    cluster_data = get_cluster(

        cluster_type,

        cluster_hash,

        token
    )

    if cluster_data:

        save_json(

            f"{domain}_{cluster_type}_{cluster_hash}.json",

            cluster_data
        )

        print_json(

            f"{cluster_type.upper()} CLUSTER DATA",

            cluster_data
        )