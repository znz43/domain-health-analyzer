def collect_clusters(repo, domain_data):

    result = {
        "auth": None,
        "infra": None,
        "access": True
    }

    clusters = domain_data.get("clusters", {})

    for cluster_type in ["auth", "infra"]:

        hash_value = clusters.get(cluster_type)

        if not hash_value:
            continue

        try:
            domains = repo.get_cluster(
                cluster_type,
                hash_value
            )

            result[cluster_type] = {
                "hash": hash_value,
                "count": len(domains),
                "domains": domains[:100]
            }


        except PermissionError:

            result["access"] = False

            result[cluster_type] = {
                "hash": hash_value,
                "error": "extended_access_required"
            }


        except Exception as e:

            result[cluster_type] = {
                "hash": hash_value,
                "error": str(e)
            }


    return result