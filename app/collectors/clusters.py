def collect_clusters(repo, domain_data):

    clusters = domain_data.get("clusters")

    if not clusters:
        return {}

    result = {}

    for cluster_type in ["auth", "infra"]:

        hash_value = clusters.get(cluster_type)

        if not hash_value:
            continue

        try:
            result[cluster_type] = repo.get_cluster(
                cluster_type,
                hash_value
            )

        except PermissionError:
            # Extended Access нема
            result[cluster_type] = {
                "available": False,
                "reason": "no_access"
            }

        except Exception:
            result[cluster_type] = {
                "available": False,
                "reason": "error"
            }

    return result