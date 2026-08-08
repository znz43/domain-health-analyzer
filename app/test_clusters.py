import json

from api.spamhaus_client import SpamhausClient

client = SpamhausClient()

domain = "garnetgrid.org"

domain_data = client.get_domain(domain)

print("Clusters:")
print(json.dumps(domain_data["clusters"], indent=2))

print()

print("Infra cluster...")
infra = client.get_infra_cluster(
    domain_data["clusters"]["infra"]
)

print(json.dumps(infra, indent=2, ensure_ascii=False))

print()

print("Auth cluster...")
auth = client.get_auth_cluster(
    domain_data["clusters"]["auth"]
)

print(json.dumps(auth, indent=2, ensure_ascii=False))