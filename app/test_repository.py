from api.spamhaus_client import SpamhausClient
from repositories.spamhaus_repository import SpamhausRepository


client = SpamhausClient()

repo = SpamhausRepository(client)


domain = "canismajoris.store"


print("\n=== DOMAIN ===")
print(repo.get_domain(domain))


print("\n=== DIMENSIONS ===")
print(repo.get_dimensions(domain))


print("\n=== CONTEXTS ===")
print(repo.get_contexts(domain))


print("\n=== CONTEXT CATALOG ===")
print(repo.get_context_catalog())


print("\n=== TAGS ===")
print(repo.get_tags())

print("\n=== NS ===")
print(repo.get_nameservers(domain))


print("\n=== A ===")
print(repo.get_a_records(domain))


print("\n=== MALWARE ===")
print(repo.get_malware(domain))