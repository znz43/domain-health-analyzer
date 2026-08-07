from collectors.dns import get_dkim


for domain in [
    "etauma.top",
    "canismajoris.store"
]:

    print("=" * 50)
    print(domain)

    result = get_dkim(domain)

    print(result)