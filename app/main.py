from api.spamhaus_client import SpamhausClient


def main():

    client = SpamhausClient()

    client.login()

    data = client.get_domain(
        "example.com"
    )

    print(data)


if __name__ == "__main__":
    main()