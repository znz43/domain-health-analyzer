import os
from dotenv import load_dotenv


load_dotenv()


SPAMHAUS_USERNAME = os.getenv(
    "SPAMHAUS_USERNAME"
)

SPAMHAUS_PASSWORD = os.getenv(
    "SPAMHAUS_PASSWORD"
)


SPAMHAUS_API_URL = "https://api.spamhaus.org"


SPAMHAUS_DQS_KEY = os.getenv(
    "SPAMHAUS_DQS_KEY"
)