from app.collectors.spamhaus_dqs import check_dqs


ip = "8.8.8.8"

result = check_dqs(ip)

print(result)