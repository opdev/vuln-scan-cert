import os
import time

import requests

ROX_API_TOKEN = os.getenv("ROX_API_TOKEN")

ROX_ENDPOINT = os.getenv("ROX_ENDPOINT")
headers = {"Authorization": f"Bearer {ROX_API_TOKEN}"}
return_code = None
scanner_health = None

while return_code != 200:
    response = requests.get(
        f"{ROX_ENDPOINT}/v1/integrationhealth/vulndefinitions?component=SCANNER_V4", headers=headers
    )
    return_code = response.status_code

    if return_code != 200:
        print("Scanner may not be ready. Retrying after 300s")
        time.sleep(300)

    scanner_health = response.json()

print("Scanner v4 DB Initialized")
print(scanner_health.get("lastUpdatedTimestamp"))
