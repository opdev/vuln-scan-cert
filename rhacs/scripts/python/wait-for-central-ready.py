import os
import time

import requests

ROX_ENDPOINT_PATH = os.environ["ROX_ENDPOINT_PATH"]


headers = {"Authorization": f"Bearer {os.getenv('OCM_TOKEN')}", "Content-Type": "application/json"}
central_request_status = None

while central_request_status != "ready":
    print("Querying central status")
    response = requests.get(
        f"https://api.openshift.com/api/rhacs/v1/centrals/{os.getenv('CENTRAL_ID')}", headers=headers
    )
    central_request = response.json()
    print(central_request)
    central_request_status = central_request.get("status")

    if central_request_status != "ready":
        print("Central is not ready yet, retrying in 10 seconds...")
        time.sleep(10)

print("Central is Ready")

with open(ROX_ENDPOINT_PATH, "w") as f:
    f.write(central_request.get("centralUIURL"))
