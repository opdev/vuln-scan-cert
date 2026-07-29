import os
import time

import requests

ocm_token = os.getenv("OCM_TOKEN")
central_id = os.getenv("CENTRAL_ID")

headers = {"Authorization": f"Bearer {ocm_token}", "Content-Type": "application/json"}
return_code = None

while return_code != 404:
    print("Querying central status")
    response = requests.get(
        f"https://api.openshift.com/api/rhacs/v1/centrals/{central_id}",
        headers=headers,
    )
    central_request = response.json()
    print(central_request)
    central_status = central_request.get("status")
    return_code = response.status_code

    if return_code != 404:
        print(f"Central has status '{central_status}', retrying in 10 seconds...")
        time.sleep(10)

print("Central is deleted")
