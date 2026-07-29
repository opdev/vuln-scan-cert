import os

import requests

ocm_token = os.getenv("OCM_TOKEN")
central_id = os.getenv("CENTRAL_ID")

API_URL = f"https://api.openshift.com/api/rhacs/v1/centrals/{central_id}?async=true"
headers = {"Authorization": f"Bearer {ocm_token}", "Content-Type": "application/json"}

print(f"Sending Central deletion request with id {central_id}")

response = requests.delete(API_URL, headers=headers)

if response.status_code != 200:
    print(f"Return code: {response.status_code}")
    response.raise_for_status()

print("Central deletion request successfully sent")
