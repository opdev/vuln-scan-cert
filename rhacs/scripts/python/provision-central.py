import os

import requests

headers = {"Authorization": f"Bearer {os.getenv('OCM_TOKEN')}", "Content-Type": "application/json"}
existing_central_id = os.getenv("EXISTING_CENTRAL_ID")

if existing_central_id:
    central_id = existing_central_id
    print(f"Using existing Central with ID {central_id}")
else:
    cloud_account_id = os.getenv("CLOUD_ACCOUNT_ID")
    if not cloud_account_id:
        raise ValueError("CLOUD_ACCOUNT_ID must be set when creating a new Central")

    API_URL = "https://api.openshift.com/api/rhacs/v1/centrals?async=true"
    central_name_suffix = os.getenv("PIPELINERUN_UID").split("-")[0]
    central_name = f"vuln-scan-cert-{central_name_suffix}"
    payload = {
        "name": central_name,
        "cloud_provider": "aws",
        "multi_az": True,
        "region": os.getenv("CENTRAL_AWS_REGION"),
        "cloud_account_id": cloud_account_id,
    }

    print(f"Sending Central creation request with name {central_name}")

    response = requests.post(
        API_URL,
        json=payload,
        headers=headers,
    )

    if response.status_code != 200:
        print(f"Return code: {response.status_code}")
        print(response.json())
        response.raise_for_status()

    central_request = response.json()
    central_id = central_request.get("id")
    print("Central creation request successfully sent")
    print(f"Central ID: {central_id}")

with open(os.environ["STEP_RESULT_PATH"], "w") as f:
    f.write(central_id)
with open(os.environ["TASK_RESULT_PATH"], "w") as f:
    f.write(central_id)
