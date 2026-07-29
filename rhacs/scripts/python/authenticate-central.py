import os

import requests

ROX_ENDPOINT = os.getenv("ROX_ENDPOINT")
OCM_TOKEN = os.getenv("OCM_TOKEN")
payload = {"idToken": OCM_TOKEN}
response = requests.post(f"{ROX_ENDPOINT}/v1/auth/m2m/exchange", json=payload)

if response.status_code != 200:
    print("Failed exchanching OIDC token. Machine to machine authentication may not be configured")
    response.raise_for_status()

print("Token exchange successful")

m2m_response = response.json()
with open(os.environ["STEP_RESULT_PATH"], "w") as f:
    f.write(m2m_response.get("accessToken"))
with open(os.environ["TASK_RESULT_PATH"], "w") as f:
    f.write(m2m_response.get("accessToken"))
