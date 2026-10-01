import os

import requests
from secret_utils import write_secret


def main() -> None:
    rox_endpoint = os.getenv("ROX_ENDPOINT")
    ocm_token = os.getenv("OCM_TOKEN")
    payload = {"idToken": ocm_token}
    response = requests.post(f"{rox_endpoint}/v1/auth/m2m/exchange", json=payload)

    if response.status_code != 200:
        print("Failed exchanching OIDC token. Machine to machine authentication may not be configured")
        response.raise_for_status()

    print("Token exchange successful")

    access_token = response.json().get("accessToken")

    # Hand the token to the sibling whoami step via an in-pod file (never logged).
    with open(os.environ["ROX_API_TOKEN_FILE"], "w") as f:
        f.write(access_token)

    # Hand the token to downstream tasks via the per-run Secret (consumed via secretKeyRef).
    write_secret({"rox-api-token": access_token})


if __name__ == "__main__":
    main()
