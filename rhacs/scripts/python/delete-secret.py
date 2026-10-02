import os

import requests

SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
K8S_API = "https://kubernetes.default.svc"


def main() -> None:
    namespace = open(f"{SA_DIR}/namespace").read().strip()
    sa_token = open(f"{SA_DIR}/token").read().strip()
    name = os.environ["CREDS_SECRET_NAME"]
    url = f"{K8S_API}/api/v1/namespaces/{namespace}/secrets/{name}"

    response = requests.delete(url, headers={"Authorization": f"Bearer {sa_token}"}, verify=f"{SA_DIR}/ca.crt")
    if response.status_code == 404:
        print(f"Secret {name} already gone")
        return
    response.raise_for_status()
    print(f"Deleted secret {name}")


if __name__ == "__main__":
    main()
