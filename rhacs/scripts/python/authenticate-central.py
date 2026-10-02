import os
import sys

import requests

SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
K8S_API = "https://kubernetes.default.svc"


def build_secret_manifest(name: str, token: str, owner_name: str, owner_uid: str) -> dict:
    """Opaque Secret holding the ROX API token, owned by the PipelineRun so it is
    garbage-collected with the run even if the finally cleanup never runs."""
    manifest = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": name},
        "type": "Opaque",
        "stringData": {"rox-api-token": token},
    }
    if owner_name and owner_uid:
        manifest["metadata"]["ownerReferences"] = [
            {
                "apiVersion": "tekton.dev/v1",
                "kind": "PipelineRun",
                "name": owner_name,
                "uid": owner_uid,
                "controller": False,
                "blockOwnerDeletion": False,
            }
        ]
    return manifest


def write_secret(token: str) -> None:
    """Create (or patch, on retry) the per-run Secret via the in-cluster API using the
    pod's ServiceAccount. Never logs the token."""
    namespace = open(f"{SA_DIR}/namespace").read().strip()
    sa_token = open(f"{SA_DIR}/token").read().strip()
    ca = f"{SA_DIR}/ca.crt"
    name = os.environ["CREDS_SECRET_NAME"]
    headers = {"Authorization": f"Bearer {sa_token}"}
    url = f"{K8S_API}/api/v1/namespaces/{namespace}/secrets"

    manifest = build_secret_manifest(name, token, os.getenv("PIPELINERUN_NAME", ""), os.getenv("PIPELINERUN_UID", ""))
    response = requests.post(url, headers=headers, json=manifest, verify=ca)
    if response.status_code == 409:
        # Secret already exists (task retry) — merge the new token in.
        response = requests.patch(
            f"{url}/{name}",
            headers={**headers, "Content-Type": "application/merge-patch+json"},
            json={"stringData": {"rox-api-token": token}},
            verify=ca,
        )
    response.raise_for_status()


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

    # Hand the token to downstream tasks via a per-run Secret (consumed via secretKeyRef).
    write_secret(access_token)


def _self_check() -> None:
    m = build_secret_manifest("rhacs-creds-abc", "tok", "rhacs-run", "uid-123")
    assert m["kind"] == "Secret"
    assert m["type"] == "Opaque"
    assert m["stringData"] == {"rox-api-token": "tok"}
    owner = m["metadata"]["ownerReferences"][0]
    assert owner["uid"] == "uid-123" and owner["kind"] == "PipelineRun"
    assert owner["controller"] is False and owner["blockOwnerDeletion"] is False
    # No owner metadata when the PipelineRun identity is absent.
    assert "ownerReferences" not in build_secret_manifest("n", "t", "", "")["metadata"]
    print("self-check ok")


if __name__ == "__main__":
    if "--self-check" in sys.argv:
        _self_check()
    else:
        main()
