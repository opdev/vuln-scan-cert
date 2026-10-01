import os
import sys

import requests

SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
K8S_API = "https://kubernetes.default.svc"


def build_secret_manifest(name: str, string_data: dict, owner_name: str, owner_uid: str) -> dict:
    """Opaque Secret holding per-run credentials, owned by the PipelineRun so it is
    garbage-collected with the run even if the finally cleanup never runs."""
    manifest = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": name},
        "type": "Opaque",
        "stringData": dict(string_data),
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


def _secrets_api() -> tuple[str, dict, str]:
    """In-cluster Secrets API endpoint, auth headers, and CA path from the pod's ServiceAccount."""
    namespace = open(f"{SA_DIR}/namespace").read().strip()
    sa_token = open(f"{SA_DIR}/token").read().strip()
    ca = f"{SA_DIR}/ca.crt"
    headers = {"Authorization": f"Bearer {sa_token}"}
    url = f"{K8S_API}/api/v1/namespaces/{namespace}/secrets"
    return url, headers, ca


def write_secret(string_data: dict) -> None:
    """Create (or patch, on retry / sibling producer) the per-run Secret via the in-cluster API
    using the pod's ServiceAccount. Merges the given keys in. Never logs the values."""
    url, headers, ca = _secrets_api()
    name = os.environ["CREDS_SECRET_NAME"]

    manifest = build_secret_manifest(
        name, string_data, os.getenv("PIPELINERUN_NAME", ""), os.getenv("PIPELINERUN_UID", "")
    )
    response = requests.post(url, headers=headers, json=manifest, verify=ca)
    if response.status_code == 409:
        # Secret already exists (task retry, or a sibling producer created it) — merge the keys in.
        response = requests.patch(
            f"{url}/{name}",
            headers={**headers, "Content-Type": "application/merge-patch+json"},
            json={"stringData": string_data},
            verify=ca,
        )
    response.raise_for_status()


def delete_secret() -> None:
    """Best-effort delete of the per-run Secret. The PipelineRun ownerReference GC is the
    backstop, so never fail a finally cleanup on a delete error — just log it."""
    url, headers, ca = _secrets_api()
    name = os.environ["CREDS_SECRET_NAME"]

    response = requests.delete(f"{url}/{name}", headers=headers, verify=ca)
    if response.status_code == 404:
        print(f"Secret {name} already gone")
        return
    if not response.ok:
        print(f"Best-effort delete of Secret {name} failed ({response.status_code}); ownerReference GC will remove it")
        return
    print(f"Deleted secret {name}")


def _self_check() -> None:
    m = build_secret_manifest("rhacs-creds-abc", {"ocm-token": "a", "rox-api-token": "b"}, "rhacs-run", "uid-123")
    assert m["kind"] == "Secret"
    assert m["type"] == "Opaque"
    assert m["stringData"] == {"ocm-token": "a", "rox-api-token": "b"}
    owner = m["metadata"]["ownerReferences"][0]
    assert owner["uid"] == "uid-123" and owner["kind"] == "PipelineRun"
    assert owner["controller"] is False and owner["blockOwnerDeletion"] is False
    # No owner metadata when the PipelineRun identity is absent.
    assert "ownerReferences" not in build_secret_manifest("n", {"k": "v"}, "", "")["metadata"]
    print("self-check ok")


if __name__ == "__main__":
    if "--self-check" in sys.argv:
        _self_check()
