# Common Tekton resources

Shared Tekton Tasks and scripts used across vulnerability scanner pipelines.

## Pre-requisites

The `upload-results` task runs Python steps using the `python3-with-requests` image.
Build and deploy it as documented in [rhacs/README.md](../rhacs/README.md#build-container-images-used-in-python-steps).

## Deploy

All Tekton resources and script ConfigMaps are managed via
[Kustomize](https://kubectl.docs.kubernetes.io/references/kustomize/kustomization/).
Scripts live as standalone files under `scripts/` and are bundled into the
`common-python-scripts` ConfigMap by the `configMapGenerator` in
`kustomization.yaml`.

```shell
oc apply -k common/
```

## Adding or modifying scripts

1. Edit the script file under `scripts/python/`
2. If adding a new script, add its path to the `configMapGenerator` entry in
   `kustomization.yaml`
3. Re-apply: `oc apply -k common/`
