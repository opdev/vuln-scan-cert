# Vulnerability scanner certification pipeline for RHACS

## Pre-requisites

### Deploy OCP cluster

Requirements TBD

### Install OpenShift Pipelines operator (Tekton)

https://docs.redhat.com/en/documentation/red_hat_openshift_pipelines/1.21/html/installing_and_configuring/installing-pipelines

### Red Hat SSO Service Account

- Follow this link to create a Red Hat Service Account: https://console.redhat.com/iam/service-accounts/
- Save Client ID and Client Secret
```shell
$ export CLIENT_ID=<my-client-id>
$ export CLIENT_SECRET=<my-client-secret>
```
- Create Kubernetes Secret
```shell
$ envsubst < rh-openid-credentials/rh-openid-credentials.template.yaml | oc apply -f -
```

### Service Account for registry.redhat.io

Test harness images are hosted on registry.redhat.io, for which you need authentication
- Create a Service Account on: https://access.redhat.com/terms-based-registry/
- Save the Username and password (token)
```shell
$ export REGISTRY_REDHAT_USERNAME=<my_service_account_name>
$ export REGISTRY_REDHAT_PASSWORD=<my_service_account_token>
```
- Create Kubernetes Secret
```shell
$ envsubst < registry-redhat-credentials/registry-redhat-credentials.template.yaml | oc apply -f -
```

### Apply RHACS Tasks and Pipeline definitions

The image scan step uses a custom rhacs-image-scan task that includes CSV conversion functionality.

```shell
$ oc apply -f configmaps/scripts.yaml
$ oc apply -f tasks/
$ oc apply -f pipeline/rhacs.yaml
```

### Increase the maximum Task result size using sidecar logs

Documentation: https://tekton.dev/docs/pipelines/additional-configs/#enabling-larger-results-using-sidecar-logs

```shell
$ oc apply -f enable-log-access-to-controller/rbac.yaml
$ oc patch cm feature-flags -n openshift-pipelines -p '{"data":{"results-from":"sidecar-logs"}}'
$ oc patch cm feature-flags -n openshift-pipelines -p '{"data":{"max-result-size":"8192"}}'
```

This is required due to the size of the `ROX_API_TOKEN`, exceeding the default 4096 bytes.

### Enable feature flag for Enum parameters

```shell
$ oc patch cm feature-flags -n openshift-pipelines -p '{"data":{"enable-param-enum":"true"}}'
```

This allows us to perform input validation using a list of authorized values.

### Build Container images used in python steps

```shell
$ oc new-build --name python3-with-requests --binary --strategy docker
$ oc patch bc/python3-with-requests -p '{"spec":{"strategy":{"dockerStrategy":{"dockerfilePath":"Containerfile"}}}}'
$ oc start-build python3-with-requests --from-dir=./python-with-requests --follow
```

The image is now available in the internal registry `image-registry.openshift-image-registry.svc:5000/default/python3-with-requests:latest`.

It is used in steps that run Python code and require the `requests` module.

## Usage

Start a pipeline run either via CLI or via Manifest file

### `tkn` CLI

```shell
$ export CLOUD_ACCOUNT_ID="REPLACE_ME"
$ export ROX_TOKEN_SECRET="rhacs-rox-api-token-$(date +%s)"
$ tkn pipeline start rhacs \
  -n default \
  --param images=registry.redhat.io/rhel9/python-312:9.6,registry.redhat.io/ubi9/ubi-minimal:latest \
  --param rox-api-token-secret-name="$ROX_TOKEN_SECRET" \
  --param service-account-creds-secret=rh-openid-credentials \
  --param registry-redhat-creds-secret=registry-redhat-credentials \
  --param cloud-account-id=$CLOUD_ACCOUNT_ID \
  --param central-aws-region=eu-west-1 \
  --param existing-central-id="" \
  --param destroy-central=true \
  -w name=bin,volumeClaimTemplateFile=./pipeline/pvc-template.yaml \
  -w name=rox-api-token-auth,secret="$ROX_TOKEN_SECRET" \
  -w name=scan-results,volumeClaimTemplateFile=./pipeline/pvc-template.yaml \
  --pipeline-timeout 2h \
  --showlog
```

`authenticate-central` creates a Secret (default name `rhacs-rox-api-token`, key `rox_api_token`) and the `rox-api-token-auth` workspace must be bound to that same Secret name (see catalog [API token example](https://artifacthub.io/packages/tekton-task/tekton-catalog-tasks/rhacs-image-scan/)). Use a unique `rox-api-token-secret-name` per concurrent PipelineRun so runs do not overwrite each other's token.

Set `--param destroy-central=false` if you want to keep the deployed Central around for debugging or later use.

Set `--param existing-central-id=<CENTRAL_ID>` to reuse an existing Central. In that mode, no new Central is created, and the finally cleanup step will not delete that existing Central.

### Apply PipelineRun YAML

This is an alternative to the `tkn` CLI.

```yaml
apiVersion: tekton.dev/v1
kind: PipelineRun
metadata:
  name: my-rhacs-run
  namespace: default
spec:
  pipelineRef:
    name: rhacs
  params:
  - name: central-aws-region
    value: eu-west-1
  - name: cloud-account-id
    value: "REPLACE_ME"
  - name: images
    value:
      - registry.redhat.io/rhel9/python-312:9.6
      - registry.redhat.io/ubi9/ubi-minimal:latest
  - name: service-account-creds-secret
    value: rh-openid-credentials
  - name: registry-redhat-creds-secret
    value: registry-redhat-credentials
  - name: existing-central-id
    value: ""
  - name: destroy-central
    value: "true"
  - name: rox-api-token-secret-name
    value: my-rhacs-run-rox-api-token
  timeouts:
    pipeline: 2h0m0s
  workspaces:
    - name: bin
      volumeClaimTemplate:
        spec:
          accessModes: ["ReadWriteOnce"]
          resources:
            requests:
              storage: 1Gi
          storageClassName: gp3-csi
          volumeMode: Filesystem
    - name: rox-api-token-auth
      secret:
        secretName: my-rhacs-run-rox-api-token
    - name: scan-results
      volumeClaimTemplate:
        spec:
          accessModes: ["ReadWriteOnce"]
          resources:
            requests:
              storage: 1Gi
          storageClassName: gp3-csi
          volumeMode: Filesystem
```

`rox-api-token-secret-name` and `rox-api-token-auth.secret.secretName` must match.

Apply and view logs:

```bash
oc apply -f run-rhacs-pr.yaml -n default
tkn pipelinerun logs -f rhacs-cli -n default
```

## Accessing Scan Results

The vulnerability scan results are saved in both JSON and CSV formats to the `scan-results` workspace. When scanning multiple images via matrix (parallel execution), each image produces uniquely named files to prevent overwriting:

- `scan-results-<image-name>.json` - Raw RHACS scan output (for debugging and detailed analysis)
- `scan-results-<image-name>.csv` - Converted format for Analyzer tools with columns: `cve_id`, `package`, `package_ve`, `rh_severity`, `rh_cvss`, `container`, `container_tag`, `advisory`

Where `<image-name>` is the image name with registry prefix removed and special characters replaced with hyphens for safe filenames.

To access the results after a pipeline run:

```bash
# Find the scan-results PVC
oc get pvc | grep scan-results

# Create a temporary pod to access the files
oc run results-viewer --image=registry.access.redhat.com/ubi9/ubi-minimal --rm -it --restart=Never \
  --overrides='{"spec":{"containers":[{"name":"results-viewer","image":"registry.access.redhat.com/ubi9/ubi-minimal","command":["sleep","3600"],"volumeMounts":[{"mountPath":"/results","name":"scan-results"}]}],"volumes":[{"name":"scan-results","persistentVolumeClaim":{"claimName":"<pvc-name>"}}]}}'

# Inside the pod, view the results
ls -la /results/
cat /results/scan-results-*.csv
head /results/scan-results-*.json

# Example: if scanning "registry.redhat.io/ubi9/ubi-minimal:latest"
# Files would be: scan-results-ubi9-ubi-minimal-latest.json and scan-results-ubi9-ubi-minimal-latest.csv
```
