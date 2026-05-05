# Vulnerability scanner certification pipeline for RHACS

## Pre-requisites 

- Deploy OCP cluster (requirements TBD)
- Create Service Account on RedHat SSO
- Create Kubernetes Secret in OCP cluster containing Client ID and Secret ID
- Install OpenShift Pipelines operator (Tekton)
- Install Tasks and Pipeline definitions:

```bash
oc apply -f tasks/
oc apply -f pipeline/
```


