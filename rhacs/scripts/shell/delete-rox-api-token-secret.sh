#!/bin/sh
set -eu
oc delete secret "${ROX_API_TOKEN_SECRET_NAME}" \
  --namespace="${TASK_RUN_NAMESPACE}" \
  --ignore-not-found=true
