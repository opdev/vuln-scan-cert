#!/bin/sh
set -eu
oc create secret generic "${ROX_API_TOKEN_SECRET_NAME}" \
  --namespace="${TASK_RUN_NAMESPACE}" \
  --from-literal=rox_api_token="${ROX_API_TOKEN}" \
  --dry-run=client -o yaml | oc apply -f -
printf '%s' "${ROX_API_TOKEN_SECRET_NAME}" > "${STEP_RESULT_PATH}"
printf '%s' "${ROX_API_TOKEN_SECRET_NAME}" > "${TASK_RESULT_PATH}"
