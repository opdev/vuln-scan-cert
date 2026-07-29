#!/bin/sh
set -eu

./ocm login --client-id "${CLIENT_ID}" --client-secret "${CLIENT_SECRET}"
token="$(./ocm token)"
printf '%s' "${token}" > "${STEP_RESULT_PATH}"
if [ -n "${TASK_RESULT_PATH:-}" ]; then
  printf '%s' "${token}" > "${TASK_RESULT_PATH}"
fi
