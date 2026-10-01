#!/bin/sh
set -eu

./ocm login --client-id "${CLIENT_ID}" --client-secret "${CLIENT_SECRET}"
token="$(./ocm token)"
# Hand the token to downstream steps/tasks via a file on a shared workspace instead of a
# Tekton result (results are persisted in TaskRun status / Tekton Results storage).
(umask 077; printf '%s' "${token}" > "${OCM_TOKEN_FILE}")
