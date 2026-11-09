# AGENTS.md

Living context for AI coding agents working in this repo. Also read by humans.
Keep it current — stale context makes agents worse, not better.
(Compatible with Claude Code `CLAUDE.md`, Cursor, and other tools that load `AGENTS.md`.)

## What this repo is

`vuln-scan-cert` is the **vulnerability-scanner certification pipeline for scanners such as RHACS**
(Red Hat Advanced Cluster Security / StackRox). It is **infrastructure-as-code, not
an application**: a Tekton pipeline that provisions a managed scanner Centrals, scans
container images for CVEs, exports results, and (optionally) tears the Central down.

The deliverable is itself a **security tool that handles credentials** — treat
security practices here as required, not optional. See `THREAT_MODEL.md`.

## Repository access hints (machine-readable)

```yaml
# Convention: wg-agentic-sdlc "repository access hints for AI agents".
# Tells an agent which tooling/auth to use to reach this repo.
platform: github
upstream: github.com/opdev/vuln-scan-cert      # canonical repo (public)
visibility: public                             # repo is public
cli: gh                                        # use gh for PRs/issues
target_platform: openshift                     # runtime is OCP + OpenShift Pipelines (Tekton)
runtime_cli: [oc, tkn, kubectl, kustomize]     # CLI tools for runtime
```

## Layout

### `rhacs/`
- `rhacs/tasks/*.yaml` — Tekton Tasks. Pipeline order:
  `provision-central` → `authenticate-central` → `configure-central` →
  `wait-for-scanner-init` → `rhacs-image-scan` → (`finally`) `destroy-central`.
- `rhacs/pipeline/rhacs.yaml` — the `rhacs` Pipeline + `pvc-template.yaml`.
- `rhacs/scripts/python/*.py` — ROX/OCM API glue over `requests`. Reads config from
  env vars, writes Tekton results to `$STEP_RESULT_PATH` / `$TASK_RESULT_PATH`.
- `rhacs/scripts/shell/*.sh` — install/verify `roxctl` & `ocm`, token helpers, scan.
- `rhacs/kustomization.yaml` — **single source of truth**. Scripts are bundled into
  two ConfigMaps (`rhacs-shell-scripts`, `rhacs-python-scripts`) via
  `configMapGenerator`. There are **no separate ConfigMap YAMLs** — do not create any.
- `rhacs/python-with-requests/Containerfile` — image for Python steps needing `requests`.
- `rhacs/*-credentials/*.template.yaml` — Secret templates rendered with `envsubst`.

## How to make changes

- **Add/modify a script**: edit the file under `scripts/{shell,python}/`. If it is a
  *new* file, also add its path to the matching `configMapGenerator` entry in
  `kustomization.yaml`. Preview changes with `kubectl kustomize rhacs/`. A human must
  run `oc apply -k rhacs/ -n <pipeline-namespace>` after approval.
- **Change a Task**: edit `rhacs/tasks/<name>.yaml`. Tasks mount the ConfigMaps and run
  scripts via `command:`.
- Prefer the smallest diff that routes through the shared script/task — don't patch one
  caller and leave siblings broken.

## Verify loop (definition of done)

```bash
make lint          # ruff check + ruff format --check + yamllint
make format        # auto-fix ruff + yamlfmt (run before committing)
```

- Python: 3.14, managed with `uv`. Ruff line-length 120, double quotes, rules `E,F,W,I,UP`.
- Pre-commit hooks enforce trailing-whitespace, EOF, yaml/json checks, ruff, yamlfmt,
  yamllint. Run `make install-hooks` once.
- There are **no unit tests yet**. If you touch non-trivial Python logic (e.g.
  `json-to-csv.py` parsing), add a minimal `pytest`/assert self-check alongside it.

## Conventions & boundaries

- **The pipeline lives in a dedicated, non-system namespace** (never `default`, `kube-*`,
  or `openshift`): OpenShift SCC admission does not assign SELinux labels to pods in
  system namespaces, so every pod gets a random MCS label from the container runtime and
  concurrently-running TaskRuns sharing a workspace PVC race to relabel it (symptom:
  `Permission denied`, exit 126). The `python3-with-requests` image must be built in that
  same namespace — Tasks reference it via `$(context.taskRun.namespace)`. See
  `rhacs/README.md` ("Create a dedicated namespace").
- **Secrets never go in code, logs, or committed files.** Credentials come from
  Kubernetes Secrets / env vars only. `*.template.yaml` files hold placeholders, not values.
- Do not weaken TLS/download verification. Downloaded binaries (`roxctl`, `ocm`) must be
  checksum-verified — see `checksum-roxctl.sh` and `THREAT_MODEL.md` (T-01).
- Do not edit `destroy-central` behavior or credential templates without explicit human review.
- `oc`/`tkn`/`kustomize` commands run against live clusters — describe them, let a human run
  them, don't execute against a real cluster on your own.

## Related projects (wg-agentic-sdlc expectation — fill in)

Before generating net-new tooling, check for overlap with existing RHACS/StackRox and
Global Engineering scanning efforts and link the closest ones here with a one-line overlap note.
