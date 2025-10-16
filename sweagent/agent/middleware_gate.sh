#!/usr/bin/env bash
set -euo pipefail

# Repo root (defaults to current)
REPO_ROOT="${REPO_ROOT:-$PWD}"
cd "$REPO_ROOT"

# Try to compute the changed Python files (SWE-bench runners often provide a base SHA)
BASE_REF="${SWE_BASE_REF:-${SWE_BENCH_BASE_SHA:-${BASE_REF:-}}}"

if [[ -n "${BASE_REF}" ]]; then
  mapfile -t CHANGED < <(git diff --name-only "${BASE_REF}...HEAD" -- '*.py' || true)
else
  # Fallback: last commit; if nothing, fall back to all tracked *.py (conservative)
  mapfile -t CHANGED < <(git diff --name-only HEAD~1 -- '*.py' || true)
  if [[ "${#CHANGED[@]}" -eq 0 ]]; then
    mapfile -t CHANGED < <(git ls-files '*.py' || true)
  fi
fi

# If nothing changed, still run (engine will no-op); ensures outputs exist.
echo "Static-analysis files: ${#CHANGED[@]} file(s)"

POLICY_FILE="${POLICY_FILE:-Policies.yaml}"
OUT_JSON="${OUT_JSON:-violations.json}"
OUT_YAML="${OUT_YAML:-violations.yaml}"
LLM_FEEDBACK="${LLM_FEEDBACK:-.middleware_feedback.md}"

REAL_TEST_CMD="CONTAINER_ID=\$(docker ps  --format \"{{.Names}}\" | head -n 1) && docker cp \$CONTAINER_ID:/testbed ./testbed-local && pytest -c /dev/null /home/tianpei/IdeaProjects/SWE-agent/testbed-local/"
#REAL_TEST_CMD="ls"
# Run the engine (gate on ERROR/HIGH)
set +e
python policy_engine.py \
  --policies "${POLICY_FILE}" \
  --files "${CHANGED[@]}" \
  --gate \
  --llm-feedback "${LLM_FEEDBACK}" \
  --out-json "${OUT_JSON}" \
  --out-yaml "${OUT_YAML}"
STATUS=$?
set -e

if [[ "${STATUS}" -ne 0 ]]; then
  echo
  echo "===== STATIC ANALYSIS (BLOCKING) ====="
  if [[ -s "${LLM_FEEDBACK}" ]]; then
    sed -n '1,200p' "${LLM_FEEDBACK}" || true
  else
    echo "Blocking issues detected; see ${OUT_JSON} / ${OUT_YAML}"
  fi
  echo "===== END STATIC ANALYSIS ====="
  # Non-zero so SWE-Agent treats this as a failed test loop and attempts a fix
  exit 1
fi

# If clean, pass through to the real test command
exec bash -lc "${REAL_TEST_CMD}"