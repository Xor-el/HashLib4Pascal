#!/usr/bin/env bash
set -euo pipefail

# Resolve which targets CI should run, from the registry in targets.json.
#
# Inputs:
#   INPUT_TARGETS  workflow_dispatch CSV. Empty => default set (default=true).
# Outputs (GITHUB_OUTPUT):
#   enabled_targets  CSV of selected ids; gates every job in make.yml via their
#                    job-level `if: contains(...)`.
#   target_map       JSON object (id -> full target entry) over the WHOLE
#                    registry; the standalone jobs in make.yml look up their
#                    runner/fpc_target by id (independent of which are enabled).
#
# targets.json is the single source of truth. Opt-in targets (default=false,
# e.g. netbsd, dragonflybsd) are excluded from the default and must be named
# explicitly via INPUT_TARGETS.

CI_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGISTRY="$CI_ROOT/targets.json"

VALID_TARGETS="$(jq -r '[.targets[].id] | join(",")' "$REGISTRY")"
DEFAULT="$(jq -r '[.targets[] | select(.default) | .id] | join(",")' "$REGISTRY")"

if [ -z "${INPUT_TARGETS// /}" ]; then
  TARGETS="$DEFAULT"
  SOURCE="default"
else
  TARGETS="${INPUT_TARGETS// /}"
  SOURCE="workflow_dispatch input"
fi

# Warn (don't fail) on unknown ids so a typo is visible but harmless: an
# unrecognised id simply matches no job.
IFS=',' read -r -a _selected <<< "$TARGETS"
IFS=',' read -r -a _valid <<< "$VALID_TARGETS"
for _id in "${_selected[@]}"; do
  [ -z "$_id" ] && continue
  _found=0
  for _v in "${_valid[@]}"; do
    if [ "$_id" = "$_v" ]; then
      _found=1
      break
    fi
  done
  if [ "$_found" -eq 0 ]; then
    echo "::warning::Unknown target id \"${_id}\" (valid: ${VALID_TARGETS})"
  fi
done

# id -> full target entry, over the entire registry (not just enabled ids). The
# standalone jobs look up their runner/fpc_target by id, so the map must resolve
# even for a target gated off by its `if:` (avoids a null runs-on). Job names
# stay literal in make.yml: an if-skipped job renders an unevaluated name
# expression in the UI, so it cannot be sourced from here.
#
# fpc_tarball_target is optional in targets.json (only set when a platform's
# tarball filename deviates from the canonical target, e.g. x86_64-freebsd11).
# Default it to fpc_target here so every entry in the map carries a concrete,
# non-empty value: jobs can then read it directly (no per-job fallback), which
# also satisfies run-on-arch-action's requirement that env values be non-empty.
TARGET_MAP="$(jq -c '.targets | map({(.id): (. + {fpc_tarball_target: (.fpc_tarball_target // .fpc_target)})}) | add' "$REGISTRY")"

{
  echo "enabled_targets=${TARGETS}"
  echo "target_map=${TARGET_MAP}"
} >> "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"

echo "Enabled targets (${SOURCE}): ${TARGETS}"
echo "Target map: ${TARGET_MAP}"
