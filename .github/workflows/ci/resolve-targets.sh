#!/usr/bin/env bash
set -euo pipefail

# Resolve which targets CI should run, from the registry in targets.json.
#
# Inputs:
#   INPUT_TARGETS  workflow_dispatch CSV. Empty => default set (default=true).
# Outputs (GITHUB_OUTPUT):
#   enabled_targets  CSV of selected ids; gates the qemu/vm jobs in make.yml.
#   native_matrix    JSON array of enabled kind=native entries; consumed as the
#                    native job's strategy.matrix.include (empty => job skipped).
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

# Filter the registry to enabled native entries. Bind .id before switching the
# pipe context to the split list; index() returns null when absent (falsy) and
# an integer otherwise (0 is truthy in jq).
NATIVE_MATRIX="$(jq -c --arg ids "$TARGETS" \
  '[.targets[] | select(.kind == "native") | select(.id as $i | ($ids | split(",") | index($i)))]' \
  "$REGISTRY")"

# Never emit an empty matrix: GitHub renders the literal `${{ matrix.name }}`
# for a job skipped via an empty matrix. A single placeholder keeps the matrix
# valid; the native job no-ops it via `matrix.fpc_target != 'none'`.
if [ "$NATIVE_MATRIX" = "[]" ]; then
  NATIVE_MATRIX='[{"name":"Native: (no targets selected)","runner":"ubuntu-latest","fpc_target":"none"}]'
fi

{
  echo "enabled_targets=${TARGETS}"
  echo "native_matrix=${NATIVE_MATRIX}"
} >> "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"

echo "Enabled targets (${SOURCE}): ${TARGETS}"
echo "Native matrix: ${NATIVE_MATRIX}"
