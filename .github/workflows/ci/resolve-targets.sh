#!/usr/bin/env bash
set -euo pipefail

# Stable targets run on every push/PR (DEFAULT). Opt-in targets (netbsd,
# dragonflybsd) are excluded from DEFAULT — pass them explicitly via
# workflow_dispatch enabled_targets.
STABLE_TARGETS="linux-arm32,linux-powerpc64-be,linux-x64,linux-arm64,windows-x64,macos-arm64,macos-x64,freebsd,solaris"
OPT_IN_TARGETS="netbsd,dragonflybsd"
VALID_TARGETS="${STABLE_TARGETS},${OPT_IN_TARGETS}"
DEFAULT="$STABLE_TARGETS"

if [ -z "${INPUT_TARGETS// /}" ]; then
  TARGETS="$DEFAULT"
  SOURCE="default"
else
  TARGETS="${INPUT_TARGETS// /}"
  SOURCE="workflow_dispatch input"
fi

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

echo "enabled_targets=${TARGETS}" >> "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
echo "Enabled targets (${SOURCE}): ${TARGETS}"
