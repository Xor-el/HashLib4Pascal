#!/usr/bin/env bash
set -euo pipefail

: "${FPC_TARGET:?FPC_TARGET is required}"

# shellcheck source=shared/common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/shared/common.sh"
ci_init_paths

if [ -n "${LD_LIBRARY_PATH_EXTRA:-}" ]; then
  export LD_LIBRARY_PATH="${LD_LIBRARY_PATH_EXTRA}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi

ci_build_standard
