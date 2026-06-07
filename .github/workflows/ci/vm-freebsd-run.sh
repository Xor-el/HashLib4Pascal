#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=shared/common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/shared/common.sh"
ci_init_paths

: "${FREEBSD_INSTALL_MODE:?FREEBSD_INSTALL_MODE is required (interim|preferred)}"

if [ "$FREEBSD_INSTALL_MODE" = "preferred" ]; then
  ci_build_standard
else
  export PATH="$HOME/lazarus-src:$PATH"
  ci_preflight
  ci_run_make
fi
