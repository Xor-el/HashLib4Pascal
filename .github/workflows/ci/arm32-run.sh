#!/usr/bin/env bash
set -euo pipefail

CI_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# run-on-arch-action `install` runs at docker build time (no repo mount).
# Install deps here in `run` so arm32-install.sh stays the single source of truth.
bash "$CI_ROOT/arm32-install.sh"

# shellcheck source=shared/common.sh
source "$CI_ROOT/shared/common.sh"
ci_init_paths

ci_build_standard
