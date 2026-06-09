#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=shared/common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/shared/common.sh"
ci_init_paths

export OPENSSL_ARCH_DIR=/usr/lib/powerpc64-linux-gnu
ci_debian_container_bootstrap gcc binutils
ci_build_standard
