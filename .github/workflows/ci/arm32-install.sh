#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=shared/common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/shared/common.sh"
ci_init_paths

export OPENSSL_ARCH_DIR=/usr/lib/arm-linux-gnueabihf
ci_debian_container_bootstrap
