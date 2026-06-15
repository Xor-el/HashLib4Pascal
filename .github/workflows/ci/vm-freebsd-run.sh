#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=shared/common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/shared/common.sh"
ci_init_paths

: "${FREEBSD_INSTALL_MODE:?FREEBSD_INSTALL_MODE is required (interim|preferred)}"

if [ "$FREEBSD_INSTALL_MODE" = "preferred" ]; then
  ci_build_standard
else
  # TODO(FPC 3.2.4): remove the interim path once the FreeBSD 15+ dist tarball
  # installs cleanly. Until then the toolchain is pkg-installed in prepare, so
  # build against it directly without re-running the installer.
  #
  # lazarus-src exists only when the lazbuild backend built it in prepare; the
  # pkg-installed fpc is already on PATH, so only prepend it when present.
  if [ -d "$HOME/lazarus-src" ]; then
    export PATH="$HOME/lazarus-src:$PATH"
  fi
  ci_build_prebuilt
fi
