#!/bin/sh
# FreeBSD VM prepare — see FREEBSD_INSTALL_MODE (interim|preferred).
# Invoked with /bin/sh (bash is not installed until this script runs).
set -eu

: "${FREEBSD_INSTALL_MODE:?FREEBSD_INSTALL_MODE is required (interim|preferred)}"

CI_ROOT="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=shared/common.sh
. "$CI_ROOT/shared/common.sh"

if [ "$FREEBSD_INSTALL_MODE" = "preferred" ]; then
  freebsd_pkg_bootstrap
  pkg install -y bash curl git gmake binutils
  exit 0
fi

# INTERIM: pkg-installed FPC until FPC 3.2.4 dist tarball works on FreeBSD 15+.
freebsd_pkg_bootstrap
pkg install -y bash fpc git wget gmake

export FPC_EXE="$(which fpc)"
export LAZARUS_DIR="$HOME/lazarus-src"
# shellcheck source=shared/lazarus-bootstrap.sh
. "$CI_ROOT/shared/lazarus-bootstrap.sh"
