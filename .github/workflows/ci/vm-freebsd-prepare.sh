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

# TODO(FPC 3.2.4): remove the interim path; use pkg-installed FPC until the
# FPC 3.2.4 dist tarball works on FreeBSD 15+ (see vm-freebsd-run.sh).
freebsd_pkg_bootstrap
pkg install -y bash fpc git wget gmake

# Only build Lazarus/lazbuild when the lazbuild backend needs it. With the fpc
# backend make.pas never invokes lazbuild, so skip the ~1-2 min clone+build
# (mirrors install-fpc-lazarus.sh, which gates Lazarus on the same var).
if [ "${MAKE_BUILD_BACKEND:-fpc}" = "lazbuild" ]; then
  export FPC_EXE="$(which fpc)"
  export LAZARUS_DIR="$HOME/lazarus-src"
  # shellcheck source=shared/lazarus-bootstrap.sh
  . "$CI_ROOT/shared/lazarus-bootstrap.sh"
else
  echo "MAKE_BUILD_BACKEND=fpc - interim mode: pkg fpc only, skipping Lazarus/lazbuild build"
fi
