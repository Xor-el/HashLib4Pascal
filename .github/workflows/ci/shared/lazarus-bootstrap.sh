#!/usr/bin/env bash
# Clone Lazarus, build lazbuild, write environmentoptions.xml, update PATH.
# Source common.sh first: uses ci_default_make_cmd, ci_is_windows,
# ci_write_lazarus_environmentoptions, ci_github_path_append.

set -euo pipefail

: "${LAZARUS_BRANCH:?LAZARUS_BRANCH is required}"
: "${LAZARUS_REPO:?LAZARUS_REPO is required}"
: "${FPC_EXE:?FPC_EXE is required (path to fpc binary for environmentoptions.xml)}"

: "${LAZARUS_DIR:=$HOME/lazarus-src}"

: "${MAKE_CMD:=$(ci_default_make_cmd)}"

git clone --depth 1 --branch "$LAZARUS_BRANCH" "$LAZARUS_REPO" "$LAZARUS_DIR"

if [ "$(uname -s)" = "DragonFly" ]; then
  df_inc="$LAZARUS_DIR/ide/packages/ideconfig/include/dragonfly"
  if [ ! -f "$df_inc/lazconf.inc" ]; then
    mkdir -p "$df_inc"
    cp "$LAZARUS_DIR/ide/packages/ideconfig/include/freebsd/lazconf.inc" \
       "$df_inc/lazconf.inc"
  fi
fi

if ci_is_windows; then
  "$MAKE_CMD" -C "$(cygpath -w "$LAZARUS_DIR")" lazbuild
else
  "$MAKE_CMD" -C "$LAZARUS_DIR" lazbuild
fi

ci_write_lazarus_environmentoptions "$LAZARUS_DIR" "$FPC_EXE"

export PATH="$LAZARUS_DIR:$PATH"
ci_github_path_append "$LAZARUS_DIR"

lazbuild --version

if [ "${MAKE_BUILD_BACKEND:-}" = "fpc" ]; then
  echo "MAKE_BUILD_BACKEND=fpc — lazbuild was built but make.pas will use the fpc backend"
fi
