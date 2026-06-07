#!/usr/bin/env bash
# Shared CI helpers — source from scripts under .github/workflows/ci/

set -euo pipefail

ci_init_paths() {
  CI_SHARED="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  CI_ROOT="$(cd "$CI_SHARED/.." && pwd)"
  WORKFLOWS_DIR="$(cd "$CI_ROOT/.." && pwd)"
  REPO_ROOT="$(cd "$WORKFLOWS_DIR/../.." && pwd)"
}

ci_install_toolchain() {
  : "${FPC_TARGET:?FPC_TARGET is required}"
  bash "$WORKFLOWS_DIR/install-fpc-lazarus.sh"
}

ci_export_toolchain_path() {
  local prefix="${INSTALL_PREFIX:-$HOME/fpc-install}"
  export PATH="${LAZARUS_DIR:-$HOME/lazarus-src}:$prefix/bin:${PATH}"
  if [ -n "${FPC_TARGET:-}" ] && [ -d "$prefix/bin/$FPC_TARGET" ]; then
    export PATH="$prefix/bin/$FPC_TARGET:$PATH"
  fi
}

ci_verify_toolchain() {
  fpc -iV
  if [ -n "${FPC_TARGET:-}" ]; then
    echo "::notice::FPC_TARGET=${FPC_TARGET}"
  fi
  if command -v lazbuild >/dev/null 2>&1; then
    lazbuild --version
  fi
}

ci_run_make() {
  instantfpc "$WORKFLOWS_DIR/make.pas"
}

ci_build_standard() {
  ci_install_toolchain
  ci_export_toolchain_path
  ci_verify_toolchain
  ci_run_make
}

ci_openssl_hack() {
  case "$(uname -s)" in
    Linux)     bash "$CI_ROOT/openssl-libssl11-shim-unix.sh" ;;
    Darwin)    bash "$CI_ROOT/openssl-libssl11-shim-macos.sh" ;;
    DragonFly) OPENSSL_USE_SUDO=0 bash "$CI_ROOT/openssl-libssl11-shim-unix.sh" /usr/local/lib ;;
  esac
}

ci_debian_container_bootstrap() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y curl ca-certificates git build-essential openssl "$@"
  OPENSSL_USE_SUDO=0 bash "$CI_ROOT/openssl-libssl11-shim-unix.sh" "${OPENSSL_ARCH_DIR:-}"
}

ci_github_path_append() {
  local dir="$1"
  [ -n "${GITHUB_PATH:-}" ] || return 0
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
      cygpath -w "$dir" >> "$GITHUB_PATH"
      ;;
    *)
      echo "$dir" >> "$GITHUB_PATH"
      ;;
  esac
}

ci_write_lazarus_environmentoptions() {
  local laz_dir="$1"
  local fpc_exe="$2"
  local laz_cfg_dir laz_dir_native fpc_exe_native

  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
      local win_local="${LOCALAPPDATA:-$USERPROFILE/AppData/Local}"
      laz_cfg_dir="$(cygpath -u "$win_local")/lazarus"
      laz_dir_native="$(cygpath -w "$laz_dir")"
      fpc_exe_native="$(cygpath -w "$fpc_exe")"
      ;;
    *)
      laz_cfg_dir="${HOME}/.lazarus"
      laz_dir_native="$laz_dir"
      fpc_exe_native="$fpc_exe"
      ;;
  esac

  mkdir -p "$laz_cfg_dir"
  cat > "$laz_cfg_dir/environmentoptions.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<CONFIG>
  <EnvironmentOptions>
    <LazarusDirectory Value="$laz_dir_native"/>
    <CompilerFilename Value="$fpc_exe_native"/>
  </EnvironmentOptions>
</CONFIG>
EOF
}

freebsd_pkg_bootstrap() {
  export ASSUME_ALWAYS_YES=yes
  export IGNORE_OSVERSION=yes
  pkg bootstrap -f
  pkg upgrade -Fqy || true
  pkg update -f
  pkg upgrade -y
}
