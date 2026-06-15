#!/usr/bin/env bash
# Shared CI helpers — source from scripts under .github/workflows/ci/

set -euo pipefail

ci_init_paths() {
  CI_SHARED="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  CI_ROOT="$(cd "$CI_SHARED/.." && pwd)"
  WORKFLOWS_DIR="$(cd "$CI_ROOT/.." && pwd)"
  REPO_ROOT="$(cd "$WORKFLOWS_DIR/../.." && pwd)"
}

# True when running under a Windows POSIX layer (Git Bash / MSYS / Cygwin).
ci_is_windows() {
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) return 0 ;;
    *)                    return 1 ;;
  esac
}

# Prints the GNU make command name for this OS. 'make' is GNU make on Linux,
# but BSD make on the *BSDs/Solaris and absent on Windows runners (only
# Strawberry Perl's gmake), so those need 'gmake'.
ci_default_make_cmd() {
  case "$(uname -s)" in
    *BSD|DragonFly|SunOS)  echo "gmake" ;;
    MINGW*|MSYS*|CYGWIN*)  echo "gmake" ;;
    *)                     echo "make"  ;;
  esac
}

# Download $1 (URL) to $2 (output path) with whatever fetcher exists.
# curl covers Linux/macOS/Windows; fetch is the FreeBSD/DragonFly base tool
# (survives pkg upgrades that drop the curl package); wget is the middle option.
ci_download() {
  local url="$1" out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fL --retry 5 --retry-delay 5 --retry-all-errors -o "$out" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget --tries=5 --retry-connrefused -O "$out" "$url"
  elif command -v fetch >/dev/null 2>&1; then
    fetch -a -o "$out" "$url"
  else
    echo "ci_download: no curl/wget/fetch available" >&2
    return 1
  fi
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

# Run fpc with an -i* info flag; retry when stdout is empty (QEMU/subprocess flake).
# Tuning: CI_FPC_PROBE_ATTEMPTS (default 3), CI_FPC_PROBE_DELAY_SECS (default 2).
# Prints the probe value to stdout; diagnostics go to stderr.
ci_fpc_info_probe() {
  local flag="$1"
  local max_attempts="${CI_FPC_PROBE_ATTEMPTS:-3}"
  local delay="${CI_FPC_PROBE_DELAY_SECS:-2}"
  local attempt=1 value

  while [ "$attempt" -le "$max_attempts" ]; do
    value="$(fpc "$flag" 2>/dev/null | head -1 | tr -d '\r\n' || true)"
    if [ -n "$value" ]; then
      if [ "$attempt" -gt 1 ]; then
        echo "fpc ${flag} succeeded on attempt ${attempt}/${max_attempts}" >&2
      fi
      printf '%s\n' "$value"
      return 0
    fi
    if [ "$attempt" -lt "$max_attempts" ]; then
      echo "::warning::fpc ${flag} returned empty (attempt ${attempt}/${max_attempts}), retrying..." >&2
      sleep "$delay"
    fi
    attempt=$((attempt + 1))
  done
  echo "::error::fpc ${flag} returned empty after ${max_attempts} attempts" >&2
  return 1
}

# Prints a C compiler path to stdout; returns 1 if none found.
ci_find_c_compiler() {
  local c
  for c in cc gcc g++; do
    if command -v "$c" >/dev/null 2>&1; then
      command -v "$c"
      return 0
    fi
  done
  for c in /usr/bin/gcc /usr/sfw/bin/gcc /opt/csw/bin/gcc /usr/gcc/*/bin/gcc; do
    if [ -x "$c" ]; then
      printf '%s\n' "$c"
      return 0
    fi
  done
  return 1
}

# Prints little | big | unknown to stdout (for capture).
ci_runtime_endian() {
  local shared_dir probe_src tmp value="unknown" cc_cmd

  shared_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  probe_src="${shared_dir}/runtime-endian-probe.c"

  cc_cmd="$(ci_find_c_compiler 2>/dev/null || true)"

  if [ -n "$cc_cmd" ] && [ -f "$probe_src" ]; then
    tmp="$(mktemp /tmp/ci-runtime-endian.XXXXXX 2>/dev/null || true)"
    if [ -z "$tmp" ]; then
      tmp="$(mktemp -t ci-runtime-endian 2>/dev/null || true)"
    fi
    if [ -n "$tmp" ]; then
      if "$cc_cmd" -O2 -o "$tmp" "$probe_src" 2>/dev/null; then
        value="$("$tmp" 2>/dev/null | tr -d '\r\n' || true)"
        case "$value" in
          little|big) ;;
          *) value="unknown" ;;
        esac
      fi
      rm -f "$tmp"
    fi
  fi

  printf '%s\n' "$value"
}

ci_preflight() {
  local tp to endian target

  ci_fpc_info_probe -iV
  tp="$(ci_fpc_info_probe -iTP)" || exit 1
  to="$(ci_fpc_info_probe -iTO)" || exit 1
  endian="$(ci_runtime_endian)"
  target="${tp}-${to}"
  echo "preflight: target=${target} endian=${endian}"
  if [ "$endian" = "unknown" ]; then
    echo "::warning::runtime endian probe returned unknown (no usable C compiler or probe failed)" >&2
  fi
  if command -v lazbuild >/dev/null 2>&1; then
    lazbuild --version
  fi
}

ci_run_make() {
  if command -v instantfpc >/dev/null 2>&1; then
    instantfpc "$WORKFLOWS_DIR/make.pas"
    return
  fi
  # Some FPC tarballs (notably the reduced x86_64-dragonfly cross build) ship
  # fpc but omit the instantfpc helper. instantfpc just compiles+runs a .pas
  # program, so do that directly with fpc instead. -FE/-FU keep build artifacts
  # in a temp dir; fpc reads the same fpc.cfg, so units resolve identically.
  local build_dir
  build_dir="$(mktemp -d 2>/dev/null || mktemp -d -t ci-make)"
  fpc -FE"$build_dir" -FU"$build_dir" -omake "$WORKFLOWS_DIR/make.pas"
  "$build_dir/make"
}

ci_build_standard() {
  ci_install_toolchain
  ci_export_toolchain_path
  ci_preflight
  ci_run_make
}

# Build when the toolchain is already installed (e.g. a distro/pkg FPC).
# Skips ci_install_toolchain; the caller is responsible for PATH.
ci_build_prebuilt() {
  ci_preflight
  ci_run_make
}

ci_openssl_hack() {
  if ci_is_windows; then
    bash "$CI_ROOT/openssl-libssl11-shim-windows.sh"
    return
  fi
  case "$(uname -s)" in
    Linux)     bash "$CI_ROOT/openssl-libssl11-shim-unix.sh" ;;
    Darwin)    bash "$CI_ROOT/openssl-libssl11-shim-macos.sh" ;;
    DragonFly) OPENSSL_USE_SUDO=0 bash "$CI_ROOT/openssl-libssl11-shim-unix.sh" /usr/local/lib ;;
  esac
}

# Fail with a clear message unless every named .deb is fully installed and
# configured ("install ok installed" per dpkg-query). POSIX sh: no arrays, since
# common.sh is also sourced under /bin/sh on the VM targets.
ci_require_dpkg_installed() {
  local pkg status missing=""
  for pkg in "$@"; do
    status="$(dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null || true)"
    [ "$status" = "install ok installed" ] || missing="$missing $pkg"
  done
  if [ -n "$missing" ]; then
    echo "::error::required packages not installed/configured:$missing" >&2
    exit 1
  fi
}

ci_debian_container_bootstrap() {
  export DEBIAN_FRONTEND=noninteractive
  # Base packages this build container needs, plus any caller-specified extras.
  # Built via positional params (set --) to stay POSIX sh compatible (no arrays).
  set -- curl ca-certificates git build-essential openssl "$@"

  apt-get update

  # Some Debian-ports sid rootfs images ship systemd (and its dependents) in an
  # unconfigured state, and its maintainer script can crash under QEMU user-mode
  # ("stack smashing detected"), making apt-get return non-zero. None of those
  # packages are needed to build FPC/Lazarus console apps, and nothing later in
  # the flow re-runs apt/dpkg (the FPC/Lazarus install builds from source). So we
  # do not let that abort the job; instead we require that the packages we
  # actually need ended up installed and configured.
  local apt_rc=0
  apt-get install -y "$@" || apt_rc=$?
  if [ "$apt_rc" -ne 0 ]; then
    echo "::warning::apt-get install exited $apt_rc; a non-essential package likely failed to configure (e.g. systemd under QEMU). Verifying required packages." >&2
  fi

  ci_require_dpkg_installed "$@"

  OPENSSL_USE_SUDO=0 bash "$CI_ROOT/openssl-libssl11-shim-unix.sh" "${OPENSSL_ARCH_DIR:-}"
}

ci_github_path_append() {
  local dir="$1"
  [ -n "${GITHUB_PATH:-}" ] || return 0
  # GITHUB_PATH expects native Windows paths (C:\foo), not MSYS (/c/foo).
  if ci_is_windows; then
    cygpath -w "$dir" >> "$GITHUB_PATH"
  else
    echo "$dir" >> "$GITHUB_PATH"
  fi
}

ci_write_lazarus_environmentoptions() {
  local laz_dir="$1"
  local fpc_exe="$2"
  local laz_cfg_dir laz_dir_native fpc_exe_native

  if ci_is_windows; then
    local win_local="${LOCALAPPDATA:-$USERPROFILE/AppData/Local}"
    laz_cfg_dir="$(cygpath -u "$win_local")/lazarus"
    laz_dir_native="$(cygpath -w "$laz_dir")"
    fpc_exe_native="$(cygpath -w "$fpc_exe")"
  else
    laz_cfg_dir="${HOME}/.lazarus"
    laz_dir_native="$laz_dir"
    fpc_exe_native="$fpc_exe"
  fi

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
