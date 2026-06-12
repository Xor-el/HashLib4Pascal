#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
#  Unified FPC + Lazarus installer for CI.
#
#  Fetches the FPC tarball from the official freepascal.org mirror,
#  runs install.sh non-interactively, then clones Lazarus and builds
#  lazbuild. Works on Linux, macOS, *BSD, Solaris, and Windows
#  (the latter via Git Bash, which ships pre-installed on
#  windows-latest GitHub runners).
#
#  All work happens under $HOME — no sudo, no system-level changes.
#
#  Inputs (env vars):
#    FPC_TARGET     e.g. x86_64-linux, aarch64-darwin, x86_64-win64
#    FPC_VERSION    FPC release version, e.g. 3.2.2
#    INSTALL_PREFIX where FPC is installed (default: $HOME/fpc-install)
#    LAZARUS_DIR    where Lazarus source is cloned and built
#                   (default: $HOME/lazarus-src)
#    LAZARUS_BRANCH branch/tag to clone, e.g. lazarus_4_4
#    LAZARUS_REPO   git URL
#    MAKE_CMD            'make' on Linux/Windows/macOS, 'gmake' on BSD/Solaris
#                        (auto-detected if unset)
#    MAKE_BUILD_BACKEND  lazbuild | fpc (default: fpc)
#                        fpc      — install FPC only; skip Lazarus/lazbuild
#                        lazbuild — also clone Lazarus and build lazbuild
#
#  Outputs (appended to $GITHUB_PATH if set):
#    $INSTALL_PREFIX/bin and $LAZARUS_DIR are added to PATH
# ─────────────────────────────────────────────────────────────────────

set -euo pipefail
# Opt-in command tracing (this installer is verbose); set CI_DEBUG=1 to enable.
# Match only truthy values so a flat CI_DEBUG=0 (the CI default) stays quiet.
case "${CI_DEBUG:-}" in 1|true|yes|on) set -x ;; esac

# tar (the FPC tarball extraction and install.sh's internal tars) inherits
# LANG/LC_* that some minimal VMs (notably DragonFly) point at a locale that
# isn't installed, which prints "tar: Failed to set default locale". Force the
# always-present C locale; harmless on every platform.
export LC_ALL=C LANG=C

INSTALL_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/shared/common.sh
source "$INSTALL_SCRIPT_DIR/ci/shared/common.sh"

: "${FPC_VERSION:?FPC_VERSION is required (e.g. 3.2.2)}"
: "${FPC_TARGET:?FPC_TARGET is required (e.g. x86_64-linux)}"
case "${MAKE_BUILD_BACKEND:-fpc}" in
  fpc)      INSTALL_LAZARUS=0 ;;
  lazbuild) INSTALL_LAZARUS=1 ;;
  *)
    echo "unknown MAKE_BUILD_BACKEND: $MAKE_BUILD_BACKEND (expected lazbuild|fpc)" >&2
    exit 1
    ;;
esac
if [ "$INSTALL_LAZARUS" = "1" ]; then
  : "${LAZARUS_BRANCH:?LAZARUS_BRANCH is required}"
  : "${LAZARUS_REPO:?LAZARUS_REPO is required}"
fi

if ci_is_windows; then IS_WINDOWS=1; else IS_WINDOWS=0; fi

: "${INSTALL_PREFIX:=$HOME/fpc-install}"
: "${LAZARUS_DIR:=$HOME/lazarus-src}"
# MAKE_CMD (gmake on BSD/Solaris/Windows) is defaulted by lazarus-bootstrap.sh,
# which is the only consumer; a caller-provided value propagates via sourcing.

# ── Fetch + extract ──────────────────────────────────────────────────

# Some BSD tarballs have an OS-version suffix in the filename, e.g.
# fpc-3.2.2.x86_64-freebsd11.tar. The tarball extracts to a directory
# WITHOUT the version suffix. Map our canonical FPC_TARGET to the
# actual filename here; let the post-extract glob handle the directory
# name.
case "$FPC_TARGET" in
  x86_64-freebsd)   TAR_TARGET="x86_64-freebsd11" ;;
  *)                TAR_TARGET="$FPC_TARGET"      ;;
esac

TARBALL="fpc-${FPC_VERSION}.${TAR_TARGET}.tar"
URL="http://downloads.freepascal.org/fpc/dist/${FPC_VERSION}/${FPC_TARGET}/${TARBALL}"

WORK_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t fpc-install)"
cd "$WORK_DIR"

echo "Downloading $URL"
# Prefer curl (Linux/macOS/Windows); fall back to wget, then the BSD base
# `fetch`. Retries ride out transient mirror hiccups.
ci_download "$URL" "$TARBALL"

tar xf "$TARBALL"

# Glob the extracted directory: name varies (freebsd11 → freebsd).
# shellcheck disable=SC2086
set -- "fpc-${FPC_VERSION}".*
EXTRACT_DIR="$1"
cd "$EXTRACT_DIR"

# ── Run install.sh non-interactively ─────────────────────────────────
#
# The script asks (in order, each conditional on a file being present):
#   1. Install prefix                                  [always]
#   2. Install Cross binutils?            (Y/n)        [if binutils-*.tar.gz]
#   3. Install Textmode IDE?              (Y/n)        [if ide.<target>.tar.gz]
#   4. Install documentation?             (Y/n)        [if doc-pdf.tar.gz]
#   5. Install demos?                     (Y/n)        [if demo.tar.gz]
#   6. Install demos in <dir>             [path]       [only if 5 was Y]
#   7. Substitute version by $fpcversion? (Y/n)        [if fpc.cfg has version]
#
# We answer the prefix explicitly, then 'n' to everything optional.
# install.sh's yesno() treats empty input as YES, so if our answer
# stream runs short we'd silently install bundles we don't want.
# We send 10 'n's (more than the max number of yesno prompts) to
# guarantee every prompt gets an explicit 'n'. A bounded list is
# preferable to `yes n` — the latter receives SIGPIPE on consumer
# exit, which `set -o pipefail` would surface as a pipeline failure.
mkdir -p "$INSTALL_PREFIX"

# install.sh doesn't `set -e`, so it returns 0 even when its final
# samplecfg call fails (which it does on Windows — see below). We
# verify the install succeeded by checking for the compiler binary.
printf '%s\nn\nn\nn\nn\nn\nn\nn\nn\nn\nn\n' "$INSTALL_PREFIX" \
  | bash ./install.sh

# ── Locate the installed compiler ────────────────────────────────────
#
# Layout differs between Unix and Windows:
#   Unix:    $PREFIX/bin/fpc                    (single binary)
#   Windows: $PREFIX/bin/<target>/fpc.exe       (target-specific)
#            $PREFIX/bin/instantfpc.exe         (target-independent
#                                                 utilities)
# Both directories need to be on PATH on Windows.
if [ "$IS_WINDOWS" = "1" ]; then
  FPC_EXE="$INSTALL_PREFIX/bin/$FPC_TARGET/fpc.exe"
  FPC_UTIL_DIR="$INSTALL_PREFIX/bin"
else
  FPC_EXE="$INSTALL_PREFIX/bin/fpc"
  FPC_UTIL_DIR=""
fi

if [ ! -f "$FPC_EXE" ]; then
  echo "ERROR: FPC compiler not found at $FPC_EXE" >&2
  ls -la "$INSTALL_PREFIX/bin/" || true
  if [ "$IS_WINDOWS" = "1" ]; then
    ls -la "$INSTALL_PREFIX/bin/$FPC_TARGET/" || true
  fi
  exit 1
fi

FPC_BIN_DIR="$(dirname "$FPC_EXE")"
if [ -n "$FPC_UTIL_DIR" ]; then
  export PATH="$FPC_BIN_DIR:$FPC_UTIL_DIR:$PATH"
else
  export PATH="$FPC_BIN_DIR:$PATH"
fi

# ── Linux glibc 2.34+ workaround ─────────────────────────────────────
#
# TODO(FPC 3.2.4): remove this whole glibc stub block (see end of comment).
#
# FPC 3.2.2 was built against glibc < 2.34 and its RTL references
# __libc_csu_init / __libc_csu_fini, which glibc 2.34 (Aug 2021) made
# private. Linking anything FPC produces against current glibc fails:
#   undefined reference to `__libc_csu_init'
#   undefined reference to `__libc_csu_fini'
#
# Ubuntu 22.04+ ships glibc 2.34+ and is affected. The fix shipped in
# FPC 3.2.4+ (and Debian/Fedora patched their packages); for our
# pre-built tarball we provide empty stub symbols ourselves.
#
# Affected: every Linux target (x86_64, aarch64, arm/armhf, powerpc64).
#
# Strategy differs by target:
#   • x86_64 / aarch64 / arm — merge csu_stubs.o into rtl/cprt0.o only.
#     Do not add -k to fpc.cfg (duplicate symbols if both are used).
#   • powerpc64-linux — si_c.o also references these symbols, so append
#     -k<stub> to fpc.cfg and do not merge into cprt0.o. The stub object
#     is cross-compiled on the x86 host (CSU_STUBS_PREBUILT); running cc
#     inside QEMU user-mode for ppc64 is unreliable.
#
# Removable once we move to FPC 3.2.4+ (see TODO above).
#
# See https://gitlab.com/freepascal.org/fpc/source/-/issues/39295
if [ "$(uname -s)" = "Linux" ]; then
  STUB_INSTALL="$INSTALL_PREFIX/lib/fpc/$FPC_VERSION/csu_stubs.o"
  STUB_C="$WORK_DIR/csu_stubs.c"
  RTL_DIR="$INSTALL_PREFIX/lib/fpc/$FPC_VERSION/units/$FPC_TARGET/rtl"
  CPRT0="$RTL_DIR/cprt0.o"

  CSU_STUBS_SRC="$INSTALL_SCRIPT_DIR/ci/shared/csu-stubs.c"
  FPC_CFG_MARKER="# glibc 2.34+ csu stubs (install-fpc-lazarus.sh)"
  append_fpc_cfg() {
    local marker="$1"
    shift
    local cfg
    for cfg in /etc/fpc.cfg "${HOME}/.fpc.cfg"; do
      if [ -f "$cfg" ] && ! grep -qF "$marker" "$cfg" 2>/dev/null; then
        {
          echo ""
          echo "$marker"
          printf '%s\n' "$@"
        } >> "$cfg"
        echo "Updated $cfg"
      fi
    done
  }

  if [ "$FPC_TARGET" = "powerpc64-linux" ]; then
    if [ -z "${CSU_STUBS_PREBUILT:-}" ] || [ ! -f "$CSU_STUBS_PREBUILT" ]; then
      echo "ERROR: CSU_STUBS_PREBUILT is required for powerpc64-linux" >&2
      echo "       (host must cross-compile csu stubs before QEMU docker run)" >&2
      exit 1
    fi
    cp "$CSU_STUBS_PREBUILT" "$STUB_INSTALL"
    append_fpc_cfg "$FPC_CFG_MARKER" "-k$STUB_INSTALL"

    if command -v gcc >/dev/null 2>&1; then
      CRT_DIR="$(dirname "$(gcc -print-file-name=crti.o)")"
      if [ -f "$CRT_DIR/crti.o" ]; then
        CRT_MARKER="# powerpc64-linux crt paths (install-fpc-lazarus.sh)"
        append_fpc_cfg "$CRT_MARKER" "-Fl$CRT_DIR" "-k-L$CRT_DIR"
        echo "Updated fpc.cfg with crt search path $CRT_DIR"
      fi
    fi
  else
    cp "$CSU_STUBS_SRC" "$STUB_C"
    cc -c -fPIC -o "$WORK_DIR/csu_stubs.o" "$STUB_C"
    if [ -f "$CPRT0" ]; then
      ld -r -o "$CPRT0.new" "$CPRT0" "$WORK_DIR/csu_stubs.o"
      mv "$CPRT0.new" "$CPRT0"
      echo "Patched $CPRT0 with glibc 2.34+ stubs."
    fi
  fi
fi

# ── Windows-specific: generate fpc.cfg ───────────────────────────────
#
# install.sh's final step calls $LIBDIR/samplecfg, which is a POSIX
# shell script that does not ship in the Windows tarball. The Windows
# replacement is fpcmkcfg.exe at $PREFIX/bin/. Without an fpc.cfg,
# the compiler can't find its own units. Note: fpc.cfg goes next to
# fpc.exe in $PREFIX/bin/<target>/, since FPC searches there first.
if [ "$IS_WINDOWS" = "1" ]; then
  FPCMKCFG="$FPC_UTIL_DIR/fpcmkcfg.exe"
  if [ ! -f "$FPCMKCFG" ]; then
    echo "ERROR: fpcmkcfg.exe not found at $FPCMKCFG" >&2
    exit 1
  fi
  "$FPCMKCFG" -d "basepath=$INSTALL_PREFIX/lib/fpc/$FPC_VERSION" \
              -o "$FPC_BIN_DIR/fpc.cfg"
fi

# Add to GitHub Actions PATH so subsequent steps see fpc.
# On Windows, GITHUB_PATH expects native Windows paths (C:\foo\bin),
# not MSYS/Git Bash paths (/c/foo/bin). cygpath converts both ways.
# Both bin/<target> and bin/ go on PATH so subsequent steps find both
# fpc.exe (the compiler) and instantfpc.exe (the utility).
ci_github_path_append "$FPC_BIN_DIR"
if [ -n "$FPC_UTIL_DIR" ]; then
  ci_github_path_append "$FPC_UTIL_DIR"
fi

# Probe the freshly installed compiler. Under QEMU user-mode (notably ppc64
# big-endian) the compiler binary can SIGSEGV intermittently, so retry via
# ci_fpc_info_probe instead of letting one emulation hiccup fail the install.
ci_fpc_info_probe -iV

# ── Build Lazarus from source (lazbuild backend only) ────────────────
#
# When INSTALL_LAZARUS=1, clone Lazarus and build lazbuild (~1–2 min).
# Packaged Lazarus on Linux/Windows pulls in the full IDE; we only need
# lazbuild for CI package/project builds.

if [ "$INSTALL_LAZARUS" = "0" ]; then
  echo "MAKE_BUILD_BACKEND=fpc — FPC install complete (lazbuild skipped)."
  exit 0
fi

export FPC_EXE
# shellcheck source=ci/shared/lazarus-bootstrap.sh
source "$INSTALL_SCRIPT_DIR/ci/shared/lazarus-bootstrap.sh"
echo "FPC + Lazarus installation complete."