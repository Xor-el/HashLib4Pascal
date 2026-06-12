#!/bin/sh
set -eu

# pkgsrc binary repo is keyed by the base release, so strip any _STABLE/_PATCH
# suffix from uname -r (e.g. 10.0_STABLE -> 10.0).
export PKG_PATH="https://cdn.NetBSD.org/pub/pkgsrc/packages/NetBSD/$(uname -p)/$(uname -r | cut -d_ -f1)/All"
# Upgrade the base pcre2 first so the new tools link against it; tolerated
# because a fresh image may have nothing to upgrade.
pkg_add -uu pcre2 || true
# -u: update already-installed packages (the base image now ships bash) instead
# of failing on a version mismatch; not-yet-installed packages install normally.
pkg_add -u bash curl git gmake mozilla-rootcerts-openssl
