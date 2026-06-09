#!/bin/sh
set -eu

# pkgsrc binary repo is keyed by the base release, so strip any _STABLE/_PATCH
# suffix from uname -r (e.g. 10.0_STABLE -> 10.0).
export PKG_PATH="https://cdn.NetBSD.org/pub/pkgsrc/packages/NetBSD/$(uname -p)/$(uname -r | cut -d_ -f1)/All"
# Upgrade the base pcre2 first so the new tools link against it; tolerated
# because a fresh image may have nothing to upgrade.
pkg_add -uu pcre2 || true
pkg_add bash curl git gmake mozilla-rootcerts-openssl
