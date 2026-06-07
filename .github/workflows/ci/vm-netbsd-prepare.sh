#!/bin/sh
set -eu

export PKG_PATH="https://cdn.NetBSD.org/pub/pkgsrc/packages/NetBSD/$(uname -p)/$(uname -r | cut -d_ -f1)/All"
pkg_add -uu pcre2 || true
pkg_add bash curl git gmake mozilla-rootcerts-openssl
