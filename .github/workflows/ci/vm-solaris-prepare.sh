#!/bin/sh
set -eu

export PATH="/opt/csw/bin:/usr/local/bin:$PATH"
pkgutil -y -i bash curl git gmake
