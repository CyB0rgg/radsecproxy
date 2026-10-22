#!/bin/sh
# Build a .deb or .rpm of a built radsecproxy tree with nfpm, for the reverse-coa-poc builds.
# usage: tools/package-nfpm.sh deb|rpm   (run from the top of a built source tree; nfpm in PATH)
#
# The package version sorts below upstream's eventual 1.12.0, so a distribution package
# replaces this one on upgrade:
#   deb  1.12.0~poc.<date>+g<commit>
#   rpm  1.12.0, release 0.poc.<date>.g<commit>
# <date> is the reverse-coa-poc-<date> tag when building from one, else today (UTC).
set -eu
fmt=${1:?deb or rpm}
commit=$(git rev-parse --short HEAD 2>/dev/null || cut -c1-7 .commit 2>/dev/null || echo unknown)
tag=$(git describe --tags --exact-match --match 'reverse-coa-poc-*' 2>/dev/null || true)
date=${tag#reverse-coa-poc-}
[ -n "$tag" ] || date=$(date -u +%Y%m%d)
case "$fmt" in
    deb) PKG_VERSION="1.12.0~poc.${date}+g${commit}"; PKG_RELEASE="" ;;
    rpm) PKG_VERSION="1.12.0"; PKG_RELEASE="0.poc.${date}.g${commit}" ;;
    *) echo "usage: $0 deb|rpm" >&2; exit 2 ;;
esac
STAGE=$(pwd)/dist/stage
rm -rf "$STAGE" && mkdir -p "$STAGE/doc/examples" "$STAGE/doc/testing" dist
cp radsecproxy radsecproxy-hash radsecproxy.conf.5 radsecproxy.8 radsecproxy-hash.8 "$STAGE/"
cp tools/coaprobe.py "$STAGE/"
cp -r examples/reverse-coa "$STAGE/doc/examples/"
cp radsecproxy.conf-example "$STAGE/doc/examples/"
cp -r docs/testing/. "$STAGE/doc/testing/"
cp README.md LICENSE "$STAGE/doc/"
find "$STAGE" -name '._*' -delete
{
    echo "radsecproxy reverse-coa-poc build"
    echo "commit:    $(git rev-parse HEAD 2>/dev/null || cat .commit 2>/dev/null || echo unknown)"
    echo "branch:    reverse-coa-poc (upstream PRs #206 and #186, the fleet fix from reverse-coa-fleet, plus examples, docs and tools)"
    echo "built:     $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "package:   ${fmt} ${PKG_VERSION}${PKG_RELEASE:+-$PKG_RELEASE} x86_64"
    echo "openssl:   $(openssl version 2>/dev/null || echo unknown)"
    echo "tests:     make check passed"
} > "$STAGE/doc/BUILD.txt"
sed -e "s|@PKG_VERSION@|${PKG_VERSION}|" -e "s|@PKG_RELEASE@|${PKG_RELEASE}|" packaging/nfpm.yaml > dist/nfpm.yaml
nfpm package -f dist/nfpm.yaml -p "$fmt" -t dist/
rm -rf "$STAGE" dist/nfpm.yaml
out=$(ls dist/*."$fmt")
# GitHub renames release assets with a tilde in the name; name the file the way it is served
case "$out" in *~*) mv "$out" "$(echo "$out" | tr '~' '.')"; out=$(ls dist/*."$fmt") ;; esac
(cd dist && sha256sum "$(basename "$out")" > "$(basename "$out").sha256")
echo "$out"
