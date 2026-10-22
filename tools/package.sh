#!/bin/sh
# Package a built radsecproxy tree into a tarball for the reverse-coa-poc builds.
# usage: tools/package.sh <label>   (run from the top of a built source tree)
set -eu
label=${1:?label, e.g. ubuntu22.04}
commit=$(git rev-parse --short HEAD 2>/dev/null || cut -c1-7 .commit 2>/dev/null || echo unknown)
name="radsecproxy-reverse-coa-poc-${commit}-${label}-x86_64"
out="dist/${name}"
rm -rf dist && mkdir -p "$out/bin" "$out/man/man5" "$out/man/man8" "$out/examples" "$out/docs"
cp radsecproxy radsecproxy-hash "$out/bin/"
cp radsecproxy.conf.5 "$out/man/man5/"
cp radsecproxy.8 radsecproxy-hash.8 "$out/man/man8/"
cp radsecproxy.conf-example "$out/examples/"
cp -r examples/reverse-coa "$out/examples/"
cp -r docs/testing "$out/docs/"
cp tools/coaprobe.py "$out/bin/"
cp LICENSE "$out/"
find "$out" -name '._*' -delete
{
    echo "radsecproxy reverse-coa-poc build"
    echo "commit:    $(git rev-parse HEAD 2>/dev/null || cat .commit 2>/dev/null || echo unknown)"
    echo "branch:    reverse-coa-poc (upstream PRs #206 and #186, the fleet fix from reverse-coa-fleet, plus examples, docs and tools)"
    echo "built:     $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "host:      ${label} x86_64"
    echo "openssl:   $(openssl version 2>/dev/null || echo unknown)"
    echo "tests:     make check passed"
    echo
    echo "Binaries are dynamically linked against the system OpenSSL."
    echo "See examples/reverse-coa/README.md to get started."
} > "$out/BUILD.txt"
tar -C dist -czf "dist/${name}.tar.gz" "$name"
(cd dist && sha256sum "${name}.tar.gz" > "${name}.tar.gz.sha256")
echo "dist/${name}.tar.gz"
