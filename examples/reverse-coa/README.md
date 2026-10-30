# reverse-coa-poc

A branch for implementers who want to try reverse CoA (draft-ietf-radext-reverse-coa,
RFC 8559 routing) in radsecproxy before it is merged upstream.

## What is on this branch

- The code exactly as it stands in the upstream pull requests
  [#206](https://github.com/radsecproxy/radsecproxy/pull/206) (CoA proxying by Operator-Name) and
  [#186](https://github.com/radsecproxy/radsecproxy/pull/186) (reverse CoA), taken from the PR
  branches by commit, not re-applied. The base commit of this branch is the current head of #186.
- `examples/reverse-coa/`: configuration for the two proxy roles and a RouterOS snippet.
- `docs/testing/`: bench records against real NAS equipment.
- `tools/coaprobe.py`: a small originator for CoA-Request and Disconnect-Request, to test
  without a RADIUS server that can send CoA.
- `.github/workflows/build.yml`: builds x86_64 binaries and packages them.

When the upstream pull requests move, this branch is rebased onto their new heads. Builds
carry the commit they were made from.

## Getting a build

Every push builds two packages, one on Ubuntu 22.04 (runs on Ubuntu 22.04 or later and
Debian 12 or later) and one on Rocky Linux 9 (RHEL, Rocky, Alma, CentOS Stream 9). They are
attached to the workflow run under Actions, and to a release for every tag named
`reverse-coa-poc-*`.

Each package contains `bin/radsecproxy`, `bin/radsecproxy-hash`, the man pages, the
examples, the testing records and a `BUILD.txt` with the commit and build host details.
The binaries link OpenSSL dynamically; install `libssl3` (Debian/Ubuntu) or `openssl-libs`
(RHEL family) if it is not already there.

The build runs `make check` (the unit tests, including the CoA and reverse CoA suites)
and fails if any test fails.

## Roles

Reverse CoA needs the two proxies on the path to agree on one thing: the ANP-side proxy
marks each request with Operator-Name and a keyed Operator-NAS-Identifier on the way up,
and routes a CoA back down by the same values. See:

- `idp-proxy.conf`: the proxy nearest the home RADIUS server (IDP, or a hub). It accepts
  CoA from a local originator and sends it down the connection of the ANP proxy whose
  `ReverseCoAOperatorRealm` matches the Operator-Name.
- `anp-proxy.conf`: the proxy nearest the NAS. It keeps the NAS's RadSec connection and
  delivers the CoA on it. For hostapd as the NAS, use the RADIUS/TLS reverse CoA series
  posted to the hostap mailing list in October 2026; stock hostapd has no reverse CoA.
- `anp-proxy-udp-nas.conf`: the client block for a NAS that has no reverse CoA of its own;
  the last hop is then an ordinary RFC 5176 request on UDP 3799.
- `single-proxy.conf`: no ANP-side proxy; the NAS connects straight to the proxy in front
  of the home RADIUS server. The NAS block and the originator block in one instance. Tested
  in `docs/testing/mikrotik-routeros-single-proxy.md`.
- `routeros.rsc`: the RouterOS side, as used in `docs/testing/mikrotik-routeros-hotspot.md`.

Replace every `<...>` placeholder. The two `ReverseCoATokenKey` values must be the same.

## NASidentifier: one NAS per block, or a fleet

A client block is a NAS, not a proxy, when it has `NASidentifier`:

- `NASidentifier <literal>`: the block is that one NAS; a request naming it by
  NAS-Identifier or Operator-NAS-Identifier, or by NAS-IP-Address equal to the
  connection's address, is delivered on it.
- `NASidentifier /regexp/`: the block is a fleet, typically many NASes on one client
  certificate behind one `host 0.0.0.0/0` block. Each connection is the NAS whose own
  NAS-Identifier (admitted by the regexp) it has sent in its requests, or, when a
  NAS-Identifier is missing on either side, whose NAS-IP-Address it has sent. A
  connection that has not sent a request yet matches nothing. Two NASes on one
  certificate and one address that also send the same NAS-Identifier cannot be told
  apart.

The Operator-NAS-Identifier added on the way up names the NAS: a keyed hash, under
`ReverseCoATokenKey`, of the certificate identity and of the NAS-Identifier the NAS
sends (its NAS-IP-Address when it sends none). The same NAS gets the same value on
every connection, from every address, on every proxy with the key, so a fleet on one
certificate gets one value per box and a CoA still reaches a box that reconnected.
Two boxes on one certificate sending the same NAS-Identifier share a value; give them
distinct identities. When several connections carry the same value, the NAS the
request names wins, then the connection that sent a request most recently. The proxy keeps no record
of which connection a session was seen on; a hub with several proxies registered for
one realm tries them in the order they registered.

What the originator (the home RADIUS server) must send: Operator-Name, the echoed
Operator-NAS-Identifier, and the NAS identification of RFC 5176 section 3
(NAS-Identifier and NAS-IP-Address as the NAS sent them), all available from the
accounting.

## Feedback

Please report what you tested, with the NAS make and firmware version, the radsecproxy log
at debug level 3 for the CoA exchange, and the NAS's own log. Issues on this fork are fine;
for anything that is a bug in the proposed code itself, the upstream pull requests are the
right place.
