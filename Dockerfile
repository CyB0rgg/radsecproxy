# radsecproxy reverse-coa-poc image.
#   docker run --rm -v /path/to/radsecproxy.conf:/etc/radsecproxy/radsecproxy.conf:ro \
#       -v /path/to/certs:/etc/radsecproxy/certs:ro -p 2083:2083 \
#       ghcr.io/cyb0rgg/radsecproxy:reverse-coa-poc
# The config, certificates and keys are mounted; nothing is baked in. Examples are in
# /usr/share/doc/radsecproxy/examples/reverse-coa/ inside the image.
FROM debian:bookworm-slim AS build
ARG COMMIT=unknown
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential autoconf automake libtool pkg-config libssl-dev git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN autoreconf -fi && ./configure --prefix=/usr --sysconfdir=/etc/radsecproxy --localstatedir=/var \
    && make -j"$(nproc)" && make check && make install DESTDIR=/out \
    && mkdir -p /out/usr/share/doc/radsecproxy/examples /out/usr/share/radsecproxy \
    && cp -r examples/reverse-coa /out/usr/share/doc/radsecproxy/examples/ \
    && cp -r docs/testing /out/usr/share/doc/radsecproxy/ \
    && cp README.md LICENSE /out/usr/share/doc/radsecproxy/ \
    && cp tools/coaprobe.py /out/usr/share/radsecproxy/ \
    && printf 'radsecproxy reverse-coa-poc image\ncommit:    %s\nbuilt:     %s\n' "${COMMIT}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > /out/usr/share/doc/radsecproxy/BUILD.txt

FROM debian:bookworm-slim
ARG COMMIT=unknown
LABEL org.opencontainers.image.title="radsecproxy, reverse CoA proof of concept" \
      org.opencontainers.image.description="radsecproxy with reverse CoA (upstream PRs #206 and #186 plus the fleet commit), built from the reverse-coa-poc branch for evaluation. Config, certificates and keys are mounted under /etc/radsecproxy/." \
      org.opencontainers.image.source="https://github.com/CyB0rgg/radsecproxy" \
      org.opencontainers.image.url="https://github.com/CyB0rgg/radsecproxy/tree/reverse-coa-poc" \
      org.opencontainers.image.documentation="https://github.com/CyB0rgg/radsecproxy/blob/reverse-coa-poc/README.md" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.licenses="BSD-3-Clause"
RUN apt-get update && apt-get install -y --no-install-recommends libssl3 ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/* && mkdir -p /etc/radsecproxy /var/log/radsecproxy
COPY --from=build /out/ /
VOLUME ["/etc/radsecproxy"]
EXPOSE 2083/tcp 1812/udp 1813/udp 3799/udp
ENTRYPOINT ["/usr/sbin/radsecproxy", "-f"]
CMD ["-c", "/etc/radsecproxy/radsecproxy.conf"]
