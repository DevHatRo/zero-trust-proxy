# syntax=docker/dockerfile:1.6
#
# Runtime image for the zero-trust-proxy server.
#
# Build prerequisite: run `./scripts/build.sh` so that
# `bin/zero-trust-proxy-server-linux-${TARGETARCH}` exists.

FROM debian:12-slim

ARG TARGETARCH

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY bin/zero-trust-proxy-server-linux-${TARGETARCH} /usr/local/bin/zero-trust-proxy
RUN chmod +x /usr/local/bin/zero-trust-proxy \
    && /usr/local/bin/zero-trust-proxy version

# /config holds server.yaml and the TLS material referenced from it
# (server.crt, server.key, ca.crt). Mount this volume at runtime.
VOLUME ["/config"]
WORKDIR /config

# :80, :443 — public ingress (HTTP redirect + HTTPS).
# :8443     — mTLS listener for agent connections.
# :2020     — optional check-domain endpoint (used by external ACME-ask probes).
EXPOSE 80 443 8443 2020

ENTRYPOINT ["/usr/local/bin/zero-trust-proxy"]
CMD ["run", "--config", "/config/server.yaml"]
