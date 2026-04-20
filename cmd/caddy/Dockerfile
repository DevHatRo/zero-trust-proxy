# syntax=docker/dockerfile:1.6
#
# Runtime image for the zero-trust-proxy server.
#
# The binary copied in is a custom Caddy build (see ./cmd/caddy) with the
# ztagents app and ztrouter handler linked in. There is no separate "server"
# process and no need to install upstream Caddy — this binary is Caddy.
#
# Build prerequisites: run `./scripts/build.sh` so that
# `bin/zero-trust-proxy-server-linux-${TARGETARCH}` exists.

FROM debian:12-slim

ARG TARGETARCH

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# The binary is a full Caddy distribution with our modules baked in.
COPY bin/zero-trust-proxy-server-linux-${TARGETARCH} /usr/local/bin/caddy
RUN chmod +x /usr/local/bin/caddy \
    && /usr/local/bin/caddy version

# /config holds the Caddyfile (or caddy.json) and the TLS material referenced
# from it (server.crt, server.key, ca.crt). Mount this volume at runtime.
VOLUME ["/config"]
WORKDIR /config

# :80, :443 — public ingress.
# :8443 — mTLS listener for agent connections (zerotrust.agents app).
# :2019 — Caddy admin API (bind to localhost in the Caddyfile for production).
EXPOSE 80 443 8443 2019

ENTRYPOINT ["/usr/local/bin/caddy"]
CMD ["run", "--config", "/config/Caddyfile", "--adapter", "caddyfile"]
