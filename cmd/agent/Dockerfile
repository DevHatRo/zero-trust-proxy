# syntax=docker/dockerfile:1.6
#
# Runtime image for the zero-trust-proxy agent.
#
# The agent shells out to `caddy validate` (see internal/caddy/validation.go)
# before accepting service configs. We copy the same custom Caddy binary the
# server image uses — that binary is a superset of upstream Caddy, so it can
# validate standard Caddy configs just fine.
#
# Build prerequisites: run `./scripts/build.sh` so that both
# `bin/zero-trust-proxy-agent-linux-${TARGETARCH}` and
# `bin/zero-trust-proxy-server-linux-${TARGETARCH}` exist.

FROM debian:12-slim

ARG TARGETARCH

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Caddy binary (custom build) — used only by the validator.
COPY bin/zero-trust-proxy-server-linux-${TARGETARCH} /usr/local/bin/caddy
RUN chmod +x /usr/local/bin/caddy \
    && /usr/local/bin/caddy version

# Agent binary.
COPY bin/zero-trust-proxy-agent-linux-${TARGETARCH} /usr/local/bin/zero-trust-proxy-agent
RUN chmod +x /usr/local/bin/zero-trust-proxy-agent

# /config holds agent.yaml and the TLS material it references
# (client cert/key + CA). Mount this volume at runtime.
VOLUME ["/config"]
WORKDIR /config

ENTRYPOINT ["/usr/local/bin/zero-trust-proxy-agent"]
CMD ["--config", "/config/agent.yaml"]
