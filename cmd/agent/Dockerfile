# syntax=docker/dockerfile:1.6
#
# Runtime image for the zero-trust-proxy agent.
#
# Build prerequisites: run `./scripts/build.sh` so that
# `bin/zero-trust-proxy-agent-linux-${TARGETARCH}` exists.

FROM debian:12-slim

ARG TARGETARCH

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Agent binary.
COPY bin/zero-trust-proxy-agent-linux-${TARGETARCH} /usr/local/bin/zero-trust-proxy-agent
RUN chmod +x /usr/local/bin/zero-trust-proxy-agent

# /config holds agent.yaml and the TLS material it references
# (client cert/key + CA). Mount this volume at runtime.
VOLUME ["/config"]
WORKDIR /config

ENTRYPOINT ["/usr/local/bin/zero-trust-proxy-agent"]
CMD ["--config", "/config/agent.yaml"]
