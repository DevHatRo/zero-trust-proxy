FROM ubuntu:24.04

ARG TARGETARCH

# Install curl and ca-certificates for downloading Caddy
RUN apt-get update && \
    apt-get install -y curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Download and install Caddy binary for configuration validation
RUN CADDY_VERSION="2.8.4" && \
    case ${TARGETARCH} in \
        amd64) CADDY_ARCH="amd64" ;; \
        arm64) CADDY_ARCH="arm64" ;; \
        *) echo "Unsupported architecture: ${TARGETARCH}" && exit 1 ;; \
    esac && \
    curl -L "https://github.com/caddyserver/caddy/releases/download/v${CADDY_VERSION}/caddy_${CADDY_VERSION}_linux_${CADDY_ARCH}.tar.gz" | \
    tar -xz -C /tmp && \
    mv /tmp/caddy /usr/local/bin/caddy && \
    chmod +x /usr/local/bin/caddy && \
    rm -rf /tmp/*

# Verify Caddy installation
RUN caddy version

# Copy the zero-trust-proxy agent binary
COPY bin/zero-trust-proxy-agent-linux-${TARGETARCH} /bin/zero-trust-proxy-agent
RUN chmod +x /bin/zero-trust-proxy-agent

VOLUME ["/config"]

ENTRYPOINT ["/bin/zero-trust-proxy-agent"]
