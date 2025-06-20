FROM ubuntu:24.04

# Install required packages
RUN apt-get update \
    && apt-get install -y caddy ca-certificates curl openssl \
    && apt-get clean

# Copy server binary based on architecture
ARG TARGETARCH

COPY bin/zero-trust-proxy-server-linux-${TARGETARCH} /bin/zero-trust-proxy-server
RUN chmod +x /bin/zero-trust-proxy-server

VOLUME ["/config"]

EXPOSE 8443 443 80

CMD ["/bin/zero-trust-proxy-server"]
