FROM ubuntu:24.04

ARG TARGETARCH

COPY bin/zero-trust-proxy-agent-linux-${TARGETARCH} /bin/zero-trust-proxy-agent
RUN chmod +x /bin/zero-trust-proxy-agent

VOLUME ["/config"]

ENTRYPOINT ["/bin/zero-trust-proxy-agent"]
