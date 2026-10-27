# syntax=docker/dockerfile:1
#
# Lightweight data-plane image for Corporate Twin nodes.
#
# Containerlab's `linux` kind requires the `ip` utility inside the container to
# wire data-plane interfaces, so a plain `alpine` image is not sufficient. This
# image stays Alpine-based (~25 MB compressed) and adds only the tooling needed
# for routing, firewalling and live state capture.
#
# Build (multi-arch safe, native on Raspberry Pi 5 / arm64):
#   docker build -t twin-host:latest -f docker/twin-host.Dockerfile docker/

FROM alpine:3.20

RUN apk add --no-cache \
        iproute2 \
        iptables \
        ip6tables \
        iputils \
        bind-tools \
        curl \
        tcpdump \
        conntrack-tools \
        procps \
        busybox-extras \
    && rm -rf /var/cache/apk/*

# Netfilter modules are loaded on the host kernel; enable forwarding by default
# so router nodes behave like a real branch gateway.
RUN sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

# Containerlab sets its own entrypoint for `linux` nodes, but keep a sane
# fallback so the image is usable standalone with `docker run`.
CMD ["sleep", "infinity"]
