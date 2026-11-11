FROM --platform=$BUILDPLATFORM golang:1.26.10 AS builder
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
ARG GOPROXY=https://proxy.golang.org,direct
RUN go env -w GOPROXY=${GOPROXY} && go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -tags "with_utls with_quic with_grpc with_wireguard with_gvisor with_clash_api" -o easy_proxies ./cmd/easy_proxies

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /etc/easy_proxies /app
WORKDIR /app
COPY --from=builder /src/easy_proxies /usr/local/bin/easy_proxies
COPY config.example.yaml /app/config.example.yaml
COPY THIRD_PARTY_NOTICES.md /app/THIRD_PARTY_NOTICES.md
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
# Windows checkouts produce CRLF; a #!/bin/sh\r shebang makes the kernel fail
# with "no such file or directory". Normalize inside the image as well.
RUN sed -i 's/\r$//' /usr/local/bin/entrypoint.sh && chmod +x /usr/local/bin/entrypoint.sh
# Pool/Hybrid mode: 2323, Management: 9091, Multi-port/Hybrid mode: 24000-24200
EXPOSE 2323 9091 24000-24200
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["--config", "/etc/easy_proxies/config.yaml"]
