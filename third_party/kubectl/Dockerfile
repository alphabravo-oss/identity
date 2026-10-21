ARG GO_VERSION
FROM golang:${GO_VERSION}-bookworm@sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110 AS build
WORKDIR /src
COPY third_party/kubectl/ ./
ENV GOWORK=off GOTOOLCHAIN=local CGO_ENABLED=0
RUN --mount=type=cache,target=/root/.cache/go-build go build -trimpath -ldflags="-s -w -X k8s.io/component-base/version.gitVersion=v1.37.1" -o /kubectl .
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates
COPY --from=build /kubectl /usr/local/bin/kubectl
LABEL org.opencontainers.image.source="https://github.com/alphabravo-oss/identity" org.opencontainers.image.vendor="Kubernetes" org.opencontainers.image.version="1.37.1-go1.27.3"
USER 65532:65532
ENTRYPOINT ["/bin/sh"]
