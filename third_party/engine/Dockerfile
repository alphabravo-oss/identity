ARG GO_VERSION
FROM golang:${GO_VERSION}-bookworm@sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110 AS build
ARG ENGINE_COMMIT=a618740b578627b7b9acbbb111a6948882d6f5dc
RUN git clone --depth 1 --branch v4.19.5 https://github.com/zitadel/zitadel /src && test "$(git -C /src rev-parse HEAD)" = "$ENGINE_COMMIT"
WORKDIR /src
ENV GOWORK=off GOTOOLCHAIN=local CGO_ENABLED=0
COPY third_party/engine/generate.sh /generate.sh
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build bash /generate.sh
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build go build -p 6 -trimpath -ldflags="-s -w -X github.com/zitadel/zitadel/cmd/build.version=v4.19.5 -X github.com/zitadel/zitadel/cmd/build.commit=${ENGINE_COMMIT}" -o /engine .
FROM gcr.io/distroless/static-debian13:nonroot@sha256:516757106de35205efb70b91ba03f6f1298424a0678c603255cf2852a7000087
COPY --from=build /engine /app/zitadel
LABEL org.opencontainers.image.source="https://github.com/alphabravo-oss/identity" org.opencontainers.image.vendor="ZITADEL" org.opencontainers.image.version="4.19.5-go1.27.3"
USER 65532:65532
ENTRYPOINT ["/app/zitadel"]
