# GO_VERSION is passed by scripts/build-images.sh from go.mod.
ARG GO_VERSION
FROM docker.io/library/golang:${GO_VERSION}-alpine@sha256:f2c872bcee949b7be9c490efd02b48a8a2fbf947cdf533f1c58525ec9d8170fd AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG SERVICE
RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /service ./cmd/${SERVICE}
RUN --mount=type=cache,target=/root/.cache/go-build if [ "$SERVICE" = bootstrap ]; then CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /demo-product ./examples/demo-product; else touch /demo-product; fi
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /service /service
COPY --from=build /demo-product /demo-product
USER 65532:65532
ENTRYPOINT ["/service"]
