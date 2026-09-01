FROM golang:1.26-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=0.0.0-dev
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=${VERSION}" -o /build/module ./cmd/module

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /build/module /
EXPOSE 9550
HEALTHCHECK --interval=30s --timeout=5s --start-period=3s --retries=3 \
  CMD ["/module", "--health-check"]
ENTRYPOINT ["/module"]
