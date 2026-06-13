FROM golang:1.26-alpine AS builder
COPY core/ /build/core/
COPY secrets-file/ /build/secrets-file/
WORKDIR /build/secrets-file
RUN go mod download
RUN CGO_ENABLED=0 go build -o /secrets-file ./cmd/module
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /secrets-file /
ENTRYPOINT ["/secrets-file"]
