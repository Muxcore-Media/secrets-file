FROM golang:1.26-alpine AS builder
COPY core/ /build/core/
COPY secrets-file/ /build/secrets-file/
WORKDIR /build/secrets-file
RUN go mod download && CGO_ENABLED=0 go build -o /secrets-file ./cmd/module
FROM alpine:3.21
RUN adduser -D -h /data secrets
USER secrets
WORKDIR /app
COPY --from=builder /secrets-file .
ENTRYPOINT ["./secrets-file"]
