package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	secretsv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/secrets/v1"
	modulesdk "github.com/Muxcore-Media/core/sdk/go/module"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"github.com/Muxcore-Media/secrets-file/internal"
)

var version = "0.0.0-dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--health-check" {
		os.Exit(runHealthCheck())
	}

	internal.Version = version
	mod := internal.NewModule(internal.Config{})
	insecureTLS := os.Getenv("MUXCORE_INSECURE_DISABLE_TLS") == "true" || os.Getenv("MUXCORE_GRPC_INSECURE") == "true"
	if err := modulesdk.Run(modulesdk.Config{
		Module:   mod,
		Insecure: insecureTLS,
	}); err != nil {
		slog.Error("module exited", "error", err)
		os.Exit(1)
	}
}

func runHealthCheck() int {
	addr := os.Getenv("SECRETS_GRPC_ADDR")
	if addr == "" {
		addr = "127.0.0.1:9550"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		if strings.HasPrefix(addr, ":") {
			host, port = "127.0.0.1", strings.TrimPrefix(addr, ":")
		} else {
			fmt.Fprintf(os.Stderr, "health-check: bad SECRETS_GRPC_ADDR: %v\n", err)
			return 1
		}
	}
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	dialAddr := net.JoinHostPort(host, port)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := grpc.NewClient(dialAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "health-check: dial: %v\n", err)
		return 1
	}
	defer func() { _ = conn.Close() }()

	md := metadata.Pairs("x-caller-id", "healthcheck")
	if token := os.Getenv("MUXCORE_MODULE_TOKEN"); token != "" {
		md.Set("authorization", "Bearer "+token)
	} else if token := os.Getenv("SECRETS_MODULE_TOKEN"); token != "" {
		md.Set("authorization", "Bearer "+token)
	}
	ctx = metadata.NewOutgoingContext(ctx, md)

	client := secretsv1.NewSecretsServiceClient(conn)
	if _, err := client.List(ctx, &secretsv1.ListRequest{}); err != nil {
		fmt.Fprintf(os.Stderr, "health-check: List RPC: %v\n", err)
		return 1
	}
	return 0
}
