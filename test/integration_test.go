//go:build integration

package test

import (
	"context"
	"net"
	"testing"

	secretsv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/secrets/v1"
	"github.com/Muxcore-Media/secrets-file/internal/server"
	"github.com/Muxcore-Media/secrets-file/internal/vault"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
)

func startSecretsService(t *testing.T) (secretsv1.SecretsServiceClient, func()) {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 3)
	}
	v, err := vault.New("", key)
	if err != nil {
		t.Fatal(err)
	}
	srv := server.New(v)
	lis := bufconn.Listen(1 << 20)
	grpcSrv := grpc.NewServer()
	srv.RegisterWithGRPC(grpcSrv)
	go func() { _ = grpcSrv.Serve(lis) }()

	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	client := secretsv1.NewSecretsServiceClient(conn)
	cleanup := func() {
		grpcSrv.Stop()
		_ = conn.Close()
	}
	return client, cleanup
}

func TestSecretsServiceCRUD(t *testing.T) {
	client, cleanup := startSecretsService(t)
	defer cleanup()

	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("x-caller-id", "integration-test"))

	if _, err := client.Set(ctx, &secretsv1.SetRequest{Key: "db", Value: "postgres://x"}); err != nil {
		t.Fatal(err)
	}

	got, err := client.Get(ctx, &secretsv1.GetRequest{Key: "db"})
	if err != nil {
		t.Fatal(err)
	}
	if got.GetValue() != "postgres://x" {
		t.Fatalf("got %q", got.GetValue())
	}

	list, err := client.List(ctx, &secretsv1.ListRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if list.GetCount() != 1 {
		t.Fatalf("count=%d", list.GetCount())
	}

	if _, err := client.Delete(ctx, &secretsv1.DeleteRequest{Key: "db"}); err != nil {
		t.Fatal(err)
	}
	list, err = client.List(ctx, &secretsv1.ListRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if list.GetCount() != 0 {
		t.Fatalf("count=%d after delete", list.GetCount())
	}
}
