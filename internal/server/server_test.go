package server

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	secretsv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/secrets/v1"
	"github.com/Muxcore-Media/secrets-file/internal/vault"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func testVault(t *testing.T) *vault.Vault {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	v, err := vault.New("", key)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func startServer(t *testing.T, v *vault.Vault) (*Server, *bufconn.Listener) {
	t.Helper()
	s := New(v)
	lis := bufconn.Listen(1 << 20)
	grpcSrv := grpc.NewServer()
	s.RegisterWithGRPC(grpcSrv)
	go func() { _ = grpcSrv.Serve(lis) }()
	t.Cleanup(func() { grpcSrv.Stop() })
	return s, lis
}

func dial(t *testing.T, lis *bufconn.Listener) secretsv1.SecretsServiceClient {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return secretsv1.NewSecretsServiceClient(conn)
}

func TestGetSetDeleteList(t *testing.T) {
	v := testVault(t)
	_, lis := startServer(t, v)
	client := dial(t, lis)
	ctx := context.Background()

	if _, err := client.Set(ctx, &secretsv1.SetRequest{Key: "api", Value: "secret"}); err != nil {
		t.Fatal(err)
	}

	resp, err := client.Get(ctx, &secretsv1.GetRequest{Key: "api"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetValue() != "secret" {
		t.Fatalf("got %q", resp.GetValue())
	}

	list, err := client.List(ctx, &secretsv1.ListRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if list.GetCount() != 1 {
		t.Fatalf("count=%d", list.GetCount())
	}

	if _, err := client.Delete(ctx, &secretsv1.DeleteRequest{Key: "api"}); err != nil {
		t.Fatal(err)
	}
	_, err = client.Get(ctx, &secretsv1.GetRequest{Key: "api"})
	if st, ok := status.FromError(err); !ok || st.Code() != codes.NotFound {
		t.Fatalf("expected NotFound, got %v", err)
	}
}

func TestGet_NotFound(t *testing.T) {
	v := testVault(t)
	_, lis := startServer(t, v)
	client := dial(t, lis)

	_, err := client.Get(context.Background(), &secretsv1.GetRequest{Key: "missing"})
	if st, ok := status.FromError(err); !ok || st.Code() != codes.NotFound {
		t.Fatalf("expected NotFound, got %v", err)
	}
}

func TestGet_DecryptFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	v, err := vault.New(path, key)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := v.Set(ctx, "k", "v"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"k":{"n":"AAAAAAAAAAAAAAAA","d":"BBBBBBBBBBBB"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	v2, err := vault.New(path, key)
	if err != nil {
		t.Fatal(err)
	}

	s := New(v2)
	if err := s.Health(ctx); err == nil {
		t.Fatal("expected health failure for corrupt entry")
	}

	_, lis := startServer(t, v2)
	client := dial(t, lis)
	_, err = client.Get(ctx, &secretsv1.GetRequest{Key: "k"})
	if st, ok := status.FromError(err); !ok || st.Code() != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition, got %v", err)
	}
}

func TestHealth(t *testing.T) {
	v := testVault(t)
	s := New(v)
	ctx := context.Background()
	if err := v.Set(ctx, "k", "v"); err != nil {
		t.Fatal(err)
	}
	if err := s.Health(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestGet_InvalidArgument(t *testing.T) {
	v := testVault(t)
	_, lis := startServer(t, v)
	client := dial(t, lis)

	_, err := client.Get(context.Background(), &secretsv1.GetRequest{})
	if st, ok := status.FromError(err); !ok || st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", err)
	}
}
