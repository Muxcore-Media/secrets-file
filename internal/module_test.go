package internal

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestModuleInfo(t *testing.T) {
	m := NewModule(Config{})
	info := m.Info()
	if info.ID == "" {
		t.Error("module ID must not be empty")
	}
	if info.Version == "" {
		t.Error("module version must not be empty")
	}
}

func TestModuleLifecycle(t *testing.T) {
	t.Setenv("MUXCORE_INSECURE_DISABLE_TLS", "")
	t.Setenv("MUXCORE_GRPC_INSECURE", "")

	dir := t.TempDir()
	m := NewModule(Config{
		KeyFile:  filepath.Join(dir, "master.key"),
		Store:    filepath.Join(dir, "secrets.json"),
		GRPCAddr: "127.0.0.1:0",
	})
	ctx := context.Background()

	if err := m.Init(ctx); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := m.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestKeyAndStorePermissions(t *testing.T) {
	t.Setenv("MUXCORE_INSECURE_DISABLE_TLS", "")
	t.Setenv("MUXCORE_GRPC_INSECURE", "")

	dir := t.TempDir()
	keyFile := filepath.Join(dir, "master.key")
	store := filepath.Join(dir, "secrets.json")
	m := NewModule(Config{KeyFile: keyFile, Store: store, GRPCAddr: "127.0.0.1:0"})
	ctx := context.Background()
	if err := m.Init(ctx); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{keyFile, store} {
		st, err := os.Stat(path)
		if err != nil {
			// store may be created lazily on first Set
			if path == store && os.IsNotExist(err) {
				continue
			}
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %o, want 0600", path, st.Mode().Perm())
		}
	}
}
