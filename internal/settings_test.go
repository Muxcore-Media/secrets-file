package internal

import (
	"path/filepath"
	"testing"
)

func TestSettingsStorePathCopiesSecrets(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "master.key")
	store1 := filepath.Join(dir, "a", "secrets.json")
	store2 := filepath.Join(dir, "b", "secrets.json")

	t.Setenv("SECRETS_MASTER_KEY", testMasterKeyHex(t))
	t.Setenv("SECRETS_KEY_FILE", keyFile)

	m := NewModule(Config{Store: store1, KeyFile: keyFile, GRPCAddr: "127.0.0.1:0"})
	if err := m.Init(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Stop(t.Context()) }()

	if err := m.vault.Set(t.Context(), "k", "v1"); err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateSetting("store_path", store2); err != nil {
		t.Fatal(err)
	}
	val, err := m.vault.Get(t.Context(), "k")
	if err != nil {
		t.Fatal(err)
	}
	if val != "v1" {
		t.Fatalf("got %q, want v1 copied to new store", val)
	}
	defs := m.Settings()
	if defs[0].Value != store2 {
		t.Fatalf("store=%q", defs[0].Value)
	}
	if err := m.UpdateSetting("store_path", ""); err == nil {
		t.Fatal("expected error")
	}
}

func TestResolveAllowedRootTempDir(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "secrets.json")
	key := filepath.Join(dir, "master.key")
	root := resolveAllowedRoot(store, key)
	if err := validateStoragePath(root, store); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestValidateStoragePath(t *testing.T) {
	root := t.TempDir()
	if err := validateStoragePath(root, ""); err == nil {
		t.Fatal("expected error for empty path")
	}
	if err := validateStoragePath(root, "."); err == nil {
		t.Fatal("expected error for .")
	}
	outside := filepath.Join(root, "..", "outside.json")
	if err := validateStoragePath(root, outside); err == nil {
		t.Fatal("expected error for path outside root")
	}
	inside := filepath.Join(root, "secrets.json")
	if err := validateStoragePath(root, inside); err != nil {
		t.Fatal(err)
	}
}
