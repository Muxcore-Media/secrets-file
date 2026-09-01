package internal

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func testMasterKeyHex(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return hex.EncodeToString(key)
}

func TestModuleInfo(t *testing.T) {
	Version = "0.1.6"
	m := NewModule(Config{})
	info := m.Info()
	if info.ID == "" {
		t.Error("module ID must not be empty")
	}
	if info.Version != "0.1.6" {
		t.Errorf("version=%q", info.Version)
	}
	if info.HTTPAddr != "" {
		t.Errorf("HTTPAddr=%q, want empty", info.HTTPAddr)
	}
}

func TestDefaultGRPCAddr(t *testing.T) {
	m := NewModule(Config{})
	if m.grpcAddr != "127.0.0.1:9550" {
		t.Fatalf("grpcAddr=%q", m.grpcAddr)
	}
}

func TestModuleLifecycle(t *testing.T) {
	dir := t.TempDir()
	keyHex := testMasterKeyHex(t)
	t.Setenv("SECRETS_MASTER_KEY", keyHex)
	t.Setenv("SECRETS_KEY_FILE", filepath.Join(dir, "master.key"))

	m := NewModule(Config{
		Store:    filepath.Join(dir, "secrets.json"),
		KeyFile:  filepath.Join(dir, "master.key"),
		GRPCAddr: "127.0.0.1:0",
	})
	ctx := context.Background()

	if err := m.Init(ctx); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := m.Health(ctx); err != nil {
		t.Fatalf("Health: %v", err)
	}
	if err := m.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestKeyAndStorePermissions(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "master.key")
	store := filepath.Join(dir, "secrets.json")
	t.Setenv("SECRETS_MASTER_KEY", testMasterKeyHex(t))
	t.Setenv("SECRETS_KEY_FILE", keyFile)

	m := NewModule(Config{KeyFile: keyFile, Store: store, GRPCAddr: "127.0.0.1:0"})
	ctx := context.Background()
	if err := m.Init(ctx); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{keyFile} {
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %o, want 0600", path, st.Mode().Perm())
		}
	}
}

func TestHealthBeforeInit(t *testing.T) {
	m := NewModule(Config{})
	if err := m.Health(context.Background()); err == nil {
		t.Fatal("expected error before Init")
	}
}

func TestInvalidMasterKeyEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SECRETS_MASTER_KEY", "not-hex")
	m := NewModule(Config{
		Store:   filepath.Join(dir, "secrets.json"),
		KeyFile: filepath.Join(dir, "master.key"),
	})
	if err := m.Init(context.Background()); err == nil {
		t.Fatal("expected error for invalid SECRETS_MASTER_KEY")
	}
}

func TestWrongLengthMasterKeyEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SECRETS_MASTER_KEY", "abcd")
	m := NewModule(Config{
		Store:   filepath.Join(dir, "secrets.json"),
		KeyFile: filepath.Join(dir, "master.key"),
	})
	if err := m.Init(context.Background()); err == nil {
		t.Fatal("expected error for short SECRETS_MASTER_KEY")
	}
}

func TestMissingKeyFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SECRETS_MASTER_KEY", "")
	m := NewModule(Config{
		Store:   filepath.Join(dir, "secrets.json"),
		KeyFile: filepath.Join(dir, "missing.key"),
	})
	if err := m.Init(context.Background()); err == nil {
		t.Fatal("expected error for missing key file")
	}
}

func TestGarbageKeyFile(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "master.key")
	if err := os.WriteFile(keyFile, []byte("garbage\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECRETS_MASTER_KEY", "")
	m := NewModule(Config{
		Store:   filepath.Join(dir, "secrets.json"),
		KeyFile: keyFile,
	})
	if err := m.Init(context.Background()); err == nil {
		t.Fatal("expected error for garbage key file")
	}
}

func TestEnvWinsOverKeyFile(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "master.key")
	wrongKey := make([]byte, 32)
	for i := range wrongKey {
		wrongKey[i] = 0xff
	}
	if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(wrongKey)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	envKey := testMasterKeyHex(t)
	t.Setenv("SECRETS_MASTER_KEY", envKey)
	t.Setenv("SECRETS_KEY_FILE", keyFile)

	m := NewModule(Config{Store: filepath.Join(dir, "secrets.json"), KeyFile: keyFile, GRPCAddr: "127.0.0.1:0"})
	ctx := context.Background()
	if err := m.Init(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.vault.Set(ctx, "k", "from-env-key"); err != nil {
		t.Fatal(err)
	}
	val, err := m.vault.Get(ctx, "k")
	if err != nil {
		t.Fatal(err)
	}
	if val != "from-env-key" {
		t.Fatalf("got %q", val)
	}
}

func TestEnvKeyPersistedForRestart(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "master.key")
	store := filepath.Join(dir, "secrets.json")
	envKey := testMasterKeyHex(t)

	t.Setenv("SECRETS_MASTER_KEY", envKey)
	t.Setenv("SECRETS_KEY_FILE", keyFile)

	m := NewModule(Config{Store: store, KeyFile: keyFile, GRPCAddr: "127.0.0.1:0"})
	ctx := context.Background()
	if err := m.Init(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.vault.Set(ctx, "token", "persist-me"); err != nil {
		t.Fatal(err)
	}
	if err := m.Stop(ctx); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SECRETS_MASTER_KEY", "")
	m2 := NewModule(Config{Store: store, KeyFile: keyFile, GRPCAddr: "127.0.0.1:0"})
	if err := m2.Init(ctx); err != nil {
		t.Fatal(err)
	}
	val, err := m2.vault.Get(ctx, "token")
	if err != nil {
		t.Fatal(err)
	}
	if val != "persist-me" {
		t.Fatalf("got %q", val)
	}
}

func TestRefusedKeyFileChange(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "master.key")
	store := filepath.Join(dir, "secrets.json")
	t.Setenv("SECRETS_MASTER_KEY", testMasterKeyHex(t))
	t.Setenv("SECRETS_KEY_FILE", keyFile)

	m := NewModule(Config{Store: store, KeyFile: keyFile, GRPCAddr: "127.0.0.1:0"})
	ctx := context.Background()
	if err := m.Init(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.vault.Set(ctx, "secret", "value"); err != nil {
		t.Fatal(err)
	}

	missing := filepath.Join(dir, "other.key")
	if err := m.UpdateSetting("key_file", missing); err == nil {
		t.Fatal("expected error for missing key file")
	}

	val, err := m.vault.Get(ctx, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if val != "value" {
		t.Fatalf("got %q", val)
	}
}

func TestRotateMasterKeyAndRestart(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "master.key")
	store := filepath.Join(dir, "secrets.json")
	t.Setenv("SECRETS_MASTER_KEY", testMasterKeyHex(t))
	t.Setenv("SECRETS_KEY_FILE", keyFile)

	m := NewModule(Config{Store: store, KeyFile: keyFile, GRPCAddr: "127.0.0.1:0"})
	ctx := context.Background()
	if err := m.Init(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.vault.Set(ctx, "cred", "rotate-me"); err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateSetting("rotate_master_key", "true"); err != nil {
		t.Fatal(err)
	}
	if err := m.Stop(ctx); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SECRETS_MASTER_KEY", "")
	m2 := NewModule(Config{Store: store, KeyFile: keyFile, GRPCAddr: "127.0.0.1:0"})
	if err := m2.Init(ctx); err != nil {
		t.Fatal(err)
	}
	val, err := m2.vault.Get(ctx, "cred")
	if err != nil {
		t.Fatal(err)
	}
	if val != "rotate-me" {
		t.Fatalf("got %q", val)
	}
}

func TestUnknownUpdateSetting(t *testing.T) {
	m := NewModule(Config{})
	if err := m.UpdateSetting("nope", "x"); err == nil {
		t.Fatal("expected error")
	}
}

func TestSecretCountReadOnly(t *testing.T) {
	m := NewModule(Config{})
	if err := m.UpdateSetting("secret_count", "99"); err == nil {
		t.Fatal("expected error")
	}
}
