package internal

import (
	"path/filepath"
	"testing"
)

func TestSettingsStorePath(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "master.key")
	store1 := filepath.Join(dir, "a", "secrets.json")
	store2 := filepath.Join(dir, "b", "secrets.json")

	m := NewModule(Config{Store: store1, KeyFile: keyFile, GRPCAddr: "127.0.0.1:0"})
	if err := m.Init(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer m.Stop(t.Context())

	if err := m.vault.Set(t.Context(), "k", "v1"); err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateSetting("store_path", store2); err != nil {
		t.Fatal(err)
	}
	defs := m.Settings()
	if defs[0].Value != store2 {
		t.Fatalf("store=%q", defs[0].Value)
	}
	// New store starts empty; set and health-check.
	if err := m.vault.Set(t.Context(), "k2", "v2"); err != nil {
		t.Fatal(err)
	}
	if err := m.Health(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateSetting("store_path", ""); err == nil {
		t.Fatal("expected error")
	}
}
