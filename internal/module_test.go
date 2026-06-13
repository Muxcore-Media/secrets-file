package internal

import (
	"context"
	"path/filepath"
	"testing"

	secretsv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/secrets/v1"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()
	return Config{
		KeyFile:  filepath.Join(dir, "master.key"),
		Store:    filepath.Join(dir, "secrets.json"),
		GRPCAddr: ":0",
	}
}

func TestModuleInfo(t *testing.T) {
	m := NewModule(Config{})
	info := m.Info()
	if info.ID == "" {
		t.Error("module ID must not be empty")
	}
	if info.Version == "" {
		t.Error("module version must not be empty")
	}
	if info.MinCoreVersion == "" {
		t.Error("MinCoreVersion must not be empty")
	}
	if len(info.Contracts) == 0 {
		t.Error("Contracts must not be empty")
	}
}

func TestModuleLifecycle(t *testing.T) {
	m := NewModule(testConfig(t))
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

func TestGetSetDeleteList(t *testing.T) {
	m := NewModule(testConfig(t))
	ctx := context.Background()
	if err := m.Init(ctx); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer m.Stop(ctx)

	srv := m.srv

	_, err := srv.Get(ctx, &secretsv1.GetRequest{Key: "missing"})
	if err == nil {
		t.Fatal("expected error for missing key")
	}

	_, err = srv.Set(ctx, &secretsv1.SetRequest{Key: "apikey", Value: "sk-1234"})
	if err != nil {
		t.Fatal(err)
	}

	get, err := srv.Get(ctx, &secretsv1.GetRequest{Key: "apikey"})
	if err != nil {
		t.Fatal(err)
	}
	if get.Value != "sk-1234" {
		t.Fatalf("expected 'sk-1234', got %q", get.Value)
	}

	list, err := srv.List(ctx, &secretsv1.ListRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Keys) != 1 || list.Keys[0] != "apikey" {
		t.Fatalf("expected [apikey], got %v", list.Keys)
	}

	_, err = srv.Delete(ctx, &secretsv1.DeleteRequest{Key: "apikey"})
	if err != nil {
		t.Fatal(err)
	}

	_, err = srv.Get(ctx, &secretsv1.GetRequest{Key: "apikey"})
	if err == nil {
		t.Fatal("expected error after delete")
	}
}

func TestHealth(t *testing.T) {
	m := NewModule(testConfig(t))
	ctx := context.Background()
	if err := m.Init(ctx); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer m.Stop(ctx)

	if err := m.Health(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestPersistence(t *testing.T) {
	cfg := testConfig(t)
	m1 := NewModule(cfg)
	ctx := context.Background()
	if err := m1.Init(ctx); err != nil {
		t.Fatalf("Init: %v", err)
	}
	m1.srv.Set(ctx, &secretsv1.SetRequest{Key: "persist", Value: "data"})
	m1.Stop(ctx)

	m2 := NewModule(cfg)
	if err := m2.Init(ctx); err != nil {
		t.Fatalf("Init second instance: %v", err)
	}
	defer m2.Stop(ctx)

	get, err := m2.srv.Get(ctx, &secretsv1.GetRequest{Key: "persist"})
	if err != nil {
		t.Fatal(err)
	}
	if get.Value != "data" {
		t.Fatalf("expected 'data', got %q", get.Value)
	}
}
