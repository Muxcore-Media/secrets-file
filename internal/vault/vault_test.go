package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func masterKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

func TestNew_MissingKey(t *testing.T) {
	_, err := New("", nil)
	if err != ErrKeyRequired {
		t.Fatalf("expected ErrKeyRequired, got %v", err)
	}
}

func TestNew_WrongKeySize(t *testing.T) {
	_, err := New("", []byte("short"))
	if err != ErrKeySize {
		t.Fatalf("expected ErrKeySize, got %v", err)
	}
}

func TestNew_CorruptStore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")
	if err := os.WriteFile(path, []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := New(path, masterKey(t))
	if err == nil {
		t.Fatal("expected error for corrupt store")
	}
	if !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("expected ErrCorruptStore, got %v", err)
	}
}

func TestSetGet(t *testing.T) {
	v, err := New("", masterKey(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	if err := v.Set(ctx, "api_key", "sk-1234secret"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	val, err := v.Get(ctx, "api_key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if val != "sk-1234secret" {
		t.Fatalf("got %q, want %q", val, "sk-1234secret")
	}
}

func TestGet_NotFound(t *testing.T) {
	v, err := New("", masterKey(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = v.Get(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestDelete(t *testing.T) {
	v, err := New("", masterKey(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	if err := v.Set(ctx, "key1", "val1"); err != nil {
		t.Fatalf("Set key1: %v", err)
	}
	if err := v.Set(ctx, "key2", "val2"); err != nil {
		t.Fatalf("Set key2: %v", err)
	}

	if err := v.Delete(ctx, "key1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err = v.Get(ctx, "key1")
	if err == nil {
		t.Fatal("expected error after delete")
	}

	val, err := v.Get(ctx, "key2")
	if err != nil {
		t.Fatalf("Get key2 after delete: %v", err)
	}
	if val != "val2" {
		t.Fatalf("got %q, want %q", val, "val2")
	}
}

func TestList(t *testing.T) {
	v, err := New("", masterKey(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	for _, pair := range []struct{ k, v string }{{"a", "1"}, {"b", "2"}, {"c", "3"}} {
		if err := v.Set(ctx, pair.k, pair.v); err != nil {
			t.Fatalf("Set %s: %v", pair.k, err)
		}
	}

	keys, err := v.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	want := map[string]bool{"a": true, "b": true, "c": true}
	if len(keys) != len(want) {
		t.Fatalf("got %d keys, want %d", len(keys), len(want))
	}
	for _, k := range keys {
		if !want[k] {
			t.Errorf("unexpected key %q", k)
		}
	}
}

func TestPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")
	ctx := context.Background()

	v, err := New(path, masterKey(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := v.Set(ctx, "token", "secret-token"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	v2, err := New(path, masterKey(t))
	if err != nil {
		t.Fatalf("New second vault: %v", err)
	}

	val, err := v2.Get(ctx, "token")
	if err != nil {
		t.Fatalf("Get from reloaded vault: %v", err)
	}
	if val != "secret-token" {
		t.Fatalf("got %q, want %q", val, "secret-token")
	}
}

func TestEmptyKey(t *testing.T) {
	v, err := New("", masterKey(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	if err := v.Set(ctx, "", "value"); err != ErrEmptyKey {
		t.Fatalf("expected ErrEmptyKey, got %v", err)
	}
	_, err = v.Get(ctx, "")
	if err != ErrEmptyKey {
		t.Fatalf("expected ErrEmptyKey, got %v", err)
	}
	if err := v.Delete(ctx, ""); err != ErrEmptyKey {
		t.Fatalf("expected ErrEmptyKey, got %v", err)
	}
}

func TestTamperedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")
	ctx := context.Background()

	v, err := New(path, masterKey(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := v.Set(ctx, "key", "value"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	if err := os.WriteFile(path, []byte(`{"key":{"n":"AAAAAAAAAAAAAAAA","d":"BBBBBBBBBBBB"}}`), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	v2, err := New(path, masterKey(t))
	if err != nil {
		t.Fatalf("New after tamper: %v", err)
	}

	_, err = v2.Get(ctx, "key")
	if err == nil {
		t.Fatal("expected error for tampered ciphertext")
	}
}

func TestSwappedEntry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")
	ctx := context.Background()

	v, err := New(path, masterKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Set(ctx, "alpha", "one"); err != nil {
		t.Fatal(err)
	}
	if err := v.Set(ctx, "beta", "two"); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var store map[string]SecretEntry
	if err := json.Unmarshal(data, &store); err != nil {
		t.Fatal(err)
	}
	store["alpha"], store["beta"] = store["beta"], store["alpha"]
	swapped, err := json.Marshal(store)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, swapped, 0600); err != nil {
		t.Fatal(err)
	}

	v2, err := New(path, masterKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v2.Get(ctx, "alpha"); err == nil {
		t.Fatal("expected decrypt failure after entry swap")
	}
	if _, err := v2.Get(ctx, "beta"); err == nil {
		t.Fatal("expected decrypt failure after entry swap")
	}
}

func TestOverwrite(t *testing.T) {
	v, err := New("", masterKey(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	if err := v.Set(ctx, "key", "value1"); err != nil {
		t.Fatalf("Set value1: %v", err)
	}
	if err := v.Set(ctx, "key", "value2"); err != nil {
		t.Fatalf("Set value2: %v", err)
	}

	val, err := v.Get(ctx, "key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if val != "value2" {
		t.Fatalf("got %q, want %q", val, "value2")
	}
}

func TestUniqueNonces(t *testing.T) {
	v, err := New("", masterKey(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	nonces := make(map[string]bool)
	for i := 0; i < 10; i++ {
		if err := v.Set(ctx, fmt.Sprintf("key%d", i), "value"); err != nil {
			t.Fatalf("Set key%d: %v", i, err)
		}
	}

	v.mu.RLock()
	for _, entry := range v.entries {
		key := string(entry.Nonce)
		if nonces[key] {
			t.Fatal("duplicate nonce detected")
		}
		nonces[key] = true
	}
	v.mu.RUnlock()
}

func TestConcurrentSetAndReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")
	key := masterKey(t)
	ctx := context.Background()

	v, err := New(path, key)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_ = v.Set(ctx, fmt.Sprintf("key%d", n), "value")
		}(i)
	}
	wg.Wait()

	v2, err := New(path, key)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := v2.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 20 {
		t.Fatalf("got %d keys after concurrent set, want 20", len(keys))
	}
}

func TestVerifyAll(t *testing.T) {
	v, err := New("", masterKey(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := v.Set(ctx, "k", "v"); err != nil {
		t.Fatal(err)
	}
	if err := v.VerifyAll(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestRotateKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")
	oldKey := masterKey(t)
	ctx := context.Background()

	v, err := New(path, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Set(ctx, "token", "secret"); err != nil {
		t.Fatal(err)
	}

	newKey := make([]byte, 32)
	for i := range newKey {
		newKey[i] = byte(255 - i)
	}
	if err := v.RotateKey(newKey); err != nil {
		t.Fatal(err)
	}

	val, err := v.Get(ctx, "token")
	if err != nil {
		t.Fatal(err)
	}
	if val != "secret" {
		t.Fatalf("got %q", val)
	}

	v2, err := New(path, newKey)
	if err != nil {
		t.Fatal(err)
	}
	val, err = v2.Get(ctx, "token")
	if err != nil {
		t.Fatal(err)
	}
	if val != "secret" {
		t.Fatalf("reloaded got %q", val)
	}
}

func TestCloseZerosMaster(t *testing.T) {
	v, err := New("", masterKey(t))
	if err != nil {
		t.Fatal(err)
	}
	v.mu.RLock()
	hadNonZero := false
	for _, b := range v.master {
		if b != 0 {
			hadNonZero = true
			break
		}
	}
	v.mu.RUnlock()
	if !hadNonZero {
		t.Fatal("expected non-zero master key before close")
	}
	v.Close()
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.master != nil {
		for _, b := range v.master {
			if b != 0 {
				t.Fatal("master key not zeroed")
			}
		}
	}
}
