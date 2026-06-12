package vault

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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

	v.Set(ctx, "key1", "val1")
	v.Set(ctx, "key2", "val2")

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

	v.Set(ctx, "a", "1")
	v.Set(ctx, "b", "2")
	v.Set(ctx, "c", "3")

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
	v.Set(ctx, "key", "value")

	os.WriteFile(path, []byte(`{"key":{"n":"AAAAAAAAAAAAAAAAAAAAAA","d":"BBBB"}}`), 0600)

	v2, err := New(path, masterKey(t))
	if err != nil {
		t.Fatalf("New after tamper: %v", err)
	}

	_, err = v2.Get(ctx, "key")
	if err == nil {
		t.Fatal("expected error for tampered ciphertext")
	}
}

func TestOverwrite(t *testing.T) {
	v, err := New("", masterKey(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	v.Set(ctx, "key", "value1")
	v.Set(ctx, "key", "value2")

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
		v.Set(ctx, fmt.Sprintf("key%d", i), "value")
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
