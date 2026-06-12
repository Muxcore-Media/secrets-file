package vault

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

var (
	ErrNotFound     = errors.New("secret not found")
	ErrKeyRequired  = errors.New("master key is required; set SECRETS_MASTER_KEY env var or provide a key file")
	ErrKeySize      = errors.New("master key must be exactly 32 bytes for AES-256")
	ErrEmptyKey     = errors.New("secret key must not be empty")
)

type SecretEntry struct {
	Nonce []byte `json:"n"`
	Data  []byte `json:"d"`
}

type Vault struct {
	mu       sync.RWMutex
	path     string
	master   []byte
	entries  map[string]SecretEntry
	dirty    bool
}

func New(path string, masterKey []byte) (*Vault, error) {
	if len(masterKey) == 0 {
		return nil, ErrKeyRequired
	}
	if len(masterKey) != 32 {
		return nil, ErrKeySize
	}

	v := &Vault{
		path:    path,
		master:  masterKey,
		entries: make(map[string]SecretEntry),
	}

	if path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, fmt.Errorf("create secrets dir: %w", err)
		}
		if data, err := os.ReadFile(path); err == nil {
			if err := json.Unmarshal(data, &v.entries); err != nil {
				slog.Warn("secrets: failed to parse existing store, starting fresh", "path", path, "error", err)
			} else {
				slog.Info("secrets: loaded existing store", "path", path, "count", len(v.entries))
			}
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("read secrets store: %w", err)
		}
	}

	return v, nil
}

func (v *Vault) Get(_ context.Context, key string) (string, error) {
	if key == "" {
		return "", ErrEmptyKey
	}
	v.mu.RLock()
	entry, ok := v.entries[key]
	v.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrNotFound, key)
	}

	plaintext, err := decrypt(v.master, entry.Nonce, entry.Data)
	if err != nil {
		return "", fmt.Errorf("decrypt %q: %w", key, err)
	}
	return string(plaintext), nil
}

func (v *Vault) Set(_ context.Context, key, value string) error {
	if key == "" {
		return ErrEmptyKey
	}

	nonce, ciphertext, err := encrypt(v.master, []byte(value))
	if err != nil {
		return fmt.Errorf("encrypt %q: %w", key, err)
	}

	v.mu.Lock()
	v.entries[key] = SecretEntry{Nonce: nonce, Data: ciphertext}
	v.dirty = true
	v.mu.Unlock()

	if err := v.persist(); err != nil {
		return err
	}
	return nil
}

func (v *Vault) Delete(_ context.Context, key string) error {
	if key == "" {
		return ErrEmptyKey
	}
	v.mu.Lock()
	delete(v.entries, key)
	v.dirty = true
	v.mu.Unlock()
	return v.persist()
}

func (v *Vault) List(_ context.Context) ([]string, error) {
	v.mu.RLock()
	keys := make([]string, 0, len(v.entries))
	for k := range v.entries {
		keys = append(keys, k)
	}
	v.mu.RUnlock()
	return keys, nil
}

func (v *Vault) Flush() error {
	return v.persist()
}

func (v *Vault) Close() {
	v.mu.Lock()
	defer v.mu.Unlock()
	for k := range v.entries {
		delete(v.entries, k)
	}
	v.mu.Unlock()
}

func (v *Vault) persist() error {
	v.mu.RLock()
	if !v.dirty || v.path == "" {
		v.mu.RUnlock()
		return nil
	}
	data, err := json.MarshalIndent(v.entries, "", "  ")
	v.mu.RUnlock()
	if err != nil {
		return fmt.Errorf("marshal secrets: %w", err)
	}

	tmp := v.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write secrets tmp: %w", err)
	}
	if err := os.Rename(tmp, v.path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename secrets: %w", err)
	}

	v.mu.Lock()
	v.dirty = false
	v.mu.Unlock()
	return nil
}

func encrypt(key, plaintext []byte) (nonce, ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce = make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext = aesGCM.Seal(nil, nonce, plaintext, nil)
	return nonce, ciphertext, nil
}

func decrypt(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(nonce) != aesGCM.NonceSize() {
		return nil, fmt.Errorf("invalid nonce length: got %d, want %d", len(nonce), aesGCM.NonceSize())
	}

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm open: %w", err)
	}
	return plaintext, nil
}
