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
	ErrCorruptStore = errors.New("secrets store is corrupt or invalid")
)

type SecretEntry struct {
	Nonce []byte `json:"n"`
	Data  []byte `json:"d"`
}

type Vault struct {
	mu      sync.RWMutex
	path    string
	master  []byte
	entries map[string]SecretEntry
	dirty   bool
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
		master:  append([]byte(nil), masterKey...),
		entries: make(map[string]SecretEntry),
	}

	if path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, fmt.Errorf("create secrets dir: %w", err)
		}
		if data, err := os.ReadFile(path); err == nil {
			if err := json.Unmarshal(data, &v.entries); err != nil {
				return nil, fmt.Errorf("%w: %v", ErrCorruptStore, err)
			}
			slog.Info("secrets: loaded existing store", "path", path, "count", len(v.entries))
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

	plaintext, err := decrypt(v.master, entry.Nonce, entry.Data, key)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}
	return string(plaintext), nil
}

func (v *Vault) Set(_ context.Context, key, value string) error {
	if key == "" {
		return ErrEmptyKey
	}

	nonce, ciphertext, err := encrypt(v.master, []byte(value), key)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	v.mu.Lock()
	v.entries[key] = SecretEntry{Nonce: nonce, Data: ciphertext}
	v.dirty = true
	err = v.persistLocked()
	v.mu.Unlock()
	return err
}

func (v *Vault) Delete(_ context.Context, key string) error {
	if key == "" {
		return ErrEmptyKey
	}
	v.mu.Lock()
	delete(v.entries, key)
	v.dirty = true
	err := v.persistLocked()
	v.mu.Unlock()
	return err
}

func (v *Vault) List(_ context.Context) ([]string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	keys := make([]string, 0, len(v.entries))
	for k := range v.entries {
		keys = append(keys, k)
	}
	return keys, nil
}

func (v *Vault) Count() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.entries)
}

// VerifyAll decrypts every stored entry; used for health checks.
func (v *Vault) VerifyAll(ctx context.Context) error {
	v.mu.RLock()
	defer v.mu.RUnlock()
	for key, entry := range v.entries {
		if _, err := decrypt(v.master, entry.Nonce, entry.Data, key); err != nil {
			return fmt.Errorf("entry decrypt failed: %w", err)
		}
	}
	return nil
}

// RotateKey re-encrypts all entries under a new master key.
func (v *Vault) RotateKey(newMaster []byte) error {
	if len(newMaster) != 32 {
		return ErrKeySize
	}
	v.mu.Lock()
	defer v.mu.Unlock()

	newEntries := make(map[string]SecretEntry, len(v.entries))
	for key, entry := range v.entries {
		plaintext, err := decrypt(v.master, entry.Nonce, entry.Data, key)
		if err != nil {
			return fmt.Errorf("decrypt during rotation: %w", err)
		}
		nonce, ciphertext, err := encrypt(newMaster, plaintext, key)
		if err != nil {
			return fmt.Errorf("encrypt during rotation: %w", err)
		}
		newEntries[key] = SecretEntry{Nonce: nonce, Data: ciphertext}
	}
	v.entries = newEntries
	for i := range v.master {
		v.master[i] = 0
	}
	v.master = append([]byte(nil), newMaster...)
	v.dirty = true
	return v.persistLocked()
}

// CopyEntries copies all secrets into dst.
func (v *Vault) CopyEntries(ctx context.Context, dst *Vault) error {
	v.mu.RLock()
	keys := make([]string, 0, len(v.entries))
	for k := range v.entries {
		keys = append(keys, k)
	}
	v.mu.RUnlock()

	for _, key := range keys {
		val, err := v.Get(ctx, key)
		if err != nil {
			return err
		}
		if err := dst.Set(ctx, key, val); err != nil {
			return err
		}
	}
	return nil
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
	for i := range v.master {
		v.master[i] = 0
	}
	v.master = nil
}

func (v *Vault) persist() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.persistLocked()
}

func (v *Vault) persistLocked() error {
	for v.dirty && v.path != "" {
		data, err := json.MarshalIndent(v.entries, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal secrets: %w", err)
		}

		tmp := v.path + ".tmp"
		f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return fmt.Errorf("open secrets tmp: %w", err)
		}
		if _, err := f.Write(data); err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
			return fmt.Errorf("write secrets tmp: %w", err)
		}
		if err := f.Sync(); err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
			return fmt.Errorf("sync secrets tmp: %w", err)
		}
		if err := f.Close(); err != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("close secrets tmp: %w", err)
		}
		if err := syncParentDir(v.path); err != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("sync secrets dir: %w", err)
		}
		if err := os.Rename(tmp, v.path); err != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("rename secrets: %w", err)
		}
		if err := syncParentDir(v.path); err != nil {
			return fmt.Errorf("sync secrets dir after rename: %w", err)
		}

		v.dirty = false
	}
	return nil
}

func syncParentDir(path string) error {
	dir := filepath.Dir(path)
	df, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = df.Close() }()
	return df.Sync()
}

func encrypt(key, plaintext []byte, aad string) (nonce, ciphertext []byte, err error) {
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

	ciphertext = aesGCM.Seal(nil, nonce, plaintext, []byte(aad))
	return nonce, ciphertext, nil
}

func decrypt(key, nonce, ciphertext []byte, aad string) ([]byte, error) {
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

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, []byte(aad))
	if err != nil {
		return nil, fmt.Errorf("aes-gcm open: %w", err)
	}
	return plaintext, nil
}
