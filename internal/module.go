package internal

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"google.golang.org/grpc"

	"github.com/Muxcore-Media/core/pkg/contracts"
	modulesdk "github.com/Muxcore-Media/core/sdk/go/module"
	"github.com/Muxcore-Media/secrets-file/internal/server"
	"github.com/Muxcore-Media/secrets-file/internal/vault"
)

type Module struct {
	vault   *vault.Vault
	srv     *server.Server
	grpcSrv *grpc.Server
	lis     net.Listener

	id          string
	cfgMu       sync.RWMutex
	store       string
	keyFile     string
	grpcAddr    string
	allowedRoot string
	moduleToken string
}

type Config struct {
	ID          string
	Store       string
	KeyFile     string
	GRPCAddr    string
	ModuleToken string
}

func NewModule(cfg Config) *Module {
	if cfg.ID == "" {
		cfg.ID = "secrets-file"
	}
	if cfg.Store == "" {
		cfg.Store = "secrets.json"
	}
	if cfg.GRPCAddr == "" {
		cfg.GRPCAddr = "127.0.0.1:9550"
	}
	if v := os.Getenv("SECRETS_STORE"); v != "" {
		cfg.Store = v
	}
	if v := os.Getenv("SECRETS_KEY_FILE"); v != "" {
		cfg.KeyFile = v
	}
	if v := os.Getenv("SECRETS_GRPC_ADDR"); v != "" {
		cfg.GRPCAddr = v
	}
	if cfg.ModuleToken == "" {
		cfg.ModuleToken = moduleTokenFromEnv()
	}
	cfg.Store = absPath(cfg.Store)
	cfg.KeyFile = absPath(cfg.KeyFile)
	return &Module{
		id:          cfg.ID,
		store:       cfg.Store,
		keyFile:     cfg.KeyFile,
		grpcAddr:    cfg.GRPCAddr,
		allowedRoot: resolveAllowedRoot(cfg.Store, cfg.KeyFile),
		moduleToken: cfg.ModuleToken,
	}
}

func (m *Module) Info() contracts.ModuleInfo {
	return contracts.ModuleInfo{
		ID:           m.id,
		Name:         "Secrets File Vault",
		Version:      Version,
		Roles:        []string{"security"},
		Description:  "AES-256-GCM encrypted file-backed secrets vault",
		Author:       "MuxCore",
		Capabilities: []string{contracts.CapabilitySecrets, "secrets.file", "settings"},
	}
}

func (m *Module) Init(ctx context.Context) error {
	m.store = absPath(m.store)
	m.keyFile = absPath(m.keyFile)
	m.allowedRoot = resolveAllowedRoot(m.store, m.keyFile)

	if err := validateStoragePath(m.allowedRoot, m.store); err != nil {
		return fmt.Errorf("store path: %w", err)
	}
	if m.keyFile != "" {
		if err := validateStoragePath(m.allowedRoot, m.keyFile); err != nil {
			return fmt.Errorf("key file path: %w", err)
		}
	}

	masterKey, err := loadMasterKey(m.keyFile, true)
	if err != nil {
		return fmt.Errorf("load master key: %w", err)
	}

	v, err := vault.New(m.store, masterKey)
	if err != nil {
		return fmt.Errorf("open vault: %w", err)
	}
	m.vault = v
	m.srv = server.New(v)

	lis, err := net.Listen("tcp", m.grpcAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", m.grpcAddr, err)
	}
	m.lis = lis

	slog.Info("secrets-file initialized", "store", m.store, "addr", m.grpcAddr)
	return nil
}

func (m *Module) Start(ctx context.Context) error {
	m.grpcSrv = grpc.NewServer(grpc.UnaryInterceptor(authUnaryInterceptor(m.moduleToken)))
	m.srv.RegisterWithGRPC(m.grpcSrv)
	modulesdk.RegisterSettings(m.grpcSrv, m.id, m)

	go func() {
		slog.Info("secrets-file gRPC service started", "addr", m.grpcAddr)
		if err := m.grpcSrv.Serve(m.lis); err != nil {
			slog.Error("secrets-file gRPC serve error", "error", err)
		}
	}()
	return nil
}

func (m *Module) Stop(ctx context.Context) error {
	if m.grpcSrv != nil {
		m.grpcSrv.GracefulStop()
	}
	if m.vault != nil {
		_ = m.vault.Flush()
		m.vault.Close()
	}
	slog.Info("secrets-file stopped")
	return nil
}

func (m *Module) Health(ctx context.Context) error {
	if m.vault == nil {
		return fmt.Errorf("not initialized")
	}
	if err := m.vault.VerifyAll(ctx); err != nil {
		return err
	}
	if m.srv != nil {
		return m.srv.Health(ctx)
	}
	return nil
}

func absPath(p string) string {
	if p == "" {
		return ""
	}
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return filepath.Clean(p)
}

func loadMasterKey(path string, persistEnvToFile bool) ([]byte, error) {
	envKey := os.Getenv("SECRETS_MASTER_KEY")
	if envKey != "" {
		key, err := decodeHexKey(envKey, "SECRETS_MASTER_KEY")
		if err != nil {
			return nil, err
		}
		if persistEnvToFile && path != "" {
			if _, err := os.Stat(path); os.IsNotExist(err) {
				if err := writeKeyFile(path, key); err != nil {
					return nil, err
				}
				slog.Info("persisted SECRETS_MASTER_KEY to key file", "path", path)
			}
		}
		return key, nil
	}

	if path == "" {
		return nil, fmt.Errorf("master key required: set SECRETS_MASTER_KEY or SECRETS_KEY_FILE")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("key file %q does not exist", path)
		}
		return nil, fmt.Errorf("read key file: %w", err)
	}

	key, err := decodeHexKey(strings.TrimSpace(string(data)), "key file")
	if err != nil {
		return nil, err
	}
	slog.Info("master key loaded from file", "path", path)
	return key, nil
}

func decodeHexKey(raw, label string) ([]byte, error) {
	key, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("%s must be hex-encoded 32 bytes: %w", label, err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("%s must be exactly 64 hex chars (32 bytes), got %d bytes", label, len(key))
	}
	return key, nil
}

func writeKeyFile(path string, key []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create key dir: %w", err)
	}
	encoded := hex.EncodeToString(key)
	if err := os.WriteFile(path, []byte(encoded+"\n"), 0600); err != nil {
		return fmt.Errorf("write key file: %w", err)
	}
	return nil
}

func (m *Module) rotateMasterKey() error {
	m.cfgMu.Lock()
	defer m.cfgMu.Unlock()

	if m.vault == nil {
		return fmt.Errorf("vault not initialized")
	}
	if m.keyFile == "" {
		return fmt.Errorf("key_file must be configured for rotation")
	}
	if err := validateStoragePath(m.allowedRoot, m.keyFile); err != nil {
		return err
	}

	newKey := make([]byte, 32)
	if _, err := rand.Read(newKey); err != nil {
		return fmt.Errorf("generate master key: %w", err)
	}
	if err := m.vault.RotateKey(newKey); err != nil {
		return fmt.Errorf("rotate vault keys: %w", err)
	}
	if err := writeKeyFile(m.keyFile, newKey); err != nil {
		return fmt.Errorf("write rotated key file: %w", err)
	}
	for i := range newKey {
		newKey[i] = 0
	}
	slog.Info("master key rotated", "path", m.keyFile)
	return nil
}
