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

	"google.golang.org/grpc"

	"github.com/Muxcore-Media/core/pkg/contracts"
	"github.com/Muxcore-Media/secrets-file/internal/server"
	"github.com/Muxcore-Media/secrets-file/internal/vault"
)

type Module struct {
	vault   *vault.Vault
	srv     *server.Server
	grpcSrv *grpc.Server
	lis     net.Listener

	id       string
	store    string
	keyFile  string
	grpcAddr string
}

type Config struct {
	ID       string
	Store    string
	KeyFile  string
	GRPCAddr string
}

func NewModule(cfg Config) *Module {
	if cfg.ID == "" {
		cfg.ID = "secrets-file"
	}
	if cfg.Store == "" {
		cfg.Store = "secrets.json"
	}
	if cfg.GRPCAddr == "" {
		cfg.GRPCAddr = ":9550"
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
	return &Module{
		id:       cfg.ID,
		store:    cfg.Store,
		keyFile:  cfg.KeyFile,
		grpcAddr: cfg.GRPCAddr,
	}
}

func (m *Module) Info() contracts.ModuleInfo {
	return contracts.ModuleInfo{
		ID:           m.id,
		Name:         "Secrets File Vault",
		Version:      "0.1.0",
		Roles:        []string{"security"},
		Description:  "AES-256-GCM encrypted file-backed secrets vault",
		Author:       "MuxCore",
		Capabilities: []string{contracts.CapabilitySecrets, "secrets.file"},
		HTTPAddr:     m.grpcAddr,
	}
}

func (m *Module) Init(ctx context.Context) error {
	masterKey, err := loadMasterKey(m.keyFile)
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
	m.grpcSrv = grpc.NewServer()
	m.srv.RegisterWithGRPC(m.grpcSrv)

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
		m.vault.Flush()
		m.vault.Close()
	}
	slog.Info("secrets-file stopped")
	return nil
}

func (m *Module) Health(ctx context.Context) error {
	if m.vault == nil {
		return fmt.Errorf("not initialized")
	}
	_, err := m.vault.List(ctx)
	return err
}

func loadMasterKey(path string) ([]byte, error) {
	envKey := os.Getenv("SECRETS_MASTER_KEY")
	if envKey != "" {
		key, err := hex.DecodeString(envKey)
		if err != nil {
			return nil, fmt.Errorf("SECRETS_MASTER_KEY must be hex-encoded 32 bytes: %w", err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("SECRETS_MASTER_KEY must be exactly 64 hex chars (32 bytes), got %d bytes", len(key))
		}
		return key, nil
	}

	if path == "" {
		return nil, fmt.Errorf("master key required: set SECRETS_MASTER_KEY or --key-file")
	}

	if data, err := os.ReadFile(path); err == nil {
		key, err := hex.DecodeString(strings.TrimSpace(string(data)))
		if err != nil {
			return nil, fmt.Errorf("key file must contain hex-encoded 32 bytes: %w", err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("key file must contain exactly 64 hex chars (32 bytes), got %d bytes", len(key))
		}
		slog.Info("master key loaded from file", "path", path)
		return key, nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("create key dir: %w", err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate master key: %w", err)
	}

	encoded := hex.EncodeToString(key)
	if err := os.WriteFile(path, []byte(encoded+"\n"), 0600); err != nil {
		return nil, fmt.Errorf("write key file: %w", err)
	}
	slog.Info("generated new master key", "path", path)
	return key, nil
}
