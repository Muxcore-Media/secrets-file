package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/Muxcore-Media/secrets-file/internal/server"
	"github.com/Muxcore-Media/secrets-file/internal/vault"
	"github.com/Muxcore-Media/core/pkg/contracts"
	modulev1 "github.com/Muxcore-Media/core/proto/gen/muxcore/module/v1"
)

func main() {
	meshAddr := flag.String("muxcore-mesh-addr", "localhost:9090", "gRPC address of the MuxCore mesh")
	moduleID := flag.String("muxcore-module-id", "secrets-file", "Module identifier")
	storePath := flag.String("store", "secrets.json", "Path to encrypted secrets store file")
	keyFile := flag.String("key-file", "", "Path to master key file (32 bytes hex); generated if missing")
	httpAddr := flag.String("http-addr", ":9500", "Address for HTTP secrets API")
	healthAddr := flag.String("health-addr", ":9501", "Address for HTTP health and metrics")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
	slog.Info("starting secrets-file", "version", "0.1.0")

	masterKey, err := loadMasterKey(*keyFile)
	if err != nil {
		slog.Error("failed to load master key", "error", err)
		os.Exit(1)
	}

	v, err := vault.New(*storePath, masterKey)
	if err != nil {
		slog.Error("failed to open vault", "error", err)
		os.Exit(1)
	}
	defer v.Close()

	srv := server.New(v)

	healthLis, err := net.Listen("tcp", *healthAddr)
	if err != nil {
		slog.Warn("health listen failed", "addr", *healthAddr, "error", err)
	} else {
		go func() {
			slog.Info("HTTP health and metrics listening", "addr", *healthAddr)
			if err := http.Serve(healthLis, srv.Handler()); err != nil {
				slog.Error("health server error", "error", err)
			}
		}()
	}

	apiLis, err := net.Listen("tcp", *httpAddr)
	if err != nil {
		slog.Error("failed to listen", "addr", *httpAddr, "error", err)
		os.Exit(1)
	}
	go func() {
		slog.Info("HTTP secrets API listening", "addr", *httpAddr)
		if err := http.Serve(apiLis, srv.Handler()); err != nil {
			slog.Error("API server error", "error", err)
		}
	}()

	conn, err := grpc.NewClient(*meshAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		slog.Warn("core not reachable, running standalone", "addr", *meshAddr, "error", err)
	} else {
		defer conn.Close()
		slog.Info("connected to core mesh", "addr", *meshAddr)

		regClient := modulev1.NewModuleRegistrationClient(conn)
		resp, err := regClient.Register(context.Background(), &modulev1.RegisterRequest{
			ModuleId: *moduleID,
			ModuleInfo: &modulev1.ModuleInfo{
				Id:           *moduleID,
				Name:         "Secrets File Vault",
				Version:      "0.1.0",
				Description:  "AES-256-GCM encrypted file-backed secrets vault",
				Author:       "MuxCore",
				Roles:        []string{"security"},
				Capabilities: []string{contracts.CapabilitySecrets},
				HttpAddr:     *httpAddr,
			},
		})
		if err != nil {
			slog.Warn("registration failed, running standalone", "error", err)
		} else if !resp.Accepted {
			slog.Warn("registration rejected, running standalone", "reason", resp.Error)
		} else {
			slog.Info("module registered with core",
				"id", *moduleID,
				"mesh_addr", resp.MeshAddr,
				"node_id", resp.NodeId,
			)
		}
	}

	sighupCh := make(chan os.Signal, 1)
	signal.Notify(sighupCh, syscall.SIGHUP)
	go func() {
		for range sighupCh {
			slog.Info("SIGHUP received — flushing secrets store")
			if err := v.Flush(); err != nil {
				slog.Error("flush failed", "error", err)
			}
		}
	}()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	<-ctx.Done()

	slog.Info("shutting down...")

	if conn != nil {
		regClient := modulev1.NewModuleRegistrationClient(conn)
		regClient.Unregister(context.Background(), &modulev1.UnregisterRequest{ModuleId: *moduleID})
	}

	v.Flush()
	slog.Info("shutdown complete")
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
		slog.Info("master key loaded from SECRETS_MASTER_KEY env var")
		return key, nil
	}

	if path == "" {
		return nil, fmt.Errorf("master key required: set SECRETS_MASTER_KEY env var or --key-file")
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

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: secrets-file [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
}
