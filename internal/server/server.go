package server

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	secretsv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/secrets/v1"
	"github.com/Muxcore-Media/secrets-file/internal/vault"
)

type Server struct {
	secretsv1.UnimplementedSecretsServiceServer
	vaultPtr atomic.Pointer[vault.Vault]
	getCount atomic.Int64
	setCount atomic.Int64
	delCount atomic.Int64
}

func New(v *vault.Vault) *Server {
	s := &Server{}
	s.vaultPtr.Store(v)
	return s
}

// ReplaceVault swaps the backing vault. Returns the previous vault (caller should Flush/Close).
func (s *Server) ReplaceVault(v *vault.Vault) *vault.Vault {
	return s.vaultPtr.Swap(v)
}

func (s *Server) vault() *vault.Vault {
	return s.vaultPtr.Load()
}

func (s *Server) RegisterWithGRPC(srv *grpc.Server) {
	secretsv1.RegisterSecretsServiceServer(srv, s)
}

func (s *Server) Health(ctx context.Context) error {
	return s.vault().VerifyAll(ctx)
}

func (s *Server) Get(ctx context.Context, req *secretsv1.GetRequest) (*secretsv1.GetResponse, error) {
	if req.GetKey() == "" {
		return nil, status.Error(codes.InvalidArgument, "key is required")
	}
	val, err := s.vault().Get(ctx, req.GetKey())
	if err != nil {
		if errors.Is(err, vault.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "secret not found")
		}
		if errors.Is(err, vault.ErrEmptyKey) {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		slog.Error("secrets: get failed", "error", err)
		return nil, status.Error(codes.FailedPrecondition, "decrypt failed")
	}
	s.getCount.Add(1)
	return &secretsv1.GetResponse{Key: req.GetKey(), Value: val}, nil
}

func (s *Server) Set(ctx context.Context, req *secretsv1.SetRequest) (*secretsv1.SetResponse, error) {
	if req.GetKey() == "" {
		return nil, status.Error(codes.InvalidArgument, "key is required")
	}
	if err := s.vault().Set(ctx, req.GetKey(), req.GetValue()); err != nil {
		slog.Error("secrets: set failed", "error", err)
		return nil, status.Error(codes.Internal, "set failed")
	}
	s.setCount.Add(1)
	return &secretsv1.SetResponse{Status: "ok"}, nil
}

func (s *Server) Delete(ctx context.Context, req *secretsv1.DeleteRequest) (*secretsv1.DeleteResponse, error) {
	if req.GetKey() == "" {
		return nil, status.Error(codes.InvalidArgument, "key is required")
	}
	if err := s.vault().Delete(ctx, req.GetKey()); err != nil {
		slog.Error("secrets: delete failed", "error", err)
		return nil, status.Error(codes.Internal, "delete failed")
	}
	s.delCount.Add(1)
	return &secretsv1.DeleteResponse{Status: "ok"}, nil
}

func (s *Server) List(ctx context.Context, req *secretsv1.ListRequest) (*secretsv1.ListResponse, error) {
	keys, err := s.vault().List(ctx)
	if err != nil {
		slog.Error("secrets: list failed", "error", err)
		return nil, status.Error(codes.Internal, "list failed")
	}
	return &secretsv1.ListResponse{Keys: keys, Count: int32(len(keys))}, nil
}
