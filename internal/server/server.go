package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/Muxcore-Media/secrets-file/internal/vault"
)

type Server struct {
	vault      *vault.Vault
	getCount   atomic.Int64
	setCount   atomic.Int64
	delCount   atomic.Int64
}

func New(v *vault.Vault) *Server {
	return &Server{vault: v}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/secrets/", s.handleKey)
	mux.HandleFunc("/v1/secrets", s.handleList)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/metrics", s.handleMetrics)
	return mux
}

func (s *Server) handleKey(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimPrefix(r.URL.Path, "/v1/secrets/")
	key = strings.TrimSuffix(key, "/")
	if key == "" {
		http.Error(w, `{"error":"key is required"}`, http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleGet(w, r, key)
	case http.MethodPut:
		s.handleSet(w, r, key)
	case http.MethodDelete:
		s.handleDelete(w, r, key)
	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request, key string) {
	val, err := s.vault.Get(r.Context(), key)
	if err != nil {
		if err == vault.ErrNotFound {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err), http.StatusNotFound)
			return
		}
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		slog.Error("secrets: get failed", "key", key, "error", err)
		return
	}
	s.getCount.Add(1)
	writeJSON(w, http.StatusOK, map[string]string{"key": key, "value": val})
}

func (s *Server) handleSet(w http.ResponseWriter, r *http.Request, key string) {
	var req struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if err := s.vault.Set(r.Context(), key, req.Value); err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		slog.Error("secrets: set failed", "key", key, "error", err)
		return
	}
	s.setCount.Add(1)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request, key string) {
	if err := s.vault.Delete(r.Context(), key); err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		slog.Error("secrets: delete failed", "key", key, "error", err)
		return
	}
	s.delCount.Add(1)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	keys, err := s.vault.List(r.Context())
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		slog.Error("secrets: list failed", "error", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys, "count": len(keys)})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	var b strings.Builder
	b.WriteString("# HELP secrets_get_total Total secret get operations\n")
	b.WriteString("# TYPE secrets_get_total counter\n")
	fmt.Fprintf(&b, "secrets_get_total %d\n", s.getCount.Load())
	b.WriteString("# HELP secrets_set_total Total secret set operations\n")
	b.WriteString("# TYPE secrets_set_total counter\n")
	fmt.Fprintf(&b, "secrets_set_total %d\n", s.setCount.Load())
	b.WriteString("# HELP secrets_delete_total Total secret delete operations\n")
	b.WriteString("# TYPE secrets_delete_total counter\n")
	fmt.Fprintf(&b, "secrets_delete_total %d\n", s.delCount.Load())
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.Write([]byte(b.String()))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
