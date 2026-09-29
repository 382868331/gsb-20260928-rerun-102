package httpapi

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"idp/internal/auth"
	"idp/internal/store"
)

type Server struct {
	svc *auth.Service
	mux *http.ServeMux
}

func New(svc *auth.Service) *Server {
	s := &Server{svc: svc, mux: http.NewServeMux()}
	s.mux.HandleFunc("POST /v1/auth/login", s.handleLogin)
	s.mux.HandleFunc("POST /v1/auth/refresh", s.handleRefresh)
	s.mux.HandleFunc("POST /v1/auth/logout", s.handleLogout)
	s.mux.HandleFunc("GET /v1/me", s.handleMe)
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type meResponse struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !decode(w, r, &req) {
		return
	}
	tokens, _, err := s.svc.Login(req.Username, req.Password)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		log.Printf("login rejected username=%q", safeName(req.Username))
		return
	}
	writeJSON(w, http.StatusOK, tokenResponse(tokens))
	log.Printf("login succeeded username=%q", safeName(req.Username))
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if !decode(w, r, &req) {
		return
	}
	tokens, err := s.svc.Refresh(req.RefreshToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "refresh token rejected")
		log.Println("refresh rejected token=redacted")
		return
	}
	writeJSON(w, http.StatusOK, tokenResponse(tokens))
	log.Println("refresh succeeded token=redacted")
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	token, ok := bearerToken(w, r)
	if !ok {
		return
	}
	if err := s.svc.Logout(token); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusUnauthorized, "session not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "logout failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
	log.Println("logout succeeded session=redacted")
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	token, ok := bearerToken(w, r)
	if !ok {
		return
	}
	u, _, err := s.svc.Authenticate(token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "access token rejected")
		return
	}
	writeJSON(w, http.StatusOK, meResponse{UserID: u.ID, Username: u.Username})
}

func decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

func bearerToken(w http.ResponseWriter, r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	token, ok := strings.CutPrefix(h, "Bearer ")
	if !ok || token == "" {
		writeError(w, http.StatusUnauthorized, "missing bearer token")
		return "", false
	}
	return token, true
}

type errorResponse struct {
	Error string `json:"error"`
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorResponse{Error: msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if status == http.StatusNoContent {
		return
	}
	_ = json.NewEncoder(w).Encode(v)
}

func safeName(name string) string {
	if len(name) > 64 {
		return name[:64]
	}
	return name
}
