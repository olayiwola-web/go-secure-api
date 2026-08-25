package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/haidee/go-secure-api/internal/auth"
	"github.com/haidee/go-secure-api/internal/config"
	"github.com/haidee/go-secure-api/pkg/response"
)

// AuthHandler serves login and token-refresh endpoints.
type AuthHandler struct {
	cfg      *config.Config
	jwt      *auth.JWTService
	sessions *auth.SessionStore
}

// NewAuthHandler constructs an AuthHandler.
func NewAuthHandler(cfg *config.Config, jwtService *auth.JWTService, sessions *auth.SessionStore) *AuthHandler {
	return &AuthHandler{cfg: cfg, jwt: jwtService, sessions: sessions}
}

type loginRequest struct {
	WalletAddress string `json:"wallet_address"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type authResponse struct {
	WalletAddress string `json:"wallet_address"`
	Role          string `json:"role"`
	SessionID     string `json:"session_id"`
	AccessToken   string `json:"access_token"`
	RefreshToken  string `json:"refresh_token"`
	ExpiresIn     int64  `json:"expires_in"`
}

// Login simulates wallet-based auth: creates a session and returns a token pair.
// POST /auth/login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}

	wallet := normalizeWallet(req.WalletAddress)
	if wallet == "" {
		response.BadRequest(w, "wallet_address is required")
		return
	}

	role := auth.RoleUser
	if h.cfg.IsAdminWallet(wallet) {
		role = auth.RoleAdmin
	}

	session, err := h.sessions.Create(wallet, role, h.jwt.RefreshTTL())
	if err != nil {
		response.Internal(w, "failed to create session")
		return
	}

	tokens, err := h.jwt.GenerateTokenPair(wallet, role, session.ID)
	if err != nil {
		_ = h.sessions.Delete(session.ID)
		response.Internal(w, "failed to issue tokens")
		return
	}

	response.OK(w, authResponse{
		WalletAddress: wallet,
		Role:          role,
		SessionID:     session.ID,
		AccessToken:   tokens.AccessToken,
		RefreshToken:  tokens.RefreshToken,
		ExpiresIn:     tokens.ExpiresIn,
	})
}

// Refresh validates a refresh token, checks the bound session, and issues a new pair.
// POST /auth/refresh
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}
	if strings.TrimSpace(req.RefreshToken) == "" {
		response.BadRequest(w, "refresh_token is required")
		return
	}

	claims, err := h.jwt.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		response.Unauthorized(w, "invalid or expired refresh token")
		return
	}

	session, err := h.sessions.Validate(claims.SessionID, claims.WalletAddress)
	if err != nil {
		response.Unauthorized(w, "session is invalid or expired")
		return
	}

	tokens, err := h.jwt.GenerateTokenPair(session.WalletAddress, session.Role, session.ID)
	if err != nil {
		response.Internal(w, "failed to issue tokens")
		return
	}

	response.OK(w, authResponse{
		WalletAddress: session.WalletAddress,
		Role:          session.Role,
		SessionID:     session.ID,
		AccessToken:   tokens.AccessToken,
		RefreshToken:  tokens.RefreshToken,
		ExpiresIn:     tokens.ExpiresIn,
	})
}

func normalizeWallet(wallet string) string {
	return strings.ToLower(strings.TrimSpace(wallet))
}
