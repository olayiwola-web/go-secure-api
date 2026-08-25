package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/haidee/go-secure-api/pkg/response"
)

type contextKey string

const (
	claimsContextKey  contextKey = "auth_claims"
	sessionContextKey contextKey = "auth_session"
)

// Middleware protects routes with JWT access-token validation and session binding.
type Middleware struct {
	jwt      *JWTService
	sessions *SessionStore
}

// NewMiddleware wires JWT validation with the in-memory session store.
func NewMiddleware(jwtService *JWTService, sessions *SessionStore) *Middleware {
	return &Middleware{jwt: jwtService, sessions: sessions}
}

// Authenticate requires a valid Bearer access token bound to an active session.
func (m *Middleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r)
		if !ok {
			response.Unauthorized(w, "missing or invalid authorization header")
			return
		}

		claims, err := m.jwt.ValidateAccessToken(token)
		if err != nil {
			response.Unauthorized(w, "invalid or expired access token")
			return
		}

		// Enforce session ↔ wallet binding so revoked/replaced sessions fail fast.
		session, err := m.sessions.Validate(claims.SessionID, claims.WalletAddress)
		if err != nil {
			response.Unauthorized(w, "session is invalid or expired")
			return
		}

		ctx := context.WithValue(r.Context(), claimsContextKey, claims)
		ctx = context.WithValue(ctx, sessionContextKey, session)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireAdmin must run after Authenticate and rejects non-admin roles.
func (m *Middleware) RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := ClaimsFromContext(r.Context())
		if !ok {
			response.Unauthorized(w, "authentication required")
			return
		}
		if claims.Role != RoleAdmin {
			response.Forbidden(w, "admin role required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ClaimsFromContext returns JWT claims previously set by Authenticate.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(claimsContextKey).(*Claims)
	return claims, ok
}

// SessionFromContext returns the bound session previously set by Authenticate.
func SessionFromContext(ctx context.Context) (*Session, bool) {
	session, ok := ctx.Value(sessionContextKey).(*Session)
	return session, ok
}

// WalletFromContext is a convenience helper for handlers.
func WalletFromContext(ctx context.Context) (string, bool) {
	claims, ok := ClaimsFromContext(ctx)
	if !ok {
		return "", false
	}
	return claims.WalletAddress, true
}

func bearerToken(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", false
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", false
	}
	return parts[1], true
}
