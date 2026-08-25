package handler

import (
	"net/http"
	"time"

	"github.com/haidee/go-secure-api/internal/auth"
	"github.com/haidee/go-secure-api/pkg/response"
)

// AdminHandler serves admin-only endpoints.
type AdminHandler struct {
	sessions *auth.SessionStore
}

// NewAdminHandler constructs an AdminHandler.
func NewAdminHandler(sessions *auth.SessionStore) *AdminHandler {
	return &AdminHandler{sessions: sessions}
}

// Dashboard returns a simple admin overview.
// GET /admin/dashboard
func (h *AdminHandler) Dashboard(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		response.Unauthorized(w, "authentication required")
		return
	}

	response.OK(w, map[string]any{
		"message":          "welcome to the admin dashboard",
		"wallet_address":   claims.WalletAddress,
		"role":             claims.Role,
		"active_sessions":  h.sessions.Len(),
		"server_time_utc":  time.Now().UTC().Format(time.RFC3339),
	})
}
