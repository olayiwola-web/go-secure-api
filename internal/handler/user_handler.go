package handler

import (
	"net/http"

	"github.com/haidee/go-secure-api/internal/auth"
	"github.com/haidee/go-secure-api/internal/model"
	"github.com/haidee/go-secure-api/pkg/response"
)

// UserHandler serves authenticated user endpoints.
type UserHandler struct{}

// NewUserHandler constructs a UserHandler.
func NewUserHandler() *UserHandler {
	return &UserHandler{}
}

// Me returns the current wallet identity from the access-token context.
// GET /me
func (h *UserHandler) Me(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		response.Unauthorized(w, "authentication required")
		return
	}

	response.OK(w, model.User{
		WalletAddress: claims.WalletAddress,
		Role:          claims.Role,
		SessionID:     claims.SessionID,
	})
}
