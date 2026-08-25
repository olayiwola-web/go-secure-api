package handler_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/haidee/go-secure-api/internal/auth"
	"github.com/haidee/go-secure-api/internal/config"
	"github.com/haidee/go-secure-api/internal/handler"
	"github.com/haidee/go-secure-api/internal/middleware"
)

func TestAuthFlow(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:         "test-secret-please-change",
		AccessTokenTTL:    15 * time.Minute,
		RefreshTokenTTL:   time.Hour,
		AdminWallets:      map[string]struct{}{"0xadmin000000000000000000000000000000000001": {}},
		RateLimitRequests: 1000,
		RateLimitWindow:   time.Minute,
	}

	jwtService, err := auth.NewJWTService(cfg.JWTSecret, cfg.AccessTokenTTL, cfg.RefreshTokenTTL)
	if err != nil {
		t.Fatal(err)
	}
	sessions := auth.NewSessionStore()
	authMw := auth.NewMiddleware(jwtService, sessions)
	limiter := middleware.NewRateLimiter(cfg.RateLimitRequests, cfg.RateLimitWindow)

	authHandler := handler.NewAuthHandler(cfg, jwtService, sessions)
	userHandler := handler.NewUserHandler()
	adminHandler := handler.NewAdminHandler(sessions)

	mux := http.NewServeMux()
	mux.Handle("POST /auth/login", limiter.Middleware(http.HandlerFunc(authHandler.Login)))
	mux.Handle("POST /auth/refresh", limiter.Middleware(http.HandlerFunc(authHandler.Refresh)))
	mux.Handle("GET /me", limiter.Middleware(authMw.Authenticate(http.HandlerFunc(userHandler.Me))))
	mux.Handle("GET /admin/dashboard", limiter.Middleware(
		authMw.Authenticate(authMw.RequireAdmin(http.HandlerFunc(adminHandler.Dashboard))),
	))

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// User login
	userBody := postJSON(t, ts.URL+"/auth/login", map[string]string{
		"wallet_address": "0xUser000000000000000000000000000000000001",
	})
	if userBody["success"] != true {
		t.Fatalf("login failed: %#v", userBody)
	}
	userData := userBody["data"].(map[string]any)
	if userData["role"] != "user" {
		t.Fatalf("expected user role, got %v", userData["role"])
	}
	access := userData["access_token"].(string)
	refresh := userData["refresh_token"].(string)

	// /me
	me := getAuth(t, ts.URL+"/me", access)
	if me["success"] != true {
		t.Fatalf("/me failed: %#v", me)
	}

	// Admin denied for user
	status, _ := getAuthStatus(t, ts.URL+"/admin/dashboard", access)
	if status != http.StatusForbidden {
		t.Fatalf("expected 403 for user on admin route, got %d", status)
	}

	// Admin login
	adminBody := postJSON(t, ts.URL+"/auth/login", map[string]string{
		"wallet_address": "0xadmin000000000000000000000000000000000001",
	})
	adminAccess := adminBody["data"].(map[string]any)["access_token"].(string)
	if adminBody["data"].(map[string]any)["role"] != "admin" {
		t.Fatalf("expected admin role")
	}
	dash := getAuth(t, ts.URL+"/admin/dashboard", adminAccess)
	if dash["success"] != true {
		t.Fatalf("admin dashboard failed: %#v", dash)
	}

	// Refresh
	ref := postJSON(t, ts.URL+"/auth/refresh", map[string]string{"refresh_token": refresh})
	if ref["success"] != true {
		t.Fatalf("refresh failed: %#v", ref)
	}
}

func postJSON(t *testing.T, url string, payload any) map[string]any {
	t.Helper()
	b, _ := json.Marshal(payload)
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func getAuth(t *testing.T, url, token string) map[string]any {
	t.Helper()
	_, body := getAuthStatus(t, url, token)
	return body
}

func getAuthStatus(t *testing.T, url, token string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}
