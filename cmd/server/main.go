package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/haidee/go-secure-api/internal/auth"
	"github.com/haidee/go-secure-api/internal/config"
	"github.com/haidee/go-secure-api/internal/handler"
	"github.com/haidee/go-secure-api/internal/middleware"
	"github.com/haidee/go-secure-api/pkg/response"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	jwtService, err := auth.NewJWTService(cfg.JWTSecret, cfg.AccessTokenTTL, cfg.RefreshTokenTTL)
	if err != nil {
		log.Fatalf("jwt: %v", err)
	}

	sessions := auth.NewSessionStore()
	authMw := auth.NewMiddleware(jwtService, sessions)
	limiter := middleware.NewRateLimiter(cfg.RateLimitRequests, cfg.RateLimitWindow)

	authHandler := handler.NewAuthHandler(cfg, jwtService, sessions)
	userHandler := handler.NewUserHandler()
	adminHandler := handler.NewAdminHandler(sessions)

	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		response.OK(w, map[string]string{"status": "ok"})
	})

	// Public auth routes (still rate-limited).
	mux.Handle("POST /auth/login", limiter.Middleware(http.HandlerFunc(authHandler.Login)))
	mux.Handle("POST /auth/refresh", limiter.Middleware(http.HandlerFunc(authHandler.Refresh)))

	// Protected user route.
	mux.Handle("GET /me", limiter.Middleware(authMw.Authenticate(http.HandlerFunc(userHandler.Me))))

	// Admin-only route (authenticate, then require admin role).
	mux.Handle("GET /admin/dashboard", limiter.Middleware(
		authMw.Authenticate(authMw.RequireAdmin(http.HandlerFunc(adminHandler.Dashboard))),
	))

	server := &http.Server{
		Addr:              cfg.Addr(),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("server listening on %s", cfg.Addr())
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		log.Fatalf("server failed: %v", err)
	case sig := <-stop:
		log.Printf("shutdown signal received: %v", sig)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("graceful shutdown failed: %v", err)
	}

	fmt.Println("server stopped")
}
