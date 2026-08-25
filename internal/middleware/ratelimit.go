package middleware

import (
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/haidee/go-secure-api/pkg/response"
)

// RateLimiter is a simple fixed-window, per-key in-memory limiter.
type RateLimiter struct {
	mu       sync.Mutex
	limit    int
	window   time.Duration
	visitors map[string]*visitor
}

type visitor struct {
	count       int
	windowStart time.Time
}

// NewRateLimiter allows `limit` requests per `window` for each key (typically client IP).
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	if limit <= 0 {
		limit = 100
	}
	if window <= 0 {
		window = time.Minute
	}
	rl := &RateLimiter{
		limit:    limit,
		window:   window,
		visitors: make(map[string]*visitor),
	}
	// Periodically prune stale entries so the map does not grow without bound.
	go rl.cleanupLoop()
	return rl
}

// Allow reports whether the key may proceed and records the attempt when allowed.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	v, ok := rl.visitors[key]
	if !ok || now.Sub(v.windowStart) >= rl.window {
		rl.visitors[key] = &visitor{count: 1, windowStart: now}
		return true
	}
	if v.count >= rl.limit {
		return false
	}
	v.count++
	return true
}

// Middleware returns an HTTP middleware that rate-limits by client IP.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := clientIP(r)
		if !rl.Allow(key) {
			response.Error(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.window)
	defer ticker.Stop()
	for range ticker.C {
		rl.cleanup()
	}
}

func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for key, v := range rl.visitors {
		if now.Sub(v.windowStart) >= rl.window {
			delete(rl.visitors, key)
		}
	}
}

func clientIP(r *http.Request) string {
	// Prefer the direct remote address; X-Forwarded-For is easy to spoof without a trusted proxy.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
