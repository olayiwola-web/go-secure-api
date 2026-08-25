package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds runtime settings loaded from the environment.
type Config struct {
	Host string
	Port string

	JWTSecret              string
	AccessTokenTTL         time.Duration
	RefreshTokenTTL        time.Duration
	AdminWallets           map[string]struct{}
	RateLimitRequests      int
	RateLimitWindow        time.Duration
	ShutdownTimeout        time.Duration
}

// Addr returns the listen address (host:port).
func (c *Config) Addr() string {
	if c.Host == "" {
		return ":" + c.Port
	}
	return c.Host + ":" + c.Port
}

// IsAdminWallet reports whether the wallet is configured as an admin.
func (c *Config) IsAdminWallet(wallet string) bool {
	_, ok := c.AdminWallets[strings.ToLower(strings.TrimSpace(wallet))]
	return ok
}

// Load reads configuration from environment variables.
// If a local .env file exists it is loaded first (does not override existing env vars).
func Load() (*Config, error) {
	_ = loadDotEnv(".env")

	cfg := &Config{
		Host:              getEnv("HOST", "0.0.0.0"),
		Port:              getEnv("PORT", "8080"),
		JWTSecret:         getEnv("JWT_SECRET", ""),
		AccessTokenTTL:    time.Duration(getEnvInt("ACCESS_TOKEN_TTL_MINUTES", 15)) * time.Minute,
		RefreshTokenTTL:   time.Duration(getEnvInt("REFRESH_TOKEN_TTL_HOURS", 168)) * time.Hour,
		AdminWallets:      parseWalletSet(getEnv("ADMIN_WALLETS", "")),
		RateLimitRequests: getEnvInt("RATE_LIMIT_REQUESTS", 100),
		RateLimitWindow:   time.Duration(getEnvInt("RATE_LIMIT_WINDOW_SECONDS", 60)) * time.Second,
		ShutdownTimeout:   10 * time.Second,
	}

	if cfg.JWTSecret == "" {
		return nil, fmt.Errorf("JWT_SECRET is required")
	}
	if cfg.Port == "" {
		return nil, fmt.Errorf("PORT is required")
	}

	return cfg, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return n
}

func parseWalletSet(raw string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, part := range strings.Split(raw, ",") {
		w := strings.ToLower(strings.TrimSpace(part))
		if w != "" {
			out[w] = struct{}{}
		}
	}
	return out
}

// loadDotEnv parses a simple KEY=VALUE .env file into the process environment.
// Existing variables are left untouched so real env wins over the file.
func loadDotEnv(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		value = strings.Trim(value, `"'`)
		if key == "" {
			continue
		}
		if _, exists := os.LookupEnv(key); !exists {
			_ = os.Setenv(key, value)
		}
	}
	return scanner.Err()
}
