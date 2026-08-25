package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// TokenTypeAccess identifies short-lived API access tokens.
	TokenTypeAccess = "access"
	// TokenTypeRefresh identifies longer-lived refresh tokens.
	TokenTypeRefresh = "refresh"

	RoleUser  = "user"
	RoleAdmin = "admin"
)

var (
	ErrInvalidToken     = errors.New("invalid token")
	ErrUnexpectedClaims = errors.New("unexpected token claims")
	ErrWrongTokenType   = errors.New("wrong token type")
)

// Claims are embedded in both access and refresh JWTs.
type Claims struct {
	WalletAddress string `json:"wallet_address"`
	Role          string `json:"role"`
	SessionID     string `json:"session_id"`
	TokenType     string `json:"token_type"`
	jwt.RegisteredClaims
}

// TokenPair is returned after a successful login/register/refresh.
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"` // access token lifetime in seconds
}

// JWTService issues and validates HS256 JWTs.
type JWTService struct {
	secret     []byte
	accessTTL  time.Duration
	refreshTTL time.Duration
	issuer     string
}

// NewJWTService constructs a JWTService.
// accessTTL defaults to 15 minutes when zero; refreshTTL defaults to 7 days.
func NewJWTService(secret string, accessTTL, refreshTTL time.Duration) (*JWTService, error) {
	if secret == "" {
		return nil, errors.New("jwt secret must not be empty")
	}
	if accessTTL <= 0 {
		accessTTL = 15 * time.Minute
	}
	if refreshTTL <= 0 {
		refreshTTL = 7 * 24 * time.Hour
	}
	return &JWTService{
		secret:     []byte(secret),
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
		issuer:     "go-secure-api",
	}, nil
}

// AccessTTL exposes the configured access-token lifetime.
func (s *JWTService) AccessTTL() time.Duration { return s.accessTTL }

// RefreshTTL exposes the configured refresh-token lifetime.
func (s *JWTService) RefreshTTL() time.Duration { return s.refreshTTL }

// GenerateTokenPair creates a linked access + refresh token for a session.
func (s *JWTService) GenerateTokenPair(walletAddress, role, sessionID string) (*TokenPair, error) {
	if walletAddress == "" || sessionID == "" {
		return nil, errors.New("wallet address and session id are required")
	}
	if role == "" {
		role = RoleUser
	}

	now := time.Now()

	access, err := s.sign(Claims{
		WalletAddress: walletAddress,
		Role:          role,
		SessionID:     sessionID,
		TokenType:     TokenTypeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        newID(),
			Subject:   walletAddress,
			Issuer:    s.issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.accessTTL)),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("sign access token: %w", err)
	}

	refresh, err := s.sign(Claims{
		WalletAddress: walletAddress,
		Role:          role,
		SessionID:     sessionID,
		TokenType:     TokenTypeRefresh,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        newID(),
			Subject:   walletAddress,
			Issuer:    s.issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.refreshTTL)),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("sign refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  access,
		RefreshToken: refresh,
		ExpiresIn:    int64(s.accessTTL.Seconds()),
	}, nil
}

// newID returns a 128-bit random hex string (UUID-like without an extra dependency).
func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// ValidateAccessToken parses and validates an access token.
func (s *JWTService) ValidateAccessToken(tokenString string) (*Claims, error) {
	return s.validate(tokenString, TokenTypeAccess)
}

// ValidateRefreshToken parses and validates a refresh token.
func (s *JWTService) ValidateRefreshToken(tokenString string) (*Claims, error) {
	return s.validate(tokenString, TokenTypeRefresh)
}

func (s *JWTService) sign(claims Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.secret)
}

func (s *JWTService) validate(tokenString, expectedType string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (any, error) {
		// Reject unexpected signing methods (e.g. "none" or asymmetric keys).
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("%w: unexpected signing method %v", ErrInvalidToken, t.Header["alg"])
		}
		return s.secret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrUnexpectedClaims
	}
	if claims.TokenType != expectedType {
		return nil, ErrWrongTokenType
	}
	if claims.WalletAddress == "" || claims.SessionID == "" {
		return nil, ErrUnexpectedClaims
	}
	return claims, nil
}
