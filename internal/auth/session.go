package auth

import (
	"errors"
	"sync"
	"time"
)

var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")
	ErrSessionMismatch = errors.New("session does not match wallet address")
)

// Session binds an authenticated client to a wallet address.
type Session struct {
	ID            string
	WalletAddress string
	Role          string
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

// IsExpired reports whether the session past its expiry.
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// SessionStore is a thread-safe in-memory session registry.
// Suitable for demos and single-instance deployments; swap for Redis/DB in production.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session // sessionID -> session
	byWallet map[string]string   // walletAddress -> sessionID (one active session per wallet)
}

// NewSessionStore creates an empty in-memory store.
func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[string]*Session),
		byWallet: make(map[string]string),
	}
}

// Create registers a new session for the wallet.
// If the wallet already has a session, the previous one is replaced.
func (st *SessionStore) Create(walletAddress, role string, ttl time.Duration) (*Session, error) {
	if walletAddress == "" {
		return nil, errors.New("wallet address is required")
	}
	if role == "" {
		role = RoleUser
	}
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}

	now := time.Now()
	session := &Session{
		ID:            newID(),
		WalletAddress: walletAddress,
		Role:          role,
		CreatedAt:     now,
		ExpiresAt:     now.Add(ttl),
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	// Drop any existing session for this wallet so only one remains active.
	if oldID, ok := st.byWallet[walletAddress]; ok {
		delete(st.sessions, oldID)
	}

	st.sessions[session.ID] = session
	st.byWallet[walletAddress] = session.ID
	return session, nil
}

// Get returns a session by ID, or an error if missing/expired.
func (st *SessionStore) Get(sessionID string) (*Session, error) {
	st.mu.RLock()
	session, ok := st.sessions[sessionID]
	st.mu.RUnlock()
	if !ok {
		return nil, ErrSessionNotFound
	}
	if session.IsExpired() {
		_ = st.Delete(sessionID)
		return nil, ErrSessionExpired
	}
	return session, nil
}

// GetByWallet returns the active session for a wallet address.
func (st *SessionStore) GetByWallet(walletAddress string) (*Session, error) {
	st.mu.RLock()
	id, ok := st.byWallet[walletAddress]
	st.mu.RUnlock()
	if !ok {
		return nil, ErrSessionNotFound
	}
	return st.Get(id)
}

// Validate ensures the session exists, is not expired, and matches the wallet.
func (st *SessionStore) Validate(sessionID, walletAddress string) (*Session, error) {
	session, err := st.Get(sessionID)
	if err != nil {
		return nil, err
	}
	if session.WalletAddress != walletAddress {
		return nil, ErrSessionMismatch
	}
	return session, nil
}

// Delete removes a session by ID.
func (st *SessionStore) Delete(sessionID string) error {
	st.mu.Lock()
	defer st.mu.Unlock()

	session, ok := st.sessions[sessionID]
	if !ok {
		return ErrSessionNotFound
	}
	delete(st.sessions, sessionID)
	if st.byWallet[session.WalletAddress] == sessionID {
		delete(st.byWallet, session.WalletAddress)
	}
	return nil
}

// DeleteByWallet removes the active session for a wallet, if any.
func (st *SessionStore) DeleteByWallet(walletAddress string) {
	st.mu.Lock()
	defer st.mu.Unlock()

	if id, ok := st.byWallet[walletAddress]; ok {
		delete(st.sessions, id)
		delete(st.byWallet, walletAddress)
	}
}

// Len returns the number of tracked sessions (for diagnostics).
func (st *SessionStore) Len() int {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return len(st.sessions)
}
