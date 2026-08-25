package model

// User is a lightweight representation of an authenticated wallet identity.
type User struct {
	WalletAddress string `json:"wallet_address"`
	Role          string `json:"role"`
	SessionID     string `json:"session_id,omitempty"`
}
