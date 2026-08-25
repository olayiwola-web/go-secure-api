package response

import (
	"encoding/json"
	"net/http"
)

// Envelope is the standard API response shape.
type Envelope struct {
	Success bool   `json:"success"`
	Data    any    `json:"data,omitempty"`
	Error   string `json:"error,omitempty"`
}

// JSON writes an arbitrary payload with the given status code.
func JSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// Success writes a successful JSON response.
func Success(w http.ResponseWriter, status int, data any) {
	JSON(w, status, Envelope{Success: true, Data: data})
}

// Error writes a failed JSON response with a message.
func Error(w http.ResponseWriter, status int, message string) {
	JSON(w, status, Envelope{Success: false, Error: message})
}

// OK is Success with HTTP 200.
func OK(w http.ResponseWriter, data any) {
	Success(w, http.StatusOK, data)
}

// Created is Success with HTTP 201.
func Created(w http.ResponseWriter, data any) {
	Success(w, http.StatusCreated, data)
}

// BadRequest is Error with HTTP 400.
func BadRequest(w http.ResponseWriter, message string) {
	Error(w, http.StatusBadRequest, message)
}

// Unauthorized is Error with HTTP 401.
func Unauthorized(w http.ResponseWriter, message string) {
	Error(w, http.StatusUnauthorized, message)
}

// Forbidden is Error with HTTP 403.
func Forbidden(w http.ResponseWriter, message string) {
	Error(w, http.StatusForbidden, message)
}

// NotFound is Error with HTTP 404.
func NotFound(w http.ResponseWriter, message string) {
	Error(w, http.StatusNotFound, message)
}

// Internal is Error with HTTP 500.
func Internal(w http.ResponseWriter, message string) {
	Error(w, http.StatusInternalServerError, message)
}
