package middleware

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"os"
	"strings"
)

type ctxKey string

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			respond403(w)
			return
		}

		parts := strings.SplitN(auth, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			respond403(w)
			return
		}
		token := parts[1]

		if !validateToken(token) {
			respond403(w)
			return
		}

		clientID := r.Header.Get("X-Client-ID")
		if clientID == "" {
			respond403(w)
			return
		}

		ctx := context.WithValue(r.Context(), ctxKey("clientID"), clientID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func validateToken(token string) bool {
	expected := os.Getenv("AUTH_TOKEN")
	if expected == "" {
		return false
	}
	if len(token) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1
}

func respond403(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   "forbidden",
		"message": "invalid or missing credentials",
	})
}

// ClientIDFromContext extracts the client ID stored by the middleware.
func ClientIDFromContext(ctx context.Context) (string, bool) {
	v := ctx.Value(ctxKey("clientID"))
	if v == nil {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}
