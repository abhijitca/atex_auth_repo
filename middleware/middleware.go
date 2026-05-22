package middleware

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
)

type ctxKey string

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			logIP(r)
			respond403(w)
			return
		}

		parts := strings.SplitN(auth, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			logIP(r)
			respond403(w)
			return
		}
		token := parts[1]

		if !validateToken(token) {
			logIP(r)
			respond403(w)
			return
		}

		clientID := r.Header.Get("X-Client-ID")
		if clientID == "" {
			logIP(r)
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

func respond403(w http.ResponseWriter, r *http.Request) {
	sourceIP := r.RemoteAddr // Extracts the source IP from the request

	// Log the source IP in a structured format
	logEntry := map[string]string{
		"error":     "forbidden",
		"message":   "invalid or missing credentials",
		"source_ip": sourceIP, // Log the source IP
	}
	logData, err := json.Marshal(logEntry) // Convert the log entry to JSON
	if err == nil {
		log.Println(string(logData)) // Log it
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   "forbidden",
		"message": "invalid or missing credentials",
	})
}

func logIP(r *http.Request) {
	ipInfo := map[string]string{
		"sourceIP": r.RemoteAddr,
	}
	logData, err := json.Marshal(ipInfo)
	if err == nil {
		log.Println(string(logData))
	}
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
