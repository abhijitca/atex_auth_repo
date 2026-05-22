package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"atex_auth_repo/middleware"
)

func main() {
	if os.Getenv("AUTH_TOKEN") == "" {
		log.Println("WARN: AUTH_TOKEN is not set. Set it before making requests to succeed authentication.")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		clientID, _ := middleware.ClientIDFromContext(r.Context())
		fmt.Fprintf(w, `{"status":"ok","client_id":"%s"}` , clientID)
	})

	handler := middleware.AuthMiddleware(mux)

	srv := &http.Server{
		Addr:         ":8080",
		Handler:      handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	log.Println("listening on :8080")
	log.Fatal(srv.ListenAndServe())
}
