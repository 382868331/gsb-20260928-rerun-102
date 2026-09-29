package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"idp/internal/auth"
	"idp/internal/httpapi"
	"idp/internal/store"
)

func main() {
	addr := flag.String("addr", envOr("IDP_ADDR", "127.0.0.1:8080"), "local listen address")
	dataDir := flag.String("data-dir", envOr("IDP_DATA_DIR", "./data"), "directory for persistent state")
	accessTTL := flag.Duration("access-ttl", 2*time.Minute, "access token lifetime")
	refreshTTL := flag.Duration("refresh-ttl", 30*time.Minute, "refresh token lifetime")
	flag.Parse()

	st, err := store.Open(filepath.Join(*dataDir, "idp-state.json"))
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	if _, ok := st.UserByUsername("alice"); !ok {
		password := os.Getenv("IDP_SEED_PASSWORD")
		if password == "" {
			generated, err := store.RandomToken()
			if err != nil {
				log.Fatalf("generate seed password: %v", err)
			}
			password = generated[:20]
		}
		salt, hash, err := auth.NewPasswordHash(password, auth.DefaultPBKDF2Iterations)
		if err != nil {
			log.Fatalf("hash seed password: %v", err)
		}
		err = st.CreateUser(store.User{
			Username:     "alice",
			Salt:         salt,
			PasswordHash: hash,
			Iterations:   auth.DefaultPBKDF2Iterations,
			Enabled:      true,
			CreatedAt:    time.Now().UTC(),
		})
		if err != nil {
			log.Fatalf("create seed user: %v", err)
		}
		credPath := filepath.Join(*dataDir, "alice-test-password.txt")
		if err := os.WriteFile(credPath, []byte(password+"\n"), 0o600); err != nil {
			log.Fatalf("write generated credentials: %v", err)
		}
		fmt.Printf("Generated test account alice; password written to %s (0600).\n", credPath)
	}

	svc := &auth.Service{Store: st, AccessTTL: *accessTTL, RefreshTTL: *refreshTTL}
	handler := httpapi.New(svc)
	log.Printf("identity service listening on %s", *addr)
	log.Printf("sensitive fields are never logged; only hashes and salts are persisted")
	if err := http.ListenAndServe(*addr, handler); err != nil {
		log.Fatal(err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
