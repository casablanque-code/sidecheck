// Realistic fixture #2: Go, standard library, zero dependencies. Unlike
// test_fixture.py, there's NO artificial delay per matched byte.
// /vulnerable uses a plain Go `==` on strings, the way it's actually
// written in production (and the way Copilot/Claude write it unless
// explicitly asked for constant-time). The leak here is whatever
// actually happens at the CPU/memory level, not an amplified demo.
//
// Run:    go run main.go
// Secret: "correct-secret-key-123456"
package main

import (
	"crypto/subtle"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
)

// Secret length is configurable via SECRET_LEN (25 by default, as in the
// original fixture). The secret is built deterministically from a
// repeating pattern, so the result is reproducible across runs at the
// same length.
func buildSecret(length int) string {
	const pattern = "correct-secret-key-123456"
	b := make([]byte, length)
	for i := range b {
		b[i] = pattern[i%len(pattern)]
	}
	return string(b)
}

func secretLength() int {
	if v := os.Getenv("SECRET_LEN"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 25
}

var secret = buildSecret(secretLength())

func vulnerableHandler(w http.ResponseWriter, r *http.Request) {
	candidate := r.Header.Get("X-API-Key")
	// exactly how this gets written in real code: a plain string
	// comparison. Go's == on strings compares length, then bytes in
	// order, and stops at the first mismatch — the exact behavior we're
	// looking for, with no amplification on our side.
	if candidate == secret {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "denied")
	}
}

func safeHandler(w http.ResponseWriter, r *http.Request) {
	candidate := r.Header.Get("X-API-Key")
	ok := subtle.ConstantTimeCompare([]byte(candidate), []byte(secret)) == 1
	if ok {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "denied")
	}
}

func main() {
	http.HandleFunc("/vulnerable", vulnerableHandler)
	http.HandleFunc("/safe", safeHandler)
	// 0.0.0.0, not 127.0.0.1: this fixture is also meant to be run from a
	// real remote vantage point (a VPS, testing over an actual network
	// path instead of loopback) — binding to 127.0.0.1 only accepts
	// connections addressed to that literal loopback address, so a client
	// hitting the box's public IP just hangs until the client's own
	// request timeout, with no hint from this side about why. This is a
	// deliberately timing-vulnerable endpoint, though — see README.md's
	// note on restricting inbound access with ufw/security groups rather
	// than leaving it open to the whole internet while it's up.
	addr := "0.0.0.0:8001"
	fmt.Printf("realistic Go fixture on http://%s (reachable on any interface, not just loopback)\n", addr)
	fmt.Println("  /vulnerable — real == comparison, no artificial delay")
	fmt.Println("  /safe       — subtle.ConstantTimeCompare")
	fmt.Printf("  secret length: %d bytes (set SECRET_LEN to change)\n", len(secret))
	fmt.Printf("  secret: %q\n", secret)
	log.Fatal(http.ListenAndServe(addr, nil))
}
