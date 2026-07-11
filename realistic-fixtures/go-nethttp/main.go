// Реалистичный полигон #2: Go, стандартная библиотека, ноль зависимостей.
// В отличие от test_fixture.py — здесь НЕТ искусственной задержки на
// совпавший байт. /vulnerable использует обычное go `==` на строках,
// как оно реально пишется в проде (и как его пишет Copilot/Claude, если
// не попросить явно про constant-time). Утечка здесь — это то, что
// действительно происходит на уровне CPU/памяти, не усиленная демонстрация.
//
// Запуск:   go run main.go
// Секрет:   "correct-secret-key-123456"
package main

import (
	"crypto/subtle"
	"fmt"
	"log"
	"net/http"
)

const secret = "correct-secret-key-123456"

func vulnerableHandler(w http.ResponseWriter, r *http.Request) {
	candidate := r.Header.Get("X-API-Key")
	// именно так это пишут в реальном коде: обычное сравнение строк.
	// go's == на строках сравнивает длину, затем байты по порядку и
	// останавливается на первом несовпадении — то самое поведение,
	// которое мы ищем, без каких-либо усилений с нашей стороны.
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
	fmt.Println("realistic Go fixture on http://127.0.0.1:8001")
	fmt.Println("  /vulnerable — real == comparison, no artificial delay")
	fmt.Println("  /safe       — subtle.ConstantTimeCompare")
	fmt.Printf("  secret: %q\n", secret)
	log.Fatal(http.ListenAndServe("127.0.0.1:8001", nil))
}
