package main

import (
	"io"
	"net/http"
	"os"
	"strings"

	spinhttp "github.com/fermyon/spin/sdk/go/http"
	"github.com/fermyon/spin/sdk/go/redis"
)

func init() {
	spinhttp.Handle(outboxHand)
}

func main() {}

func outboxHand(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/outbox" {
		http.NotFound(w, r)
		return
	}

	//TODO ***verify signature***
	//TODO ***verify date***

	// restrict max to 1MB
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)
	buf, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Unexpected content body", http.StatusRequestEntityTooLarge)
		return
	}
	defer r.Body.Close()

	// just capture it for now (and process it later)
	if err := addDebug(r.Header, buf); err != nil {
		http.Error(w, "debug", http.StatusInsufficientStorage)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func addDebug(h http.Header, buf []byte) error {
	// save request to debug
	var pseudo = h.Get("Digest")
	var b strings.Builder
	b.Write(buf)
	b.WriteString(";DEBUG:")
	b.WriteString(h.Get("Signature"))
	return save(pseudo, []byte(b.String()))
}

func save(key string, val []byte) error {
	var addr = os.Getenv("REDIS_ADDRESS")
	return redis.Set(addr, key, val)
}
