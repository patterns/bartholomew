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
	spinhttp.Handle(inboxHand)
}

func main() {}

func inboxHand(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/inbox" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Not implemented yet", http.StatusNotImplemented)
		return
	}
	var sig = r.Header.Get("Signature")
	var ct = r.Header.Get("Content-Type")
	if sig == "" || ct == "" {
		http.Error(w, "Missing headers", http.StatusPreconditionFailed)
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
	var bag = rehydrate(ct, buf)
	if len(bag) == 0 {
		http.Error(w, "Unknown JSON", http.StatusUnprocessableEntity)
		return
	}
	act, ok := bag["type"]
	if !ok {
		http.Error(w, "Activity type is required", http.StatusPreconditionRequired)
		return
	}
	switch act {
	case "Reject", "Undo":
		if err := addFilter(r.Header, buf); err != nil {
			http.Error(w, "Not saved", http.StatusInternalServerError)
			return
		}
	case "Accept":
		if err := acknowledge(r.Header, buf); err != nil {
			http.Error(w, "Not saved", http.StatusInternalServerError)
			return
		}
	case "Follow":
		if err := addSubscription(r.Header, buf); err != nil {
			http.Error(w, "Not saved", http.StatusInternalServerError)
			return
		}

	default:
		//Create
		//Remove
		//Delete
		// (No content yet, so ignored for now)
		if err := addDebug(r.Header, buf); err != nil {
			http.Error(w, "debug", http.StatusInsufficientStorage)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
}

func addFilter(h http.Header, buf []byte) error {
	// save request to filter recipients list
	////return publish("channelFilter", buf)
	var pseudo = h.Get("digest")
	return save(pseudo, buf)
}
func addSubscription(h http.Header, buf []byte) error {
	// save request, someone wants our newsletter
	// TODO answer with the Accept activity
	//      (publish event to redis channel for another component)
	////return publish("channelNewsletter", buf)
	var pseudo = h.Get("digest")
	return save(pseudo, buf)

}
func acknowledge(h http.Header, buf []byte) error {
	// save request to know subscribe-to worked
	////return publish("channelAck", buf)
	var pseudo = h.Get("digest")
	return save(pseudo, buf)
}
func addDebug(h http.Header, buf []byte) error {
	// save request to debug
	////return publish("channelDebug", buf)
	var pseudo = h.Get("digest")
	return save(pseudo, buf)
}

func publish(ch string, val []byte) error {
	// addr is the environment variable set in `spin.toml` that points to the
	// address of the Redis server.
	var addr = os.Getenv("REDIS_ADDRESS")
	return redis.Publish(addr, ch, val)
}

func save(key string, val []byte) error {
	// addr is the environment variable set in `spin.toml` that points to the
	// address of the Redis server.
	var addr = os.Getenv("REDIS_ADDRESS")
	return redis.Set(addr, key, val)
}

func rehydrate(ct string, buf []byte) map[string]string {
	/*
		if !strings.Contains(ct, "json") {
			return make(map[string]string)
		}*/

	////err = json.Unmarshal(buf, &data)
	//todo naive json until better understanding of encode/json
	//     (dont need anything complicated for now)

	raw := string(buf)
	txt := strings.Trim(raw, "{}")
	pairs := strings.Split(txt, ",")
	data := make(map[string]string)
	for _, p := range pairs {
		kv := strings.Split(p, ":")
		if len(kv) < 2 {
			continue
		}
		name := strings.Trim(kv[0], `"' `)
		val := strings.Trim(kv[1], `"' `)
		low := strings.ToLower(name)
		data[low] = val
	}

	return data
}
