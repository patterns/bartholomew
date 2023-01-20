// Actor component to demo static JSON
package main

import (
	_ "embed"
	"net/http"
	"os"

	spinhttp "github.com/fermyon/spin/sdk/go/http"
)

//go:embed actor.json
var actorJSON []byte

//go:embed followers.json
var followersJSON []byte

//go:embed following.json
var followingJSON []byte

func init() {
	spinhttp.Handle(actorHand)
}

func actorHand(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	var path = "/u/" + os.Getenv("SELF_ACTOR")
	switch r.URL.Path {
	case path:
		w.Write(actorJSON)
	case path + "/followers":
		w.Write(followersJSON)
	case path + "/following":
		w.Write(followingJSON)
	default:
		http.NotFound(w, r)
	}
}

func main() {}
