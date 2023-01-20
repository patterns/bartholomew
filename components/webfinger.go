// Webfinger component to demo static JSON
package main

import (
	_ "embed"
	"net/http"
	"os"

	spinhttp "github.com/fermyon/spin/sdk/go/http"
)

//go:embed webfinger.json
var webfingerJSON []byte

func init() {
	spinhttp.Handle(webfingerHand)
}

func main() {}

func webfingerHand(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/well-known/webfinger" &&
		r.URL.Path != "/.well-known/webfinger" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	var resource = r.URL.Query().Get("resource")
	if resource == "" {
		http.Error(w, "The resource query parameter is missing", http.StatusBadRequest)
		return
	}

	if unknownResource(resource) {
		http.Error(w, "Unknown resource", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/jrd+json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	w.Write(webfingerJSON)
}

func unknownResource(resource string) bool {
	var match = false
	var re = formatResource()
	for _, known := range re {
		if resource == known {
			match = true
			break
		}
	}
	return !match
}
func formatResource() []string {
	var self = os.Getenv("SELF_ACTOR")
	var subd = os.Getenv("SITE_NAME")
	var ar []string

	//case "acct:self@subd":
	ar = append(ar, "acct:"+self+"@"+subd+".fermyon.app")

	//case "mailto:self@subd"
	ar = append(ar, "mailto:"+self+"@"+subd+".fermyon.app")

	//case "https://subd"
	ar = append(ar, "https:"+subd+".fermyon.app")

	//case "https://subd/"
	ar = append(ar, "https:"+subd+".fermyon.app/")

	return ar
}
