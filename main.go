package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/go-webauthn/webauthn/webauthn"
)

var webAuthn *webauthn.WebAuthn
var err error
var passkeyStore *PasskeyStore

func main() {
	proto := getEnv("PROTO", "http")
	host := getEnv("HOST", "localhost")
	port := getEnv("PORT", ":8080")
	origin := fmt.Sprintf("%s://%s%s", proto, host, port)

	log.Printf("[INFO] make webauthn config")
	wconfig := &webauthn.Config{
		RPDisplayName: "Go Webauthn",    // Display Name for your site
		RPID:          host,             // Generally the FQDN for your site
		RPOrigins:     []string{origin}, // The origin URLs allowed for WebAuthn
	}

	log.Printf("[INFO] create webauthn")
	webAuthn, err = webauthn.New(wconfig)
	if err != nil {
		fmt.Printf("[FATA] %s", err.Error())
		os.Exit(1)
	}

	log.Printf("[INFO] create datastore")
	passkeyStore = New()

	log.Printf("[INFO] register routes")
	// Serve the web files
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir("./web")))

	// Add auth the routes
	mux.HandleFunc("/api/passkey/registerStart", BeginRegistration)
	mux.HandleFunc("/api/passkey/registerFinish", FinishRegistration)
	mux.HandleFunc("/api/passkey/loginStart", BeginLogin)
	mux.HandleFunc("/api/passkey/loginFinish", FinishLogin)
	mux.HandleFunc("/api/passkey/logout", Logout)

	mux.Handle("/private", LoggedInMiddleware(http.HandlerFunc(PrivatePage)))

	// Start the server
	log.Printf("[INFO] start server at %s", origin)
	if err := http.ListenAndServe(port, mux); err != nil {
		fmt.Println(err)
	}
}
