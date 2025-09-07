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

	wconfig := &webauthn.Config{
		RPDisplayName: "Go Webauthn",                             // Display Name for your site
		RPID:          host,                                      // Generally the FQDN for your site
		RPOrigins:     []string{origin, "http://localhost:2020"}, // The origin URLs allowed for WebAuthn
	}

	webAuthn, err = webauthn.New(wconfig)
	if err != nil {
		fmt.Printf("[FATA] %s", err.Error())
		os.Exit(1)
	}

	passkeyStore = New()

	// Serve the web files
	mux := http.NewServeMux()
	// mux.Handle("/", http.FileServer(http.Dir("./web")))

	// Add auth the routes
	mux.HandleFunc("/api/passkey/registerStart", CORS(BeginRegistration))
	mux.HandleFunc("/api/passkey/registerFinish", CORS(FinishRegistration))
	mux.HandleFunc("/api/passkey/loginStart", CORS(BeginLogin))
	mux.HandleFunc("/api/passkey/loginFinish", CORS(FinishLogin))
	mux.HandleFunc("/api/passkey/logout", CORS(Logout))

	mux.HandleFunc("/api/passkey/private", CORS(LoggedInMiddleware(Private)))

	// Start the server
	log.Printf("[INFO] start server at %s", origin)
	if err := http.ListenAndServe(port, mux); err != nil {
		log.Println(err)
	}
}
