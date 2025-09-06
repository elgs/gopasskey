package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

var webAuthn *webauthn.WebAuthn
var err error
var datastore *PasskeyStore

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
	datastore = NewInMem()

	log.Printf("[INFO] register routes")
	// Serve the web files
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir("./web")))

	// Add auth the routes
	mux.HandleFunc("/api/passkey/registerStart", BeginRegistration)
	mux.HandleFunc("/api/passkey/registerFinish", FinishRegistration)
	mux.HandleFunc("/api/passkey/loginStart", BeginLogin)
	mux.HandleFunc("/api/passkey/loginFinish", FinishLogin)

	mux.Handle("/private", LoggedInMiddleware(http.HandlerFunc(PrivatePage)))

	// Start the server
	log.Printf("[INFO] start server at %s", origin)
	if err := http.ListenAndServe(port, mux); err != nil {
		fmt.Println(err)
	}
}

func PrivatePage(w http.ResponseWriter, r *http.Request) {
	// just show "Hello, World!" for now
	_, _ = w.Write([]byte("Hello, World!"))
}

// JSONResponse is a helper function to send json response
func JSONResponse(w http.ResponseWriter, data any, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// getUsername is a helper function to extract the username from json request
func getUsername(r *http.Request) (string, error) {
	type Username struct {
		Username string `json:"username"`
	}
	var u Username
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		return "", err
	}

	return u.Username, nil
}

func LoggedInMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: url to redirect to should be passed as a parameter

		sid, err := r.Cookie("sid")
		if err != nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)

			return
		}

		session := datastore.GetSession(sid.Value)
		if session == nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)

			return
		}

		if session.Expires.Before(time.Now()) {
			http.Redirect(w, r, "/", http.StatusSeeOther)

			return
		}

		next.ServeHTTP(w, r)
	})
}
