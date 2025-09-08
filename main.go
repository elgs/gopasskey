package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	"github.com/go-webauthn/webauthn/webauthn"
)

var err error
var webAuthn *webauthn.WebAuthn
var passkeyStore *PasskeyStore
var db *sql.DB

func main() {
	initDB()
	defer db.Close()
	initPasskeyStore()
	initApiServer()
}

func initApiServer() {
	host := os.Getenv("HOST")
	port := os.Getenv("PORT")

	mux := http.NewServeMux()
	mux.HandleFunc("/api/passkey/registerStart", CORS(BeginRegistration))
	mux.HandleFunc("/api/passkey/registerFinish", CORS(FinishRegistration))
	mux.HandleFunc("/api/passkey/loginStart", CORS(BeginLogin))
	mux.HandleFunc("/api/passkey/loginFinish", CORS(FinishLogin))
	mux.HandleFunc("/api/passkey/logout", CORS(Logout))
	mux.HandleFunc("/api/passkey/private", CORS(LoggedInMiddleware(Private)))

	if err := http.ListenAndServe(fmt.Sprintf("%s:%s", host, port), mux); err != nil {
		log.Println(err)
	}
}

func initPasskeyStore() {
	rpName := os.Getenv("RP_NAME")
	host := os.Getenv("HOST")
	origins := os.Getenv("ORIGINS")
	wconfig := &webauthn.Config{
		RPDisplayName: rpName,                      // Display Name for your site
		RPID:          host,                        // Generally the FQDN for your site
		RPOrigins:     strings.Split(origins, ","), // The origin URLs allowed for WebAuthn
	}
	webAuthn, err = webauthn.New(wconfig)
	if err != nil {
		fmt.Printf("[FATA] %s", err.Error())
		os.Exit(1)
	}
	passkeyStore = NewPasskeyStore()
}

func initDB() {
	var err error
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbName := os.Getenv("DB_NAME")

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true", dbUser, dbPassword, dbHost, dbPort, dbName)
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		fmt.Printf("[FATA] %s", err.Error())
		os.Exit(1)
	}

	if err = db.Ping(); err != nil {
		fmt.Printf("[FATA] %s", err.Error())
		os.Exit(1)
	}

	fmt.Println("[INFO] connected to database")
}
